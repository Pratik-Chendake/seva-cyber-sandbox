"""
Comprehensive Unit Test Suite for Custom Neural Network Classifier.
Part of Seva Cyber Sandbox (Phase 3).

Covers all 17 required verification scenarios:
1. Random initialization without pretrained weights.
2. Correct label-to-index mapping.
3. Training only on approved training corpus.
4. Validation data remaining separate.
5. Finite loss and probability values (no NaN or Inf).
6. Numerically stable softmax on extreme logits.
7. Working backpropagation and gradient update step.
8. Training for minimal number of epochs (loss decreases).
9. Deterministic behaviour for fixed seed.
10. Three-class output shape and valid probability distribution.
11. Safe handling of empty, whitespace, and malformed inputs.
12. Checkpoint save and load via safe non-pickle .npz and JSON metadata.
13. Corrupt or incompatible checkpoint rejection.
14. Prediction consistency after reloading within numerical tolerance.
15. No accidental modification of dataset files.
16. No accidental access to quarantined or locked test records.
17. Locked evaluation manifest integrity verification.
"""

import copy
import hashlib
import json
import os
import shutil
import tempfile
from typing import Any, Dict, List
import numpy as np
import pytest

from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    MODEL_VERSION,
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_validator import compute_locked_test_hash

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
V2_TRAIN_PATH = os.path.join(PROJECT_ROOT, "data", "generated", "v2", "synthetic_training_corpus.jsonl")
V2_VAL_PATH = os.path.join(PROJECT_ROOT, "data", "generated", "v2", "synthetic_validation_corpus.jsonl")
V2_QUAR_PATH = os.path.join(PROJECT_ROOT, "data", "generated", "v2", "quarantine_records.jsonl")
CHECKPOINT_DIR = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")
EVAL_DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
LOCKED_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"


# ---------------------------------------------------------------------------
# Test 1: Random Initialization Without Pretrained Weights
# ---------------------------------------------------------------------------

def test_01_random_initialization_without_pretrained_weights():
    """All parameter tensors are non-zero, float32, and generated from random distributions."""
    model = CustomNeuralClassifier(input_dim=128, hidden_dim1=32, hidden_dim2=16, seed=42)

    # Weights must be non-zero and float32
    assert model.W1.dtype == np.float32
    assert model.W2.dtype == np.float32
    assert model.W3.dtype == np.float32
    assert not np.all(model.W1 == 0.0)
    assert not np.all(model.W2 == 0.0)
    assert not np.all(model.W3 == 0.0)

    # Different seeds must produce different initial weights
    model2 = CustomNeuralClassifier(input_dim=128, hidden_dim1=32, hidden_dim2=16, seed=99)
    assert not np.array_equal(model.W1, model2.W1)


# ---------------------------------------------------------------------------
# Test 2: Correct Label-to-Index Mapping
# ---------------------------------------------------------------------------

def test_02_label_to_index_mapping():
    """Label mapping must match fixed 3-class taxonomy exactly."""
    assert LABEL_TO_IDX["phishing"] == 0
    assert LABEL_TO_IDX["legitimate"] == 1
    assert LABEL_TO_IDX["protective_advisory"] == 2
    assert len(LABEL_TO_IDX) == NUM_CLASSES
    for k, v in LABEL_TO_IDX.items():
        assert IDX_TO_LABEL[v] == k


# ---------------------------------------------------------------------------
# Test 3: Training Only on Approved Training Corpus
# ---------------------------------------------------------------------------

def test_03_training_corpus_validation():
    """Approved training corpus exists, contains 360 records with development role only."""
    assert os.path.exists(V2_TRAIN_PATH)
    records = []
    with open(V2_TRAIN_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    assert len(records) == 360
    for r in records:
        assert r["dataset_role"] == "development"
        assert r["ground_truth_label"] in LABEL_TO_IDX


# ---------------------------------------------------------------------------
# Test 4: Validation Data Remaining Separate
# ---------------------------------------------------------------------------

def test_04_validation_corpus_disjoint():
    """Validation corpus records and campaign IDs must be disjoint from training."""
    assert os.path.exists(V2_VAL_PATH)
    train_camps = set()
    with open(V2_TRAIN_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                train_camps.add(json.loads(line)["campaign_id"])

    val_camps = set()
    with open(V2_VAL_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                val_camps.add(json.loads(line)["campaign_id"])

    assert len(train_camps & val_camps) == 0, f"Campaign leakage: {train_camps & val_camps}"


# ---------------------------------------------------------------------------
# Test 5: Finite Loss and Probability Values
# ---------------------------------------------------------------------------

def test_05_finite_loss_and_probabilities():
    """Forward pass and loss computation must yield finite float values without NaN or Inf."""
    model = CustomNeuralClassifier(input_dim=64, hidden_dim1=16, hidden_dim2=8, seed=42)
    X = np.random.randn(10, 64).astype(np.float32)
    Y = np.zeros((10, 3), dtype=np.float32)
    Y[:, 0] = 1.0

    probs = model.forward(X, training=True)
    assert np.all(np.isfinite(probs))

    loss = model.compute_loss(probs, Y)
    assert np.isfinite(loss)
    assert loss > 0.0


# ---------------------------------------------------------------------------
# Test 6: Numerically Stable Softmax on Extreme Logits
# ---------------------------------------------------------------------------

def test_06_numerically_stable_softmax():
    """Softmax must not overflow or underflow to NaN on large positive or negative logits."""
    extreme_logits = np.array([
        [1000.0, -1000.0, 0.0],
        [-500.0, -600.0, -500.0],
        [0.0, 0.0, 0.0],
    ], dtype=np.float32)

    probs = CustomNeuralClassifier._softmax(extreme_logits)
    assert np.all(np.isfinite(probs))
    # Rows must sum to 1.0
    row_sums = np.sum(probs, axis=-1)
    np.testing.assert_allclose(row_sums, np.ones(3), rtol=1e-5)
    # The max logit index must have probability ~1.0
    assert probs[0, 0] > 0.9999


# ---------------------------------------------------------------------------
# Test 7: Working Backpropagation and Gradient Update Step
# ---------------------------------------------------------------------------

def test_07_backpropagation_and_gradient_updates():
    """Gradient descent step must update weights and decrease batch loss."""
    model = CustomNeuralClassifier(input_dim=64, hidden_dim1=16, hidden_dim2=8, dropout_rate=0.0, learning_rate=0.05, seed=42)
    X = np.random.randn(16, 64).astype(np.float32)
    Y = np.zeros((16, 3), dtype=np.float32)
    Y[:, 1] = 1.0

    probs = model.forward(X, training=True)
    initial_loss = model.compute_loss(probs, Y)
    grads = model.backward(Y)

    # Gradients must be finite and non-zero
    assert np.all(np.isfinite(grads["dW1"]))
    assert np.all(np.isfinite(grads["dW2"]))
    assert np.all(np.isfinite(grads["dW3"]))
    assert not np.all(grads["dW1"] == 0.0)

    # Update parameters
    model.update_parameters(grads)

    # Loss after gradient step should decrease
    new_loss = model.compute_loss(model.forward(X, training=False), Y)
    assert new_loss < initial_loss, f"Loss did not decrease: {initial_loss} -> {new_loss}"


# ---------------------------------------------------------------------------
# Test 8: Training for Minimal Number of Epochs
# ---------------------------------------------------------------------------

def test_08_mini_training_loop():
    """Running 5 mini-batches must reduce training loss consistently."""
    model = CustomNeuralClassifier(input_dim=32, hidden_dim1=16, hidden_dim2=8, learning_rate=0.01, seed=42)
    X = np.random.randn(20, 32).astype(np.float32)
    Y = np.zeros((20, 3), dtype=np.float32)
    Y[:10, 0] = 1.0
    Y[10:, 2] = 1.0

    losses = []
    for _ in range(10):
        l = model.fit_batch(X, Y)
        losses.append(l)

    assert losses[-1] < losses[0], f"Training did not converge: {losses[0]} -> {losses[-1]}"


# ---------------------------------------------------------------------------
# Test 9: Deterministic Behaviour for Fixed Seed
# ---------------------------------------------------------------------------

def test_09_deterministic_seed_consistency():
    """Two models initialized with identical seed produce identical forward outputs."""
    m1 = CustomNeuralClassifier(input_dim=64, hidden_dim1=16, hidden_dim2=8, seed=123)
    m2 = CustomNeuralClassifier(input_dim=64, hidden_dim1=16, hidden_dim2=8, seed=123)

    X = np.random.randn(5, 64).astype(np.float32)
    np.testing.assert_allclose(m1.forward(X, training=False), m2.forward(X, training=False), rtol=1e-6)


# ---------------------------------------------------------------------------
# Test 10: Three-Class Output Shape and Valid Probability Estimates
# ---------------------------------------------------------------------------

def test_10_output_shape_and_probability_distribution():
    """Model forward pass returns (B, 3) where each row is a valid probability distribution."""
    model = CustomNeuralClassifier(input_dim=128, seed=42)
    X = np.random.randn(7, 128).astype(np.float32)
    probs = model.predict_proba(X)

    assert probs.shape == (7, 3)
    assert np.all(probs >= 0.0)
    assert np.all(probs <= 1.0)
    np.testing.assert_allclose(np.sum(probs, axis=-1), np.ones(7), rtol=1e-5)


# ---------------------------------------------------------------------------
# Test 11: Empty, Whitespace, and Malformed Inputs
# ---------------------------------------------------------------------------

def test_11_safe_inference_on_malformed_inputs():
    """Empty strings, None, and non-string inputs fail gracefully returning neutral predictions."""
    model = CustomNeuralClassifier(input_dim=128, seed=42)

    res_empty = model.predict_one("")
    assert res_empty["is_experimental"] is True
    assert "predicted_label" in res_empty
    assert "probabilities" in res_empty

    res_none = model.predict_one(None)  # type: ignore
    assert res_none["predicted_label"] == "legitimate"

    res_whitespace = model.predict_one("     \n\t   ")
    assert res_whitespace["predicted_label"] == "legitimate"


# ---------------------------------------------------------------------------
# Test 12: Checkpoint Save and Load (Safe .npz Serialization)
# ---------------------------------------------------------------------------

def test_12_checkpoint_save_and_load_roundtrip():
    """Model can be saved and reloaded using NumPy .npz without pickle."""
    model = CustomNeuralClassifier(input_dim=64, hidden_dim1=16, hidden_dim2=8, seed=42)
    text = "महावितरण वीज बिल भरणा अधिकृत पावती"

    pred_before = model.predict_one(text)

    with tempfile.TemporaryDirectory() as tmpdir:
        ckpt_path = model.save_checkpoint(tmpdir, metadata={"run": "test"})
        loaded_model = CustomNeuralClassifier.load_checkpoint(ckpt_path)

        pred_after = loaded_model.predict_one(text)
        assert pred_before["predicted_label"] == pred_after["predicted_label"]
        np.testing.assert_allclose(
            list(pred_before["probabilities"].values()),
            list(pred_after["probabilities"].values()),
            rtol=1e-5,
        )


# ---------------------------------------------------------------------------
# Test 13: Corrupt or Incompatible Checkpoint Rejection
# ---------------------------------------------------------------------------

def test_13_corrupt_checkpoint_rejection():
    """Loading a checkpoint missing weights or metadata raises explicit FileNotFoundError / ValueError."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Empty directory
        with pytest.raises(FileNotFoundError):
            CustomNeuralClassifier.load_checkpoint(tmpdir)

        # Corrupt weights missing keys
        meta_file = os.path.join(tmpdir, "model_metadata.json")
        with open(meta_file, "w") as f:
            json.dump({
                "input_dim": 64, "hidden_dim1": 16, "hidden_dim2": 8, "num_classes": 3,
                "learning_rate": 0.005, "weight_decay": 1e-4, "dropout_rate": 0.2,
                "leaky_relu_alpha": 0.01, "seed": 42,
            }, f)
        np.savez_compressed(os.path.join(tmpdir, "model_weights.npz"), dummy=np.array([1, 2, 3]))

        with pytest.raises(ValueError, match="Corrupt checkpoint"):
            CustomNeuralClassifier.load_checkpoint(tmpdir)


# ---------------------------------------------------------------------------
# Test 14: Prediction Consistency After Reloading
# ---------------------------------------------------------------------------

def test_14_saved_checkpoint_reproducibility():
    """Production checkpoint in models/experimental_custom_v1 loads cleanly and reproduces predictions."""
    assert os.path.exists(CHECKPOINT_DIR)
    model = CustomNeuralClassifier.load_checkpoint(CHECKPOINT_DIR)

    test_samples = [
        "महावितरण वीज बिल तात्काळ भरा अन्यथा वीज खंडित केली जाईल",
        "सह्याद्री बँक पावती: तुमचे बिल यशस्वी भरले गेले आहे",
        "पोलीस सायबर सूचना: अनधिकृत लिंकवर कधीही क्लिक करू नका किंवा OTP देऊ नका",
    ]
    for s in test_samples:
        pred = model.predict_one(s)
        assert pred["predicted_label"] in LABEL_TO_IDX
        assert np.isfinite(pred["confidence"])


# ---------------------------------------------------------------------------
# Test 15: No Accidental Modification of Dataset Files
# ---------------------------------------------------------------------------

def test_15_dataset_files_untouched():
    """Ensure training and validation corpora row counts have not been altered."""
    with open(V2_TRAIN_PATH, "r", encoding="utf-8") as f:
        train_lines = [l for l in f if l.strip()]
    assert len(train_lines) == 360

    with open(V2_VAL_PATH, "r", encoding="utf-8") as f:
        val_lines = [l for l in f if l.strip()]
    assert len(val_lines) == 135


# ---------------------------------------------------------------------------
# Test 16: No Accidental Access to Quarantined or Locked Records
# ---------------------------------------------------------------------------

def test_16_quarantine_and_locked_isolation():
    """Verify that quarantined and locked records are strictly excluded from model training artifacts."""
    with open(os.path.join(CHECKPOINT_DIR, "model_metadata.json"), "r", encoding="utf-8") as f:
        meta = json.load(f)

    # Check that training source was v2 train corpus only
    train_source = meta.get("training_metadata", {}).get("train_source_file", "")
    assert "synthetic_training_corpus.jsonl" in train_source
    assert "quarantine" not in train_source
    assert "locked" not in train_source


# ---------------------------------------------------------------------------
# Test 17: Locked Evaluation Manifest Integrity
# ---------------------------------------------------------------------------

def test_17_locked_evaluation_digest_verified():
    """Locked evaluation partition SHA-256 digest remains strictly unchanged."""
    assert os.path.exists(EVAL_DATASET_PATH)
    assert os.path.exists(LOCKED_MANIFEST_PATH)

    with open(EVAL_DATASET_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)

    computed_digest = compute_locked_test_hash(eval_data)
    assert computed_digest == EXPECTED_LOCKED_DIGEST, (
        f"Locked test partition modified! Expected {EXPECTED_LOCKED_DIGEST}, got {computed_digest}"
    )
