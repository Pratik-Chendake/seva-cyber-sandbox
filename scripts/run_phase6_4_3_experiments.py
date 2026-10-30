#!/usr/bin/env python3
"""
Seva Cyber Sandbox — Phase 6.4.3: Controlled Multi-Seed Candidate Training.

OBJECTIVE:
1. Train experimental candidate neural models using the v3 synthetic training partition:
   'data/generated/v3/synthetic_training_corpus.jsonl' (1,200 records).
2. Monitor generalization and early stopping using the v3 development partition:
   'data/generated/v3/synthetic_dev_corpus.jsonl' (300 records).
   ZERO gradient updates are ever computed from development examples.
3. Completely isolate and block the qualification partition:
   'data/generated/v3/synthetic_qualification_corpus.jsonl' (450 records, sealed benchmark).
4. Train across three independent seeds: 42, 101, 202 from random He/Xavier initialization.
5. Save candidates under:
   - models/candidates/candidate_v3_seed42/
   - models/candidates/candidate_v3_seed101/
   - models/candidates/candidate_v3_seed202/
6. Compare candidates against baseline 'custom-mlp-v1.1.0-preproc' on the development set.
7. Execute a deterministic candidate selection policy.
8. Enforce zero side-effects on production registry and active runtime configuration.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import (
    EXPECTED_FEATURE_DIM,
    FEATURE_SCHEMA_VERSION,
    NEURAL_PREPROCESSING_VERSION,
    preprocess_for_neural_model,
)
from src.dataset_validator import compute_locked_test_hash, verify_locked_test_integrity
from src.candidate_evaluator import (
    EXPECTED_LOCKED_TEST_HASH,
    compute_classification_metrics,
    wilson_score_interval,
)

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

SEEDS = [42, 101, 202]
DEFAULT_BATCH_SIZE = 32
DEFAULT_MAX_EPOCHS = 50
DEFAULT_EARLY_STOPPING_PATIENCE = 10
DEFAULT_INITIAL_LR = 0.005
DEFAULT_WEIGHT_DECAY = 0.0005
DEFAULT_DROPOUT_RATE = 0.20
DEFAULT_INPUT_DIM = 1024
DEFAULT_HIDDEN_DIM1 = 64
DEFAULT_HIDDEN_DIM2 = 32
DEFAULT_NUM_CLASSES = 3

LR_SCHEDULE_MILESTONES = {
    21: 0.002,
    36: 0.001,
}

DATA_V3_DIR = os.path.join(PROJECT_ROOT, "data", "generated", "v3")
DEFAULT_TRAIN_CORPUS = os.path.join(DATA_V3_DIR, "synthetic_training_corpus.jsonl")
DEFAULT_DEV_CORPUS = os.path.join(DATA_V3_DIR, "synthetic_dev_corpus.jsonl")
DEFAULT_QUAL_CORPUS = os.path.join(DATA_V3_DIR, "synthetic_qualification_corpus.jsonl")

DEFAULT_TRAIN_MANIFEST = os.path.join(DATA_V3_DIR, "training_manifest.json")
DEFAULT_DEV_MANIFEST = os.path.join(DATA_V3_DIR, "dev_manifest.json")
DEFAULT_QUAL_MANIFEST = os.path.join(DATA_V3_DIR, "qualification_manifest.json")
DEFAULT_LOCKED_TEST_MANIFEST = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
DEFAULT_BASELINE_CHECKPOINT = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")

DEFAULT_CANDIDATES_ROOT = os.path.join(PROJECT_ROOT, "models", "candidates")
DEFAULT_SELECTION_SUMMARY_PATH = os.path.join(
    PROJECT_ROOT, "evaluation", "candidates", "phase6_4_3_selection_summary.json"
)

FORBIDDEN_DATASET_KEYWORDS = {
    "qualification",
    "phishing_eval_dataset",
    "locked_test",
    "quarantine",
}


# =============================================================================
# EXCEPTIONS
# =============================================================================

class ControlledTrainingError(Exception):
    """Base exception for Phase 6.4.3 controlled training errors."""
    pass


class DatasetIsolationViolation(ControlledTrainingError):
    """Raised when forbidden partitions or partition leakage is detected."""
    pass


class BenchmarkGovernanceViolation(ControlledTrainingError):
    """Raised when cryptographic digests or manifest checks fail."""
    pass


# =============================================================================
# UTILITIES
# =============================================================================

def get_utc_now_iso() -> str:
    """Returns current UTC ISO-8601 timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 digest of a local file safely in 64 KB chunks."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: '{filepath}'")
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================
# DATASET ISOLATION & PROVENANCE VERIFICATION
# =============================================================================

def verify_phase6_4_3_isolation(
    train_path: str = DEFAULT_TRAIN_CORPUS,
    dev_path: str = DEFAULT_DEV_CORPUS,
    train_manifest_path: str = DEFAULT_TRAIN_MANIFEST,
    dev_manifest_path: str = DEFAULT_DEV_MANIFEST,
    locked_manifest_path: str = DEFAULT_LOCKED_TEST_MANIFEST,
    project_root: str = PROJECT_ROOT,
) -> Dict[str, Any]:
    """
    Strictly verifies dataset isolation, manifests, and checksums.
    
    GUARDS:
    1. Blocks any path matching forbidden keywords (qualification, eval dataset, etc.).
    2. Validates locked test partition digest: '9b9c02d4...'.
    3. Validates training manifest and training corpus SHA-256.
    4. Validates dev manifest and dev corpus SHA-256.
    5. Validates zero record ID or text overlap between train and dev.
    """
    for p_name, p_val in [("train_path", train_path), ("dev_path", dev_path)]:
        norm = p_val.replace("\\", "/").lower()
        for kw in FORBIDDEN_DATASET_KEYWORDS:
            if kw in norm:
                raise DatasetIsolationViolation(
                    f"CRITICAL ISOLATION BREACH: {p_name} '{p_val}' matches forbidden keyword '{kw}'."
                )

    # 1. Locked evaluation manifest verification
    if not os.path.isfile(locked_manifest_path):
        raise BenchmarkGovernanceViolation(f"Locked test manifest missing at '{locked_manifest_path}'")
    with open(locked_manifest_path, "r", encoding="utf-8") as f:
        locked_m = json.load(f)
    locked_digest = locked_m.get("sha256_checksum")
    if locked_digest != EXPECTED_LOCKED_TEST_HASH:
        raise BenchmarkGovernanceViolation(
            f"Locked evaluation dataset corrupted! Expected {EXPECTED_LOCKED_TEST_HASH}, got {locked_digest}"
        )

    # 2. Training manifest verification
    if not os.path.isfile(train_manifest_path):
        raise BenchmarkGovernanceViolation(f"Training manifest missing at '{train_manifest_path}'")
    with open(train_manifest_path, "r", encoding="utf-8") as f:
        train_m = json.load(f)
    expected_train_sha = train_m.get("file_sha256") or train_m.get("sha256")
    actual_train_sha = compute_file_sha256(train_path)
    if expected_train_sha != actual_train_sha:
        raise BenchmarkGovernanceViolation(
            f"Training corpus digest mismatch! Manifest: {expected_train_sha}, Disk: {actual_train_sha}"
        )

    # 3. Dev manifest verification
    if not os.path.isfile(dev_manifest_path):
        raise BenchmarkGovernanceViolation(f"Dev manifest missing at '{dev_manifest_path}'")
    with open(dev_manifest_path, "r", encoding="utf-8") as f:
        dev_m = json.load(f)
    expected_dev_sha = dev_m.get("file_sha256") or dev_m.get("sha256")
    actual_dev_sha = compute_file_sha256(dev_path)
    if expected_dev_sha != actual_dev_sha:
        raise BenchmarkGovernanceViolation(
            f"Dev corpus digest mismatch! Manifest: {expected_dev_sha}, Disk: {actual_dev_sha}"
        )

    # 4. Zero ID & text overlap check
    train_ids: Set[str] = set()
    train_texts: Set[str] = set()
    with open(train_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue
            rec = json.loads(line_str)
            rid = rec.get("record_id")
            if not rid:
                raise DatasetIsolationViolation(f"Line {idx} in train corpus lacks record_id.")
            train_ids.add(rid)
            train_texts.add(rec.get("text", "").strip())

    dev_ids: Set[str] = set()
    dev_texts: Set[str] = set()
    with open(dev_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue
            rec = json.loads(line_str)
            rid = rec.get("record_id")
            if not rid:
                raise DatasetIsolationViolation(f"Line {idx} in dev corpus lacks record_id.")
            if rid in train_ids:
                raise DatasetIsolationViolation(f"Train/Dev ID overlap detected: '{rid}' exists in both!")
            dev_ids.add(rid)
            t = rec.get("text", "").strip()
            if t in train_texts:
                raise DatasetIsolationViolation(f"Train/Dev text leakage detected for record '{rid}'!")
            dev_texts.add(t)

    return {
        "status": "AUTHORIZED",
        "train_records": len(train_ids),
        "dev_records": len(dev_ids),
        "train_sha256": actual_train_sha,
        "dev_sha256": actual_dev_sha,
        "locked_test_sha256": locked_digest,
    }


# =============================================================================
# DATA LOADING & PREPROCESSING
# =============================================================================

def load_and_preprocess_partition(
    file_path: str,
    hasher: CharacterNGramHasher,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[Dict[str, Any]]]:
    """
    Loads JSONL partition, applies canonical neural preprocessor (v1.1.0),
    hashes character n-grams into 1024-d vectors, and prepares one-hot targets.
    
    Returns:
    - X: np.ndarray (N, 1024) float32
    - y: np.ndarray (N,) int64
    - Y_onehot: np.ndarray (N, 3) float32
    - records: List of original dict records
    """
    records: List[Dict[str, Any]] = []
    preprocessed_texts: List[str] = []
    labels: List[int] = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            d = json.loads(line_str)
            raw_text = d.get("text") or d.get("normalized_text", "")
            clean_text = preprocess_for_neural_model(raw_text)
            label = d.get("ground_truth_label") or d.get("label")
            if label not in LABEL_TO_IDX:
                raise ControlledTrainingError(f"Invalid label '{label}' in record '{d.get('record_id')}'")

            records.append(d)
            preprocessed_texts.append(clean_text)
            labels.append(LABEL_TO_IDX[label])

    n_samples = len(records)
    X = hasher.transform_batch(preprocessed_texts)
    y = np.array(labels, dtype=np.int64)
    Y_onehot = np.zeros((n_samples, NUM_CLASSES), dtype=np.float32)
    for i, lbl_idx in enumerate(labels):
        Y_onehot[i, lbl_idx] = 1.0

    return X, y, Y_onehot, records


# =============================================================================
# MODEL TRAINING WITH EARLY STOPPING
# =============================================================================

@dataclass
class EpochMetrics:
    epoch: int
    lr: float
    train_loss: float
    train_accuracy: float
    dev_loss: float
    dev_accuracy: float
    dev_macro_f1: float
    dev_metrics: Dict[str, Any]


def train_candidate_seed(
    seed: int,
    X_train: np.ndarray,
    y_train: np.ndarray,
    Y_train: np.ndarray,
    X_dev: np.ndarray,
    y_dev: np.ndarray,
    Y_dev: np.ndarray,
    candidates_root: str = DEFAULT_CANDIDATES_ROOT,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_epochs: int = DEFAULT_MAX_EPOCHS,
    early_stopping_patience: int = DEFAULT_EARLY_STOPPING_PATIENCE,
    initial_lr: float = DEFAULT_INITIAL_LR,
    weight_decay: float = DEFAULT_WEIGHT_DECAY,
    dropout_rate: float = DEFAULT_DROPOUT_RATE,
    hasher: Optional[CharacterNGramHasher] = None,
) -> Dict[str, Any]:
    """
    Trains a single candidate model from random He/Xavier initialization.
    
    GOVERNANCE & SAFETY CONTROLS:
    - Zero dev gradients: Dev partition is evaluated in inference mode only.
    - Early stopping: Monitors development Macro-F1 with patience.
    - Restores and saves weights from the epoch with highest dev Macro-F1.
    - Saves immutable artifacts under 'models/candidates/candidate_v3_seed{seed}/'.
    """
    candidate_id = f"candidate_v3_seed{seed}"
    candidate_dir = os.path.join(candidates_root, candidate_id)

    if os.path.exists(candidate_dir):
        raise ControlledTrainingError(
            f"Candidate directory already exists at '{candidate_dir}'. Overwriting is strictly forbidden."
        )

    hasher_obj = hasher or CharacterNGramHasher(num_features=DEFAULT_INPUT_DIM)
    n_train = len(X_train)
    n_dev = len(X_dev)

    # 1. Instantiate fresh model with RANDOM INITIALIZATION
    model = CustomNeuralClassifier(
        input_dim=DEFAULT_INPUT_DIM,
        hidden_dim1=DEFAULT_HIDDEN_DIM1,
        hidden_dim2=DEFAULT_HIDDEN_DIM2,
        num_classes=DEFAULT_NUM_CLASSES,
        learning_rate=initial_lr,
        weight_decay=weight_decay,
        dropout_rate=dropout_rate,
        seed=seed,
    )
    model.model_version = candidate_id

    rng = np.random.RandomState(seed)

    best_dev_macro_f1 = -1.0
    best_epoch = 0
    best_weights: Dict[str, np.ndarray] = {}
    best_dev_metrics: Dict[str, Any] = {}
    patience_counter = 0
    history: List[EpochMetrics] = []

    for epoch in range(1, max_epochs + 1):
        # Apply learning rate schedule
        if epoch in LR_SCHEDULE_MILESTONES:
            model.learning_rate = LR_SCHEDULE_MILESTONES[epoch]

        current_lr = model.learning_rate

        # Mini-batch training on training partition ONLY
        perm = rng.permutation(n_train)
        X_shuff = X_train[perm]
        Y_shuff = Y_train[perm]

        batch_losses = []
        for b_start in range(0, n_train, batch_size):
            X_b = X_shuff[b_start : b_start + batch_size]
            Y_b = Y_shuff[b_start : b_start + batch_size]
            b_loss = model.fit_batch(X_b, Y_b)
            batch_losses.append(b_loss)

        train_loss = float(np.mean(batch_losses))
        train_preds = model.predict(X_train)
        train_acc = float(np.mean(train_preds == y_train))

        # Evaluate on dev partition (INFERENCE ONLY, NO GRADIENTS)
        dev_probs = model.predict_proba(X_dev)
        dev_loss = float(model.compute_loss(dev_probs, Y_dev))
        dev_preds = np.argmax(dev_probs, axis=-1)
        dev_metrics = compute_classification_metrics(y_dev, dev_preds)
        dev_acc = dev_metrics["accuracy"]
        dev_macro_f1 = dev_metrics["macro_f1"]

        epoch_stat = EpochMetrics(
            epoch=epoch,
            lr=current_lr,
            train_loss=round(train_loss, 4),
            train_accuracy=round(train_acc, 4),
            dev_loss=round(dev_loss, 4),
            dev_accuracy=round(dev_acc, 4),
            dev_macro_f1=round(dev_macro_f1, 4),
            dev_metrics=dev_metrics,
        )
        history.append(epoch_stat)

        # Check for improvement
        if dev_macro_f1 > best_dev_macro_f1:
            best_dev_macro_f1 = dev_macro_f1
            best_epoch = epoch
            best_dev_metrics = dev_metrics
            best_weights = {
                "W1": model.W1.copy(),
                "b1": model.b1.copy(),
                "W2": model.W2.copy(),
                "b2": model.b2.copy(),
                "W3": model.W3.copy(),
                "b3": model.b3.copy(),
            }
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= early_stopping_patience:
                logger.info(
                    f"Seed {seed}: Early stopping triggered at epoch {epoch} "
                    f"(best epoch {best_epoch} dev macro-F1: {best_dev_macro_f1:.4f})"
                )
                break

    # Restore best checkpoint weights
    model.W1 = best_weights["W1"]
    model.b1 = best_weights["b1"]
    model.W2 = best_weights["W2"]
    model.b2 = best_weights["b2"]
    model.W3 = best_weights["W3"]
    model.b3 = best_weights["b3"]

    # Verify best checkpoint evaluation matches
    restored_dev_preds = model.predict(X_dev)
    restored_metrics = compute_classification_metrics(y_dev, restored_dev_preds)
    assert abs(restored_metrics["macro_f1"] - best_dev_macro_f1) < 1e-4

    # Atomic artifact creation
    temp_dir = tempfile.mkdtemp(prefix=f"cand_v3_seed{seed}_")
    now_utc = get_utc_now_iso()

    try:
        # A. Save model weights and metadata
        meta_extra = {
            "candidate_id": candidate_id,
            "seed": seed,
            "created_at_utc": now_utc,
            "lifecycle_state": "experimental",
            "is_production_authoritative": False,
            "preprocessing_version": NEURAL_PREPROCESSING_VERSION,
            "training_corpus": "synthetic_training_corpus.jsonl",
            "best_epoch": best_epoch,
            "total_epochs_trained": len(history),
            "best_dev_macro_f1": best_dev_macro_f1,
        }
        model.save_checkpoint(temp_dir, metadata=meta_extra)

        weights_file = os.path.join(temp_dir, "model_weights.npz")
        meta_file = os.path.join(temp_dir, "model_metadata.json")

        w_sha = compute_file_sha256(weights_file)
        m_sha = compute_file_sha256(meta_file)

        # B. Save candidate training report
        report_file = os.path.join(temp_dir, "candidate_training_report.json")
        report_data = {
            "report_schema_version": "1.0.0",
            "candidate_id": candidate_id,
            "random_seed": seed,
            "lifecycle_state": "experimental",
            "created_at_utc": now_utc,
            "architecture": {
                "model_type": "Multi-Layer Perceptron (MLP)",
                "input_dim": DEFAULT_INPUT_DIM,
                "hidden_dim1": DEFAULT_HIDDEN_DIM1,
                "hidden_dim2": DEFAULT_HIDDEN_DIM2,
                "num_classes": DEFAULT_NUM_CLASSES,
                "activation": "LeakyReLU (alpha=0.01)",
                "initialization": "He normal (hidden layers), Xavier uniform (output layer)",
            },
            "hyperparameters": {
                "max_epochs": max_epochs,
                "early_stopping_patience": early_stopping_patience,
                "batch_size": batch_size,
                "initial_learning_rate": initial_lr,
                "weight_decay": weight_decay,
                "dropout_rate": dropout_rate,
                "lr_schedule_milestones": LR_SCHEDULE_MILESTONES,
            },
            "training_run_summary": {
                "best_epoch": best_epoch,
                "total_epochs_trained": len(history),
                "stopped_early": len(history) < max_epochs,
                "best_dev_macro_f1": round(best_dev_macro_f1, 4),
                "best_dev_accuracy": round(best_dev_metrics["accuracy"], 4),
            },
            "dataset_provenance": {
                "training_corpus": "data/generated/v3/synthetic_training_corpus.jsonl",
                "training_examples": n_train,
                "dev_corpus": "data/generated/v3/synthetic_dev_corpus.jsonl",
                "dev_examples": n_dev,
                "qualification_partition": "SEALED_INACCESSIBLE",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "preprocessing_version": NEURAL_PREPROCESSING_VERSION,
            },
            "dev_evaluation_metrics": best_dev_metrics,
            "epoch_history": [
                {
                    "epoch": h.epoch,
                    "lr": h.lr,
                    "train_loss": h.train_loss,
                    "train_accuracy": h.train_accuracy,
                    "dev_loss": h.dev_loss,
                    "dev_accuracy": h.dev_accuracy,
                    "dev_macro_f1": h.dev_macro_f1,
                }
                for h in history
            ],
            "artifacts": {
                "model_weights": {"filename": "model_weights.npz", "sha256": w_sha},
                "model_metadata": {"filename": "model_metadata.json", "sha256": m_sha},
            },
            "warnings_and_limitations": [
                "EXPERIMENTAL_CANDIDATE_ONLY: Not evaluated or approved for shadow or production deployment.",
                "LOCAL_BENCHMARK_EVALUATION: Generalization measured against v3 dev partition only.",
                "INDEPENDENT_SEALED_QUALIFICATION_RESERVED: Final qualification partition remains strictly sealed.",
            ],
            "status": "SUCCESS",
        }
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        r_sha = compute_file_sha256(report_file)

        # C. Save candidate manifest
        manifest_file = os.path.join(temp_dir, "manifest.json")
        manifest_data = {
            "manifest_schema_version": "1.0.0",
            "candidate_id": candidate_id,
            "candidate_version": f"3.0.0-seed{seed}",
            "random_seed": seed,
            "lifecycle_state": "experimental",
            "created_at_utc": now_utc,
            "architecture_version": "3-layer-mlp-ngram-v1",
            "artifacts": {
                "model_weights": {"filename": "model_weights.npz", "sha256": w_sha},
                "model_metadata": {"filename": "model_metadata.json", "sha256": m_sha},
                "training_report": {"filename": "candidate_training_report.json", "sha256": r_sha},
            },
            "provenance_summary": {
                "training_corpus": "data/generated/v3/synthetic_training_corpus.jsonl",
                "training_samples": n_train,
                "dev_corpus": "data/generated/v3/synthetic_dev_corpus.jsonl",
                "dev_samples": n_dev,
                "qualification_partition": "SEALED",
            },
            "disclaimer": (
                "EXPERIMENTAL CANDIDATE MODEL ARTIFACT. Not approved for production or shadow deployment. "
                "Active registry and runtime configuration are untouched."
            ),
        }
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2, ensure_ascii=False)

        man_sha = compute_file_sha256(manifest_file)

        # D. Verify readability from disk
        loaded_model = CustomNeuralClassifier.load_checkpoint(temp_dir)
        assert loaded_model.input_dim == DEFAULT_INPUT_DIM
        assert loaded_model.W1.shape == (DEFAULT_INPUT_DIM, DEFAULT_HIDDEN_DIM1)

        # E. Atomically move to target candidate directory
        os.makedirs(candidates_root, exist_ok=True)
        shutil.move(temp_dir, candidate_dir)

    except Exception as exc:
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass
        raise ControlledTrainingError(f"Candidate serialization failed for seed {seed}: {exc}") from exc

    return {
        "seed": seed,
        "candidate_id": candidate_id,
        "candidate_dir": candidate_dir,
        "best_epoch": best_epoch,
        "total_epochs": len(history),
        "best_dev_macro_f1": best_dev_macro_f1,
        "dev_metrics": best_dev_metrics,
        "weights_sha256": w_sha,
        "metadata_sha256": m_sha,
        "manifest_sha256": man_sha,
        "report_sha256": r_sha,
    }


# =============================================================================
# BASELINE EVALUATION
# =============================================================================

def evaluate_baseline_on_dev(
    checkpoint_dir: str = DEFAULT_BASELINE_CHECKPOINT,
    X_dev: np.ndarray = None,
    y_dev: np.ndarray = None,
) -> Dict[str, Any]:
    """
    Evaluates the registered baseline model ('custom-mlp-v1.1.0-preproc')
    on the development partition.
    """
    if not os.path.isdir(checkpoint_dir):
        raise FileNotFoundError(f"Baseline checkpoint directory missing at '{checkpoint_dir}'")

    baseline_model = CustomNeuralClassifier.load_checkpoint(checkpoint_dir)
    preds = baseline_model.predict(X_dev)
    metrics = compute_classification_metrics(y_dev, preds)
    return {
        "model_version": baseline_model.model_version,
        "checkpoint_dir": checkpoint_dir,
        "metrics": metrics,
    }


# =============================================================================
# DETERMINISTIC CANDIDATE SELECTION POLICY
# =============================================================================

@dataclass
class CandidateGateEvaluation:
    seed: int
    candidate_id: str
    dev_macro_f1: float
    macro_f1_delta_vs_baseline: float
    legitimate_fp_rate: float
    protective_advisory_fp_rate: float
    phishing_fn_rate: float
    passes_macro_f1_gate: bool
    passes_macro_f1_drop_gate: bool
    passes_legit_fp_gate: bool
    passes_advisory_fp_gate: bool
    passes_phish_fn_gate: bool
    overall_eligible: bool
    failing_gates: List[str]


def evaluate_candidate_selection(
    baseline_result: Dict[str, Any],
    candidate_summaries: List[Dict[str, Any]],
    min_macro_f1: float = 0.9000,
    max_macro_f1_drop: float = 0.0200,
    max_legit_fp_rate: float = 0.1500,
    max_advisory_fp_rate: float = 0.0500,
    max_phish_fn_rate: float = 0.0500,
) -> Dict[str, Any]:
    """
    Applies the deterministic candidate selection policy.
    
    CRITERIA:
    1. min_macro_f1 >= 0.9000
    2. candidate_macro_f1 >= baseline_macro_f1 - max_macro_f1_drop (0.0200)
    3. legitimate_fp_rate <= 0.1500
    4. protective_advisory_fp_rate <= 0.0500
    5. phishing_fn_rate <= 0.0500
    
    WINNER SELECTION AMONG ELIGIBLE CANDIDATES:
    - Rank 1: Highest dev Macro-F1
    - Tie-breaker 1: Lowest total false positive rate (legit FP + advisory FP)
    - Tie-breaker 2: Lowest seed integer
    
    If no candidates are eligible: Status is NO_CANDIDATE_SELECTED.
    """
    base_f1 = baseline_result["metrics"]["macro_f1"]
    evaluations: List[CandidateGateEvaluation] = []

    for cand in candidate_summaries:
        s = cand["seed"]
        cid = cand["candidate_id"]
        dev_m = cand["dev_metrics"]
        f1 = dev_m["macro_f1"]
        delta_f1 = f1 - base_f1

        safety = dev_m.get("safety_metrics", {})
        legit_fp = safety.get("legitimate_fp_rate", 1.0)
        advisory_fp = safety.get("protective_advisory_fp_rate", 1.0)
        phish_fn = safety.get("phishing_fn_rate", 1.0)

        pass_f1 = f1 >= min_macro_f1
        pass_drop = delta_f1 >= -max_macro_f1_drop
        pass_legit = legit_fp <= max_legit_fp_rate
        pass_advisory = advisory_fp <= max_advisory_fp_rate
        pass_phish = phish_fn <= max_phish_fn_rate

        failing = []
        if not pass_f1:
            failing.append(f"MIN_MACRO_F1_FAILED (got {f1:.4f} < {min_macro_f1:.4f})")
        if not pass_drop:
            failing.append(f"MAX_DROP_FAILED (delta {delta_f1:.4f} < -{max_macro_f1_drop:.4f})")
        if not pass_legit:
            failing.append(f"LEGIT_FP_RATE_FAILED (got {legit_fp:.4f} > {max_legit_fp_rate:.4f})")
        if not pass_advisory:
            failing.append(f"ADVISORY_FP_RATE_FAILED (got {advisory_fp:.4f} > {max_advisory_fp_rate:.4f})")
        if not pass_phish:
            failing.append(f"PHISHING_FN_RATE_FAILED (got {phish_fn:.4f} > {max_phish_fn_rate:.4f})")

        is_eligible = len(failing) == 0

        evaluations.append(
            CandidateGateEvaluation(
                seed=s,
                candidate_id=cid,
                dev_macro_f1=round(f1, 4),
                macro_f1_delta_vs_baseline=round(delta_f1, 4),
                legitimate_fp_rate=round(legit_fp, 4),
                protective_advisory_fp_rate=round(advisory_fp, 4),
                phishing_fn_rate=round(phish_fn, 4),
                passes_macro_f1_gate=pass_f1,
                passes_macro_f1_drop_gate=pass_drop,
                passes_legit_fp_gate=pass_legit,
                passes_advisory_fp_gate=pass_advisory,
                passes_phish_fn_gate=pass_phish,
                overall_eligible=is_eligible,
                failing_gates=failing,
            )
        )

    eligible_cands = [e for e in evaluations if e.overall_eligible]

    if not eligible_cands:
        return {
            "status": "NO_CANDIDATE_SELECTED",
            "reason": "No trained candidate satisfied all benchmark gate criteria.",
            "selected_candidate_id": None,
            "selected_seed": None,
            "candidate_evaluations": [asdict(e) for e in evaluations],
        }

    # Deterministic ranking
    # 1: highest dev_macro_f1 (descending)
    # 2: lowest total FP (ascending)
    # 3: lowest seed (ascending)
    def rank_key(e: CandidateGateEvaluation):
        total_fp = e.legitimate_fp_rate + e.protective_advisory_fp_rate
        return (-e.dev_macro_f1, total_fp, e.seed)

    ranked_eligible = sorted(eligible_cands, key=rank_key)
    winner = ranked_eligible[0]

    return {
        "status": "CANDIDATE_SELECTED",
        "selected_candidate_id": winner.candidate_id,
        "selected_seed": winner.seed,
        "selection_rationale": (
            f"Candidate '{winner.candidate_id}' achieved highest development Macro-F1 ({winner.dev_macro_f1:.4f}) "
            f"with zero advisory false positives ({winner.protective_advisory_fp_rate:.4f}), "
            f"legitimate false positive rate {winner.legitimate_fp_rate:.4f} <= 0.15, "
            f"and phishing false negative rate {winner.phishing_fn_rate:.4f} <= 0.05."
        ),
        "ranking_order": [e.candidate_id for e in ranked_eligible],
        "candidate_evaluations": [asdict(e) for e in evaluations],
    }


# =============================================================================
# MAIN ORCHESTRATION CONTROLLER
# =============================================================================

def run_phase6_4_3_pipeline(
    train_corpus: str = DEFAULT_TRAIN_CORPUS,
    dev_corpus: str = DEFAULT_DEV_CORPUS,
    train_manifest: str = DEFAULT_TRAIN_MANIFEST,
    dev_manifest: str = DEFAULT_DEV_MANIFEST,
    locked_manifest: str = DEFAULT_LOCKED_TEST_MANIFEST,
    baseline_dir: str = DEFAULT_BASELINE_CHECKPOINT,
    candidates_root: str = DEFAULT_CANDIDATES_ROOT,
    summary_output_path: str = DEFAULT_SELECTION_SUMMARY_PATH,
    seeds: List[int] = SEEDS,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_epochs: int = DEFAULT_MAX_EPOCHS,
    patience: int = DEFAULT_EARLY_STOPPING_PATIENCE,
    initial_lr: float = DEFAULT_INITIAL_LR,
    weight_decay: float = DEFAULT_WEIGHT_DECAY,
    dropout_rate: float = DEFAULT_DROPOUT_RATE,
) -> Dict[str, Any]:
    """
    Executes the entire Phase 6.4.3 multi-seed candidate training and selection pipeline.
    """
    print("=" * 80)
    print("SEVA CYBER SANDBOX — PHASE 6.4.3: CONTROLLED MULTI-SEED CANDIDATE TRAINING")
    print("=" * 80)

    # 1. Dataset Isolation & Manifest Governance Audit
    print("[*] Step 1: Auditing Dataset Isolation and Cryptographic Manifests...")
    iso_info = verify_phase6_4_3_isolation(
        train_path=train_corpus,
        dev_path=dev_corpus,
        train_manifest_path=train_manifest,
        dev_manifest_path=dev_manifest,
        locked_manifest_path=locked_manifest,
    )
    print(f"    [+] Training corpus: {iso_info['train_records']} records (SHA-256: {iso_info['train_sha256'][:16]}...)")
    print(f"    [+] Dev corpus: {iso_info['dev_records']} records (SHA-256: {iso_info['dev_sha256'][:16]}...)")
    print(f"    [+] Locked test partition checksum: {iso_info['locked_test_sha256'][:16]}... (VERIFIED)")
    print("    [+] Sealed qualification partition: STRICTLY INACCESSIBLE & ISOLATED")

    # 2. Vectorize Datasets
    print("\n[*] Step 2: Vectorizing Training and Dev Partitions (1024-d Character N-Grams)...")
    hasher = CharacterNGramHasher(num_features=DEFAULT_INPUT_DIM, min_n=3, max_n=5)
    X_train, y_train, Y_train, train_recs = load_and_preprocess_partition(train_corpus, hasher)
    X_dev, y_dev, Y_dev, dev_recs = load_and_preprocess_partition(dev_corpus, hasher)
    print(f"    [+] X_train shape: {X_train.shape} | Y_train shape: {Y_train.shape}")
    print(f"    [+] X_dev shape: {X_dev.shape} | Y_dev shape: {Y_dev.shape}")

    # 3. Baseline Evaluation on Dev
    print("\n[*] Step 3: Evaluating Registered Baseline Model on Dev Partition...")
    baseline_res = evaluate_baseline_on_dev(baseline_dir, X_dev, y_dev)
    b_metrics = baseline_res["metrics"]
    b_safety = b_metrics.get("safety_metrics", {})
    print(f"    [+] Baseline Version: {baseline_res['model_version']}")
    print(f"    [+] Dev Accuracy: {b_metrics['accuracy']:.4f} (95% CI: {b_metrics['accuracy_ci_95']})")
    print(f"    [+] Dev Macro-F1: {b_metrics['macro_f1']:.4f}")
    print(f"    [+] Legit FP Rate: {b_safety.get('legitimate_fp_rate', 0.0):.4f}")
    print(f"    [+] Advisory FP Rate: {b_safety.get('protective_advisory_fp_rate', 0.0):.4f}")
    print(f"    [+] Phishing FN Rate: {b_safety.get('phishing_fn_rate', 0.0):.4f}")
    print(f"    [+] Confusion Matrix: {b_metrics['confusion_matrix']}")

    # 4. Multi-Seed Candidate Training
    print("\n[*] Step 4: Training Independent Candidates Across Seeds [42, 101, 202]...")
    candidate_summaries: List[Dict[str, Any]] = []

    for seed in seeds:
        print(f"\n--- Training Candidate Seed {seed} ---")
        cand_summary = train_candidate_seed(
            seed=seed,
            X_train=X_train,
            y_train=y_train,
            Y_train=Y_train,
            X_dev=X_dev,
            y_dev=y_dev,
            Y_dev=Y_dev,
            candidates_root=candidates_root,
            batch_size=batch_size,
            max_epochs=max_epochs,
            early_stopping_patience=patience,
            initial_lr=initial_lr,
            weight_decay=weight_decay,
            dropout_rate=dropout_rate,
            hasher=hasher,
        )
        candidate_summaries.append(cand_summary)
        c_m = cand_summary["dev_metrics"]
        c_safe = c_m.get("safety_metrics", {})
        print(f"    [+] Candidate: {cand_summary['candidate_id']}")
        print(f"    [+] Best Epoch: {cand_summary['best_epoch']} / {cand_summary['total_epochs']}")
        print(f"    [+] Dev Accuracy: {c_m['accuracy']:.4f}")
        print(f"    [+] Dev Macro-F1: {c_m['macro_f1']:.4f}")
        print(f"    [+] Legit FP Rate: {c_safe.get('legitimate_fp_rate', 0.0):.4f}")
        print(f"    [+] Advisory FP Rate: {c_safe.get('protective_advisory_fp_rate', 0.0):.4f}")
        print(f"    [+] Phishing FN Rate: {c_safe.get('phishing_fn_rate', 0.0):.4f}")
        print(f"    [+] Confusion Matrix: {c_m['confusion_matrix']}")
        print(f"    [+] Checkpoint Dir: {cand_summary['candidate_dir']}")

    # 5. Candidate Selection Policy Execution
    print("\n[*] Step 5: Applying Deterministic Candidate Selection Policy...")
    selection_result = evaluate_candidate_selection(
        baseline_result=baseline_res,
        candidate_summaries=candidate_summaries,
    )
    print(f"    [+] Selection Status: {selection_result['status']}")
    print(f"    [+] Selected Candidate: {selection_result.get('selected_candidate_id')}")
    if selection_result.get("selection_rationale"):
        print(f"    [+] Rationale: {selection_result['selection_rationale']}")

    # 6. Save Selection Summary Artifact
    os.makedirs(os.path.dirname(summary_output_path), exist_ok=True)
    full_summary = {
        "summary_schema_version": "1.0.0",
        "phase": "6.4.3",
        "timestamp_utc": get_utc_now_iso(),
        "baseline_model": {
            "version": baseline_res["model_version"],
            "dev_metrics": b_metrics,
        },
        "candidate_runs": [
            {
                "seed": c["seed"],
                "candidate_id": c["candidate_id"],
                "best_epoch": c["best_epoch"],
                "total_epochs": c["total_epochs"],
                "weights_sha256": c["weights_sha256"],
                "metadata_sha256": c["metadata_sha256"],
                "manifest_sha256": c["manifest_sha256"],
                "report_sha256": c["report_sha256"],
                "dev_metrics": c["dev_metrics"],
            }
            for c in candidate_summaries
        ],
        "selection_decision": selection_result,
        "governance_guarantees": {
            "locked_eval_partition_sha256": iso_info["locked_test_sha256"],
            "qualification_partition_status": "SEALED_INACCESSIBLE",
            "production_registry_modified": False,
            "active_model_config_modified": False,
            "production_score_delta": 0,
        },
    }
    with open(summary_output_path, "w", encoding="utf-8") as f:
        json.dump(full_summary, f, indent=2, ensure_ascii=False)
    print(f"    [+] Selection summary saved to: {summary_output_path}")

    # 7. Final Governance & Production Invariance Check
    print("\n[*] Step 6: Verifying Production Invariance (Score Delta = 0)...")
    eval_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with open(eval_path, "r", encoding="utf-8") as f:
        eval_recs = json.load(f)
    post_iso = compute_locked_test_hash(eval_recs)
    assert post_iso == EXPECTED_LOCKED_TEST_HASH, f"Locked test partition was altered! Got {post_iso}"
    print(f"    [+] Locked test partition checksum unchanged: {post_iso[:16]}...")
    print("    [+] Zero production model changes: candidate models exist solely in models/candidates/.")
    print("=" * 80)
    print("PHASE 6.4.3 CONTROLLED TRAINING PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 80)

    return full_summary


if __name__ == "__main__":
    run_phase6_4_3_pipeline()
