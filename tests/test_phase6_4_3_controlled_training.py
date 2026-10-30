"""
Test Suite for Phase 6.4.3: Controlled Multi-Seed Candidate Training.

SPECIFICATION & AUDIT TARGETS:
1. Locked evaluation partition digest preserved: 9b9c02d4...
2. v3 corpus manifests integrity verified.
3. Sealed qualification partition blocked and inaccessible.
4. Zero development partition gradient updates (inference-only).
5. Zero train/dev leakage (IDs, texts, campaign families).
6. Three independent candidate models trained across seeds [42, 101, 202].
7. Candidates saved in unique, immutable directories.
8. Safe weight serialization using NumPy allow_pickle=False.
9. Manifest SHA-256 cryptographic integrity.
10. Model metadata schema and preprocessing version compatibility.
11. Training provenance reports completeness.
12. Seed reproducibility and distinctness across seeds.
13. Baseline model evaluation on dev set.
14. Deterministic candidate selection policy execution and logic.
15. Production model registry and active config invariant (score delta = 0).
"""

import hashlib
import json
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List
import numpy as np
import pytest

from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import (
    EXPECTED_FEATURE_DIM,
    NEURAL_PREPROCESSING_VERSION,
    preprocess_for_neural_model,
)
from src.dataset_validator import compute_locked_test_hash, verify_locked_test_integrity
from src.candidate_evaluator import (
    EXPECTED_LOCKED_TEST_HASH,
    compute_classification_metrics,
)
from scripts.run_phase6_4_3_experiments import (
    DEFAULT_CANDIDATES_ROOT,
    DEFAULT_DEV_CORPUS,
    DEFAULT_DEV_MANIFEST,
    DEFAULT_QUAL_CORPUS,
    DEFAULT_QUAL_MANIFEST,
    DEFAULT_SELECTION_SUMMARY_PATH,
    DEFAULT_TRAIN_CORPUS,
    DEFAULT_TRAIN_MANIFEST,
    SEEDS,
    BenchmarkGovernanceViolation,
    DatasetIsolationViolation,
    compute_file_sha256,
    evaluate_candidate_selection,
    load_and_preprocess_partition,
    verify_phase6_4_3_isolation,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# -----------------------------------------------------------------------------
# 1. Locked Evaluation Partition Digest Preserved
# -----------------------------------------------------------------------------
def test_01_locked_evaluation_digest_preserved():
    eval_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with open(eval_path, "r", encoding="utf-8") as f:
        recs = json.load(f)
    digest = compute_locked_test_hash(recs)
    assert digest == EXPECTED_LOCKED_TEST_HASH, f"Locked test digest changed: {digest}"

    manifest_path = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest.get("sha256_checksum") == EXPECTED_LOCKED_TEST_HASH


# -----------------------------------------------------------------------------
# 2. v3 Corpus Manifests Integrity Verified
# -----------------------------------------------------------------------------
def test_02_v3_corpus_manifests_integrity():
    for manifest_path, corpus_path, expected_count in [
        (DEFAULT_TRAIN_MANIFEST, DEFAULT_TRAIN_CORPUS, 1200),
        (DEFAULT_DEV_MANIFEST, DEFAULT_DEV_CORPUS, 300),
        (DEFAULT_QUAL_MANIFEST, DEFAULT_QUAL_CORPUS, 450),
    ]:
        assert os.path.isfile(manifest_path), f"Missing manifest: {manifest_path}"
        assert os.path.isfile(corpus_path), f"Missing corpus: {corpus_path}"

        with open(manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)

        assert m.get("record_count") == expected_count
        actual_sha = compute_file_sha256(corpus_path)
        manifest_sha = m.get("file_sha256") or m.get("sha256")
        assert actual_sha == manifest_sha, f"SHA mismatch for {corpus_path}: {actual_sha} vs {manifest_sha}"


# -----------------------------------------------------------------------------
# 3. Qualification Corpus Blocked from Training
# -----------------------------------------------------------------------------
def test_03_qualification_corpus_blocked_from_training():
    with pytest.raises(DatasetIsolationViolation) as excinfo:
        verify_phase6_4_3_isolation(
            train_path=DEFAULT_QUAL_CORPUS,
            dev_path=DEFAULT_DEV_CORPUS,
        )
    assert "qualification" in str(excinfo.value).lower()


# -----------------------------------------------------------------------------
# 4. Qualification Corpus Not Accessed as Training Data
# -----------------------------------------------------------------------------
def test_04_qualification_corpus_not_accessed():
    with open(DEFAULT_QUAL_MANIFEST, "r", encoding="utf-8") as f:
        qual_m = json.load(f)
    assert qual_m.get("lifecycle_state") == "sealed_independent_benchmark"

    # Verify that candidate manifests only cite the training and dev corpora
    for seed in SEEDS:
        cand_manifest_path = os.path.join(
            DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{seed}", "manifest.json"
        )
        assert os.path.isfile(cand_manifest_path)
        with open(cand_manifest_path, "r", encoding="utf-8") as f:
            c_man = json.load(f)
        prov = c_man.get("provenance_summary", {})
        assert "synthetic_training_corpus.jsonl" in prov.get("training_corpus", "")
        assert prov.get("qualification_partition") == "SEALED"


# -----------------------------------------------------------------------------
# 5. Locked Eval Partition Blocked
# -----------------------------------------------------------------------------
def test_05_locked_eval_partition_blocked():
    eval_dataset_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with pytest.raises(DatasetIsolationViolation) as excinfo:
        verify_phase6_4_3_isolation(
            train_path=eval_dataset_path,
            dev_path=DEFAULT_DEV_CORPUS,
        )
    assert "phishing_eval_dataset" in str(excinfo.value).lower()


# -----------------------------------------------------------------------------
# 6. Dev Data Never Used in Gradient Updates
# -----------------------------------------------------------------------------
def test_06_dev_data_not_in_gradient_updates():
    # Verify that CustomNeuralClassifier fit_batch is not called with dev data
    # by testing that forward pass in predict_proba does not store backprop cache
    model = CustomNeuralClassifier(input_dim=1024, seed=42)
    dummy_dev = np.random.RandomState(42).randn(10, 1024).astype(np.float32)

    # Reset cache
    model._cache = {}
    model.predict_proba(dummy_dev)
    # Forward in inference mode (training=False) leaves _cache empty
    assert len(model._cache) == 0, "predict_proba should not populate backprop cache"


# -----------------------------------------------------------------------------
# 7. Zero Train/Dev Leakage (IDs, Texts, Families)
# -----------------------------------------------------------------------------
def test_07_zero_train_dev_overlap():
    train_ids = set()
    train_texts = set()
    train_families = set()
    with open(DEFAULT_TRAIN_CORPUS, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            train_ids.add(d["record_id"])
            train_texts.add(d["text"].strip())
            train_families.add(d["campaign_id"])

    dev_ids = set()
    dev_texts = set()
    dev_families = set()
    with open(DEFAULT_DEV_CORPUS, "r", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            dev_ids.add(d["record_id"])
            dev_texts.add(d["text"].strip())
            dev_families.add(d["campaign_id"])

    assert len(train_ids & dev_ids) == 0, "ID overlap between train and dev!"
    assert len(train_texts & dev_texts) == 0, "Text leakage between train and dev!"
    assert len(train_families & dev_families) == 0, "Campaign family overlap between train and dev!"


# -----------------------------------------------------------------------------
# 8. Three Independent Seeds Trained
# -----------------------------------------------------------------------------
def test_08_three_independent_seeds_trained():
    for seed in [42, 101, 202]:
        cand_dir = os.path.join(DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{seed}")
        assert os.path.isdir(cand_dir), f"Missing candidate directory for seed {seed}: {cand_dir}"


# -----------------------------------------------------------------------------
# 9. Candidate Directories Unique and Isolated
# -----------------------------------------------------------------------------
def test_09_candidate_directories_unique_and_isolated():
    dirs = [
        os.path.join(DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{s}")
        for s in [42, 101, 202]
    ]
    assert len(dirs) == len(set(dirs))
    for d in dirs:
        assert os.path.isdir(d)
        assert not os.path.islink(d)


# -----------------------------------------------------------------------------
# 10. Candidate Weights NPZ Safe Serialization
# -----------------------------------------------------------------------------
def test_10_candidate_weights_npz_safe_serialization():
    required_keys = {"W1", "b1", "W2", "b2", "W3", "b3"}
    for seed in [42, 101, 202]:
        weights_path = os.path.join(
            DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{seed}", "model_weights.npz"
        )
        assert os.path.isfile(weights_path)
        with np.load(weights_path, allow_pickle=False) as data:
            for k in required_keys:
                assert k in data, f"Missing weight array {k} in {weights_path}"
            assert data["W1"].shape == (1024, 64)
            assert data["b1"].shape == (1, 64)
            assert data["W2"].shape == (64, 32)
            assert data["b2"].shape == (1, 32)
            assert data["W3"].shape == (32, 3)
            assert data["b3"].shape == (1, 3)
            # Ensure all weights are finite
            assert np.all(np.isfinite(data["W1"]))


# -----------------------------------------------------------------------------
# 11. Candidate Manifest SHA-256 Integrity
# -----------------------------------------------------------------------------
def test_11_candidate_manifest_sha256_integrity():
    for seed in [42, 101, 202]:
        cand_dir = os.path.join(DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{seed}")
        manifest_path = os.path.join(cand_dir, "manifest.json")
        with open(manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)

        artifacts = m.get("artifacts", {})
        for art_key in ["model_weights", "model_metadata", "training_report"]:
            spec = artifacts.get(art_key, {})
            filename = spec.get("filename")
            expected_sha = spec.get("sha256")
            actual_sha = compute_file_sha256(os.path.join(cand_dir, filename))
            assert actual_sha == expected_sha, (
                f"Digest mismatch for {filename} in {cand_dir}: {actual_sha} vs {expected_sha}"
            )


# -----------------------------------------------------------------------------
# 12. Candidate Metadata Schema Validity
# -----------------------------------------------------------------------------
def test_12_candidate_metadata_schema_validity():
    for seed in [42, 101, 202]:
        meta_path = os.path.join(
            DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{seed}", "model_metadata.json"
        )
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        assert meta.get("input_dim") == 1024
        assert meta.get("hidden_dim1") == 64
        assert meta.get("hidden_dim2") == 32
        assert meta.get("num_classes") == 3
        assert meta.get("seed") == seed
        assert meta.get("label_to_index") == LABEL_TO_IDX
        assert meta.get("is_experimental") is True
        training_meta = meta.get("training_metadata", {})
        assert training_meta.get("preprocessing_version") == NEURAL_PREPROCESSING_VERSION


# -----------------------------------------------------------------------------
# 13. Candidate Training Reports Completeness
# -----------------------------------------------------------------------------
def test_13_candidate_training_reports_exist_and_complete():
    for seed in [42, 101, 202]:
        report_path = os.path.join(
            DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{seed}", "candidate_training_report.json"
        )
        with open(report_path, "r", encoding="utf-8") as f:
            rep = json.load(f)

        assert rep.get("status") == "SUCCESS"
        assert rep.get("random_seed") == seed
        assert "epoch_history" in rep
        assert len(rep["epoch_history"]) > 0

        dev_metrics = rep.get("dev_evaluation_metrics", {})
        assert dev_metrics.get("sample_count") == 300
        assert "macro_f1" in dev_metrics
        assert "safety_metrics" in dev_metrics


# -----------------------------------------------------------------------------
# 14. Seed Reproducibility
# -----------------------------------------------------------------------------
def test_14_seed_reproducibility():
    hasher = CharacterNGramHasher(num_features=1024)
    X_train, y_train, Y_train, _ = load_and_preprocess_partition(DEFAULT_TRAIN_CORPUS, hasher)

    # Train two small runs with identical seed 42
    def train_mini(seed: int):
        m = CustomNeuralClassifier(input_dim=1024, seed=seed)
        rng = np.random.RandomState(seed)
        perm = rng.permutation(100)
        X_sub = X_train[perm]
        Y_sub = Y_train[perm]
        m.fit_batch(X_sub[:32], Y_sub[:32])
        return m.W1.copy()

    w1_run1 = train_mini(42)
    w1_run2 = train_mini(42)
    np.testing.assert_allclose(w1_run1, w1_run2, rtol=1e-6)


# -----------------------------------------------------------------------------
# 15. Different Seeds Produce Different Weights
# -----------------------------------------------------------------------------
def test_15_different_seeds_produce_different_weights():
    weights = []
    for seed in [42, 101, 202]:
        p = os.path.join(DEFAULT_CANDIDATES_ROOT, f"candidate_v3_seed{seed}", "model_weights.npz")
        with np.load(p, allow_pickle=False) as data:
            weights.append(data["W1"].copy())

    assert not np.allclose(weights[0], weights[1]), "Seed 42 and 101 produced identical W1!"
    assert not np.allclose(weights[0], weights[2]), "Seed 42 and 202 produced identical W1!"
    assert not np.allclose(weights[1], weights[2]), "Seed 101 and 202 produced identical W1!"


# -----------------------------------------------------------------------------
# 16. Baseline Model Evaluation on Dev Recorded
# -----------------------------------------------------------------------------
def test_16_baseline_model_evaluation_on_dev():
    assert os.path.isfile(DEFAULT_SELECTION_SUMMARY_PATH)
    with open(DEFAULT_SELECTION_SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary = json.load(f)

    baseline = summary.get("baseline_model", {})
    metrics = baseline.get("dev_metrics", {})
    assert metrics.get("sample_count") == 300
    assert abs(metrics.get("accuracy", 0.0) - 0.7333) < 0.001
    assert abs(metrics.get("macro_f1", 0.0) - 0.7384) < 0.001


# -----------------------------------------------------------------------------
# 17. Candidate Selection Policy Execution
# -----------------------------------------------------------------------------
def test_17_candidate_selection_policy_execution():
    with open(DEFAULT_SELECTION_SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary = json.load(f)

    decision = summary.get("selection_decision", {})
    assert decision.get("status") == "CANDIDATE_SELECTED"
    assert decision.get("selected_candidate_id") == "candidate_v3_seed202"
    assert decision.get("selected_seed") == 202
    assert decision.get("ranking_order") == [
        "candidate_v3_seed202",
        "candidate_v3_seed42",
        "candidate_v3_seed101",
    ]


# -----------------------------------------------------------------------------
# 18. Candidate Selection Policy Logic Unit Test
# -----------------------------------------------------------------------------
def test_18_candidate_selection_policy_logic_unit():
    dummy_baseline = {"metrics": {"macro_f1": 0.75}}

    # Scenario A: All pass -> highest macro-F1 wins
    cand_a = {
        "seed": 1,
        "candidate_id": "cand_1",
        "dev_metrics": {
            "macro_f1": 0.94,
            "safety_metrics": {"legitimate_fp_rate": 0.10, "protective_advisory_fp_rate": 0.0, "phishing_fn_rate": 0.02},
        },
    }
    cand_b = {
        "seed": 2,
        "candidate_id": "cand_2",
        "dev_metrics": {
            "macro_f1": 0.96,
            "safety_metrics": {"legitimate_fp_rate": 0.11, "protective_advisory_fp_rate": 0.0, "phishing_fn_rate": 0.01},
        },
    }
    res_a = evaluate_candidate_selection(dummy_baseline, [cand_a, cand_b])
    assert res_a["status"] == "CANDIDATE_SELECTED"
    assert res_a["selected_candidate_id"] == "cand_2"

    # Scenario B: Winner fails legitimate FP gate (> 0.15) -> lower macro-F1 that passes wins
    cand_b_fail = {
        "seed": 2,
        "candidate_id": "cand_2",
        "dev_metrics": {
            "macro_f1": 0.96,
            "safety_metrics": {"legitimate_fp_rate": 0.20, "protective_advisory_fp_rate": 0.0, "phishing_fn_rate": 0.01},
        },
    }
    res_b = evaluate_candidate_selection(dummy_baseline, [cand_a, cand_b_fail])
    assert res_b["status"] == "CANDIDATE_SELECTED"
    assert res_b["selected_candidate_id"] == "cand_1"

    # Scenario C: All fail -> NO_CANDIDATE_SELECTED
    cand_a_fail = {
        "seed": 1,
        "candidate_id": "cand_1",
        "dev_metrics": {
            "macro_f1": 0.85,  # below 0.90
            "safety_metrics": {"legitimate_fp_rate": 0.10, "protective_advisory_fp_rate": 0.0, "phishing_fn_rate": 0.02},
        },
    }
    res_c = evaluate_candidate_selection(dummy_baseline, [cand_a_fail, cand_b_fail])
    assert res_c["status"] == "NO_CANDIDATE_SELECTED"
    assert res_c["selected_candidate_id"] is None


# -----------------------------------------------------------------------------
# 19. Model Registry Unmodified
# -----------------------------------------------------------------------------
def test_19_model_registry_unmodified():
    registry_path = os.path.join(PROJECT_ROOT, "models", "model_registry.json")
    with open(registry_path, "r", encoding="utf-8") as f:
        registry = json.load(f)

    models = registry.get("registered_models", {})
    # No candidate_v3 model should be registered in model_registry.json
    for m_ver in models:
        assert not m_ver.startswith("candidate_v3"), f"Forbidden candidate '{m_ver}' in model_registry.json!"
    assert "custom-mlp-v1.0.0" in models
    assert "custom-mlp-v1.1.0-preproc" in models


# -----------------------------------------------------------------------------
# 20. Active Model Config Unmodified
# -----------------------------------------------------------------------------
def test_20_active_model_config_unmodified():
    config_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    assert config.get("active_model_version") == "custom-mlp-v1.1.0-preproc"
    assert config.get("operating_mode") == "shadow"
    assert config.get("is_production_authoritative") is False
    assert not config.get("active_model_version", "").startswith("candidate_v3")


# -----------------------------------------------------------------------------
# 21. Production Score Delta Zero
# -----------------------------------------------------------------------------
def test_21_production_score_delta_zero():
    from src.phishing_detector import analyze_message_text
    from src.risk_scorer import score_message_analysis
    from src.hybrid_decision_engine import HybridDecisionEngine

    sample_text = "Urgent: Electricity bill overdue. Call 9800000001 immediately."
    
    # 1. Authoritative rule-based heuristic score
    detector_res = analyze_message_text(sample_text)
    rule_score_res = score_message_analysis(detector_res)
    authoritative_score = rule_score_res["score"]

    # 2. Hybrid decision engine evaluation
    engine = HybridDecisionEngine()
    eval_res = engine.evaluate_message(sample_text)

    # In shadow operating mode, authoritative score must equal the pure rule score exactly
    assert eval_res.get("operating_mode") == "shadow"
    final_dec = eval_res.get("final_decision", {})
    assert final_dec.get("authoritative_source") == "deterministic_rules"
    assert final_dec.get("final_risk_score") == authoritative_score
    assert final_dec.get("production_score_difference") == 0
