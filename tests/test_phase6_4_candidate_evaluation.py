"""
Unit and Integration Test Suite for Candidate Model Evaluation and Benchmark Gate (Phase 6.4).
Verifies all 24 required safety, integrity, metric, subgroup, robustness, and governance scenarios:
 1. Correct baseline model identification.
 2. Correct candidate identification.
 3. Candidate checkpoint hash validation.
 4. Candidate metadata hash validation.
 5. Manifest tampering detection.
 6. Path traversal rejection.
 7. Feature schema mismatch.
 8. Label mapping mismatch.
 9. Preprocessing mismatch.
10. Validation dataset manifest verification.
11. Training/validation overlap rejection.
12. Locked evaluation isolation.
13. Missing class handling.
14. Confusion matrix correctness.
15. Per-class metric correctness.
16. False-positive rate calculations.
17. Confidence interval calculations.
18. Small-sample insufficient-evidence decisions.
19. Counterfactual test reporting.
20. Incompatible model rejection.
21. Failed evaluation leaves all artifacts unchanged.
22. Evaluation does not invoke training.
23. Active model configuration remains unchanged.
24. Production score delta remains zero.
"""

import copy
import json
import os
import shutil
import tempfile
import numpy as np
import pytest

from src.candidate_evaluator import (
    ArtifactIntegrityError,
    BenchmarkPolicy,
    BenchmarkVerdict,
    CandidateEvaluator,
    CandidateIncompatibleError,
    DatasetIsolationError,
    compute_classification_metrics,
    compute_confusion_matrix,
    compute_file_sha256,
    wilson_score_interval,
)
from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.hybrid_decision_engine import HybridDecisionEngine

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CANDIDATE_PATH = "models/candidates/candidate_custom_v1.0.0"
VAL_CORPUS_PATH = "data/generated/v2/synthetic_validation_corpus.jsonl"
TRAIN_CORPUS_PATH = "data/generated/v2/synthetic_training_corpus.jsonl"
BASELINE_FIXTURE_PATH = os.path.join(PROJECT_ROOT, "tests", "fixtures", "model_configs", "pre_phase6_5_baseline.json")


@pytest.fixture
def evaluator():
    return CandidateEvaluator(project_root=PROJECT_ROOT)


# -----------------------------------------------------------------------------
# 1. Correct baseline model identification
# -----------------------------------------------------------------------------
def test_01_correct_baseline_model_identification(evaluator):
    base_info = evaluator.discover_baseline_model(active_config_path=BASELINE_FIXTURE_PATH)
    assert base_info["model_version"] == "custom-mlp-v1.1.0-preproc"
    assert "models/experimental_custom_v1" in base_info["checkpoint_dir"].replace("\\", "/")
    assert base_info["operating_mode"] == "shadow"
    assert base_info["is_production_authoritative"] is False
    assert len(base_info["weights_sha256"]) == 64


# -----------------------------------------------------------------------------
# 2. Correct candidate identification
# -----------------------------------------------------------------------------
def test_02_correct_candidate_identification(evaluator):
    cand_info = evaluator.verify_candidate_provenance(CANDIDATE_PATH)
    assert cand_info["candidate_id"] == "candidate_custom_v1.0.0"
    assert cand_info["candidate_version"] == "1.0.0"
    assert cand_info["lifecycle_state"] == "experimental"
    assert cand_info["provenance_summary"]["composition_policy"] == "synthetic_only"
    assert len(cand_info["weights_sha256"]) == 64


# -----------------------------------------------------------------------------
# 3. Candidate checkpoint hash validation
# -----------------------------------------------------------------------------
def test_03_candidate_checkpoint_hash_validation(tmp_path):
    # Copy candidate artifacts to temporary directory inside models/
    tmp_cand_dir = os.path.join(PROJECT_ROOT, "models", "_test_tampered_weights")
    if os.path.exists(tmp_cand_dir):
        shutil.rmtree(tmp_cand_dir)
    shutil.copytree(os.path.join(PROJECT_ROOT, CANDIDATE_PATH), tmp_cand_dir)

    try:
        # Tamper with weights file
        weights_file = os.path.join(tmp_cand_dir, "model_weights.npz")
        with open(weights_file, "ab") as f:
            f.write(b"\x00\x00corrupt")

        evaluator = CandidateEvaluator(project_root=PROJECT_ROOT)
        with pytest.raises(ArtifactIntegrityError, match="Candidate weights SHA-256 mismatch"):
            evaluator.verify_candidate_provenance("models/_test_tampered_weights")
    finally:
        if os.path.exists(tmp_cand_dir):
            shutil.rmtree(tmp_cand_dir)


# -----------------------------------------------------------------------------
# 4. Candidate metadata hash validation
# -----------------------------------------------------------------------------
def test_04_candidate_metadata_hash_validation():
    tmp_cand_dir = os.path.join(PROJECT_ROOT, "models", "_test_tampered_meta")
    if os.path.exists(tmp_cand_dir):
        shutil.rmtree(tmp_cand_dir)
    shutil.copytree(os.path.join(PROJECT_ROOT, CANDIDATE_PATH), tmp_cand_dir)

    try:
        meta_file = os.path.join(tmp_cand_dir, "model_metadata.json")
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["tampered"] = True
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f)

        evaluator = CandidateEvaluator(project_root=PROJECT_ROOT)
        with pytest.raises(ArtifactIntegrityError, match="Candidate metadata SHA-256 mismatch"):
            evaluator.verify_candidate_provenance("models/_test_tampered_meta")
    finally:
        if os.path.exists(tmp_cand_dir):
            shutil.rmtree(tmp_cand_dir)


# -----------------------------------------------------------------------------
# 5. Manifest tampering detection
# -----------------------------------------------------------------------------
def test_05_manifest_tampering_detection():
    tmp_cand_dir = os.path.join(PROJECT_ROOT, "models", "_test_tampered_manifest")
    if os.path.exists(tmp_cand_dir):
        shutil.rmtree(tmp_cand_dir)
    shutil.copytree(os.path.join(PROJECT_ROOT, CANDIDATE_PATH), tmp_cand_dir)

    try:
        manifest_file = os.path.join(tmp_cand_dir, "manifest.json")
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        # Change recorded weights digest
        manifest["artifacts"]["model_weights"]["sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        evaluator = CandidateEvaluator(project_root=PROJECT_ROOT)
        with pytest.raises(ArtifactIntegrityError, match="Candidate weights SHA-256 mismatch"):
            evaluator.verify_candidate_provenance("models/_test_tampered_manifest")
    finally:
        if os.path.exists(tmp_cand_dir):
            shutil.rmtree(tmp_cand_dir)


# -----------------------------------------------------------------------------
# 6. Path traversal rejection
# -----------------------------------------------------------------------------
def test_06_path_traversal_rejection(evaluator):
    with pytest.raises(CandidateIncompatibleError, match="Path traversal detected"):
        evaluator.validate_safe_model_path("../../../etc/passwd")

    with pytest.raises(CandidateIncompatibleError, match="Security violation"):
        evaluator.validate_safe_model_path("src")


# -----------------------------------------------------------------------------
# 7. Feature schema mismatch
# -----------------------------------------------------------------------------
def test_07_feature_schema_mismatch():
    tmp_cand_dir = os.path.join(PROJECT_ROOT, "models", "_test_mismatch_schema")
    if os.path.exists(tmp_cand_dir):
        shutil.rmtree(tmp_cand_dir)
    shutil.copytree(os.path.join(PROJECT_ROOT, CANDIDATE_PATH), tmp_cand_dir)

    try:
        meta_file = os.path.join(tmp_cand_dir, "model_metadata.json")
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["input_dim"] = 512
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f)

        # Update manifest to match new metadata hash so it passes hash check and hits dimension check
        new_meta_sha = compute_file_sha256(meta_file)
        manifest_file = os.path.join(tmp_cand_dir, "manifest.json")
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["artifacts"]["model_metadata"]["sha256"] = new_meta_sha
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        evaluator = CandidateEvaluator(project_root=PROJECT_ROOT)
        with pytest.raises(CandidateIncompatibleError, match="Candidate feature dimension must be 1024, found 512"):
            evaluator.verify_candidate_provenance("models/_test_mismatch_schema")
    finally:
        if os.path.exists(tmp_cand_dir):
            shutil.rmtree(tmp_cand_dir)


# -----------------------------------------------------------------------------
# 8. Label mapping mismatch
# -----------------------------------------------------------------------------
def test_08_label_mapping_mismatch():
    tmp_cand_dir = os.path.join(PROJECT_ROOT, "models", "_test_mismatch_lbl")
    if os.path.exists(tmp_cand_dir):
        shutil.rmtree(tmp_cand_dir)
    shutil.copytree(os.path.join(PROJECT_ROOT, CANDIDATE_PATH), tmp_cand_dir)

    try:
        meta_file = os.path.join(tmp_cand_dir, "model_metadata.json")
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        # Invert labels
        meta["label_to_index"] = {"phishing": 1, "legitimate": 0, "protective_advisory": 2}
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f)

        manifest_file = os.path.join(tmp_cand_dir, "manifest.json")
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["artifacts"]["model_metadata"]["sha256"] = compute_file_sha256(meta_file)
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        evaluator = CandidateEvaluator(project_root=PROJECT_ROOT)
        with pytest.raises(CandidateIncompatibleError, match="Candidate label mapping mismatch"):
            evaluator.verify_candidate_provenance("models/_test_mismatch_lbl")
    finally:
        if os.path.exists(tmp_cand_dir):
            shutil.rmtree(tmp_cand_dir)


# -----------------------------------------------------------------------------
# 9. Preprocessing mismatch
# -----------------------------------------------------------------------------
def test_09_preprocessing_mismatch():
    tmp_cand_dir = os.path.join(PROJECT_ROOT, "models", "_test_mismatch_preproc")
    if os.path.exists(tmp_cand_dir):
        shutil.rmtree(tmp_cand_dir)
    shutil.copytree(os.path.join(PROJECT_ROOT, CANDIDATE_PATH), tmp_cand_dir)

    try:
        report_file = os.path.join(tmp_cand_dir, "candidate_training_report.json")
        with open(report_file, "r", encoding="utf-8") as f:
            rep = json.load(f)
        rep["dataset_provenance"]["preprocessing_version"] = "legacy-raw-v0.9.0"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(rep, f)

        manifest_file = os.path.join(tmp_cand_dir, "manifest.json")
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["artifacts"]["training_report"]["sha256"] = compute_file_sha256(report_file)
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        evaluator = CandidateEvaluator(project_root=PROJECT_ROOT)
        with pytest.raises(CandidateIncompatibleError, match="Candidate preprocessing version mismatch"):
            evaluator.verify_candidate_provenance("models/_test_mismatch_preproc")
    finally:
        if os.path.exists(tmp_cand_dir):
            shutil.rmtree(tmp_cand_dir)


# -----------------------------------------------------------------------------
# 10. Validation dataset manifest verification
# -----------------------------------------------------------------------------
def test_10_validation_dataset_manifest_verification(evaluator):
    iso_info = evaluator.verify_dataset_isolation(os.path.join(PROJECT_ROOT, VAL_CORPUS_PATH))
    assert iso_info["validation_records_count"] == 135
    assert iso_info["validation_dataset_sha256"] == "77911f9db811de13c5e89f7f756cb13bbc73c4ad9c13c0d401a62287052cf777"
    assert iso_info["locked_test_manifest_sha256"] == "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"
    assert iso_info["training_validation_overlap_count"] == 0
    assert iso_info["isolation_guarantee"] == "VERIFIED_ISOLATED"


# -----------------------------------------------------------------------------
# 11. Training/validation overlap rejection
# -----------------------------------------------------------------------------
def test_11_training_validation_overlap_rejection(tmp_path, evaluator):
    # Create fake validation corpus containing an ID from the training corpus
    val_file = tmp_path / "fake_val_corpus.jsonl"
    with open(val_file, "w", encoding="utf-8") as f:
        # syn_v2_train_0001 is a known training ID
        f.write(json.dumps({
            "record_id": "syn_v2_train_0001",
            "text": "Overlapping message text",
            "ground_truth_label": "phishing",
            "dataset_role": "validation"
        }) + "\n")

    with pytest.raises(DatasetIsolationError, match="Data contamination detected"):
        evaluator.verify_dataset_isolation(
            val_path=str(val_file),
            train_path=os.path.join(PROJECT_ROOT, TRAIN_CORPUS_PATH)
        )


# -----------------------------------------------------------------------------
# 12. Locked evaluation isolation
# -----------------------------------------------------------------------------
def test_12_locked_evaluation_isolation(evaluator):
    # Attempting to evaluate on locked evaluation dataset itself must raise critical error
    eval_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with pytest.raises(DatasetIsolationError, match="CRITICAL SECURITY VIOLATION"):
        evaluator.verify_dataset_isolation(val_path=eval_path)


# -----------------------------------------------------------------------------
# 13. Missing class handling
# -----------------------------------------------------------------------------
def test_13_missing_class_handling():
    # Only class 0 and 1 present; class 2 missing
    y_true = np.array([0, 0, 1, 1], dtype=np.int64)
    y_pred = np.array([0, 0, 1, 1], dtype=np.int64)

    metrics = compute_classification_metrics(y_true, y_pred)
    assert metrics["per_class"]["protective_advisory"]["support"] == 0
    assert metrics["per_class"]["protective_advisory"]["precision"] == 0.0
    assert metrics["per_class"]["protective_advisory"]["recall"] == 0.0
    assert metrics["per_class"]["protective_advisory"]["f1"] == 0.0
    assert metrics["accuracy"] == 1.0


# -----------------------------------------------------------------------------
# 14. Confusion matrix correctness
# -----------------------------------------------------------------------------
def test_14_confusion_matrix_correctness():
    y_true = np.array([0, 0, 1, 1, 2, 2], dtype=np.int64)
    y_pred = np.array([0, 1, 1, 1, 2, 0], dtype=np.int64)
    cm = compute_confusion_matrix(y_true, y_pred, num_classes=3)
    # Row 0: True 0 -> Pred 0 (1), Pred 1 (1), Pred 2 (0)
    assert cm[0] == [1, 1, 0]
    # Row 1: True 1 -> Pred 0 (0), Pred 1 (2), Pred 2 (0)
    assert cm[1] == [0, 2, 0]
    # Row 2: True 2 -> Pred 0 (1), Pred 1 (0), Pred 2 (1)
    assert cm[2] == [1, 0, 1]


# -----------------------------------------------------------------------------
# 15. Per-class metric correctness
# -----------------------------------------------------------------------------
def test_15_per_class_metric_correctness():
    # 2 true class 0: 1 predicted 0, 1 predicted 1
    # 2 true class 1: 2 predicted 1
    y_true = np.array([0, 0, 1, 1], dtype=np.int64)
    y_pred = np.array([0, 1, 1, 1], dtype=np.int64)
    metrics = compute_classification_metrics(y_true, y_pred)

    p0 = metrics["per_class"]["phishing"]
    assert p0["true_positives"] == 1
    assert p0["support"] == 2
    assert p0["recall"] == 0.5
    assert p0["precision"] == 1.0
    assert p0["recall_fraction"] == "1/2"
    assert p0["precision_fraction"] == "1/1"


# -----------------------------------------------------------------------------
# 16. False-positive rate calculations
# -----------------------------------------------------------------------------
def test_16_false_positive_rate_calculations():
    # 2 legitimate: 1 predicted phishing, 1 predicted legitimate
    # 1 advisory: 0 predicted phishing
    y_true = np.array([1, 1, 2], dtype=np.int64)
    y_pred = np.array([0, 1, 2], dtype=np.int64)
    metrics = compute_classification_metrics(y_true, y_pred)

    safety = metrics["safety_metrics"]
    assert safety["legitimate_fp_rate"] == 0.5
    assert safety["legitimate_fp_fraction"] == "1/2"
    assert safety["protective_advisory_fp_rate"] == 0.0
    assert safety["protective_advisory_fp_fraction"] == "0/1"


# -----------------------------------------------------------------------------
# 17. Confidence interval calculations
# -----------------------------------------------------------------------------
def test_17_confidence_interval_calculations():
    # Wilson interval for 128 / 135
    low, high = wilson_score_interval(128, 135, confidence=0.95)
    assert 0.89 < low < 0.90
    assert 0.97 < high < 0.98

    # Zero successes
    low_0, high_0 = wilson_score_interval(0, 45, confidence=0.95)
    assert low_0 == 0.0
    assert 0.07 < high_0 < 0.09

    # Perfect successes
    low_p, high_p = wilson_score_interval(45, 45, confidence=0.95)
    assert 0.92 < low_p < 0.93
    assert high_p == 1.0


# -----------------------------------------------------------------------------
# 18. Small-sample insufficient-evidence decisions
# -----------------------------------------------------------------------------
def test_18_small_sample_insufficient_evidence_decisions(evaluator):
    # Baseline & candidate metrics with very small sample size N=10
    tiny_base = {
        "sample_count": 10,
        "macro_f1": 0.95,
        "per_class": {"phishing": {"support": 3}, "legitimate": {"support": 4}, "protective_advisory": {"support": 3}},
        "safety_metrics": {"legitimate_fp_rate": 0.0, "protective_advisory_fp_rate": 0.0, "phishing_fn_rate": 0.0},
    }
    tiny_cand = copy.deepcopy(tiny_base)
    robustness = {"whitespace_invariance": {"candidate_flip_rate": 0.0}, "zero_width_invariance": {"candidate_flip_rate": 0.0}, "devanagari_numeral_invariance": {"candidate_flip_rate": 0.0}}

    gate = evaluator.evaluate_benchmark_gate(tiny_base, tiny_cand, robustness)
    assert gate["verdict"] == BenchmarkVerdict.INSUFFICIENT_EVIDENCE.value
    assert any("Insufficient total validation samples" in r for r in gate["reasons"])


# -----------------------------------------------------------------------------
# 19. Counterfactual test reporting
# -----------------------------------------------------------------------------
def test_19_counterfactual_test_reporting(evaluator):
    val_records = evaluator.load_validation_records(os.path.join(PROJECT_ROOT, VAL_CORPUS_PATH))
    base_model = CustomNeuralClassifier.load_checkpoint(os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1"))
    cand_model = CustomNeuralClassifier.load_checkpoint(os.path.join(PROJECT_ROOT, CANDIDATE_PATH))

    # Test on a small slice of 10 records
    sub_records = val_records[:10]
    res = evaluator.run_counterfactual_robustness_tests(sub_records, base_model, cand_model)

    assert "whitespace_invariance" in res
    assert "zero_width_invariance" in res
    assert "devanagari_numeral_invariance" in res
    assert res["whitespace_invariance"]["samples_tested"] == 10
    assert res["whitespace_invariance"]["baseline_flip_rate"] == 0.0
    assert res["whitespace_invariance"]["candidate_flip_rate"] == 0.0


# -----------------------------------------------------------------------------
# 20. Incompatible model rejection
# -----------------------------------------------------------------------------
def test_20_incompatible_model_rejection():
    tmp_cand_dir = os.path.join(PROJECT_ROOT, "models", "_test_incompatible_classes")
    if os.path.exists(tmp_cand_dir):
        shutil.rmtree(tmp_cand_dir)
    shutil.copytree(os.path.join(PROJECT_ROOT, CANDIDATE_PATH), tmp_cand_dir)

    try:
        meta_file = os.path.join(tmp_cand_dir, "model_metadata.json")
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["num_classes"] = 5
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta, f)

        manifest_file = os.path.join(tmp_cand_dir, "manifest.json")
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        manifest["artifacts"]["model_metadata"]["sha256"] = compute_file_sha256(meta_file)
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        evaluator = CandidateEvaluator(project_root=PROJECT_ROOT)
        with pytest.raises(CandidateIncompatibleError, match="Candidate num_classes must be 3, found 5"):
            evaluator.verify_candidate_provenance("models/_test_incompatible_classes")
    finally:
        if os.path.exists(tmp_cand_dir):
            shutil.rmtree(tmp_cand_dir)



# -----------------------------------------------------------------------------
# 21. Failed evaluation leaves all artifacts unchanged
# -----------------------------------------------------------------------------
def test_21_failed_evaluation_leaves_all_artifacts_unchanged(evaluator):
    cand_weights = os.path.join(PROJECT_ROOT, CANDIDATE_PATH, "model_weights.npz")
    cand_meta = os.path.join(PROJECT_ROOT, CANDIDATE_PATH, "model_metadata.json")
    hash_w_before = compute_file_sha256(cand_weights)
    hash_m_before = compute_file_sha256(cand_meta)

    # Run full evaluation (which results in FAIL for the 5-epoch candidate)
    report = evaluator.run_full_evaluation(CANDIDATE_PATH)
    assert report["benchmark_gate"]["verdict"] == BenchmarkVerdict.FAIL.value

    assert compute_file_sha256(cand_weights) == hash_w_before
    assert compute_file_sha256(cand_meta) == hash_m_before


# -----------------------------------------------------------------------------
# 22. Evaluation does not invoke training
# -----------------------------------------------------------------------------
def test_22_evaluation_does_not_invoke_training(evaluator):
    cand_weights = os.path.join(PROJECT_ROOT, CANDIDATE_PATH, "model_weights.npz")
    mtime_before = os.path.getmtime(cand_weights)

    evaluator.run_full_evaluation(CANDIDATE_PATH)

    mtime_after = os.path.getmtime(cand_weights)
    assert mtime_before == mtime_after


# -----------------------------------------------------------------------------
# 23. Active model configuration remains unchanged
# -----------------------------------------------------------------------------
def test_23_active_model_configuration_remains_unchanged(evaluator):
    cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    reg_path = os.path.join(PROJECT_ROOT, "models", "model_registry.json")

    hash_cfg_before = compute_file_sha256(cfg_path)
    hash_reg_before = compute_file_sha256(reg_path)

    evaluator.run_full_evaluation(CANDIDATE_PATH)

    assert compute_file_sha256(cfg_path) == hash_cfg_before
    assert compute_file_sha256(reg_path) == hash_reg_before


# -----------------------------------------------------------------------------
# 24. Production score delta remains zero
# -----------------------------------------------------------------------------
def test_24_production_score_delta_remains_zero():
    engine = HybridDecisionEngine()
    test_message = "Dear citizen, please claim your Mahavitaran electricity refund at http://msedcl.invalid"
    res = engine.evaluate_message(test_message)

    final_dec = res.get("final_decision", {})
    assert final_dec.get("production_score_difference") == 0
    assert final_dec.get("authoritative_source") == "deterministic_rules"
    assert "GR-01 (Rule Primacy)" in final_dec.get("guardrails_applied", [])[0]
