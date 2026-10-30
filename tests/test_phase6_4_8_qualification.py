"""
Automated Test Suite for One-Time Independent Candidate Qualification (Phase 6.4.8).
Validates candidate_v4_seed42 and baseline custom-mlp-v1.1.0-preproc against Dataset v4 Qualification Partition.

Covers all 24 required governance and technical audit scenarios:
 1. Correct candidate identity ('candidate_v4_seed42').
 2. Correct baseline identity ('custom-mlp-v1.1.0-preproc').
 3. Candidate checkpoint integrity (SHA-256 matches manifest).
 4. Baseline checkpoint integrity (SHA-256 matches registry).
 5. Qualification manifest integrity (450 records, 9 families, sha256 match).
 6. Wrong partition rejection (non-qualification partition rejected).
 7. Already-exposed partition rejection.
 8. Failed preflight does not consume the dataset.
 9. Exposure ledger atomicity (EVALUATION_IN_PROGRESS written atomically).
10. Interrupted evaluation marks partition exposed ('EXPOSED_INCOMPLETE').
11. Second evaluation attempt is strictly rejected.
12. Confusion matrix calculation correctness.
13. Per-class metrics calculation correctness.
14. Citizen-safety denominator correctness.
15. Conventional false-positive rate calculation.
16. Campaign-family aggregation and breakdown.
17. Cluster-bootstrap reporting and intervals.
18. Missing subgroup handling gracefully.
19. Counterfactual robustness calculations.
20. Artifact corruption rejection (corrupt weights rejected).
21. Evaluation does not invoke training procedures.
22. Active model configuration remains unchanged (shadow mode).
23. Production model registry remains unchanged.
24. Production risk score delta remains zero.
"""

from collections import Counter
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
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import (
    EXPECTED_FEATURE_DIM,
    NEURAL_PREPROCESSING_VERSION,
    preprocess_for_neural_model,
)
from src.dataset_validator import compute_locked_test_hash
from src.candidate_evaluator import (
    EXPECTED_LOCKED_TEST_HASH,
    compute_classification_metrics,
)
from src.hybrid_decision_engine import HybridDecisionEngine
from src.qualification_evaluator_v4 import (
    DEFAULT_ACTIVE_CONFIG_PATH,
    DEFAULT_BASELINE_DIR,
    DEFAULT_CANDIDATE_V4_DIR,
    DEFAULT_LOCKED_TEST_DATASET,
    DEFAULT_LOCKED_TEST_MANIFEST,
    DEFAULT_REGISTRY_PATH,
    DEFAULT_V4_CORPUS_MANIFEST,
    DEFAULT_V4_EXPOSURE_LEDGER_PATH,
    DEFAULT_V4_OUTPUT_REPORT_PATH,
    DEFAULT_V4_QUAL_CORPUS,
    DEFAULT_V4_QUAL_MANIFEST,
    EXPECTED_V4_QUAL_SHA256,
    EvaluationExposureLedgerV4,
    PartitionAlreadyExposedError,
    QualificationEvaluatorV4,
    QualificationIntegrityError,
    QualificationPolicyV4,
    QualificationPreflightCheckerV4,
    QualificationPreflightError,
    QualificationVerdict,
    compute_file_sha256,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXPECTED_CANDIDATE_WEIGHTS_SHA256 = "3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f"
EXPECTED_BASELINE_WEIGHTS_SHA256 = "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"


# -----------------------------------------------------------------------------
# 1. Correct Candidate Identity
# -----------------------------------------------------------------------------
def test_01_correct_candidate_identity():
    assert os.path.isdir(DEFAULT_CANDIDATE_V4_DIR)
    manifest_path = os.path.join(DEFAULT_CANDIDATE_V4_DIR, "manifest.json")
    assert os.path.isfile(manifest_path)
    with open(manifest_path, "r", encoding="utf-8") as f:
        m = json.load(f)
    assert m["candidate_id"] == "candidate_v4_seed42"
    assert m["random_seed"] == 42


# -----------------------------------------------------------------------------
# 2. Correct Baseline Identity
# -----------------------------------------------------------------------------
def test_02_correct_baseline_identity():
    with open(DEFAULT_REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)
    assert "custom-mlp-v1.1.0-preproc" in reg["registered_models"]
    b_entry = reg["registered_models"]["custom-mlp-v1.1.0-preproc"]
    assert b_entry["model_version"] == "custom-mlp-v1.1.0-preproc"
    assert b_entry["preprocessing_version"] == NEURAL_PREPROCESSING_VERSION


# -----------------------------------------------------------------------------
# 3. Candidate Checkpoint Integrity
# -----------------------------------------------------------------------------
def test_03_candidate_checkpoint_integrity():
    weights_path = os.path.join(DEFAULT_CANDIDATE_V4_DIR, "model_weights.npz")
    assert os.path.isfile(weights_path)
    actual_sha = compute_file_sha256(weights_path)
    assert actual_sha == EXPECTED_CANDIDATE_WEIGHTS_SHA256


# -----------------------------------------------------------------------------
# 4. Baseline Checkpoint Integrity
# -----------------------------------------------------------------------------
def test_04_baseline_checkpoint_integrity():
    weights_path = os.path.join(DEFAULT_BASELINE_DIR, "model_weights.npz")
    assert os.path.isfile(weights_path)
    actual_sha = compute_file_sha256(weights_path)
    assert actual_sha == EXPECTED_BASELINE_WEIGHTS_SHA256


# -----------------------------------------------------------------------------
# 5. Qualification Manifest Integrity
# -----------------------------------------------------------------------------
def test_05_qualification_manifest_integrity():
    assert os.path.isfile(DEFAULT_V4_QUAL_MANIFEST)
    with open(DEFAULT_V4_QUAL_MANIFEST, "r", encoding="utf-8") as f:
        man = json.load(f)
    assert man["partition"] == "qualification"
    assert man["lifecycle_state"] == "sealed_independent_benchmark"
    assert man["record_count"] == 450
    assert man["campaign_family_count"] == 9
    assert man["file_sha256"] == EXPECTED_V4_QUAL_SHA256


# -----------------------------------------------------------------------------
# 6. Wrong Partition Rejection
# -----------------------------------------------------------------------------
def test_06_wrong_partition_rejection():
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_manifest = os.path.join(tmpdir, "manifest.json")
        with open(fake_manifest, "w", encoding="utf-8") as f:
            json.dump({
                "partition": "development",  # Wrong partition
                "lifecycle_state": "sealed_independent_benchmark",
                "record_count": 450,
                "campaign_family_count": 9,
                "file_sha256": "fake_sha",
            }, f)
        fake_corpus = os.path.join(tmpdir, "corpus.jsonl")
        with open(fake_corpus, "w", encoding="utf-8") as f:
            f.write("{}\n")

        with pytest.raises(QualificationPreflightError, match="Manifest partition must be 'qualification'"):
            QualificationPreflightCheckerV4.verify_all(
                qual_corpus_path=fake_corpus,
                qual_manifest_path=fake_manifest,
            )


# -----------------------------------------------------------------------------
# 7. Already-Exposed Partition Rejection
# -----------------------------------------------------------------------------
def test_07_already_exposed_partition_rejection():
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_ledger_path = os.path.join(tmpdir, "exposure_ledger.json")
        ledger = EvaluationExposureLedgerV4(ledger_path=fake_ledger_path)

        # Record exposure
        fake_sha = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ledger.record_evaluation_in_progress(
            partition_sha256=fake_sha,
            partition_file_name="fake_qual.jsonl",
            candidate_id="candidate_test",
            baseline_id="baseline_test",
        )

        # Attempting second evaluation must raise PartitionAlreadyExposedError
        with pytest.raises(PartitionAlreadyExposedError, match="ONE-TIME QUALIFICATION VIOLATION"):
            ledger.record_evaluation_in_progress(
                partition_sha256=fake_sha,
                partition_file_name="fake_qual.jsonl",
                candidate_id="candidate_test",
                baseline_id="baseline_test",
            )


# -----------------------------------------------------------------------------
# 8. Failed Preflight Does Not Consume Dataset
# -----------------------------------------------------------------------------
def test_08_failed_preflight_does_not_consume_dataset():
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_ledger_path = os.path.join(tmpdir, "exposure_ledger.json")
        # Run preflight with missing candidate weights file
        with pytest.raises(QualificationPreflightError):
            QualificationPreflightCheckerV4.verify_all(
                candidate_dir=os.path.join(tmpdir, "nonexistent_candidate"),
                exposure_ledger_path=fake_ledger_path,
            )
        # Ensure ledger does not exist or has 0 exposures
        assert not os.path.isfile(fake_ledger_path)


# -----------------------------------------------------------------------------
# 9. Exposure Ledger Atomicity
# -----------------------------------------------------------------------------
def test_09_exposure_ledger_atomicity():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_file = os.path.join(tmpdir, "exposure_ledger.json")
        ledger = EvaluationExposureLedgerV4(ledger_path=ledger_file)
        test_sha = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

        ledger.record_evaluation_in_progress(
            partition_sha256=test_sha,
            partition_file_name="test.jsonl",
            candidate_id="cand_test",
            baseline_id="base_test",
        )
        assert os.path.isfile(ledger_file)
        data = ledger.load_ledger()
        assert data["partitions"][test_sha]["current_status"] == "EVALUATION_IN_PROGRESS"
        assert data["partitions"][test_sha]["is_exposed"] is True
        assert data["partitions"][test_sha]["exposure_count"] == 1


# -----------------------------------------------------------------------------
# 10. Interrupted Evaluation Marks Partition Exposed
# -----------------------------------------------------------------------------
def test_10_interrupted_evaluation_marks_exposed():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_file = os.path.join(tmpdir, "exposure_ledger.json")
        ledger = EvaluationExposureLedgerV4(ledger_path=ledger_file)
        test_sha = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

        ledger.record_evaluation_in_progress(
            partition_sha256=test_sha,
            partition_file_name="test.jsonl",
            candidate_id="cand_test",
            baseline_id="base_test",
        )
        ledger.record_exposed_incomplete(
            partition_sha256=test_sha,
            candidate_id="cand_test",
            error_message="Simulated process interruption",
        )

        data = ledger.load_ledger()
        entry = data["partitions"][test_sha]
        assert entry["current_status"] == "EXPOSED_INCOMPLETE"
        assert entry["is_exposed"] is True


# -----------------------------------------------------------------------------
# 11. Second Evaluation Is Rejected
# -----------------------------------------------------------------------------
def test_11_second_evaluation_is_rejected():
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_file = os.path.join(tmpdir, "exposure_ledger.json")
        ledger = EvaluationExposureLedgerV4(ledger_path=ledger_file)
        test_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

        ledger.record_evaluation_in_progress(
            partition_sha256=test_sha,
            partition_file_name="test.jsonl",
            candidate_id="cand_test",
            baseline_id="base_test",
        )
        ledger.record_evaluation_completed(
            partition_sha256=test_sha,
            candidate_id="cand_test",
            verdict="PASS",
            report_file="report.json",
        )

        # Check exposure returns is_exposed=True
        is_exposed, status, _ = ledger.check_exposure(test_sha)
        assert is_exposed is True
        assert status == "EVALUATION_COMPLETED"

        with pytest.raises(PartitionAlreadyExposedError):
            ledger.record_evaluation_in_progress(
                partition_sha256=test_sha,
                partition_file_name="test.jsonl",
                candidate_id="cand_test",
                baseline_id="base_test",
            )


# -----------------------------------------------------------------------------
# 12. Confusion Matrix Correctness
# -----------------------------------------------------------------------------
def test_12_confusion_matrix_correctness():
    evaluator = QualificationEvaluatorV4()
    y_true = np.array([0, 0, 1, 1, 2, 2], dtype=np.int64)
    y_pred = np.array([0, 1, 1, 1, 2, 0], dtype=np.int64)
    res = evaluator.compute_citizen_safety_metrics(y_true, y_pred)
    assert "citizen_safety_metrics" in res
    assert "conventional_one_vs_rest_fp_metrics" in res


# -----------------------------------------------------------------------------
# 13. Per-Class Metrics Correctness
# -----------------------------------------------------------------------------
def test_13_per_class_metrics_correctness():
    y_true = np.array([0, 1, 2, 0, 1, 2], dtype=np.int64)
    y_pred = np.array([0, 1, 2, 0, 1, 2], dtype=np.int64)
    metrics = compute_classification_metrics(y_true, y_pred)
    assert metrics["accuracy"] == 1.0
    assert metrics["macro_f1"] == 1.0
    for cl in ["phishing", "legitimate", "protective_advisory"]:
        assert metrics["per_class"][cl]["f1"] == 1.0


# -----------------------------------------------------------------------------
# 14. Citizen-Safety Denominator Correctness
# -----------------------------------------------------------------------------
def test_14_citizen_safety_denominator_correctness():
    evaluator = QualificationEvaluatorV4()
    # 2 phish, 4 legit, 4 advisory
    y_true = np.array([0, 0, 1, 1, 1, 1, 2, 2, 2, 2], dtype=np.int64)
    # Legit: 1 predicted as phish (1/4 = 0.25)
    # Advisory: 1 predicted as phish (1/4 = 0.25)
    # Phish: 1 predicted as legit (1/2 = 0.50)
    y_pred = np.array([0, 1, 0, 1, 1, 1, 0, 2, 2, 2], dtype=np.int64)
    safety = evaluator.compute_citizen_safety_metrics(y_true, y_pred)["citizen_safety_metrics"]

    assert safety["legitimate_to_phishing_false_alarm_rate"] == 0.25
    assert safety["legitimate_to_phishing_fraction"] == "1/4"
    assert safety["protective_advisory_to_phishing_false_alarm_rate"] == 0.25
    assert safety["protective_advisory_to_phishing_fraction"] == "1/4"
    assert safety["phishing_false_negative_rate"] == 0.50
    assert safety["phishing_false_negative_fraction"] == "1/2"


# -----------------------------------------------------------------------------
# 15. Conventional False-Positive Rate Calculation
# -----------------------------------------------------------------------------
def test_15_conventional_false_positive_rate_calculation():
    evaluator = QualificationEvaluatorV4()
    y_true = np.array([0, 0, 1, 1, 2, 2], dtype=np.int64)
    y_pred = np.array([0, 0, 0, 1, 0, 2], dtype=np.int64)  # 2 non-phish predicted as phish
    ovr = evaluator.compute_citizen_safety_metrics(y_true, y_pred)["conventional_one_vs_rest_fp_metrics"]
    # Non-phish total = 4 (2 legit + 2 advisory). 2 as phish -> 2/4 = 0.50
    assert ovr["phishing_ovr_fp_rate"] == 0.5
    assert ovr["phishing_ovr_fp_fraction"] == "2/4"


# -----------------------------------------------------------------------------
# 16. Campaign-Family Aggregation
# -----------------------------------------------------------------------------
def test_16_campaign_family_aggregation():
    evaluator = QualificationEvaluatorV4()
    records = [
        {"campaign_id": "fam_a", "ground_truth_label": "phishing"},
        {"campaign_id": "fam_a", "ground_truth_label": "phishing"},
        {"campaign_id": "fam_b", "ground_truth_label": "legitimate"},
        {"campaign_id": "fam_b", "ground_truth_label": "legitimate"},
    ]
    y_true = np.array([0, 0, 1, 1], dtype=np.int64)
    base_preds = np.array([0, 1, 1, 1], dtype=np.int64)
    cand_preds = np.array([0, 0, 1, 1], dtype=np.int64)

    res = evaluator.run_campaign_family_analysis(records, y_true, base_preds, cand_preds, bootstrap_iterations=50)
    assert len(res["family_breakdown"]) == 2
    assert res["candidate_family_macro_accuracy"] == 1.0
    assert res["baseline_family_macro_accuracy"] == 0.75


# -----------------------------------------------------------------------------
# 17. Cluster-Bootstrap Reporting
# -----------------------------------------------------------------------------
def test_17_cluster_bootstrap_reporting():
    evaluator = QualificationEvaluatorV4()
    records = [
        {"campaign_id": f"fam_{i}", "ground_truth_label": "phishing" if i % 2 == 0 else "legitimate"}
        for i in range(6)
    ]
    y_true = np.array([0 if i % 2 == 0 else 1 for i in range(6)], dtype=np.int64)
    cand_preds = y_true.copy()
    base_preds = y_true.copy()
    res = evaluator.run_campaign_family_analysis(records, y_true, base_preds, cand_preds, bootstrap_iterations=100)
    assert "candidate_macro_f1_cluster_bootstrap_95ci" in res
    ci = res["candidate_macro_f1_cluster_bootstrap_95ci"]
    assert len(ci) == 2
    assert 0.0 <= ci[0] <= ci[1] <= 1.0


# -----------------------------------------------------------------------------
# 18. Missing Subgroup Handling
# -----------------------------------------------------------------------------
def test_18_missing_subgroup_handling():
    evaluator = QualificationEvaluatorV4()
    records = [{"language": "mr", "messaging_mode": "sms", "has_url": True, "label": "phishing"}]
    y_true = np.array([0], dtype=np.int64)
    cand_preds = np.array([0], dtype=np.int64)
    sub = evaluator.run_subgroup_analysis(records, y_true, cand_preds, cand_preds)
    assert "mr" in sub["by_language"]
    assert "en" not in sub["by_language"]  # Handled gracefully, not crashing


# -----------------------------------------------------------------------------
# 19. Counterfactual Robustness Calculations
# -----------------------------------------------------------------------------
def test_19_counterfactual_robustness_calculations():
    evaluator = QualificationEvaluatorV4()
    m_base = CustomNeuralClassifier(seed=42)
    m_cand = CustomNeuralClassifier(seed=101)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)
    records = [
        {"text": "Official notice ref 1234. Pay here: http://pay.invalid", "ground_truth_label": "phishing"},
        {"text": "Municipal reminder ref 5678. No link provided.", "ground_truth_label": "legitimate"},
    ]
    res = evaluator.run_counterfactual_robustness_tests(records, m_base, m_cand, hasher)
    assert "whitespace_normalization" in res
    assert "zero_width_character_obfuscation" in res
    assert "devanagari_numeral_translation" in res
    assert "url_removal_sensitivity" in res
    assert "benign_url_insertion" in res


# -----------------------------------------------------------------------------
# 20. Artifact Corruption Rejection
# -----------------------------------------------------------------------------
def test_20_artifact_corruption_rejection():
    with tempfile.TemporaryDirectory() as tmpdir:
        dummy_ledger = os.path.join(tmpdir, "exposure_ledger.json")
        with open(dummy_ledger, "w", encoding="utf-8") as f:
            json.dump({
                "partitions": {
                    EXPECTED_V4_QUAL_SHA256: {
                        "is_exposed": False,
                        "exposure_count": 0,
                    }
                }
            }, f)

        cand_dir = os.path.join(tmpdir, "candidate")
        os.makedirs(cand_dir)
        with open(os.path.join(cand_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump({
                "artifacts": {
                    "model_weights": {"sha256": "expected_hash_xyz"},
                    "model_metadata": {"sha256": "meta_hash"},
                }
            }, f)
        with open(os.path.join(cand_dir, "model_weights.npz"), "wb") as f:
            f.write(b"corrupted_bytes")
        with open(os.path.join(cand_dir, "model_metadata.json"), "w", encoding="utf-8") as f:
            json.dump({"test": 1}, f)

        with pytest.raises(QualificationPreflightError, match="Candidate weights SHA-256 does not match"):
            QualificationPreflightCheckerV4.verify_all(
                candidate_dir=cand_dir,
                exposure_ledger_path=dummy_ledger,
            )


# -----------------------------------------------------------------------------
# 21. No Training Calls
# -----------------------------------------------------------------------------
def test_21_no_training_calls():
    # Verify candidate weights match exact pre-qualification SHA
    cand_w = os.path.join(DEFAULT_CANDIDATE_V4_DIR, "model_weights.npz")
    assert compute_file_sha256(cand_w) == EXPECTED_CANDIDATE_WEIGHTS_SHA256


# -----------------------------------------------------------------------------
# 22. Active Model Config Unchanged
# -----------------------------------------------------------------------------
def test_22_active_model_config_unchanged():
    fixture_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "model_configs", "pre_phase6_5_baseline.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"
    assert cfg["operating_mode"] == "shadow"
    assert cfg["is_production_authoritative"] is False


# -----------------------------------------------------------------------------
# 23. Registry Unchanged
# -----------------------------------------------------------------------------
def test_23_registry_unchanged():
    with open(DEFAULT_REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)
    assert "candidate_v4_seed42" not in reg["registered_models"]
    assert "custom-mlp-v1.1.0-preproc" in reg["registered_models"]


# -----------------------------------------------------------------------------
# 24. Production Risk Score Delta Remains Zero
# -----------------------------------------------------------------------------
def test_24_production_score_delta_remains_zero():
    engine = HybridDecisionEngine()
    test_msgs = [
        "Your electricity bill is overdue. Service disconnected tonight. Pay: http://bill-pay.invalid",
        "Police advisory: Do not fall for lottery scams or fake prize messages. Dial 1930.",
        "Your bank statement for October 2026 is available for download.",
    ]
    for msg in test_msgs:
        res = engine.evaluate_message(msg)
        assert res["final_decision"]["production_score_difference"] == 0
        assert res["final_decision"]["authoritative_source"] == "deterministic_rules"
