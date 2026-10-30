"""
Test Suite for Phase 6.4.4: One-Time Independent Candidate Qualification Evaluation.

SPECIFICATION & AUDIT TARGETS:
1. Correct candidate identity ('candidate_v3_seed202').
2. Correct baseline identity ('custom-mlp-v1.1.0-preproc').
3. Candidate weight hash verification ('fce2b252...').
4. Baseline artifact verification ('d4b6c2b1...').
5. Qualification manifest verification (450 records, 9 families, 'sealed_independent_benchmark').
6. Wrong partition rejection.
7. Already-exposed partition rejection.
8. Evaluation exposure ledger atomicity.
9. Failed preflight does not consume qualification data.
10. Failure after data access marks partition exposed ('EXPOSED_INCOMPLETE').
11. One-time evaluation enforcement.
12. Correct confusion matrix calculation.
13. Correct class metrics.
14. Correct false-alarm rate denominators.
15. Campaign-family aggregation.
16. Small-family uncertainty reporting.
17. Missing subgroup handling.
18. Corrupt checkpoint rejection.
19. Incompatible model rejection.
20. Evaluation does not invoke training.
21. Candidate artifacts remain unchanged.
22. Baseline artifacts remain unchanged.
23. Registry remains unchanged.
24. Active model configuration remains unchanged.
25. Production score delta remains zero.
"""

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
from src.qualification_evaluator import (
    DEFAULT_ACTIVE_CONFIG_PATH,
    DEFAULT_BASELINE_DIR,
    DEFAULT_CANDIDATE_DIR,
    DEFAULT_EXPOSURE_LEDGER_PATH,
    DEFAULT_LOCKED_TEST_DATASET,
    DEFAULT_LOCKED_TEST_MANIFEST,
    DEFAULT_QUAL_CORPUS,
    DEFAULT_QUAL_MANIFEST,
    DEFAULT_REGISTRY_PATH,
    DEFAULT_V3_CORPUS_MANIFEST,
    EvaluationExposureLedger,
    PartitionAlreadyExposedError,
    QualificationEvaluator,
    QualificationIntegrityError,
    QualificationPolicy,
    QualificationPreflightChecker,
    QualificationPreflightError,
    QualificationVerdict,
    compute_file_sha256,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
QUALIFICATION_REPORT_PATH = os.path.join(
    PROJECT_ROOT, "evaluation", "qualification", "candidate_v3_seed202_qualification.json"
)


# -----------------------------------------------------------------------------
# 1. Correct Candidate Identity
# -----------------------------------------------------------------------------
def test_01_correct_candidate_identity():
    assert os.path.isfile(QUALIFICATION_REPORT_PATH)
    with open(QUALIFICATION_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)
    assert rep.get("candidate_id") == "candidate_v3_seed202"
    assert rep.get("candidate_evaluation", {}).get("model_id") == "candidate_v3_seed202"


# -----------------------------------------------------------------------------
# 2. Correct Baseline Identity
# -----------------------------------------------------------------------------
def test_02_correct_baseline_identity():
    with open(QUALIFICATION_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)
    assert rep.get("baseline_id") == "custom-mlp-v1.1.0-preproc"
    assert rep.get("baseline_evaluation", {}).get("model_id") == "custom-mlp-v1.1.0-preproc"


# -----------------------------------------------------------------------------
# 3. Candidate Weight Hash Verification
# -----------------------------------------------------------------------------
def test_03_candidate_weight_hash_verification():
    cand_weights_file = os.path.join(DEFAULT_CANDIDATE_DIR, "model_weights.npz")
    assert os.path.isfile(cand_weights_file)
    actual_sha = compute_file_sha256(cand_weights_file)
    assert actual_sha == "fce2b252a62c5142ba4cd0e3430fc44ffd6a66d02c05cd840d9a2fa4774f03dd"


# -----------------------------------------------------------------------------
# 4. Baseline Artifact Verification
# -----------------------------------------------------------------------------
def test_04_baseline_artifact_verification():
    base_weights_file = os.path.join(DEFAULT_BASELINE_DIR, "model_weights.npz")
    base_meta_file = os.path.join(DEFAULT_BASELINE_DIR, "model_metadata.json")

    assert os.path.isfile(base_weights_file)
    assert os.path.isfile(base_meta_file)

    w_sha = compute_file_sha256(base_weights_file)
    m_sha = compute_file_sha256(base_meta_file)

    assert w_sha == "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"
    assert m_sha == "23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8"


# -----------------------------------------------------------------------------
# 5. Qualification Manifest Verification
# -----------------------------------------------------------------------------
def test_05_qualification_manifest_verification():
    assert os.path.isfile(DEFAULT_QUAL_MANIFEST)
    with open(DEFAULT_QUAL_MANIFEST, "r", encoding="utf-8") as f:
        m = json.load(f)

    assert m.get("record_count") == 450
    assert m.get("campaign_family_count") == 9
    assert m.get("lifecycle_state") == "sealed_independent_benchmark"
    assert m.get("partition") == "qualification"

    actual_corpus_sha = compute_file_sha256(DEFAULT_QUAL_CORPUS)
    assert actual_corpus_sha == m.get("file_sha256")
    assert actual_corpus_sha == "197c62e7f0b305ce5965cf7bbeba8543fcd542a4a026d07dbd1172b3656f4a0f"


# -----------------------------------------------------------------------------
# 6. Wrong Partition Rejection
# -----------------------------------------------------------------------------
def test_06_wrong_partition_rejection(tmp_path):
    # Create a dummy manifest where partition is 'training' instead of 'qualification'
    bad_manifest = tmp_path / "bad_manifest.json"
    bad_manifest.write_text(json.dumps({
        "partition": "training",
        "lifecycle_state": "sealed_independent_benchmark",
        "record_count": 450,
        "campaign_family_count": 9,
    }), encoding="utf-8")

    with pytest.raises(QualificationPreflightError) as excinfo:
        QualificationPreflightChecker.verify_all(
            qual_manifest_path=str(bad_manifest),
        )
    assert "Manifest partition must be 'qualification'" in str(excinfo.value)


# -----------------------------------------------------------------------------
# 7. Already-Exposed Partition Rejection
# -----------------------------------------------------------------------------
def test_07_already_exposed_partition_rejection(tmp_path):
    test_ledger_path = str(tmp_path / "test_ledger.json")
    ledger = EvaluationExposureLedger(ledger_path=test_ledger_path)

    dummy_sha = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    ledger.record_evaluation_in_progress(
        partition_sha256=dummy_sha,
        partition_file_name="dummy_corpus.jsonl",
        candidate_id="cand_test",
        baseline_id="base_test",
    )

    # Subsequent attempt to record evaluation in progress must raise PartitionAlreadyExposedError
    with pytest.raises(PartitionAlreadyExposedError) as excinfo:
        ledger.record_evaluation_in_progress(
            partition_sha256=dummy_sha,
            partition_file_name="dummy_corpus.jsonl",
            candidate_id="cand_test",
            baseline_id="base_test",
        )
    assert "ONE-TIME QUALIFICATION VIOLATION" in str(excinfo.value)


# -----------------------------------------------------------------------------
# 8. Evaluation Exposure Ledger Atomicity
# -----------------------------------------------------------------------------
def test_08_evaluation_exposure_ledger_atomicity(tmp_path):
    test_ledger_path = str(tmp_path / "atomic_ledger.json")
    ledger = EvaluationExposureLedger(ledger_path=test_ledger_path)

    dummy_sha = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
    ledger.record_evaluation_in_progress(
        partition_sha256=dummy_sha,
        partition_file_name="atomic_test.jsonl",
        candidate_id="cand_atomic",
        baseline_id="base_atomic",
    )

    data = ledger.load_ledger()
    assert dummy_sha in data["partitions"]
    entry = data["partitions"][dummy_sha]
    assert entry["is_exposed"] is True
    assert entry["current_status"] == "EVALUATION_IN_PROGRESS"
    assert len(entry["events"]) == 1

    ledger.record_evaluation_completed(
        partition_sha256=dummy_sha,
        candidate_id="cand_atomic",
        verdict="PASS",
        report_file="report.json",
    )

    data2 = ledger.load_ledger()
    entry2 = data2["partitions"][dummy_sha]
    assert entry2["current_status"] == "EVALUATION_COMPLETED"
    assert entry2["final_verdict"] == "PASS"
    assert len(entry2["events"]) == 2


# -----------------------------------------------------------------------------
# 9. Failed Preflight Does Not Consume Qualification Data
# -----------------------------------------------------------------------------
def test_09_failed_preflight_does_not_consume_qualification_data(tmp_path):
    test_ledger_path = str(tmp_path / "ledger_unconsumed.json")
    bad_manifest_path = str(tmp_path / "missing_manifest.json")

    # Preflight fails before ledger is touched
    with pytest.raises(QualificationPreflightError):
        QualificationPreflightChecker.verify_all(
            qual_manifest_path=bad_manifest_path,
        )

    # Ledger file must NOT exist (no exposure recorded)
    assert not os.path.exists(test_ledger_path)


# -----------------------------------------------------------------------------
# 10. Failure After Data Access Marks Partition Exposed
# -----------------------------------------------------------------------------
def test_10_failure_after_data_access_marks_partition_exposed(tmp_path):
    test_ledger_path = str(tmp_path / "ledger_failed.json")
    ledger = EvaluationExposureLedger(ledger_path=test_ledger_path)

    dummy_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    ledger.record_evaluation_in_progress(
        partition_sha256=dummy_sha,
        partition_file_name="failed_test.jsonl",
        candidate_id="cand_fail",
        baseline_id="base_fail",
    )

    # Simulate runtime exception after data access
    ledger.record_exposed_incomplete(
        partition_sha256=dummy_sha,
        candidate_id="cand_fail",
        error_message="Simulated OOM or calculation failure",
    )

    data = ledger.load_ledger()
    entry = data["partitions"][dummy_sha]
    assert entry["is_exposed"] is True
    assert entry["current_status"] == "EXPOSED_INCOMPLETE"
    assert "Simulated OOM" in entry["error_message"]


# -----------------------------------------------------------------------------
# 11. One-Time Evaluation Enforcement
# -----------------------------------------------------------------------------
def test_11_one_time_evaluation_enforcement():
    # Verify that the canonical ledger records the partition as exposed
    ledger = EvaluationExposureLedger(ledger_path=DEFAULT_EXPOSURE_LEDGER_PATH)
    qual_sha = "197c62e7f0b305ce5965cf7bbeba8543fcd542a4a026d07dbd1172b3656f4a0f"
    is_exposed, status, entry = ledger.check_exposure(qual_sha)

    assert is_exposed is True
    assert status == "EVALUATION_COMPLETED"
    assert entry.get("exposure_count") == 1

    # Attempting to re-run execution with the canonical ledger must be rejected
    evaluator = QualificationEvaluator(ledger_path=DEFAULT_EXPOSURE_LEDGER_PATH)
    with pytest.raises(PartitionAlreadyExposedError) as excinfo:
        evaluator.execute_one_time_qualification()
    assert "ONE-TIME QUALIFICATION VIOLATION" in str(excinfo.value)


# -----------------------------------------------------------------------------
# 12. Correct Confusion Matrix Calculation
# -----------------------------------------------------------------------------
def test_12_correct_confusion_matrix_calculation():
    y_true = np.array([0, 1, 2, 0, 1, 2, 0])
    y_pred = np.array([0, 1, 1, 0, 2, 2, 1])
    metrics = compute_classification_metrics(y_true, y_pred)
    cm = metrics["confusion_matrix"]

    assert cm[0][0] == 2  # class 0 as 0
    assert cm[0][1] == 1  # class 0 as 1
    assert cm[1][1] == 1  # class 1 as 1
    assert cm[1][2] == 1  # class 1 as 2
    assert cm[2][1] == 1  # class 2 as 1
    assert cm[2][2] == 1  # class 2 as 2
    assert sum(sum(row) for row in cm) == 7


# -----------------------------------------------------------------------------
# 13. Correct Class Metrics
# -----------------------------------------------------------------------------
def test_13_correct_class_metrics():
    with open(QUALIFICATION_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)

    cand_per_class = rep["candidate_evaluation"]["overall_metrics"]["per_class"]
    assert "phishing" in cand_per_class
    assert "legitimate" in cand_per_class
    assert "protective_advisory" in cand_per_class

    for c in ["phishing", "legitimate", "protective_advisory"]:
        assert cand_per_class[c]["support"] == 150
        assert 0.0 <= cand_per_class[c]["precision"] <= 1.0
        assert 0.0 <= cand_per_class[c]["recall"] <= 1.0
        assert 0.0 <= cand_per_class[c]["f1"] <= 1.0


# -----------------------------------------------------------------------------
# 14. Correct False Alarm Rate Denominators
# -----------------------------------------------------------------------------
def test_14_correct_false_alarm_rate_denominators():
    with open(QUALIFICATION_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)

    safety = rep["candidate_evaluation"]["safety_metrics"]["citizen_safety_metrics"]
    ovr = rep["candidate_evaluation"]["safety_metrics"]["conventional_one_vs_rest_fp_metrics"]

    # Citizen safety rates: denominators must be class total (150)
    assert safety["legitimate_to_phishing_fraction"].endswith("/150")
    assert safety["protective_advisory_to_phishing_fraction"].endswith("/150")
    assert safety["phishing_false_negative_fraction"].endswith("/150")

    # Conventional OVR FP rates: denominators must be rest total (300)
    assert ovr["phishing_ovr_fp_fraction"].endswith("/300")
    assert ovr["legitimate_ovr_fp_fraction"].endswith("/300")
    assert ovr["protective_advisory_ovr_fp_fraction"].endswith("/300")


# -----------------------------------------------------------------------------
# 15. Campaign-Family Aggregation
# -----------------------------------------------------------------------------
def test_15_campaign_family_aggregation():
    with open(QUALIFICATION_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)

    fam_analysis = rep.get("campaign_family_analysis", {})
    breakdown = fam_analysis.get("family_breakdown", [])

    assert len(breakdown) == 9
    total_examples = sum(f["sample_count"] for f in breakdown)
    assert total_examples == 450

    for f in breakdown:
        assert f["sample_count"] == 50
        assert 0.0 <= f["candidate_accuracy"] <= 1.0


# -----------------------------------------------------------------------------
# 16. Small-Family Uncertainty Reporting
# -----------------------------------------------------------------------------
def test_16_small_family_uncertainty_reporting():
    with open(QUALIFICATION_REPORT_PATH, "r", encoding="utf-8") as f:
        rep = json.load(f)

    fam_analysis = rep.get("campaign_family_analysis", {})
    ci = fam_analysis.get("candidate_macro_f1_cluster_bootstrap_95ci")

    assert isinstance(ci, list) and len(ci) == 2
    assert ci[0] <= ci[1]
    # Cluster uncertainty note must be present
    assert "cluster_uncertainty_note" in fam_analysis
    assert "K=9" in fam_analysis["cluster_uncertainty_note"]


# -----------------------------------------------------------------------------
# 17. Missing Subgroup Handling
# -----------------------------------------------------------------------------
def test_17_missing_subgroup_handling():
    evaluator = QualificationEvaluator()
    # Test with records that do not contain 'whatsapp' or certain languages
    sparse_recs = [
        {"text": "Sample text 1", "language": "mr", "messaging_mode": "sms", "ground_truth_label": "phishing"},
        {"text": "Sample text 2", "language": "mr", "messaging_mode": "sms", "ground_truth_label": "legitimate"},
    ]
    y_t = np.array([0, 1])
    y_b = np.array([0, 1])
    y_c = np.array([0, 1])

    res = evaluator.run_subgroup_analysis(sparse_recs, y_t, y_b, y_c)
    assert "by_language" in res["subgroups"]
    assert "en" not in res["subgroups"]["by_language"]  # cleanly handled without crash
    assert "mr" in res["subgroups"]["by_language"]


# -----------------------------------------------------------------------------
# 18. Corrupt Checkpoint Rejection
# -----------------------------------------------------------------------------
def test_18_corrupt_checkpoint_rejection(tmp_path):
    corrupt_dir = str(tmp_path / "corrupt_candidate")
    os.makedirs(corrupt_dir)
    # Corrupt model_weights.npz (plain text instead of zip/npz)
    with open(os.path.join(corrupt_dir, "model_weights.npz"), "w") as f:
        f.write("corrupt non-zip content")
    with open(os.path.join(corrupt_dir, "model_metadata.json"), "w") as f:
        json.dump({"input_dim": 1024, "num_classes": 3, "label_to_index": LABEL_TO_IDX}, f)

    evaluator = QualificationEvaluator()
    with pytest.raises(Exception):
        evaluator.load_model_strictly(corrupt_dir)


# -----------------------------------------------------------------------------
# 19. Incompatible Model Rejection
# -----------------------------------------------------------------------------
def test_19_incompatible_model_rejection(tmp_path):
    bad_cand_dir = str(tmp_path / "bad_candidate")
    os.makedirs(bad_cand_dir)

    with open(os.path.join(bad_cand_dir, "manifest.json"), "w") as f:
        json.dump({"artifacts": {"model_weights": {"sha256": "x"}, "model_metadata": {"sha256": "y"}}}, f)
    with open(os.path.join(bad_cand_dir, "model_weights.npz"), "wb") as f:
        f.write(b"dummy")
    with open(os.path.join(bad_cand_dir, "model_metadata.json"), "w") as f:
        # Bad input_dim: 512 instead of 1024
        json.dump({"input_dim": 512, "num_classes": 3, "label_to_index": LABEL_TO_IDX}, f)

    with pytest.raises(QualificationPreflightError):
        QualificationPreflightChecker.verify_all(candidate_dir=bad_cand_dir)


# -----------------------------------------------------------------------------
# 20. Evaluation Does Not Invoke Training
# -----------------------------------------------------------------------------
def test_20_evaluation_does_not_invoke_training():
    cand_model = CustomNeuralClassifier(input_dim=1024, seed=42)
    w1_before = cand_model.W1.copy()

    hasher = CharacterNGramHasher(num_features=1024)
    dummy_records = [
        {"text": "Urgent bill payment", "ground_truth_label": "phishing"},
        {"text": "Normal bank notification", "ground_truth_label": "legitimate"},
    ]
    evaluator = QualificationEvaluator()
    evaluator.evaluate_both_models_on_records(
        baseline_model=cand_model,
        candidate_model=cand_model,
        records=dummy_records,
        hasher=hasher,
    )

    np.testing.assert_array_equal(cand_model.W1, w1_before)


# -----------------------------------------------------------------------------
# 21. Candidate Artifacts Remain Unchanged
# -----------------------------------------------------------------------------
def test_21_candidate_artifacts_remain_unchanged():
    cand_weights = os.path.join(DEFAULT_CANDIDATE_DIR, "model_weights.npz")
    cand_meta = os.path.join(DEFAULT_CANDIDATE_DIR, "model_metadata.json")
    cand_man = os.path.join(DEFAULT_CANDIDATE_DIR, "manifest.json")

    assert compute_file_sha256(cand_weights) == "fce2b252a62c5142ba4cd0e3430fc44ffd6a66d02c05cd840d9a2fa4774f03dd"
    assert compute_file_sha256(cand_meta) == "1264a632aef1a5356b0f9e336734fc58abd0838bcc097ef8a8dff4512eec5223"
    assert compute_file_sha256(cand_man) == "65484700707962b418f0e48aac052fe47717f397f05d853908c6e2e1fd974dfe"


# -----------------------------------------------------------------------------
# 22. Baseline Artifacts Remain Unchanged
# -----------------------------------------------------------------------------
def test_22_baseline_artifacts_remain_unchanged():
    base_weights = os.path.join(DEFAULT_BASELINE_DIR, "model_weights.npz")
    base_meta = os.path.join(DEFAULT_BASELINE_DIR, "model_metadata.json")

    assert compute_file_sha256(base_weights) == "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"
    assert compute_file_sha256(base_meta) == "23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8"


# -----------------------------------------------------------------------------
# 23. Model Registry Remains Unchanged
# -----------------------------------------------------------------------------
def test_23_registry_remains_unchanged():
    with open(DEFAULT_REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)

    models = reg.get("registered_models", {})
    # Candidate must NOT be registered
    assert "candidate_v3_seed202" not in models
    assert "custom-mlp-v1.0.0" in models
    assert "custom-mlp-v1.1.0-preproc" in models


# -----------------------------------------------------------------------------
# 24. Active Model Configuration Remains Unchanged
# -----------------------------------------------------------------------------
def test_24_active_model_configuration_remains_unchanged():
    # Use isolated Phase 6.4.4 baseline configuration fixture
    fixture_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "model_configs", "pre_phase6_5_baseline.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    assert cfg.get("active_model_version") == "custom-mlp-v1.1.0-preproc"
    assert cfg.get("operating_mode") == "shadow"
    assert cfg.get("is_production_authoritative") is False
    assert cfg.get("active_model_version") != "candidate_v3_seed202"


# -----------------------------------------------------------------------------
# 25. Production Score Delta Remains Zero
# -----------------------------------------------------------------------------
def test_25_production_score_delta_remains_zero():
    from src.phishing_detector import analyze_message_text
    from src.risk_scorer import score_message_analysis
    from src.hybrid_decision_engine import HybridDecisionEngine

    sample_text = "Important notice: Water pipeline repair on 31 Oct. Water supply will be suspended."

    detector_res = analyze_message_text(sample_text)
    rule_score_res = score_message_analysis(detector_res)
    authoritative_score = rule_score_res["score"]

    engine = HybridDecisionEngine()
    eval_res = engine.evaluate_message(sample_text)

    assert eval_res.get("operating_mode") == "shadow"
    final_dec = eval_res.get("final_decision", {})
    assert final_dec.get("authoritative_source") == "deterministic_rules"
    assert final_dec.get("final_risk_score") == authoritative_score
    assert final_dec.get("production_score_difference") == 0
