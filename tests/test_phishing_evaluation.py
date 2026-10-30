"""
Comprehensive Automated Test Suite for Phishing Detection Evaluation and Dataset Quality.
Verifies all 12 testing scenarios required for Task 4:
1. Dataset schema validation for valid records.
2. Rejection of missing required schema fields.
3. Rejection of invalid ground-truth labels.
4. Rejection of invalid provenance categories.
5. Rejection of missing provenance or license information.
6. Rejection of duplicate record IDs.
7. Warning detection for exact duplicate texts.
8. Privacy validation: rejection of unmasked personal phone and Aadhaar numbers.
9. Group-aware split integrity: zero campaign leakage between train and test.
10. Deterministic evaluation reproducibility with fixed random seed.
11. Accurate metric calculation and zero-division safety.
12. Small-sample warning emission and honest reporting.
13. Rule-based and ML baseline output separation.
14. Preservation of existing dataset and message analysis interface.
"""

import json
import os
import pytest
from typing import Any, Dict, List

from src.dataset_validator import (
    DatasetValidationError,
    VALID_LABELS,
    VALID_PROVENANCES,
    load_and_validate_dataset,
    validate_dataset,
    validate_record,
)
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_message_analysis
from evaluation.evaluate_phishing import (
    compute_binary_metrics,
    evaluate_rule_based_detector,
    get_cached_evaluation_report,
    group_aware_train_test_split,
    run_phishing_evaluation,
)


# ---------------------------------------------------------------------------
# Fixture & Helpers
# ---------------------------------------------------------------------------

def _valid_dummy_record() -> Dict[str, Any]:
    return {
        "record_id": "test_rec_001",
        "text": "महावितरण वीज बिल भरण्यासाठी अधिकृत पोर्टलला भेट द्या.",
        "ground_truth_label": "legitimate",
        "language": "mr",
        "script": "Devanagari",
        "provenance_category": "human_reviewed_curated",
        "provenance_verification_status": "curated_exemplar",
        "source_reference": "MSEDCL Advisory Notice 2024",
        "license_info": "Public Informational Notice",
        "collection_date": "2024-10-15",
        "review_status": "reviewed",
        "campaign_id": "camp_test_billing",
        "dataset_role": "development",
        "notes": "Valid test record for schema validation.",
    }


# ---------------------------------------------------------------------------
# 1. Dataset Schema Validation (Valid Records)
# ---------------------------------------------------------------------------

def test_01_valid_record_passes_schema():
    rec = _valid_dummy_record()
    valid, errors = validate_record(rec)
    assert valid is True
    assert errors == []


# ---------------------------------------------------------------------------
# 2. Rejection of Missing Required Fields
# ---------------------------------------------------------------------------

def test_02_missing_required_fields_rejected():
    rec = _valid_dummy_record()
    del rec["campaign_id"]
    del rec["license_info"]

    valid, errors = validate_record(rec)
    assert valid is False
    assert any("Missing required field: 'campaign_id'" in err for err in errors)
    assert any("Missing required field: 'license_info'" in err for err in errors)


# ---------------------------------------------------------------------------
# 3. Rejection of Invalid Ground-Truth Labels
# ---------------------------------------------------------------------------

def test_03_invalid_labels_rejected():
    rec = _valid_dummy_record()
    rec["ground_truth_label"] = "spam_or_danger"  # Invalid taxonomy

    valid, errors = validate_record(rec)
    assert valid is False
    assert any("Invalid ground_truth_label 'spam_or_danger'" in err for err in errors)


# ---------------------------------------------------------------------------
# 4. Rejection of Invalid Provenance Categories
# ---------------------------------------------------------------------------

def test_04_invalid_provenance_category_rejected():
    rec = _valid_dummy_record()
    rec["provenance_category"] = "unverified_internet_scrape"  # Invalid provenance

    valid, errors = validate_record(rec)
    assert valid is False
    assert any("Invalid provenance_category" in err for err in errors)


# ---------------------------------------------------------------------------
# 5. Rejection of Missing Source Reference or License Info
# ---------------------------------------------------------------------------

def test_05_missing_source_or_license_rejected():
    rec1 = _valid_dummy_record()
    rec1["source_reference"] = "   "
    valid1, errors1 = validate_record(rec1)
    assert valid1 is False
    assert any("source_reference" in err for err in errors1)

    rec2 = _valid_dummy_record()
    rec2["license_info"] = ""
    valid2, errors2 = validate_record(rec2)
    assert valid2 is False
    assert any("license_info" in err for err in errors2)


# ---------------------------------------------------------------------------
# 6. Rejection of Duplicate Record IDs
# ---------------------------------------------------------------------------

def test_06_duplicate_record_ids_rejected():
    rec1 = _valid_dummy_record()
    rec2 = _valid_dummy_record()
    rec2["text"] = "वेगळा मेसेज मजकूर आहे."

    dataset = [rec1, rec2]  # Both have record_id = "test_rec_001"
    report = validate_dataset(dataset)
    assert report["is_valid"] is False
    assert any("Duplicate record_id 'test_rec_001'" in err for err in report["errors"])


# ---------------------------------------------------------------------------
# 7. Exact Duplicate Text Warning
# ---------------------------------------------------------------------------

def test_07_exact_duplicate_text_detection():
    rec1 = _valid_dummy_record()
    rec1["record_id"] = "test_rec_001"
    rec2 = _valid_dummy_record()
    rec2["record_id"] = "test_rec_002"
    rec2["text"] = rec1["text"]  # Exact text duplicate

    dataset = [rec1, rec2]
    report = validate_dataset(dataset)
    assert any("Exact duplicate text found" in warn for warn in report["warnings"])


# ---------------------------------------------------------------------------
# 8. Privacy Validation (Rejection of Unmasked Phone or Aadhaar Numbers)
# ---------------------------------------------------------------------------

def test_08_privacy_rejection_of_unmasked_numbers():
    rec_phone = _valid_dummy_record()
    rec_phone["text"] = "Call real personal officer at 9823456789 immediately."
    valid_p, errors_p = validate_record(rec_phone)
    assert valid_p is False
    assert any("unmasked personal phone number" in err for err in errors_p)

    rec_aadhaar = _valid_dummy_record()
    rec_aadhaar["text"] = "Aadhaar number 1234 5678 9012 submitted."
    valid_a, errors_a = validate_record(rec_aadhaar)
    assert valid_a is False
    assert any("unmasked Aadhaar number" in err for err in errors_a)


# ---------------------------------------------------------------------------
# 9. Group-Aware Split Integrity (Zero Campaign Leakage)
# ---------------------------------------------------------------------------

def test_09_group_aware_split_integrity():
    records, _ = load_and_validate_dataset()
    train_recs, test_recs = group_aware_train_test_split(records, test_size=0.35, random_state=42)

    train_camps = {r["campaign_id"] for r in train_recs}
    test_camps = {r["campaign_id"] for r in test_recs}

    assert len(train_camps) > 0
    assert len(test_camps) > 0
    # Strict mathematical guarantee: train and test campaigns must be completely disjoint
    assert train_camps.isdisjoint(test_camps), "Campaign leakage detected between train and test splits!"


# ---------------------------------------------------------------------------
# 10. Deterministic Evaluation Reproducibility
# ---------------------------------------------------------------------------

def test_10_deterministic_evaluation_reproducibility():
    report1 = run_phishing_evaluation(random_state=42, output_report_path=None)
    report2 = run_phishing_evaluation(random_state=42, output_report_path=None)

    # Identical random state must produce identical group split and metrics
    split1 = report1["splitting_methodology"]
    split2 = report2["splitting_methodology"]
    assert split1["train_campaigns"] == split2["train_campaigns"]
    assert split1["test_campaigns"] == split2["test_campaigns"]

    metrics1 = report1["rule_based_evaluation"]["overall_binary_metrics"]
    metrics2 = report2["rule_based_evaluation"]["overall_binary_metrics"]
    assert metrics1["accuracy"] == metrics2["accuracy"]
    assert metrics1["f1_score"] == metrics2["f1_score"]


# ---------------------------------------------------------------------------
# 11. Accurate Metric Calculation and Zero-Division Safety
# ---------------------------------------------------------------------------

def test_11_metric_calculation_and_zero_division():
    # Case 1: Standard clean predictions
    y_true = [1, 1, 0, 0]
    y_pred = [1, 0, 0, 1]
    m = compute_binary_metrics(y_true, y_pred)
    assert m["true_positives"] == 1
    assert m["false_positives"] == 1
    assert m["true_negatives"] == 1
    assert m["false_negatives"] == 1
    assert m["accuracy"] == 0.5
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["f1_score"] == 0.5

    # Case 2: Zero positives predicted (precision denominator = 0)
    y_true_zero = [1, 1, 0, 0]
    y_pred_zero = [0, 0, 0, 0]
    m_zero = compute_binary_metrics(y_true_zero, y_pred_zero)
    assert m_zero["precision"] == 0.0
    assert m_zero["f1_score"] == 0.0
    assert m_zero["accuracy"] == 0.5


# ---------------------------------------------------------------------------
# 12. Small-Sample Warning Behavior
# ---------------------------------------------------------------------------

def test_12_small_sample_warning_behavior():
    report = run_phishing_evaluation(output_report_path=None)
    assert report["sample_size_warning"] is not None
    assert "too small for statistical real-world generalization claims" in report["sample_size_warning"]


# ---------------------------------------------------------------------------
# 13. Rule-Based and ML Output Separation & Advisory Handling
# ---------------------------------------------------------------------------

def test_13_rule_based_and_ml_separation():
    report = run_phishing_evaluation(output_report_path=None)
    rb_eval = report["rule_based_evaluation"]
    ml_eval = report["ml_baseline_evaluation"]

    assert rb_eval["engine"] != ml_eval["engine"]
    assert "protective_advisory_evaluation" in rb_eval
    assert "protective_advisory_evaluation" in ml_eval

    # Verify rule-based detector successfully clears protective advisories
    adv_rb = rb_eval["protective_advisory_evaluation"]
    assert adv_rb["safeguard_success_pct"] == 100.0


# ---------------------------------------------------------------------------
# 14. Preservation of Existing Dataset and Message Analysis Interface
# ---------------------------------------------------------------------------

def test_14_preservation_of_existing_dataset_and_interface():
    # 1. Existing sample_messages.json must exist and have 20 samples
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "sample_messages.json",
    )
    assert os.path.exists(sample_path)
    with open(sample_path, "r", encoding="utf-8") as f:
        samples = json.load(f)
    assert len(samples) == 20
    assert samples[0]["id"] == "msg_01"

    # 2. Existing analyze_message_text function signature and return schema intact
    test_text = "महावितरण वीज बिल आज रात्री बंद होईल 9800000000 वर संपर्क करा."
    res = analyze_message_text(test_text)
    assert "is_empty" in res
    assert "findings" in res
    assert "script_detected" in res
    assert "observed_facts" in res
    assert "heuristic_inferences" in res

    scored = score_message_analysis(res)
    assert "score" in scored
    assert "risk_level" in scored
    assert "badge_color" in scored
