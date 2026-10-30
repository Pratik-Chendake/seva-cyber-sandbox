"""
Automated Test Suite for Dataset Provenance, Cryptographic Integrity & Evaluation Rigor.
Verifies all 16 scenarios required for Task 4.1:
1. Valid record passes provenance schema and validation.
2. Rejection of invalid provenance_category.
3. Rejection of invalid provenance_verification_status.
4. Rejection of unverified_intake status in locked_test partition.
5. Full production dataset schema and provenance validation (all 39 records).
6. Strict campaign-role consistency (zero campaigns split across roles).
7. Detection and rejection of campaign leakage across roles.
8. Locked test partition cryptographic SHA-256 integrity verification against manifest.
9. Tamper detection: modifying text in a locked record causes integrity failure.
10. Tamper detection: modifying ground_truth_label causes integrity failure.
11. Tamper detection: adding unauthorized record to locked_test causes integrity failure.
12. Tamper detection: deleting a locked record causes integrity failure.
13. Near-duplicate token detection with Jaccard similarity.
14. Comprehensive binary metric reporting with sample count N and true denominators.
15. Separation of protective advisories and ambiguous records from binary metrics.
16. Mandatory in-sample tuning disclosures and sample size warnings.
"""

import copy
import json
import os
import pytest
from typing import Any, Dict, List

from src.dataset_validator import (
    DatasetValidationError,
    VALID_DATASET_ROLES,
    VALID_LABELS,
    VALID_PROVENANCES,
    VALID_PROVENANCE_STATUSES,
    compute_locked_test_hash,
    detect_near_duplicates,
    load_and_validate_dataset,
    validate_dataset,
    validate_record,
    verify_locked_test_integrity,
)
from evaluation.evaluate_phishing import (
    compute_binary_metrics,
    evaluate_rule_based_on_records,
    run_phishing_evaluation,
)


def _valid_test_record() -> Dict[str, Any]:
    return {
        "record_id": "prov_test_001",
        "text": "महावितरण वीज ग्राहक कृपया लक्ष द्या, बिल भरण्यासाठी अधिकृत महावितरण अ‍ॅप वापरा.",
        "ground_truth_label": "legitimate",
        "language": "mr",
        "script": "Devanagari",
        "provenance_category": "human_reviewed_curated",
        "provenance_verification_status": "curated_exemplar",
        "source_reference": "MSEDCL Official Advisory Circular 2024",
        "license_info": "Public Government Notice",
        "collection_date": "2024-10-15",
        "review_status": "reviewed",
        "campaign_id": "camp_test_advisory",
        "dataset_role": "development",
        "notes": "Valid test record for provenance verification.",
    }


# ---------------------------------------------------------------------------
# 1. Valid Record Passes Schema and Provenance
# ---------------------------------------------------------------------------

def test_01_valid_record_passes_provenance_schema():
    rec = _valid_test_record()
    valid, errors = validate_record(rec)
    assert valid is True
    assert errors == []


# ---------------------------------------------------------------------------
# 2. Rejection of Invalid Provenance Category
# ---------------------------------------------------------------------------

def test_02_invalid_provenance_category_rejected():
    rec = _valid_test_record()
    rec["provenance_category"] = "unverified_internet_scrape"
    valid, errors = validate_record(rec)
    assert valid is False
    assert any("Invalid provenance_category" in err for err in errors)


# ---------------------------------------------------------------------------
# 3. Rejection of Invalid Provenance Verification Status
# ---------------------------------------------------------------------------

def test_03_invalid_provenance_status_rejected():
    rec = _valid_test_record()
    rec["provenance_verification_status"] = "crowdsourced_guess"
    valid, errors = validate_record(rec)
    assert valid is False
    assert any("Invalid provenance_verification_status" in err for err in errors)


# ---------------------------------------------------------------------------
# 4. Rejection of Unverified Intake in Locked Test Partition
# ---------------------------------------------------------------------------

def test_04_unverified_intake_rejected_from_locked_test():
    rec = _valid_test_record()
    rec["dataset_role"] = "locked_test"
    rec["provenance_verification_status"] = "unverified_intake"
    valid, errors = validate_record(rec)
    assert valid is False
    assert any("cannot be assigned to locked_test partition" in err for err in errors)


# ---------------------------------------------------------------------------
# 5. Full Production Dataset Validation
# ---------------------------------------------------------------------------

def test_05_production_dataset_passes_full_validation():
    records, report = load_and_validate_dataset()
    assert report["is_valid"] is True
    assert len(report["errors"]) == 0
    assert report["total_records"] == 39

    # Verify all 4 provenance statuses are represented or valid
    for status in report["stats"]["provenance_verification_statuses"]:
        assert status in VALID_PROVENANCE_STATUSES

    # Verify all 3 dataset roles are populated
    roles = report["stats"]["dataset_roles"]
    assert roles["development"] == 19
    assert roles["validation"] == 10
    assert roles["locked_test"] == 10


# ---------------------------------------------------------------------------
# 6. Campaign-Role Consistency in Production Dataset
# ---------------------------------------------------------------------------

def test_06_production_dataset_campaign_role_consistency():
    records, _ = load_and_validate_dataset()
    campaign_to_role: Dict[str, str] = {}
    for r in records:
        cid = r["campaign_id"]
        role = r["dataset_role"]
        if cid in campaign_to_role:
            assert campaign_to_role[cid] == role, f"Campaign {cid} split across roles!"
        else:
            campaign_to_role[cid] = role

    dev_camps = {r["campaign_id"] for r in records if r["dataset_role"] == "development"}
    val_camps = {r["campaign_id"] for r in records if r["dataset_role"] == "validation"}
    locked_camps = {r["campaign_id"] for r in records if r["dataset_role"] == "locked_test"}

    # Disjointness check: campaigns(dev) ∩ campaigns(val) ∩ campaigns(locked) = ∅
    assert dev_camps.isdisjoint(val_camps), "Leakage between dev and val!"
    assert dev_camps.isdisjoint(locked_camps), "Leakage between dev and locked_test!"
    assert val_camps.isdisjoint(locked_camps), "Leakage between val and locked_test!"


# ---------------------------------------------------------------------------
# 7. Detection of Campaign Leakage Across Roles
# ---------------------------------------------------------------------------

def test_07_campaign_leakage_detected_and_rejected():
    rec1 = _valid_test_record()
    rec1["record_id"] = "rec_leak_01"
    rec1["campaign_id"] = "camp_shared_leak"
    rec1["dataset_role"] = "development"

    rec2 = _valid_test_record()
    rec2["record_id"] = "rec_leak_02"
    rec2["campaign_id"] = "camp_shared_leak"
    rec2["dataset_role"] = "locked_test"

    report = validate_dataset([rec1, rec2])
    assert report["is_valid"] is False
    assert any("Campaign leakage: campaign 'camp_shared_leak'" in err for err in report["errors"])


# ---------------------------------------------------------------------------
# 8. Locked Test Partition Cryptographic Integrity
# ---------------------------------------------------------------------------

def test_08_locked_test_partition_cryptographic_integrity():
    records, _ = load_and_validate_dataset()
    is_valid, issues = verify_locked_test_integrity(records)
    assert is_valid is True, f"Integrity failed: {issues}"
    assert issues == []

    # Verify hash matches manifest file
    manifest_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "locked_test_manifest.json",
    )
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    computed_hash = compute_locked_test_hash(records)
    assert computed_hash == manifest["sha256_checksum"]


# ---------------------------------------------------------------------------
# 9. Tamper Detection: Text Modification
# ---------------------------------------------------------------------------

def test_09_tamper_detection_text_modification():
    records, _ = load_and_validate_dataset()
    tampered_records = copy.deepcopy(records)

    # Tamper with first locked record's text
    for r in tampered_records:
        if r["dataset_role"] == "locked_test":
            r["text"] = r["text"] + " [TAMPERED_CONTENT]"
            break

    is_valid, issues = verify_locked_test_integrity(tampered_records)
    assert is_valid is False
    assert any("SHA-256 mismatch" in iss for iss in issues)


# ---------------------------------------------------------------------------
# 10. Tamper Detection: Label Modification
# ---------------------------------------------------------------------------

def test_10_tamper_detection_label_modification():
    records, _ = load_and_validate_dataset()
    tampered_records = copy.deepcopy(records)

    for r in tampered_records:
        if r["dataset_role"] == "locked_test" and r["ground_truth_label"] == "phishing":
            r["ground_truth_label"] = "legitimate"
            break

    is_valid, issues = verify_locked_test_integrity(tampered_records)
    assert is_valid is False
    assert any("SHA-256 mismatch" in iss for iss in issues)


# ---------------------------------------------------------------------------
# 11. Tamper Detection: Unauthorized Insertion
# ---------------------------------------------------------------------------

def test_11_tamper_detection_unauthorized_insertion():
    records, _ = load_and_validate_dataset()
    tampered_records = copy.deepcopy(records)

    bogus_locked = _valid_test_record()
    bogus_locked["record_id"] = "eval_unauthorized_999"
    bogus_locked["dataset_role"] = "locked_test"
    bogus_locked["campaign_id"] = "camp_bogus_extra"
    tampered_records.append(bogus_locked)

    is_valid, issues = verify_locked_test_integrity(tampered_records)
    assert is_valid is False
    assert any("SHA-256 mismatch" in iss for iss in issues)


# ---------------------------------------------------------------------------
# 12. Tamper Detection: Record Deletion
# ---------------------------------------------------------------------------

def test_12_tamper_detection_record_deletion():
    records, _ = load_and_validate_dataset()
    tampered_records = [r for r in records if r["record_id"] != "eval_phish_005"]

    is_valid, issues = verify_locked_test_integrity(tampered_records)
    assert is_valid is False
    assert any("SHA-256 mismatch" in iss for iss in issues)


# ---------------------------------------------------------------------------
# 13. Near-Duplicate Detection
# ---------------------------------------------------------------------------

def test_13_near_duplicate_detection():
    rec1 = _valid_test_record()
    rec1["record_id"] = "dup_rec_01"
    rec1["text"] = "महावितरण वीज बिल त्वरित भरा अन्यथा वीज पुरवठा खंडित होईल."

    rec2 = _valid_test_record()
    rec2["record_id"] = "dup_rec_02"
    rec2["text"] = "महावितरण वीज बिल त्वरित भरा अन्यथा वीज पुरवठा खंडित करण्यात येईल."  # Very similar

    near_dups = detect_near_duplicates([rec1, rec2], jaccard_threshold=0.70)
    assert len(near_dups) == 1
    assert near_dups[0]["record_a"] == "dup_rec_01"
    assert near_dups[0]["record_b"] == "dup_rec_02"
    assert near_dups[0]["jaccard_similarity"] > 0.70


# ---------------------------------------------------------------------------
# 14. Comprehensive Binary Metric Reporting with Sample Count N
# ---------------------------------------------------------------------------

def test_14_binary_metric_reporting_completeness():
    y_true = [1, 1, 0, 0, 0]
    y_pred = [1, 0, 0, 0, 1]

    m = compute_binary_metrics(y_true, y_pred)
    assert m["total_samples"] == 5
    assert m["positive_ground_truth"] == 2
    assert m["negative_ground_truth"] == 3
    assert m["true_positives"] == 1
    assert m["false_positives"] == 1
    assert m["true_negatives"] == 2
    assert m["false_negatives"] == 1

    # Check metric percentages and rates
    assert "accuracy_pct" in m
    assert "precision_pct" in m
    assert "recall_pct" in m
    assert "specificity_pct" in m
    assert "f1_score_pct" in m
    assert "false_positive_rate_pct" in m
    assert "false_negative_rate_pct" in m
    assert "display_summary" in m
    assert "(3/5)" in m["display_summary"]


# ---------------------------------------------------------------------------
# 15. Separation of Protective Advisories from Binary Metrics
# ---------------------------------------------------------------------------

def test_15_protective_advisories_separated():
    records, _ = load_and_validate_dataset()
    res = evaluate_rule_based_on_records(records)

    adv_eval = res["protective_advisory_evaluation"]
    assert adv_eval["total_advisories"] == 5
    assert adv_eval["correctly_cleared_count"] == 5
    assert adv_eval["safeguard_success_pct"] == 100.0

    # Ensure binary count does NOT include the 5 advisories or 4 ambiguous records
    assert res["binary_records_count"] == 30
    assert res["total_records_in_partition"] == 39


# ---------------------------------------------------------------------------
# 16. Mandatory In-Sample Disclosures and Warnings
# ---------------------------------------------------------------------------

def test_16_mandatory_disclosures_present():
    report = run_phishing_evaluation(output_report_path=None)

    assert "in_sample_tuning_disclosure" in report
    assert "HISTORICAL IN-SAMPLE TUNING DISCLOSURE" in report["in_sample_tuning_disclosure"]
    assert "sample_size_warning" in report
    assert "too small for statistical real-world generalization claims" in report["sample_size_warning"]

    # Verify partition roles are documented
    part = report["dataset_role_partitioning"]
    assert "development_partition" in part
    assert "validation_partition" in part
    assert "locked_test_partition" in part
    assert part["development_partition"]["records_count"] == 19
    assert part["validation_partition"]["records_count"] == 10
    assert part["locked_test_partition"]["records_count"] == 10
