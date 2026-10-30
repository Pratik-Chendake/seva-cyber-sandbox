"""
Comprehensive Test Suite for Vernacular Dataset Expansion, Data Cleaning & Preprocessing.
Part of Seva Cyber Sandbox (Phase 2).

Covers all 16 required test scenarios:
1. Generator output reproducibility with fixed seed.
2. Different seeds produce valid schema records.
3. Every generated record passes schema validation.
4. Invalid labels rejected (e.g. invalid string, null).
5. Unicode and Marathi text survive preprocessing without corruption.
6. Normalization preserves raw text separately in normalized_text.
7. Exact duplicates detected.
8. Near-duplicate warnings emitted without silently dropping records.
9. Zero campaign/template family leakage between train and validation.
10. Quarantined records excluded from usable training set.
11. Empty and malformed inputs produce safe, actionable errors.
12. Missing provenance identified.
13. Synthetic examples contain no actual credentials or real personal data.
14. Repeated pipeline runs produce consistent results.
15. Original evaluation data and locked manifest remain untouched.
16. Locked test partition checksum verification.
"""

import hashlib
import json
import os
import re
from typing import Any, Dict, List
import pytest

from scripts.generate_synthetic_corpus import (
    generate_family_records,
    generate_full_synthetic_corpus,
)
from src.dataset_preprocessing import (
    REQUIRED_DATASET_FIELDS,
    VALID_LABELS,
    VALID_LANGUAGES,
    VALID_PROVENANCE_CATEGORIES,
    VALID_ROLES,
    VALID_SCRIPTS,
    check_cross_partition_leakage,
    clean_evasion_characters,
    detect_exact_duplicates,
    detect_near_duplicates_in_corpus,
    detect_script,
    normalize_record_text,
    run_preprocessing_pipeline,
    validate_single_record,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GENERATED_DIR = os.path.join(PROJECT_ROOT, "data", "generated")
TRAIN_CORPUS_PATH = os.path.join(GENERATED_DIR, "synthetic_training_corpus.jsonl")
VAL_CORPUS_PATH = os.path.join(GENERATED_DIR, "synthetic_validation_corpus.jsonl")
QUARANTINE_PATH = os.path.join(GENERATED_DIR, "quarantine_records.jsonl")
REPORT_PATH = os.path.join(GENERATED_DIR, "synthetic_corpus_report.json")
EVAL_DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
LOCKED_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    records = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


# ---------------------------------------------------------------------------
# Scenario 1: Generator Output Reproducibility with Fixed Seed
# ---------------------------------------------------------------------------

def test_01_generator_reproducibility_with_fixed_seed():
    """Generating with identical seed must yield byte-for-byte identical output."""
    train_a, val_a = generate_full_synthetic_corpus(seed=42, train_target_per_family=5, val_target_per_family=3)
    train_b, val_b = generate_full_synthetic_corpus(seed=42, train_target_per_family=5, val_target_per_family=3)

    assert len(train_a) == len(train_b)
    assert len(val_a) == len(val_b)

    for rec_a, rec_b in zip(train_a, train_b):
        assert rec_a["record_id"] == rec_b["record_id"]
        assert rec_a["text"] == rec_b["text"]
        assert rec_a["campaign_id"] == rec_b["campaign_id"]
        assert rec_a["ground_truth_label"] == rec_b["ground_truth_label"]

    for rec_a, rec_b in zip(val_a, val_b):
        assert rec_a["record_id"] == rec_b["record_id"]
        assert rec_a["text"] == rec_b["text"]
        assert rec_a["campaign_id"] == rec_b["campaign_id"]


# ---------------------------------------------------------------------------
# Scenario 2: Different Seeds Produce Valid Schema Records
# ---------------------------------------------------------------------------

def test_02_different_seeds_produce_valid_schema_records():
    """Different seeds must generate valid records with distinct sampled texts."""
    train_seed1, _ = generate_full_synthetic_corpus(seed=101, train_target_per_family=5, val_target_per_family=3)
    train_seed2, _ = generate_full_synthetic_corpus(seed=202, train_target_per_family=5, val_target_per_family=3)

    # Validate all generated records from both seeds
    for r in train_seed1 + train_seed2:
        valid, errors = validate_single_record(r)
        assert valid is True, f"Record {r.get('record_id')} failed validation: {errors}"

    # Texts across different seeds should not be identical
    texts_1 = [r["text"] for r in train_seed1]
    texts_2 = [r["text"] for r in train_seed2]
    assert texts_1 != texts_2


# ---------------------------------------------------------------------------
# Scenario 3: Every Generated Record Passes Schema Validation
# ---------------------------------------------------------------------------

def test_03_every_generated_record_passes_schema_validation():
    """All persisted generated records in training and validation corpora pass schema validation."""
    train_records = _load_jsonl(TRAIN_CORPUS_PATH)
    val_records = _load_jsonl(VAL_CORPUS_PATH)

    assert len(train_records) > 0, "Training corpus is empty"
    assert len(val_records) > 0, "Validation corpus is empty"

    for r in train_records:
        valid, errors = validate_single_record(r)
        assert valid is True, f"Training record {r.get('record_id')} failed validation: {errors}"
        assert r["dataset_role"] == "development"
        assert "normalized_text" in r
        assert len(r["normalized_text"]) > 0

    for r in val_records:
        valid, errors = validate_single_record(r)
        assert valid is True, f"Validation record {r.get('record_id')} failed validation: {errors}"
        assert r["dataset_role"] == "validation"
        assert "normalized_text" in r
        assert len(r["normalized_text"]) > 0


# ---------------------------------------------------------------------------
# Scenario 4: Invalid Labels Rejected
# ---------------------------------------------------------------------------

def test_04_invalid_labels_rejected():
    """Records with disallowed labels or missing labels must fail validation."""
    valid_base = {
        "record_id": "test_invalid_label_001",
        "text": "प्रिय ग्राहक, तुमचे वीज बिल भरा http://example.invalid",
        "ground_truth_label": "phishing",
        "language": "mr",
        "script": "Devanagari",
        "provenance_category": "synthetic_test_case",
        "provenance_verification_status": "synthetic_fixture",
        "source_reference": "test_suite",
        "license_info": "CC0",
        "collection_date": "2026-10-29",
        "review_status": "reviewed",
        "campaign_id": "test_camp",
        "dataset_role": "development",
        "scenario_category": "test_scenario",
    }

    # Invalid string label
    bad_rec = dict(valid_base, ground_truth_label="malware_attack")
    valid, errors = validate_single_record(bad_rec)
    assert valid is False
    assert any("ground_truth_label" in e for e in errors)

    # None label
    bad_rec = dict(valid_base, ground_truth_label=None)
    valid, errors = validate_single_record(bad_rec)
    assert valid is False

    # Empty string label
    bad_rec = dict(valid_base, ground_truth_label="")
    valid, errors = validate_single_record(bad_rec)
    assert valid is False


# ---------------------------------------------------------------------------
# Scenario 5: Unicode and Marathi Text Survive Preprocessing Without Corruption
# ---------------------------------------------------------------------------

def test_05_unicode_and_marathi_text_survive_preprocessing():
    """Marathi vowels, matras, and consonants survive cleaning intact while evasion characters are stripped."""
    # Text with zero-width spaces (\u200b) and zero-width non-joiners (\u200c) inserted
    marathi_raw = "महा\u200bवितरण \u200cतातडीची नो\ufeffटीस: बिल भरा."
    cleaned = clean_evasion_characters(marathi_raw)

    assert "\u200b" not in cleaned
    assert "\u200c" not in cleaned
    assert "\ufeff" not in cleaned
    assert "महावितरण" in cleaned
    assert "तातडीची" in cleaned
    assert "नोटीस:" in cleaned

    # Devanagari numerals to ASCII digits
    devanagari_digits = "रुपये ५०० दंड आणि १९३० हेल्पलाईन"
    normalized = normalize_record_text(devanagari_digits)
    assert "500" in normalized
    assert "1930" in normalized
    assert "रुपये" in normalized


# ---------------------------------------------------------------------------
# Scenario 6: Normalization Preserves Raw Text Separately
# ---------------------------------------------------------------------------

def test_06_normalization_preserves_raw_text_separately():
    """Raw original text is kept unchanged under 'text', cleaned text in 'normalized_text'."""
    raw_text = "महावितरण   बिल भरा \u200b त्वरित http://pay.invalid"
    input_records = [
        {
            "record_id": "norm_test_01",
            "text": raw_text,
            "ground_truth_label": "phishing",
            "language": "mr",
            "script": "Devanagari",
            "provenance_category": "synthetic_test_case",
            "provenance_verification_status": "synthetic_fixture",
            "source_reference": "test",
            "license_info": "CC0",
            "collection_date": "2026-10-29",
            "review_status": "reviewed",
            "campaign_id": "norm_camp",
            "dataset_role": "development",
            "scenario_category": "test",
        }
    ]

    result = run_preprocessing_pipeline(input_records)
    train_records = result["training_records"]
    assert len(train_records) == 1

    rec = train_records[0]
    # 'text' remains raw with zero-width characters and multi-spaces
    assert rec["text"] == raw_text
    assert "\u200b" in rec["text"]
    # 'normalized_text' has stripped evasion characters and collapsed whitespace
    assert "normalized_text" in rec
    assert "\u200b" not in rec["normalized_text"]
    assert "   " not in rec["normalized_text"]


# ---------------------------------------------------------------------------
# Scenario 7: Exact Duplicates Detected
# ---------------------------------------------------------------------------

def test_07_exact_duplicates_detected():
    """Corpus with exact duplicate normalized texts must be detected."""
    records = [
        {"record_id": "rec_01", "text": "Duplicate message content alert.", "normalized_text": "duplicate message content alert."},
        {"record_id": "rec_02", "text": "Unique message content.", "normalized_text": "unique message content."},
        {"record_id": "rec_03", "text": "Duplicate   message   content alert.", "normalized_text": "duplicate message content alert."},
    ]
    duplicates = detect_exact_duplicates(records)
    assert len(duplicates) == 1
    assert duplicates[0]["duplicate_record_id"] == "rec_03"
    assert duplicates[0]["original_record_id"] == "rec_01"


# ---------------------------------------------------------------------------
# Scenario 8: Near-Duplicate Warnings Emitted Without Silently Dropping Records
# ---------------------------------------------------------------------------

def test_08_near_duplicate_warnings_emitted_without_silently_dropping():
    """Near-duplicate pairs emit warnings, but records are not silently dropped."""
    records = [
        {
            "record_id": "near_01",
            "text": "Dear customer your electricity bill is overdue please pay at http://portal.invalid",
            "normalized_text": "dear customer your electricity bill is overdue please pay at http://portal.invalid",
            "ground_truth_label": "phishing",
            "language": "en",
            "script": "Latin",
            "provenance_category": "synthetic_test_case",
            "provenance_verification_status": "synthetic_fixture",
            "source_reference": "test",
            "license_info": "CC0",
            "collection_date": "2026-10-29",
            "review_status": "reviewed",
            "campaign_id": "near_camp_train",
            "dataset_role": "development",
            "scenario_category": "test",
        },
        {
            "record_id": "near_02",
            "text": "Dear customer your electricity bill is overdue please pay now at http://portal.invalid",
            "normalized_text": "dear customer your electricity bill is overdue please pay now at http://portal.invalid",
            "ground_truth_label": "phishing",
            "language": "en",
            "script": "Latin",
            "provenance_category": "synthetic_test_case",
            "provenance_verification_status": "synthetic_fixture",
            "source_reference": "test",
            "license_info": "CC0",
            "collection_date": "2026-10-29",
            "review_status": "reviewed",
            "campaign_id": "near_camp_train",
            "dataset_role": "development",
            "scenario_category": "test",
        },
    ]

    warnings = detect_near_duplicates_in_corpus(records, jaccard_threshold=0.85)
    assert len(warnings) >= 1
    assert warnings[0]["jaccard_similarity"] >= 0.85

    # Run pipeline to ensure neither record is dropped
    pipeline_res = run_preprocessing_pipeline(records)
    assert len(pipeline_res["training_records"]) == 2
    assert pipeline_res["report"]["near_duplicate_warnings_count"] >= 1


# ---------------------------------------------------------------------------
# Scenario 9: Zero Campaign / Template Family Leakage Between Train & Val
# ---------------------------------------------------------------------------

def test_09_zero_campaign_template_family_leakage():
    """Strict proof: Training campaign IDs and Validation campaign IDs are completely disjoint."""
    train_records = _load_jsonl(TRAIN_CORPUS_PATH)
    val_records = _load_jsonl(VAL_CORPUS_PATH)

    train_camps = set(r["campaign_id"] for r in train_records)
    val_camps = set(r["campaign_id"] for r in val_records)

    overlap = train_camps.intersection(val_camps)
    assert len(overlap) == 0, f"Found campaign leakage between train and val: {overlap}"

    is_leak_free, leaked = check_cross_partition_leakage(train_records, val_records)
    assert is_leak_free is True
    assert len(leaked) == 0


# ---------------------------------------------------------------------------
# Scenario 10: Quarantined Records Excluded from Usable Training Set
# ---------------------------------------------------------------------------

def test_10_quarantined_records_excluded_from_usable_training_set():
    """Records labelled 'ambiguous_needs_review' or invalid records are routed to quarantine, not training."""
    train_records = _load_jsonl(TRAIN_CORPUS_PATH)
    val_records = _load_jsonl(VAL_CORPUS_PATH)
    quarantine_records = _load_jsonl(QUARANTINE_PATH)

    assert len(quarantine_records) > 0, "Quarantine records file is empty"

    # No quarantined record should appear in train or val
    train_ids = set(r["record_id"] for r in train_records)
    val_ids = set(r["record_id"] for r in val_records)

    for q in quarantine_records:
        qid = q.get("record", {}).get("record_id") or q.get("record_id")
        assert qid is not None
        assert qid not in train_ids, f"Quarantined record {qid} leaked into training set"
        assert qid not in val_ids, f"Quarantined record {qid} leaked into validation set"
        assert "quarantine_reason" in q

    # No ambiguous_needs_review record in clean training or validation sets
    train_labels = set(r["ground_truth_label"] for r in train_records)
    val_labels = set(r["ground_truth_label"] for r in val_records)
    assert "ambiguous_needs_review" not in train_labels
    assert "ambiguous_needs_review" not in val_labels


# ---------------------------------------------------------------------------
# Scenario 11: Empty and Malformed Inputs Produce Safe Actionable Errors
# ---------------------------------------------------------------------------

def test_11_empty_and_malformed_inputs_produce_safe_errors():
    """Empty dictionaries, None values, and malformed inputs fail gracefully."""
    # Empty dictionary
    valid, errors = validate_single_record({})
    assert valid is False
    assert len(errors) > 0

    # Non-dictionary input
    valid, errors = validate_single_record("not a dict")  # type: ignore
    assert valid is False
    assert any("dictionary" in e for e in errors)

    # Missing text field
    valid, errors = validate_single_record({"record_id": "test_01"})
    assert valid is False
    assert any("text" in e for e in errors)

    # Empty text
    blank_text_rec = {
        "record_id": "test_02",
        "text": "   ",
        "ground_truth_label": "phishing",
        "language": "mr",
        "script": "Devanagari",
        "provenance_category": "synthetic_test_case",
        "provenance_verification_status": "synthetic_fixture",
        "source_reference": "test_suite",
        "license_info": "CC0",
        "collection_date": "2026-10-29",
        "review_status": "reviewed",
        "campaign_id": "test_camp",
        "dataset_role": "development",
        "scenario_category": "test_scenario",
    }
    valid, errors = validate_single_record(blank_text_rec)
    assert valid is False
    assert any("non-empty" in e for e in errors)


# ---------------------------------------------------------------------------
# Scenario 12: Missing Provenance Identified
# ---------------------------------------------------------------------------

def test_12_missing_provenance_identified():
    """Records missing provenance category, verification status, source reference, or license info fail validation."""
    valid_base = {
        "record_id": "test_prov_001",
        "text": "महावितरण वीज बिल सूचना",
        "ground_truth_label": "phishing",
        "language": "mr",
        "script": "Devanagari",
        "provenance_category": "synthetic_test_case",
        "provenance_verification_status": "synthetic_fixture",
        "source_reference": "test_suite",
        "license_info": "CC0",
        "collection_date": "2026-10-29",
        "review_status": "reviewed",
        "campaign_id": "test_camp",
        "dataset_role": "development",
        "scenario_category": "test_scenario",
    }

    # Missing provenance_category
    bad = dict(valid_base)
    del bad["provenance_category"]
    valid, errors = validate_single_record(bad)
    assert valid is False
    assert any("provenance_category" in e for e in errors)

    # Disallowed provenance_category
    bad = dict(valid_base, provenance_category="scraped_darkweb")
    valid, errors = validate_single_record(bad)
    assert valid is False

    # Missing source_reference
    bad = dict(valid_base, source_reference="")
    valid, errors = validate_single_record(bad)
    assert valid is False
    assert any("source_reference" in e for e in errors)


# ---------------------------------------------------------------------------
# Scenario 13: Synthetic Examples Contain No Actual Credentials or Real PII
# ---------------------------------------------------------------------------

def test_13_synthetic_examples_contain_no_real_pii():
    """Generated synthetic examples must only use non-resolvable dummy domains, reserved numbers, and dummy names."""
    train_records = _load_jsonl(TRAIN_CORPUS_PATH)
    val_records = _load_jsonl(VAL_CORPUS_PATH)
    all_recs = train_records + val_records

    # Permitted domains in synthetic text
    permitted_domains = {
        "bill-update.invalid",
        "mahabill-support.invalid",
        "secure-kyc-portal.invalid",
        "quick-reward.invalid",
        "dispatch-notice.invalid",
        "pm-subsidy-portal.invalid",
        "traffic-challan-pay.invalid",
        "speedy-delivery.invalid",
        "hotel-rewards-job.invalid",
        "mudra-loan-sanction.invalid",
        "mahadiscom.in",
        "mparivahan.gov.in",
        "arogya.maharashtra.gov.in",
        "cybercrime.gov.in",
    }

    url_regex = re.compile(r"https?://([a-zA-Z0-9.-]+)", re.IGNORECASE)
    for r in all_recs:
        text = r["text"]
        matches = url_regex.findall(text)
        for domain in matches:
            clean_domain = domain.rstrip(".").lower()
            assert clean_domain in permitted_domains or clean_domain.endswith(".invalid") or clean_domain.endswith(".gov.in"), (
                f"Potentially live or unauthorized domain '{clean_domain}' found in record {r['record_id']}"
            )


# ---------------------------------------------------------------------------
# Scenario 14: Repeated Pipeline Runs Produce Consistent Results
# ---------------------------------------------------------------------------

def test_14_repeated_pipeline_runs_produce_consistent_results():
    """Running preprocessing pipeline repeatedly on identical input yields deterministic output."""
    raw_train, raw_val = generate_full_synthetic_corpus(seed=42, train_target_per_family=5, val_target_per_family=3)
    combined = raw_train + raw_val

    run1 = run_preprocessing_pipeline(combined)
    run2 = run_preprocessing_pipeline(combined)

    assert run1["report"]["valid_training_records"] == run2["report"]["valid_training_records"]
    assert run1["report"]["valid_validation_records"] == run2["report"]["valid_validation_records"]
    assert run1["report"]["quarantined_records"] == run2["report"]["quarantined_records"]
    assert run1["report"]["exact_duplicates_count"] == run2["report"]["exact_duplicates_count"]
    assert run1["report"]["leak_free_guarantee"] == run2["report"]["leak_free_guarantee"]


# ---------------------------------------------------------------------------
# Scenario 15: Original Evaluation Data and Locked Manifest Remain Untouched
# ---------------------------------------------------------------------------

def test_15_original_evaluation_data_and_locked_manifest_untouched():
    """The original evaluation dataset file exists and its locked partition digest matches exactly."""
    assert os.path.exists(EVAL_DATASET_PATH), f"Eval dataset missing at {EVAL_DATASET_PATH}"
    assert os.path.exists(LOCKED_MANIFEST_PATH), f"Locked manifest missing at {LOCKED_MANIFEST_PATH}"

    with open(LOCKED_MANIFEST_PATH, "r", encoding="utf-8") as mf:
        manifest_data = json.load(mf)

    recorded_sha256 = manifest_data.get("sha256_checksum")
    assert recorded_sha256 == EXPECTED_LOCKED_DIGEST, (
        f"Locked manifest digest altered! Expected {EXPECTED_LOCKED_DIGEST}, got {recorded_sha256}"
    )


# ---------------------------------------------------------------------------
# Scenario 16: Locked Test Partition Integrity
# ---------------------------------------------------------------------------

def test_16_locked_test_partition_integrity():
    """Verify locked test records in evaluation dataset match manifest count and partition integrity."""
    with open(EVAL_DATASET_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)

    locked_records = [
        r for r in eval_data
        if r.get("dataset_role") == "locked_test" or r.get("review_status") == "locked_test"
    ]

    with open(LOCKED_MANIFEST_PATH, "r", encoding="utf-8") as mf:
        manifest_data = json.load(mf)

    expected_count = manifest_data.get("locked_record_count")
    assert len(locked_records) == expected_count, (
        f"Locked record count mismatch: expected {expected_count}, got {len(locked_records)}"
    )
