"""
Comprehensive Test Suite for Dataset Deconfounding & Candidate Corpus v2.
Part of Seva Cyber Sandbox (Phase 2.2).

Covers:
1. Generator output reproducibility with fixed seed.
2. Correct schema and valid labels in v2.
3. Candidate corpus counts and class balance (1:1:1 ratio).
4. Zero template-family leakage between training and validation.
5. Zero cross-partition exact duplicates.
6. Detection and reporting of near-duplicates.
7. URL presence across different classes (no trivial URL shortcut).
8. Phishing examples represented with and without links.
9. Protective advisories represented with and without links.
10. Legitimate examples represented with and without links.
11. All four language categories present (mr, mr-Latn, en, mr-en).
12. No real or live URLs in newly generated data.
13. Quarantine exclusion (ambiguous records strictly isolated).
14. Provenance completeness and review status.
15. Preservation of original Phase 2 artifacts (v1 files untouched).
16. Locked evaluation manifest integrity (SHA-256 digest verified).
"""

from collections import Counter
import hashlib
import json
import os
import re
from typing import Any, Dict, List
import pytest

from scripts.generate_synthetic_corpus_v2 import (
    generate_full_synthetic_corpus_v2,
)
from src.dataset_preprocessing import (
    REQUIRED_DATASET_FIELDS,
    VALID_LABELS,
    VALID_LANGUAGES,
    VALID_PROVENANCE_CATEGORIES,
    VALID_ROLES,
    VALID_SCRIPTS,
    check_cross_partition_leakage,
    detect_exact_duplicates,
    detect_near_duplicates_in_corpus,
    validate_single_record,
)
from src.dataset_validator import compute_locked_test_hash

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
V1_DIR = os.path.join(PROJECT_ROOT, "data", "generated")
V2_DIR = os.path.join(PROJECT_ROOT, "data", "generated", "v2")

V2_TRAIN_PATH = os.path.join(V2_DIR, "synthetic_training_corpus.jsonl")
V2_VAL_PATH = os.path.join(V2_DIR, "synthetic_validation_corpus.jsonl")
V2_QUAR_PATH = os.path.join(V2_DIR, "quarantine_records.jsonl")
V2_REPORT_PATH = os.path.join(V2_DIR, "synthetic_corpus_report.json")

V1_TRAIN_PATH = os.path.join(V1_DIR, "synthetic_training_corpus.jsonl")
EVAL_DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
LOCKED_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"

URL_REGEX = re.compile(r"https?://", re.IGNORECASE)


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
# Test 1: Deterministic Output
# ---------------------------------------------------------------------------

def test_01_v2_generator_reproducibility():
    """Generating with fixed seed produces identical output."""
    train_a, val_a = generate_full_synthetic_corpus_v2(seed=42, train_target_per_family=5, val_target_per_family=3)
    train_b, val_b = generate_full_synthetic_corpus_v2(seed=42, train_target_per_family=5, val_target_per_family=3)

    assert len(train_a) == len(train_b)
    assert len(val_a) == len(val_b)
    for a, b in zip(train_a, train_b):
        assert a["record_id"] == b["record_id"]
        assert a["text"] == b["text"]
        assert a["ground_truth_label"] == b["ground_truth_label"]


# ---------------------------------------------------------------------------
# Test 2: Correct Schema and Valid Labels in v2
# ---------------------------------------------------------------------------

def test_02_v2_schema_and_labels_validation():
    """Every persisted record in v2 must pass schema validation with valid labels."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    val_recs = _load_jsonl(V2_VAL_PATH)

    assert len(train_recs) > 0
    assert len(val_recs) > 0

    for r in train_recs + val_recs:
        valid, errors = validate_single_record(r)
        assert valid is True, f"Record {r.get('record_id')} failed validation: {errors}"
        assert r["ground_truth_label"] in {"phishing", "legitimate", "protective_advisory"}
        assert "normalized_text" in r
        assert len(r["normalized_text"]) > 0


# ---------------------------------------------------------------------------
# Test 3: Candidate Corpus Counts and Class Balance (1:1:1 Ratio)
# ---------------------------------------------------------------------------

def test_03_v2_class_balance_and_counts():
    """v2 corpus must have balanced class representation (1:1:1 ratio)."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    val_recs = _load_jsonl(V2_VAL_PATH)

    # Training class counts: 120 / 120 / 120
    train_labels = [r["ground_truth_label"] for r in train_recs]
    assert train_labels.count("phishing") == 120
    assert train_labels.count("legitimate") == 120
    assert train_labels.count("protective_advisory") == 120
    assert len(train_recs) == 360

    # Validation class counts: 45 / 45 / 45
    val_labels = [r["ground_truth_label"] for r in val_recs]
    assert val_labels.count("phishing") == 45
    assert val_labels.count("legitimate") == 45
    assert val_labels.count("protective_advisory") == 45
    assert len(val_recs) == 135


# ---------------------------------------------------------------------------
# Test 4: Zero Template-Family Leakage
# ---------------------------------------------------------------------------

def test_04_v2_zero_template_family_leakage():
    """Training and Validation partitions must share zero campaign families."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    val_recs = _load_jsonl(V2_VAL_PATH)

    is_leak_free, leaked = check_cross_partition_leakage(train_recs, val_recs)
    assert is_leak_free is True
    assert len(leaked) == 0

    train_camps = set(r["campaign_id"] for r in train_recs)
    val_camps = set(r["campaign_id"] for r in val_recs)
    assert len(train_camps & val_camps) == 0


# ---------------------------------------------------------------------------
# Test 5: Zero Cross-Partition Exact Duplicates
# ---------------------------------------------------------------------------

def test_05_v2_zero_cross_partition_exact_duplicates():
    """No exact duplicate message texts between training and validation sets."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    val_recs = _load_jsonl(V2_VAL_PATH)

    train_texts = set(r["normalized_text"] for r in train_recs)
    val_texts = set(r["normalized_text"] for r in val_recs)
    assert len(train_texts & val_texts) == 0


# ---------------------------------------------------------------------------
# Test 6: Detection and Reporting of Near-Duplicates
# ---------------------------------------------------------------------------

def test_06_v2_near_duplicate_handling():
    """Near duplicates emit warnings without silently dropping records."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    assert os.path.exists(V2_REPORT_PATH)

    with open(V2_REPORT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert "near_duplicate_warnings_count" in report
    assert report["valid_training_records"] == 360
    assert report["valid_validation_records"] == 135


# ---------------------------------------------------------------------------
# Test 7: URL Presence Across Different Classes (Shortcut Removed)
# ---------------------------------------------------------------------------

def test_07_v2_no_trivial_url_shortcut():
    """URLs must be present in a moderate proportion (25% to 75%) across ALL classes, not 100% or 0%."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)

    by_label = {"phishing": [], "legitimate": [], "protective_advisory": []}
    for r in train_recs:
        by_label[r["ground_truth_label"]].append(r)

    for lbl, recs in by_label.items():
        with_url = sum(1 for r in recs if URL_REGEX.search(r["text"]))
        rate = with_url / len(recs)
        # Rate must be balanced (between 25% and 75%), proving it is not an accidental shortcut
        assert 0.25 <= rate <= 0.75, f"Class {lbl} URL rate {rate:.2f} is extreme!"


# ---------------------------------------------------------------------------
# Test 8: Phishing Examples With and Without Links
# ---------------------------------------------------------------------------

def test_08_v2_phishing_both_with_and_without_links():
    """Phishing class must contain both link-bearing and link-free messages."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    phish = [r for r in train_recs if r["ground_truth_label"] == "phishing"]

    phish_with_link = [r for r in phish if URL_REGEX.search(r["text"])]
    phish_no_link = [r for r in phish if not URL_REGEX.search(r["text"])]

    assert len(phish_with_link) > 20, "Too few link-bearing phishing examples"
    assert len(phish_no_link) > 20, "Too few link-free phishing examples"


# ---------------------------------------------------------------------------
# Test 9: Protective Advisories With and Without Links
# ---------------------------------------------------------------------------

def test_09_v2_protective_both_with_and_without_links():
    """Protective advisory class must contain both link-bearing and link-free messages."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    prot = [r for r in train_recs if r["ground_truth_label"] == "protective_advisory"]

    prot_with_link = [r for r in prot if URL_REGEX.search(r["text"])]
    prot_no_link = [r for r in prot if not URL_REGEX.search(r["text"])]

    assert len(prot_with_link) > 20, "Too few link-bearing protective examples"
    assert len(prot_no_link) > 20, "Too few link-free protective examples"


# ---------------------------------------------------------------------------
# Test 10: Legitimate Examples With and Without Links
# ---------------------------------------------------------------------------

def test_10_v2_legitimate_both_with_and_without_links():
    """Legitimate class must contain both link-bearing and link-free messages."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    legit = [r for r in train_recs if r["ground_truth_label"] == "legitimate"]

    legit_with_link = [r for r in legit if URL_REGEX.search(r["text"])]
    legit_no_link = [r for r in legit if not URL_REGEX.search(r["text"])]

    assert len(legit_with_link) > 20, "Too few link-bearing legitimate examples"
    assert len(legit_no_link) > 20, "Too few link-free legitimate examples"


# ---------------------------------------------------------------------------
# Test 11: All Four Language Categories Present
# ---------------------------------------------------------------------------

def test_11_v2_all_four_languages_present():
    """mr, mr-Latn, en, and mr-en must all be substantially represented in v2."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    langs = Counter(r["language"] for r in train_recs)

    for req_lang in ("mr", "mr-Latn", "en", "mr-en"):
        assert req_lang in langs
        assert langs[req_lang] >= 40, f"Language {req_lang} underrepresented: {langs[req_lang]}"


# ---------------------------------------------------------------------------
# Test 12: No Real or Live URLs in Newly Generated Data
# ---------------------------------------------------------------------------

def test_12_v2_no_live_domains():
    """All generated domains must be reserved (.invalid) or verified official (.gov.in / .in)."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    val_recs = _load_jsonl(V2_VAL_PATH)

    domain_regex = re.compile(r"https?://([a-zA-Z0-9.-]+)", re.IGNORECASE)
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
        "mahadiscom-receipt.invalid",
        "civil-hospital-portal.invalid",
        "bank-statement.invalid",
        "lpg-booking.invalid",
        "exam-portal.invalid",
        "citizen-service.invalid",
        "utility-selfservice.invalid",
        "cybercrime-alert.invalid",
        "police-cybercell.invalid",
        "rbi-safety.invalid",
        "certin-advisory.invalid",
        "consumer-vigilance.invalid",
        "mahadiscom.in",
        "mparivahan.gov.in",
        "arogya.maharashtra.gov.in",
        "cybercrime.gov.in",
    }

    for r in train_recs + val_recs:
        matches = domain_regex.findall(r["text"])
        for d in matches:
            clean_d = d.rstrip(".").lower()
            assert clean_d in permitted_domains or clean_d.endswith(".invalid") or clean_d.endswith(".gov.in"), (
                f"Unauthorized or live domain '{clean_d}' in record {r['record_id']}"
            )


# ---------------------------------------------------------------------------
# Test 13: Quarantine Exclusion
# ---------------------------------------------------------------------------

def test_13_v2_quarantine_exclusion():
    """Quarantined records must not leak into clean training or validation files."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    val_recs = _load_jsonl(V2_VAL_PATH)
    quar_entries = _load_jsonl(V2_QUAR_PATH)

    assert len(quar_entries) == 45

    train_ids = set(r["record_id"] for r in train_recs)
    val_ids = set(r["record_id"] for r in val_recs)

    for q in quar_entries:
        rec = q.get("record", q)
        qid = rec.get("record_id")
        assert qid not in train_ids, f"Quarantined record {qid} in train set"
        assert qid not in val_ids, f"Quarantined record {qid} in val set"
        assert rec.get("ground_truth_label") == "ambiguous_needs_review"


# ---------------------------------------------------------------------------
# Test 14: Provenance Completeness
# ---------------------------------------------------------------------------

def test_14_v2_provenance_completeness():
    """All v2 records document complete provenance and review status."""
    train_recs = _load_jsonl(V2_TRAIN_PATH)
    val_recs = _load_jsonl(V2_VAL_PATH)

    for r in train_recs + val_recs:
        assert r["provenance_category"] == "synthetic_test_case"
        assert r["provenance_verification_status"] == "synthetic_fixture"
        assert r["review_status"] == "reviewed"
        assert len(r["source_reference"]) > 0
        assert len(r["license_info"]) > 0


# ---------------------------------------------------------------------------
# Test 15: Preservation of Original Phase 2 Artifacts (v1 files untouched)
# ---------------------------------------------------------------------------

def test_15_v1_artifacts_untouched():
    """Phase 2 original files must remain unchanged and present in data/generated/."""
    assert os.path.exists(V1_TRAIN_PATH)
    v1_recs = _load_jsonl(V1_TRAIN_PATH)
    assert len(v1_recs) == 315, f"Original Phase 2 train count altered! Expected 315, got {len(v1_recs)}"


# ---------------------------------------------------------------------------
# Test 16: Locked Evaluation Manifest Integrity
# ---------------------------------------------------------------------------

def test_16_locked_evaluation_digest_verified():
    """Locked evaluation partition SHA-256 digest remains strictly unchanged."""
    assert os.path.exists(EVAL_DATASET_PATH)
    assert os.path.exists(LOCKED_MANIFEST_PATH)

    with open(EVAL_DATASET_PATH, "r", encoding="utf-8") as f:
        eval_data = json.load(f)

    computed_digest = compute_locked_test_hash(eval_data)
    assert computed_digest == EXPECTED_LOCKED_DIGEST, (
        f"Locked test partition modified! Expected {EXPECTED_LOCKED_DIGEST}, got {computed_digest}"
    )
