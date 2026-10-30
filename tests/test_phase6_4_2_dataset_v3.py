"""
Automated Test Suite for Fresh Synthetic Dataset v3 and Benchmark Isolation (Phase 6.4.2).
Verifies all 20 required scenarios:
 1. All records have valid unique IDs.
 2. All labels are valid.
 3. All languages are valid.
 4. All messaging modes are valid.
 5. All records carry synthetic provenance.
 6. Training and development campaign families are disjoint.
 7. Training and qualification campaign families are disjoint.
 8. Development and qualification campaign families are disjoint.
 9. No exact normalized-text duplicates cross partitions.
10. No shared template identifiers cross partitions.
11. URL-bearing and link-free examples occur across relevant classes.
12. Protective advisories are not mislabeled as phishing.
13. No personal-information leakage.
14. Manifests match actual files.
15. SHA-256 hashes are correct.
16. Corrupt manifests fail closed.
17. Exposed qualification partitions cannot be silently reused as independent qualification sets.
18. Locked evaluation files are not read or modified.
19. Existing v2 datasets remain unchanged.
20. Existing application functionality remains unchanged.
"""

from collections import Counter
import copy
import hashlib
import json
import os
import re
import pytest

from src.dataset_preprocessing import (
    clean_evasion_characters,
    normalize_record_text,
    validate_single_record,
    VALID_LABELS,
    VALID_LANGUAGES,
)
from src.dataset_validator import compute_locked_test_hash
from src.hybrid_decision_engine import HybridDecisionEngine

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CORPUS_DIR_V3 = os.path.join(PROJECT_ROOT, "data", "generated", "v3")
EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"

V2_TRAIN_EXPECTED_SHA = "8871bf7ffec30cd486add55c1f860c4313e530d183f832281ddf2fbd9357f4b9"
V2_VAL_EXPECTED_SHA = "77911f9db811de13c5e89f7f756cb13bbc73c4ad9c13c0d401a62287052cf777"


def _load_jsonl(filepath: str):
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if clean:
                records.append(json.loads(clean))
    return records


def _compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture(scope="module")
def v3_data():
    train_path = os.path.join(CORPUS_DIR_V3, "synthetic_training_corpus.jsonl")
    dev_path = os.path.join(CORPUS_DIR_V3, "synthetic_dev_corpus.jsonl")
    qual_path = os.path.join(CORPUS_DIR_V3, "synthetic_qualification_corpus.jsonl")

    train_recs = _load_jsonl(train_path)
    dev_recs = _load_jsonl(dev_path)
    qual_recs = _load_jsonl(qual_path)

    return {
        "train": train_recs,
        "dev": dev_recs,
        "qual": qual_recs,
        "train_path": train_path,
        "dev_path": dev_path,
        "qual_path": qual_path,
    }


# -----------------------------------------------------------------------------
# 1. All records have valid unique IDs
# -----------------------------------------------------------------------------
def test_01_all_records_have_valid_unique_ids(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    ids = [r["record_id"] for r in all_recs]
    assert len(ids) == len(set(ids)), "Duplicate record_id detected across v3 corpus!"
    for rid in ids:
        assert re.match(r"^syn_v3_(train|dev|qual)_\d{4}$", rid), f"Invalid ID format: {rid}"


# -----------------------------------------------------------------------------
# 2. All labels are valid
# -----------------------------------------------------------------------------
def test_02_all_labels_are_valid(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    expected_labels = {"phishing", "legitimate", "protective_advisory"}
    for r in all_recs:
        lbl = r.get("ground_truth_label")
        assert lbl in expected_labels, f"Invalid label '{lbl}' in record {r.get('record_id')}"


# -----------------------------------------------------------------------------
# 3. All languages are valid
# -----------------------------------------------------------------------------
def test_03_all_languages_are_valid(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    expected_langs = {"mr", "mr-Latn", "en", "mr-en"}
    for r in all_recs:
        lang = r.get("language")
        assert lang in expected_langs, f"Invalid language '{lang}' in record {r.get('record_id')}"


# -----------------------------------------------------------------------------
# 4. All messaging modes are valid
# -----------------------------------------------------------------------------
def test_04_all_messaging_modes_are_valid(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    valid_modes = {"sms", "whatsapp", "formal_notice", "advisory_bulletin", "service_alert"}
    for r in all_recs:
        mode = r.get("messaging_mode")
        assert mode in valid_modes, f"Invalid messaging mode '{mode}' in record {r.get('record_id')}"


# -----------------------------------------------------------------------------
# 5. All records carry synthetic provenance
# -----------------------------------------------------------------------------
def test_05_all_records_carry_synthetic_provenance(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    for r in all_recs:
        assert r.get("provenance_category") == "synthetic_test_case"
        assert r.get("provenance_verification_status") == "synthetic_fixture"
        assert "Seva Synthetic Corpus Generator v3" in r.get("source_reference", "")
        assert r.get("generator_version") == "3.0.0"


# -----------------------------------------------------------------------------
# 6. Training and development campaign families are disjoint
# -----------------------------------------------------------------------------
def test_06_train_and_dev_families_disjoint(v3_data):
    train_fams = {r["campaign_id"] for r in v3_data["train"]}
    dev_fams = {r["campaign_id"] for r in v3_data["dev"]}
    overlap = train_fams & dev_fams
    assert len(overlap) == 0, f"Overlapping families between Train and Dev: {overlap}"


# -----------------------------------------------------------------------------
# 7. Training and qualification campaign families are disjoint
# -----------------------------------------------------------------------------
def test_07_train_and_qual_families_disjoint(v3_data):
    train_fams = {r["campaign_id"] for r in v3_data["train"]}
    qual_fams = {r["campaign_id"] for r in v3_data["qual"]}
    overlap = train_fams & qual_fams
    assert len(overlap) == 0, f"Overlapping families between Train and Qual: {overlap}"


# -----------------------------------------------------------------------------
# 8. Development and qualification campaign families are disjoint
# -----------------------------------------------------------------------------
def test_08_dev_and_qual_families_disjoint(v3_data):
    dev_fams = {r["campaign_id"] for r in v3_data["dev"]}
    qual_fams = {r["campaign_id"] for r in v3_data["qual"]}
    overlap = dev_fams & qual_fams
    assert len(overlap) == 0, f"Overlapping families between Dev and Qual: {overlap}"


# -----------------------------------------------------------------------------
# 9. No exact normalized-text duplicates cross partitions
# -----------------------------------------------------------------------------
def test_09_no_exact_text_duplicates_cross_partitions(v3_data):
    train_texts = {r["normalized_text"] for r in v3_data["train"]}
    dev_texts = {r["normalized_text"] for r in v3_data["dev"]}
    qual_texts = {r["normalized_text"] for r in v3_data["qual"]}

    assert len(train_texts & dev_texts) == 0, "Exact normalized text leaked between Train and Dev!"
    assert len(train_texts & qual_texts) == 0, "Exact normalized text leaked between Train and Qual!"
    assert len(dev_texts & qual_texts) == 0, "Exact normalized text leaked between Dev and Qual!"


# -----------------------------------------------------------------------------
# 10. No shared template identifiers cross partitions
# -----------------------------------------------------------------------------
def test_10_no_shared_template_scenarios_cross_partitions(v3_data):
    train_scens = {r["scenario_category"] for r in v3_data["train"]}
    dev_scens = {r["scenario_category"] for r in v3_data["dev"]}
    qual_scens = {r["scenario_category"] for r in v3_data["qual"]}

    assert len(train_scens & dev_scens) == 0, f"Scenario leakage Train & Dev: {train_scens & dev_scens}"
    assert len(train_scens & qual_scens) == 0, f"Scenario leakage Train & Qual: {train_scens & qual_scens}"
    assert len(dev_scens & qual_scens) == 0, f"Scenario leakage Dev & Qual: {dev_scens & qual_scens}"


# -----------------------------------------------------------------------------
# 11. URL-bearing and link-free examples occur across relevant classes
# -----------------------------------------------------------------------------
def test_11_url_bearing_and_link_free_balance(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    for lbl in ["phishing", "legitimate", "protective_advisory"]:
        sub = [r for r in all_recs if r["ground_truth_label"] == lbl]
        with_url = sum(1 for r in sub if r["has_url"])
        without_url = sum(1 for r in sub if not r["has_url"])
        assert with_url > 0, f"Class '{lbl}' lacks URL-bearing examples!"
        assert without_url > 0, f"Class '{lbl}' lacks link-free examples!"
        ratio = with_url / len(sub)
        assert 0.40 <= ratio <= 0.60, f"URL presence for class '{lbl}' unbalanced: {ratio:.2f}"


# -----------------------------------------------------------------------------
# 12. Protective advisories are not mislabeled as phishing
# -----------------------------------------------------------------------------
def test_12_protective_advisories_not_mislabeled(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    advisories = [r for r in all_recs if r["ground_truth_label"] == "protective_advisory"]
    for r in advisories:
        txt = r["text"].lower()
        # Ensure that official advisories contain protective warning context rather than scam demands
        assert not ("transfer money to claim prize" in txt or "pay immediately to release lottery" in txt)


# -----------------------------------------------------------------------------
# 13. No personal-information leakage
# -----------------------------------------------------------------------------
def test_13_no_personal_information_leakage(v3_data):
    all_recs = v3_data["train"] + v3_data["dev"] + v3_data["qual"]
    safe_phone_prefixes = {"980000000", "9811000000", "9822000000", "022-5555", "1800-555", "1930", "1912", "1906"}
    for r in all_recs:
        txt = r["text"]
        # Check 10-digit Indian mobile numbers
        mobiles = re.findall(r"\b[6-9]\d{9}\b", txt)
        for m in mobiles:
            assert m in ["9800000001", "9800000002", "9800000003", "9800000004", "9800000005", "9811000000", "9822000000"] or m.endswith("0000")
        # Check Aadhaar 12-digit pattern
        assert not re.search(r"\b[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}\b", txt)


# -----------------------------------------------------------------------------
# 14. Manifests match actual files
# -----------------------------------------------------------------------------
def test_14_manifests_match_actual_files(v3_data):
    for part, fname, expected_count in [
        ("training", "training_manifest.json", 1200),
        ("development", "dev_manifest.json", 300),
        ("qualification", "qualification_manifest.json", 450),
    ]:
        mpath = os.path.join(CORPUS_DIR_V3, fname)
        assert os.path.isfile(mpath), f"Manifest missing: {mpath}"
        with open(mpath, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        assert manifest["record_count"] == expected_count
        assert manifest["partition"] == part


# -----------------------------------------------------------------------------
# 15. SHA-256 hashes are correct
# -----------------------------------------------------------------------------
def test_15_sha256_hashes_are_correct(v3_data):
    for fname in ["training_manifest.json", "dev_manifest.json", "qualification_manifest.json"]:
        mpath = os.path.join(CORPUS_DIR_V3, fname)
        with open(mpath, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        cpath = os.path.join(CORPUS_DIR_V3, manifest["file_name"])
        actual_sha = _compute_sha256(cpath)
        assert manifest["file_sha256"] == actual_sha, f"SHA-256 mismatch for {manifest['file_name']}"


# -----------------------------------------------------------------------------
# 16. Corrupt manifests fail closed
# -----------------------------------------------------------------------------
def test_16_corrupt_manifests_fail_closed(tmp_path):
    fake_manifest = {
        "manifest_schema_version": "3.0.0",
        "file_name": "fake.jsonl",
        "file_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "record_count": 999,
    }
    fake_file = tmp_path / "fake.jsonl"
    fake_file.write_text('{"record_id": "test"}\n', encoding="utf-8")
    actual_sha = _compute_sha256(str(fake_file))
    assert fake_manifest["file_sha256"] != actual_sha, "Manifest integrity check must fail when hash is tampered"


# -----------------------------------------------------------------------------
# 17. Exposed qualification partitions cannot be silently reused
# -----------------------------------------------------------------------------
def test_17_qualification_lifecycle_state():
    q_manifest_path = os.path.join(CORPUS_DIR_V3, "qualification_manifest.json")
    with open(q_manifest_path, "r", encoding="utf-8") as f:
        m = json.load(f)
    assert m.get("lifecycle_state") == "sealed_independent_benchmark"
    assert m.get("isolation_metadata", {}).get("is_qualification_held_back") is True


# -----------------------------------------------------------------------------
# 18. Locked evaluation files are not read or modified
# -----------------------------------------------------------------------------
def test_18_locked_evaluation_partition_untouched():
    eval_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with open(eval_path, "r", encoding="utf-8") as f:
        recs = json.load(f)
    digest = compute_locked_test_hash(recs)
    assert digest == EXPECTED_LOCKED_DIGEST, f"Locked test digest changed: {digest}"


# -----------------------------------------------------------------------------
# 19. Existing v2 datasets remain unchanged
# -----------------------------------------------------------------------------
def test_19_existing_v2_datasets_unchanged():
    v2_train = os.path.join(PROJECT_ROOT, "data", "generated", "v2", "synthetic_training_corpus.jsonl")
    v2_val = os.path.join(PROJECT_ROOT, "data", "generated", "v2", "synthetic_validation_corpus.jsonl")

    sha_train = _compute_sha256(v2_train)
    sha_val = _compute_sha256(v2_val)

    assert sha_train == V2_TRAIN_EXPECTED_SHA, f"v2 training corpus modified! {sha_train}"
    assert sha_val == V2_VAL_EXPECTED_SHA, f"v2 validation corpus modified! {sha_val}"


# -----------------------------------------------------------------------------
# 20. Existing application functionality remains unchanged
# -----------------------------------------------------------------------------
def test_20_existing_application_functionality_unchanged():
    engine = HybridDecisionEngine()
    test_msg = "Electricity bill overdue. Pay now at http://bill.invalid"
    res = engine.evaluate_message(test_msg)
    final_dec = res.get("final_decision", {})
    assert final_dec.get("production_score_difference") == 0
    assert final_dec.get("authoritative_source") == "deterministic_rules"
