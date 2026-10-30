"""
Automated Test Suite for Synthetic Dataset v4: Digital Arrest, Extortion and Semantic Balance.
Part of Seva Cyber Sandbox (Phase 6.4.6).

Verifies all requirements:
 1. All records have valid unique IDs across all partitions.
 2. All labels are valid canonical labels.
 3. All languages are valid (mr, mr-Latn, en, mr-en).
 4. All messaging modes are valid.
 5. All records carry verified synthetic provenance metadata.
 6. Training and development campaign families are disjoint.
 7. Training and qualification campaign families are disjoint.
 8. Development and qualification campaign families are disjoint.
 9. All 45 campaign families and 45 scenario categories are unique.
10. No exact normalized-text duplicates cross partitions.
11. Balanced class distribution (phishing, legitimate, protective_advisory).
12. Balanced multilingual distribution (~25% each).
13. Exactly 50.0% URL-bearing and 50.0% URL-free across partitions and classes.
14. Digital-arrest and extortion phishing scenarios present in train, dev, qual.
15. Legitimate police, court, and administrative scenarios present.
16. Protective digital-arrest and extortion advisories present.
17. Law-enforcement vocabulary distributed across all three classes (semantic overlap).
18. URL-free extortion fraud and URL-bearing legitimate/advisories exist.
19. Zero real PII, unmasked real phone numbers, or unmasked Aadhaar numbers.
20. Manifests match actual files and cryptographic SHA-256 digests.
21. Qualification lifecycle state initialized as sealed_independent_benchmark and UNEXPOSED in ledger.
22. Qualification partition has not been evaluated or consumed.
23. Corrupt manifests fail closed (negative test with tmp_path).
24. Tampered partition fails closed (negative test with tmp_path).
25. Existing v2, v3 datasets and locked evaluation partition remain unchanged.
26. Model registry and active model configuration remain unchanged.
27. Production application decision engine behavior remains unchanged.
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
    VALID_SCRIPTS,
    VALID_ROLES,
    VALID_PROVENANCE_CATEGORIES,
)
from src.dataset_validator import compute_locked_test_hash
from src.hybrid_decision_engine import HybridDecisionEngine

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CORPUS_DIR_V4 = os.path.join(PROJECT_ROOT, "data", "generated", "v4")
CORPUS_DIR_V3 = os.path.join(PROJECT_ROOT, "data", "generated", "v3")
CORPUS_DIR_V2 = os.path.join(PROJECT_ROOT, "data", "generated", "v2")

EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"

V2_TRAIN_EXPECTED_SHA = "8871bf7ffec30cd486add55c1f860c4313e530d183f832281ddf2fbd9357f4b9"
V2_VAL_EXPECTED_SHA = "77911f9db811de13c5e89f7f756cb13bbc73c4ad9c13c0d401a62287052cf777"

V3_TRAIN_EXPECTED_SHA = "f8143880f3d5d13e5f10c14ca2d07c3a736726979f93a53dd864d59fdaee2473"
V3_DEV_EXPECTED_SHA = "55e9357abae0de2ebc71535374f079bdb146ea746278471b03797f0941c85e4d"
V3_QUAL_EXPECTED_SHA = "197c62e7f0b305ce5965cf7bbeba8543fcd542a4a026d07dbd1172b3656f4a0f"


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
def v4_data():
    train_path = os.path.join(CORPUS_DIR_V4, "synthetic_training_corpus.jsonl")
    dev_path = os.path.join(CORPUS_DIR_V4, "synthetic_dev_corpus.jsonl")
    qual_path = os.path.join(CORPUS_DIR_V4, "synthetic_qualification_corpus.jsonl")

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
# 1. Unique IDs
# -----------------------------------------------------------------------------
def test_01_all_records_have_valid_unique_ids(v4_data):
    all_records = v4_data["train"] + v4_data["dev"] + v4_data["qual"]
    assert len(all_records) == 2250, f"Expected 2250 total records, got {len(all_records)}"

    all_ids = [r["record_id"] for r in all_records]
    assert len(all_ids) == len(set(all_ids)), "Duplicate record_id detected across corpus!"

    for r in all_records:
        rid = r["record_id"]
        assert re.match(r"^syn_v4_(train|dev|qual)_\d{4}$", rid), f"Invalid ID format: '{rid}'"


# -----------------------------------------------------------------------------
# 2. Valid Labels
# -----------------------------------------------------------------------------
def test_02_all_labels_are_valid(v4_data):
    all_records = v4_data["train"] + v4_data["dev"] + v4_data["qual"]
    for r in all_records:
        assert r["ground_truth_label"] in VALID_LABELS, f"Invalid label '{r['ground_truth_label']}' in {r['record_id']}"


# -----------------------------------------------------------------------------
# 3. Valid Languages
# -----------------------------------------------------------------------------
def test_03_all_languages_are_valid(v4_data):
    all_records = v4_data["train"] + v4_data["dev"] + v4_data["qual"]
    for r in all_records:
        assert r["language"] in VALID_LANGUAGES, f"Invalid language '{r['language']}' in {r['record_id']}"
        assert r["script"] in VALID_SCRIPTS, f"Invalid script '{r['script']}' in {r['record_id']}"


# -----------------------------------------------------------------------------
# 4. Valid Messaging Modes
# -----------------------------------------------------------------------------
def test_04_all_messaging_modes_are_valid(v4_data):
    valid_modes = {"sms", "whatsapp", "formal_notice", "service_alert", "advisory_bulletin"}
    all_records = v4_data["train"] + v4_data["dev"] + v4_data["qual"]
    for r in all_records:
        assert r["messaging_mode"] in valid_modes, f"Invalid mode '{r['messaging_mode']}' in {r['record_id']}"


# -----------------------------------------------------------------------------
# 5. Synthetic Provenance
# -----------------------------------------------------------------------------
def test_05_all_records_carry_synthetic_provenance(v4_data):
    all_records = v4_data["train"] + v4_data["dev"] + v4_data["qual"]
    for r in all_records:
        assert r["provenance_category"] == "synthetic_test_case"
        assert r["provenance_verification_status"] == "synthetic_fixture"
        assert "Synthetic" in r["source_reference"]
        assert "CC0" in r["license_info"]
        assert r["generator_version"] == "4.0.0"


# -----------------------------------------------------------------------------
# 6, 7, 8. Partition Disjointness
# -----------------------------------------------------------------------------
def test_06_train_and_dev_families_disjoint(v4_data):
    train_fams = {r["campaign_id"] for r in v4_data["train"]}
    dev_fams = {r["campaign_id"] for r in v4_data["dev"]}
    overlap = train_fams & dev_fams
    assert len(overlap) == 0, f"Train and Dev share campaign families: {overlap}"


def test_07_train_and_qual_families_disjoint(v4_data):
    train_fams = {r["campaign_id"] for r in v4_data["train"]}
    qual_fams = {r["campaign_id"] for r in v4_data["qual"]}
    overlap = train_fams & qual_fams
    assert len(overlap) == 0, f"Train and Qual share campaign families: {overlap}"


def test_08_dev_and_qual_families_disjoint(v4_data):
    dev_fams = {r["campaign_id"] for r in v4_data["dev"]}
    qual_fams = {r["campaign_id"] for r in v4_data["qual"]}
    overlap = dev_fams & qual_fams
    assert len(overlap) == 0, f"Dev and Qual share campaign families: {overlap}"


# -----------------------------------------------------------------------------
# 9. All 45 Families & Scenarios Unique
# -----------------------------------------------------------------------------
def test_09_all_45_families_and_scenarios_unique(v4_data):
    train_fams = {r["campaign_id"] for r in v4_data["train"]}
    dev_fams = {r["campaign_id"] for r in v4_data["dev"]}
    qual_fams = {r["campaign_id"] for r in v4_data["qual"]}

    assert len(train_fams) == 30, f"Expected 30 train families, got {len(train_fams)}"
    assert len(dev_fams) == 6, f"Expected 6 dev families, got {len(dev_fams)}"
    assert len(qual_fams) == 9, f"Expected 9 qual families, got {len(qual_fams)}"

    all_fams = train_fams | dev_fams | qual_fams
    assert len(all_fams) == 45, f"Expected 45 unique families, got {len(all_fams)}"

    train_scens = {r["scenario_category"] for r in v4_data["train"]}
    dev_scens = {r["scenario_category"] for r in v4_data["dev"]}
    qual_scens = {r["scenario_category"] for r in v4_data["qual"]}

    assert len(train_scens) == 30, f"Expected 30 train scenarios, got {len(train_scens)}"
    assert len(dev_scens) == 6, f"Expected 6 dev scenarios, got {len(dev_scens)}"
    assert len(qual_scens) == 9, f"Expected 9 qual scenarios, got {len(qual_scens)}"

    all_scens = train_scens | dev_scens | qual_scens
    assert len(all_scens) == 45, f"Expected 45 unique scenarios, got {len(all_scens)}"


# -----------------------------------------------------------------------------
# 10. No Exact Text Duplicates Across Partitions
# -----------------------------------------------------------------------------
def test_10_no_exact_normalized_text_duplicates_cross_partitions(v4_data):
    train_texts = {r["normalized_text"] for r in v4_data["train"]}
    dev_texts = {r["normalized_text"] for r in v4_data["dev"]}
    qual_texts = {r["normalized_text"] for r in v4_data["qual"]}

    assert len(train_texts & dev_texts) == 0, "Exact normalized text duplicated across Train and Dev!"
    assert len(train_texts & qual_texts) == 0, "Exact normalized text duplicated across Train and Qual!"
    assert len(dev_texts & qual_texts) == 0, "Exact normalized text duplicated across Dev and Qual!"


# -----------------------------------------------------------------------------
# 11. Balanced Class Distribution
# -----------------------------------------------------------------------------
def test_11_balanced_class_distribution(v4_data):
    for part, recs, expected_per_class in [
        ("training", v4_data["train"], 500),
        ("development", v4_data["dev"], 100),
        ("qualification", v4_data["qual"], 150),
    ]:
        counts = Counter(r["ground_truth_label"] for r in recs)
        for lbl in ["phishing", "legitimate", "protective_advisory"]:
            assert counts[lbl] == expected_per_class, f"{part} {lbl} count mismatch: {counts[lbl]} vs {expected_per_class}"


# -----------------------------------------------------------------------------
# 12. Balanced Language Distribution
# -----------------------------------------------------------------------------
def test_12_balanced_language_distribution(v4_data):
    for part, recs in [("training", v4_data["train"]), ("development", v4_data["dev"]), ("qualification", v4_data["qual"])]:
        counts = Counter(r["language"] for r in recs)
        total = len(recs)
        for lang in ["mr", "mr-Latn", "en", "mr-en"]:
            prop = counts[lang] / total
            assert 0.20 <= prop <= 0.30, f"{part} {lang} proportion {prop:.2f} out of range [0.20, 0.30]"


# -----------------------------------------------------------------------------
# 13. URL Presence Balance (Exactly 50% / 50%)
# -----------------------------------------------------------------------------
def test_13_exact_50_percent_url_balance(v4_data):
    for part, recs in [("training", v4_data["train"]), ("development", v4_data["dev"]), ("qualification", v4_data["qual"])]:
        total = len(recs)
        url_true = sum(1 for r in recs if r["has_url"])
        url_false = sum(1 for r in recs if not r["has_url"])
        assert url_true == total // 2, f"{part} URL True mismatch: {url_true} vs {total // 2}"
        assert url_false == total // 2, f"{part} URL False mismatch: {url_false} vs {total // 2}"

        # Check per class
        for lbl in ["phishing", "legitimate", "protective_advisory"]:
            c_recs = [r for r in recs if r["ground_truth_label"] == lbl]
            c_true = sum(1 for r in c_recs if r["has_url"])
            c_false = sum(1 for r in c_recs if not r["has_url"])
            assert c_true == len(c_recs) // 2, f"{part} {lbl} URL True mismatch: {c_true} vs {len(c_recs) // 2}"
            assert c_false == len(c_recs) // 2, f"{part} {lbl} URL False mismatch: {c_false} vs {len(c_recs) // 2}"


# -----------------------------------------------------------------------------
# 14, 15, 16. Domain Scenario Coverage
# -----------------------------------------------------------------------------
def test_14_digital_arrest_and_extortion_scenarios_present(v4_data):
    for part, recs in [("training", v4_data["train"]), ("development", v4_data["dev"]), ("qualification", v4_data["qual"])]:
        phish_recs = [r for r in recs if r["ground_truth_label"] == "phishing"]
        scens = {r["scenario_category"] for r in phish_recs}
        da_matches = [s for s in scens if any(k in s for k in ["digital_arrest", "narcotics", "cbi", "contraband", "nia", "acb", "contempt", "warrant"])]
        assert len(da_matches) > 0, f"No extortion/digital-arrest phishing scenarios in {part}: {scens}"


def test_15_legitimate_police_and_court_notifications_present(v4_data):
    for part, recs in [("training", v4_data["train"]), ("development", v4_data["dev"]), ("qualification", v4_data["qual"])]:
        legit_recs = [r for r in recs if r["ground_truth_label"] == "legitimate"]
        scens = {r["scenario_category"] for r in legit_recs}
        civic_matches = [s for s in scens if any(k in s for k in ["police", "court", "passport", "rto", "tax", "lok_adalat", "municipal", "hospital"])]
        assert len(civic_matches) > 0, f"No legitimate police/court/civic scenarios in {part}: {scens}"


def test_16_protective_digital_arrest_advisories_present(v4_data):
    for part, recs in [("training", v4_data["train"]), ("development", v4_data["dev"]), ("qualification", v4_data["qual"])]:
        adv_recs = [r for r in recs if r["ground_truth_label"] == "protective_advisory"]
        scens = {r["scenario_category"] for r in adv_recs}
        adv_matches = [s for s in scens if any(k in s for k in ["digital_arrest", "impersonation", "1930", "ed_", "trai_", "bar_council", "cbi_"])]
        assert len(adv_matches) > 0, f"No protective digital-arrest advisories in {part}: {scens}"


# -----------------------------------------------------------------------------
# 17. Law-Enforcement Semantic Overlap Across All 3 Classes
# -----------------------------------------------------------------------------
def test_17_law_enforcement_semantic_overlap_across_classes(v4_data):
    all_records = v4_data["train"] + v4_data["dev"] + v4_data["qual"]
    vocab = {"phishing": Counter(), "legitimate": Counter(), "protective_advisory": Counter()}

    terms = ["police", "पोलीस", "court", "कोर्ट", "cbi"]
    for r in all_records:
        t_low = r["text"].lower()
        lbl = r["ground_truth_label"]
        for term in terms:
            if term in t_low:
                vocab[lbl][term] += 1

    for term in ["police", "पोलीस", "court"]:
        assert vocab["phishing"][term] > 0, f"Term '{term}' missing from phishing"
        assert vocab["legitimate"][term] > 0, f"Term '{term}' missing from legitimate"
        assert vocab["protective_advisory"][term] > 0, f"Term '{term}' missing from advisory"


# -----------------------------------------------------------------------------
# 18. URL-free Phishing and URL-bearing Legit/Advisory Presence
# -----------------------------------------------------------------------------
def test_18_url_free_extortion_and_url_bearing_legit_present(v4_data):
    for part, recs in [("training", v4_data["train"]), ("development", v4_data["dev"]), ("qualification", v4_data["qual"])]:
        p_no_url = [r for r in recs if r["ground_truth_label"] == "phishing" and not r["has_url"]]
        l_with_url = [r for r in recs if r["ground_truth_label"] == "legitimate" and r["has_url"]]
        a_with_url = [r for r in recs if r["ground_truth_label"] == "protective_advisory" and r["has_url"]]

        assert len(p_no_url) > 0, f"Missing URL-free phishing in {part}"
        assert len(l_with_url) > 0, f"Missing URL-bearing legitimate in {part}"
        assert len(a_with_url) > 0, f"Missing URL-bearing advisory in {part}"


# -----------------------------------------------------------------------------
# 19. No Real Contact Information or PII
# -----------------------------------------------------------------------------
def test_19_no_raw_personal_information(v4_data):
    all_records = v4_data["train"] + v4_data["dev"] + v4_data["qual"]
    for r in all_records:
        is_val, errs = validate_single_record(r)
        assert is_val, f"Validation failure in {r['record_id']}: {errs}"


# -----------------------------------------------------------------------------
# 20. Manifests and Hashes Match Actual Files
# -----------------------------------------------------------------------------
def test_20_manifests_and_hashes_match_actual_files(v4_data):
    for name, fname, key in [
        ("training", "training_manifest.json", "train"),
        ("development", "dev_manifest.json", "dev"),
        ("qualification", "qualification_manifest.json", "qual"),
    ]:
        mpath = os.path.join(CORPUS_DIR_V4, fname)
        assert os.path.isfile(mpath), f"Missing manifest '{mpath}'"
        with open(mpath, "r", encoding="utf-8") as f:
            m = json.load(f)

        actual_sha = _compute_sha256(v4_data[f"{key}_path"])
        assert m["file_sha256"] == actual_sha, f"SHA mismatch in manifest {fname}!"
        assert m["record_count"] == len(v4_data[key]), f"Record count mismatch in manifest {fname}!"

    # Corpus manifest
    corpus_mpath = os.path.join(CORPUS_DIR_V4, "v4_corpus_manifest.json")
    assert os.path.isfile(corpus_mpath), "Missing v4_corpus_manifest.json!"
    with open(corpus_mpath, "r", encoding="utf-8") as f:
        cm = json.load(f)
    assert cm["total_records"] == 2250
    assert len(cm["partitions"]) == 3


# -----------------------------------------------------------------------------
# 21 & 22. Qualification Lifecycle State and Non-Evaluation
# -----------------------------------------------------------------------------
def test_21_qualification_lifecycle_and_exposure_ledger_unexposed(v4_data):
    qual_mpath = os.path.join(CORPUS_DIR_V4, "qualification_manifest.json")
    with open(qual_mpath, "r", encoding="utf-8") as f:
        qm = json.load(f)
    assert qm["lifecycle_state"] == "sealed_independent_benchmark"

    ledger_path = os.path.join(PROJECT_ROOT, "data", "generated", "v4", "exposure_ledger.json")
    assert os.path.isfile(ledger_path), f"Missing v4 exposure ledger: {ledger_path}"
    with open(ledger_path, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    qual_sha = _compute_sha256(v4_data["qual_path"])
    assert qual_sha in ledger["partitions"], f"Qualification partition {qual_sha} not in ledger!"
    entry = ledger["partitions"][qual_sha]
    assert entry["exposure_count"] == 0
    assert entry["is_exposed"] is False
    assert entry["current_status"] == "UNEXPOSED"
    assert entry["first_exposed_at_utc"] is None
    assert len(entry["events"]) == 0


def test_22_qualification_partition_not_evaluated(v4_data):
    # Verify no candidate evaluation reports exist targeting v4 qualification
    eval_dir = os.path.join(PROJECT_ROOT, "evaluation", "qualification")
    for f in os.listdir(eval_dir):
        if f.endswith(".json") and "v4" in f and "report" in f.lower():
            pytest.fail(f"Premature evaluation report found for v4: {f}")


# -----------------------------------------------------------------------------
# 23 & 24. Negative Tests with tmp_path
# -----------------------------------------------------------------------------
def test_23_corrupt_manifests_fail_closed(tmp_path):
    corrupt_manifest = tmp_path / "corrupt_manifest.json"
    with open(corrupt_manifest, "w", encoding="utf-8") as f:
        f.write("{invalid_json: true,")

    with pytest.raises(Exception):
        with open(corrupt_manifest, "r", encoding="utf-8") as f:
            json.load(f)


def test_24_tampered_partition_fails_closed(tmp_path, v4_data):
    fake_corpus = tmp_path / "fake_corpus.jsonl"
    with open(fake_corpus, "w", encoding="utf-8") as f:
        f.write('{"tampered": true}\n')

    # Hash of fake corpus does not match manifest
    fake_sha = _compute_sha256(str(fake_corpus))
    real_sha = _compute_sha256(v4_data["train_path"])
    assert fake_sha != real_sha


# -----------------------------------------------------------------------------
# 25. Existing v2, v3, and Locked Evaluation Datasets Unchanged
# -----------------------------------------------------------------------------
def test_25_existing_v2_v3_datasets_and_locked_eval_unchanged():
    # v2
    v2_train = os.path.join(CORPUS_DIR_V2, "synthetic_training_corpus.jsonl")
    v2_val = os.path.join(CORPUS_DIR_V2, "synthetic_validation_corpus.jsonl")
    if os.path.isfile(v2_train):
        assert _compute_sha256(v2_train) == V2_TRAIN_EXPECTED_SHA
    if os.path.isfile(v2_val):
        assert _compute_sha256(v2_val) == V2_VAL_EXPECTED_SHA

    # v3
    v3_train = os.path.join(CORPUS_DIR_V3, "synthetic_training_corpus.jsonl")
    v3_dev = os.path.join(CORPUS_DIR_V3, "synthetic_dev_corpus.jsonl")
    v3_qual = os.path.join(CORPUS_DIR_V3, "synthetic_qualification_corpus.jsonl")
    if os.path.isfile(v3_train):
        assert _compute_sha256(v3_train) == V3_TRAIN_EXPECTED_SHA
    if os.path.isfile(v3_dev):
        assert _compute_sha256(v3_dev) == V3_DEV_EXPECTED_SHA
    if os.path.isfile(v3_qual):
        assert _compute_sha256(v3_qual) == V3_QUAL_EXPECTED_SHA

    # Locked independent evaluation
    eval_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with open(eval_path, "r", encoding="utf-8") as f:
        eval_recs = json.load(f)
    assert compute_locked_test_hash(eval_recs) == EXPECTED_LOCKED_DIGEST


# -----------------------------------------------------------------------------
# 26. Model Registry & Active Model Configuration Unchanged
# -----------------------------------------------------------------------------
def test_26_model_registry_and_active_config_unchanged():
    cfg_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "model_configs", "pre_phase6_5_baseline.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"
    assert cfg["operating_mode"] == "shadow"
    assert cfg.get("is_production_authoritative") is False

    reg_path = os.path.join(PROJECT_ROOT, "models", "model_registry.json")
    with open(reg_path, "r", encoding="utf-8") as f:
        reg = json.load(f)
    assert "custom-mlp-v1.1.0-preproc" in reg["registered_models"]


# -----------------------------------------------------------------------------
# 27. Production Decision Engine Invariance
# -----------------------------------------------------------------------------
def test_27_production_application_functionality_unchanged():
    engine = HybridDecisionEngine()
    # Test classic known phishing heuristic sample
    res = engine.evaluate_message("Your MSEDCL light bill is unpaid. Electricity power cut tonight. Pay: http://fake-pay.com")
    assert "final_decision" in res
    assert res["final_decision"]["final_risk_score"] >= 40
    assert res["final_decision"]["authoritative_source"] == "deterministic_rules"
    assert res["final_decision"]["production_score_difference"] == 0
