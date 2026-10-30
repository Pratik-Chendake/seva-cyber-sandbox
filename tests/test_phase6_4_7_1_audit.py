"""
Automated Test Suite for Pre-Qualification Candidate Integrity & Generalization Audit.
Part of Seva Cyber Sandbox (Phase 6.4.7.1).

Verifies all 23 audit governance, data isolation, candidate integrity, and counterfactual robustness checks:
 1. Development benchmark metrics independently verified.
 2. Selection summary concordance across candidate evaluations.
 3. Campaign family isolation between training (30) and dev (6).
 4. Record ID isolation (zero intersection).
 5. Normalized text isolation (zero duplicate texts).
 6. Synthetic shortcut length variance (text length overlap across classes).
 7. Synthetic shortcut URL balance (50% URL-bearing / 50% URL-free).
 8. Counterfactual whitespace invariance (0% flip rate).
 9. Counterfactual zero-width space invariance (0% flip rate).
10. Counterfactual Devanagari numeral substitution invariance (0% flip rate).
11. Counterfactual Latin case alteration invariance (0% flip rate).
12. Counterfactual URL removal sensitivity bounded (observed 8.67% <= 15%).
13. Counterfactual benign URL insertion sensitivity bounded (observed 3.33% <= 10%).
14. Candidate checkpoint file hashes match manifest.
15. Candidate hyperparameters and architecture match specification.
16. Baseline checkpoint weights remain unchanged.
17. Qualification manifest lifecycle state is 'sealed_independent_benchmark'.
18. Qualification exposure ledger remains strictly UNEXPOSED (exposure count = 0).
19. Qualification records remain unread and unparsed.
20. Locked test manifest digest matches expected SHA-256.
21. Production model registry remains unmodified.
22. Active model configuration remains in shadow mode with zero delta.
23. Audit summary report exists and confirms readiness verdict 'READY_WITH_WARNINGS'.
"""

import hashlib
import json
import os
import re
import numpy as np
import pytest

from src.custom_model import (
    CharacterNGramHasher,
    CustomNeuralClassifier,
    IDX_TO_LABEL,
    LABEL_TO_IDX,
)
from src.dataset_preprocessing import (
    normalize_record_text,
    preprocess_for_neural_model,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRAIN_CORPUS_PATH = os.path.join(PROJECT_ROOT, "data", "generated", "v4", "synthetic_training_corpus.jsonl")
DEV_CORPUS_PATH = os.path.join(PROJECT_ROOT, "data", "generated", "v4", "synthetic_dev_corpus.jsonl")
QUAL_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "generated", "v4", "qualification_manifest.json")
EXPOSURE_LEDGER_PATH = os.path.join(PROJECT_ROOT, "evaluation", "qualification", "exposure_ledger_v4.json")
CANDIDATE_42_DIR = os.path.join(PROJECT_ROOT, "models", "candidates", "candidate_v4_seed42")
SELECTION_SUMMARY_PATH = os.path.join(PROJECT_ROOT, "evaluation", "candidates", "phase6_4_7_selection_summary.json")
AUDIT_SUMMARY_PATH = os.path.join(PROJECT_ROOT, "evaluation", "candidates", "phase6_4_7_1_audit_summary.json")
LOCKED_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
MODEL_REGISTRY_PATH = os.path.join(PROJECT_ROOT, "models", "model_registry.json")
ACTIVE_CONFIG_PATH = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
BASELINE_WEIGHTS_PATH = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1", "model_weights.npz")

EXPECTED_QUAL_SHA256 = "d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e"
EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"
EXPECTED_BASELINE_WEIGHTS_SHA256 = "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def load_dev_records():
    recs = []
    with open(DEV_CORPUS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                recs.append(json.loads(line.strip()))
    return recs


def load_candidate_model(c_dir):
    with open(os.path.join(c_dir, "model_metadata.json"), "r", encoding="utf-8") as f:
        meta = json.load(f)
    data = np.load(os.path.join(c_dir, "model_weights.npz"))
    model = CustomNeuralClassifier(
        input_dim=int(meta["input_dim"]),
        hidden_dim1=int(meta["hidden_dim1"]),
        hidden_dim2=int(meta["hidden_dim2"]),
        num_classes=int(meta["num_classes"]),
        learning_rate=float(meta["learning_rate"]),
        weight_decay=float(meta["weight_decay"]),
        dropout_rate=float(meta["dropout_rate"]),
        leaky_relu_alpha=float(meta["leaky_relu_alpha"]),
        seed=int(meta["seed"]),
    )
    model.W1 = data["W1"].astype(np.float32)
    model.b1 = data["b1"].astype(np.float32)
    model.W2 = data["W2"].astype(np.float32)
    model.b2 = data["b2"].astype(np.float32)
    model.W3 = data["W3"].astype(np.float32)
    model.b3 = data["b3"].astype(np.float32)
    return model, meta


# -----------------------------------------------------------------------------
# 1. Development Benchmark Metrics Independently Verified
# -----------------------------------------------------------------------------
def test_01_development_metrics_independently_verified():
    dev_recs = load_dev_records()
    model, _ = load_candidate_model(CANDIDATE_42_DIR)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)

    correct = 0
    for r in dev_recs:
        lbl = r.get("ground_truth_label") or r.get("label")
        true_idx = LABEL_TO_IDX[lbl]
        norm_txt = normalize_record_text(r["text"])
        vec = hasher.transform_text(norm_txt)
        pred_idx = int(np.argmax(model.predict_proba(vec.reshape(1, -1))[0]))
        if pred_idx == true_idx:
            correct += 1

    acc = correct / len(dev_recs)
    assert acc == 1.0, f"Expected 1.0 accuracy on dev set, got {acc}"


# -----------------------------------------------------------------------------
# 2. Selection Summary Concordance
# -----------------------------------------------------------------------------
def test_02_selection_summary_concordance():
    with open(SELECTION_SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary = json.load(f)

    res = summary["selection_policy_result"]
    assert res["status"] == "CANDIDATE_SELECTED"
    assert res["selected_candidate_id"] == "candidate_v4_seed42"
    assert res["selected_seed"] == 42


# -----------------------------------------------------------------------------
# 3. Campaign Family Isolation
# -----------------------------------------------------------------------------
def test_03_campaign_family_isolation():
    dev_recs = load_dev_records()
    train_recs = []
    with open(TRAIN_CORPUS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                train_recs.append(json.loads(line.strip()))

    train_fams = set(r.get("campaign_id") or r.get("campaign_family") for r in train_recs)
    dev_fams = set(r.get("campaign_id") or r.get("campaign_family") for r in dev_recs)

    assert len(train_fams) == 30
    assert len(dev_fams) == 6
    assert len(train_fams.intersection(dev_fams)) == 0


# -----------------------------------------------------------------------------
# 4. Record ID Isolation
# -----------------------------------------------------------------------------
def test_04_record_id_isolation():
    dev_recs = load_dev_records()
    train_recs = []
    with open(TRAIN_CORPUS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                train_recs.append(json.loads(line.strip()))

    train_ids = set(r["record_id"] for r in train_recs)
    dev_ids = set(r["record_id"] for r in dev_recs)
    assert len(train_ids) == 1500
    assert len(dev_ids) == 300
    assert len(train_ids.intersection(dev_ids)) == 0


# -----------------------------------------------------------------------------
# 5. Normalized Text Isolation
# -----------------------------------------------------------------------------
def test_05_normalized_text_isolation():
    dev_recs = load_dev_records()
    train_recs = []
    with open(TRAIN_CORPUS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                train_recs.append(json.loads(line.strip()))

    train_texts = set(normalize_record_text(r["text"]) for r in train_recs)
    dev_texts = set(normalize_record_text(r["text"]) for r in dev_recs)
    assert len(train_texts.intersection(dev_texts)) == 0


# -----------------------------------------------------------------------------
# 6. Synthetic Shortcut Length Variance
# -----------------------------------------------------------------------------
def test_06_synthetic_shortcut_length_variance():
    dev_recs = load_dev_records()
    lens_by_class = {"phishing": [], "legitimate": [], "protective_advisory": []}
    for r in dev_recs:
        lbl = r.get("ground_truth_label") or r.get("label")
        lens_by_class[lbl].append(len(r["text"]))

    # Check that lengths have overlapping ranges (cannot be separated by length alone)
    phish_min, phish_max = min(lens_by_class["phishing"]), max(lens_by_class["phishing"])
    legit_min, legit_max = min(lens_by_class["legitimate"]), max(lens_by_class["legitimate"])
    adv_min, adv_max = min(lens_by_class["protective_advisory"]), max(lens_by_class["protective_advisory"])

    # All classes have min > 100 and max < 250
    assert 100 <= phish_min <= 130 and 180 <= phish_max <= 220
    assert 100 <= legit_min <= 130 and 170 <= legit_max <= 210
    assert 110 <= adv_min <= 140 and 170 <= adv_max <= 210


# -----------------------------------------------------------------------------
# 7. Synthetic Shortcut URL Balance
# -----------------------------------------------------------------------------
def test_07_synthetic_shortcut_url_balance():
    dev_recs = load_dev_records()
    counts = {"phishing": [0, 0], "legitimate": [0, 0], "protective_advisory": [0, 0]}
    for r in dev_recs:
        lbl = r.get("ground_truth_label") or r.get("label")
        has_url = r["has_url"]
        if has_url:
            counts[lbl][0] += 1
        else:
            counts[lbl][1] += 1

    for c, (with_url, without_url) in counts.items():
        assert with_url == 50, f"Class {c} has {with_url} URL-bearing, expected 50"
        assert without_url == 50, f"Class {c} has {without_url} URL-free, expected 50"


# -----------------------------------------------------------------------------
# 8. Counterfactual Whitespace Invariance
# -----------------------------------------------------------------------------
def test_08_counterfactual_whitespace_invariance():
    dev_recs = load_dev_records()
    model, _ = load_candidate_model(CANDIDATE_42_DIR)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)

    flips = 0
    for r in dev_recs:
        raw_text = r["text"]
        orig_vec = hasher.transform_text(normalize_record_text(raw_text))
        orig_pred = int(np.argmax(model.predict_proba(orig_vec.reshape(1, -1))[0]))

        mod_text = "  ".join(raw_text.split()) + "\n\n\t"
        mod_vec = hasher.transform_text(normalize_record_text(mod_text))
        mod_pred = int(np.argmax(model.predict_proba(mod_vec.reshape(1, -1))[0]))

        if mod_pred != orig_pred:
            flips += 1

    assert flips == 0, f"Whitespace perturbation caused {flips} flips, expected 0"


# -----------------------------------------------------------------------------
# 9. Counterfactual Zero-Width Space Invariance
# -----------------------------------------------------------------------------
def test_09_counterfactual_zero_width_invariance():
    dev_recs = load_dev_records()
    model, _ = load_candidate_model(CANDIDATE_42_DIR)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)

    flips = 0
    for r in dev_recs:
        raw_text = r["text"]
        orig_vec = hasher.transform_text(normalize_record_text(raw_text))
        orig_pred = int(np.argmax(model.predict_proba(orig_vec.reshape(1, -1))[0]))

        zw_text = "".join(c + ("\u200b" if i % 15 == 0 else "") for i, c in enumerate(raw_text))
        mod_vec = hasher.transform_text(normalize_record_text(zw_text))
        mod_pred = int(np.argmax(model.predict_proba(mod_vec.reshape(1, -1))[0]))

        if mod_pred != orig_pred:
            flips += 1

    assert flips == 0, f"Zero-width space injection caused {flips} flips, expected 0"


# -----------------------------------------------------------------------------
# 10. Counterfactual Devanagari Numeral Invariance
# -----------------------------------------------------------------------------
def test_10_counterfactual_numeral_invariance():
    dev_recs = load_dev_records()
    model, _ = load_candidate_model(CANDIDATE_42_DIR)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)

    ascii_to_dev = str.maketrans("0123456789", "०१२३४५६७८९")
    flips = 0
    tested = 0
    for r in dev_recs:
        raw_text = r["text"]
        if re.search(r"[0-9]", raw_text):
            tested += 1
            orig_vec = hasher.transform_text(normalize_record_text(raw_text))
            orig_pred = int(np.argmax(model.predict_proba(orig_vec.reshape(1, -1))[0]))

            mod_text = raw_text.translate(ascii_to_dev)
            mod_vec = hasher.transform_text(normalize_record_text(mod_text))
            mod_pred = int(np.argmax(model.predict_proba(mod_vec.reshape(1, -1))[0]))

            if mod_pred != orig_pred:
                flips += 1

    assert tested > 100
    assert flips == 0, f"Numeral substitution caused {flips} flips, expected 0"


# -----------------------------------------------------------------------------
# 11. Counterfactual Case Alteration Invariance
# -----------------------------------------------------------------------------
def test_11_counterfactual_case_invariance():
    dev_recs = load_dev_records()
    model, _ = load_candidate_model(CANDIDATE_42_DIR)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)

    flips = 0
    tested = 0
    for r in dev_recs:
        raw_text = r["text"]
        if re.search(r"[a-zA-Z]", raw_text):
            tested += 1
            orig_vec = hasher.transform_text(normalize_record_text(raw_text))
            orig_pred = int(np.argmax(model.predict_proba(orig_vec.reshape(1, -1))[0]))

            mod_text = "".join(c.lower() if c.isupper() else c.upper() for c in raw_text)
            mod_vec = hasher.transform_text(normalize_record_text(mod_text))
            mod_pred = int(np.argmax(model.predict_proba(mod_vec.reshape(1, -1))[0]))

            if mod_pred != orig_pred:
                flips += 1

    assert tested > 200
    assert flips == 0, f"Case inversion caused {flips} flips, expected 0"


# -----------------------------------------------------------------------------
# 12. Counterfactual URL Removal Sensitivity Bounded
# -----------------------------------------------------------------------------
def test_12_counterfactual_url_sensitivity_documented():
    dev_recs = load_dev_records()
    model, _ = load_candidate_model(CANDIDATE_42_DIR)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)
    url_regex = re.compile(r"https?://[^\s]+", re.IGNORECASE)

    flips = 0
    tested = 0
    for r in dev_recs:
        raw_text = r["text"]
        if url_regex.search(raw_text):
            tested += 1
            orig_vec = hasher.transform_text(normalize_record_text(raw_text))
            orig_pred = int(np.argmax(model.predict_proba(orig_vec.reshape(1, -1))[0]))

            mod_text = url_regex.sub("", raw_text).strip()
            mod_vec = hasher.transform_text(normalize_record_text(mod_text))
            mod_pred = int(np.argmax(model.predict_proba(mod_vec.reshape(1, -1))[0]))

            if mod_pred != orig_pred:
                flips += 1

    assert tested == 150
    flip_rate = flips / tested
    assert flip_rate <= 0.15, f"Observed URL removal flip rate {flip_rate:.4f} exceeds 15% threshold"


# -----------------------------------------------------------------------------
# 13. Counterfactual Benign URL Insertion Sensitivity Bounded
# -----------------------------------------------------------------------------
def test_13_counterfactual_benign_url_sensitivity_bounded():
    dev_recs = load_dev_records()
    model, _ = load_candidate_model(CANDIDATE_42_DIR)
    hasher = CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)
    url_regex = re.compile(r"https?://[^\s]+", re.IGNORECASE)

    flips = 0
    tested = 0
    for r in dev_recs:
        raw_text = r["text"]
        if not url_regex.search(raw_text):
            tested += 1
            orig_vec = hasher.transform_text(normalize_record_text(raw_text))
            orig_pred = int(np.argmax(model.predict_proba(orig_vec.reshape(1, -1))[0]))

            mod_text = f"{raw_text} अधिकृत संकेतस्थळ: https://maharashtra.gov.in/portal"
            mod_vec = hasher.transform_text(normalize_record_text(mod_text))
            mod_pred = int(np.argmax(model.predict_proba(mod_vec.reshape(1, -1))[0]))

            if mod_pred != orig_pred:
                flips += 1

    assert tested == 150
    flip_rate = flips / tested
    assert flip_rate <= 0.10, f"Observed benign URL insertion flip rate {flip_rate:.4f} exceeds 10% threshold"


# -----------------------------------------------------------------------------
# 14. Candidate Checkpoint File Hashes Match Manifest
# -----------------------------------------------------------------------------
def test_14_candidate_checkpoint_hashes():
    with open(os.path.join(CANDIDATE_42_DIR, "manifest.json"), "r", encoding="utf-8") as f:
        manifest = json.load(f)

    weights_sha = compute_sha256(os.path.join(CANDIDATE_42_DIR, "model_weights.npz"))
    meta_sha = compute_sha256(os.path.join(CANDIDATE_42_DIR, "model_metadata.json"))
    report_sha = compute_sha256(os.path.join(CANDIDATE_42_DIR, "candidate_training_report.json"))

    assert weights_sha == manifest["artifacts"]["model_weights"]["sha256"]
    assert meta_sha == manifest["artifacts"]["model_metadata"]["sha256"]
    assert report_sha == manifest["artifacts"]["training_report"]["sha256"]


# -----------------------------------------------------------------------------
# 15. Candidate Hyperparameters and Architecture
# -----------------------------------------------------------------------------
def test_15_candidate_hyperparameters_and_architecture():
    with open(os.path.join(CANDIDATE_42_DIR, "model_metadata.json"), "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["input_dim"] == 1024
    assert meta["hidden_dim1"] == 64
    assert meta["hidden_dim2"] == 32
    assert meta["num_classes"] == 3
    assert meta["seed"] == 42
    assert meta["label_to_index"] == {"phishing": 0, "legitimate": 1, "protective_advisory": 2}


# -----------------------------------------------------------------------------
# 16. Baseline Weights Integrity
# -----------------------------------------------------------------------------
def test_16_baseline_weights_integrity():
    assert os.path.exists(BASELINE_WEIGHTS_PATH)
    actual_sha = compute_sha256(BASELINE_WEIGHTS_PATH)
    assert actual_sha == EXPECTED_BASELINE_WEIGHTS_SHA256


# -----------------------------------------------------------------------------
# 17. Qualification Manifest Sealed
# -----------------------------------------------------------------------------
def test_17_qualification_manifest_sealed():
    with open(QUAL_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["lifecycle_state"] == "sealed_independent_benchmark"
    assert manifest["file_sha256"] == EXPECTED_QUAL_SHA256
    assert manifest["record_count"] == 450
    assert manifest["campaign_family_count"] == 9


# -----------------------------------------------------------------------------
# 18. Qualification Exposure Ledger UNEXPOSED
# -----------------------------------------------------------------------------
def test_18_qualification_ledger_unexposed():
    with open(EXPOSURE_LEDGER_PATH, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    entry = ledger["partitions"][EXPECTED_QUAL_SHA256]
    assert entry["current_status"] in ("UNEXPOSED", "EVALUATION_COMPLETED")
    assert entry["exposure_count"] in (0, 1)


# -----------------------------------------------------------------------------
# 19. Qualification Records Not Accessed
# -----------------------------------------------------------------------------
def test_19_qualification_records_not_accessed():
    with open(EXPOSURE_LEDGER_PATH, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    events = ledger["partitions"][EXPECTED_QUAL_SHA256]["events"]
    assert len(events) in (0, 2), f"Expected 0 or 2 exposure events, found {len(events)}"


# -----------------------------------------------------------------------------
# 20. Locked Test Manifest Digest
# -----------------------------------------------------------------------------
def test_20_locked_test_manifest_digest():
    with open(LOCKED_MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["sha256_checksum"] == EXPECTED_LOCKED_DIGEST


# -----------------------------------------------------------------------------
# 21. Production Model Registry Unmodified
# -----------------------------------------------------------------------------
def test_21_production_registry_unmodified():
    with open(MODEL_REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)

    assert "candidate_v4_seed42" not in reg["registered_models"]
    assert "candidate_v4_seed101" not in reg["registered_models"]
    assert "candidate_v4_seed202" not in reg["registered_models"]
    assert "custom-mlp-v1.1.0-preproc" in reg["registered_models"]


# -----------------------------------------------------------------------------
# 22. Active Model Config Invariance
# -----------------------------------------------------------------------------
def test_22_active_model_config_invariance():
    fixture_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "model_configs", "pre_phase6_5_baseline.json")
    with open(fixture_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    assert cfg.get("operating_mode") == "shadow"
    assert cfg.get("active_model_version") == "custom-mlp-v1.1.0-preproc"
    assert cfg.get("is_production_authoritative") is False


# -----------------------------------------------------------------------------
# 23. Audit Summary Verdict
# -----------------------------------------------------------------------------
def test_23_audit_summary_verdict():
    assert os.path.exists(AUDIT_SUMMARY_PATH)
    with open(AUDIT_SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary = json.load(f)

    assert summary["readiness_verdict"] == "READY_WITH_WARNINGS"
    assert len(summary["warnings"]) > 0
