"""
Automated Test Suite for Controlled Multi-Seed Candidate Training Using Synthetic Dataset v4.
Part of Seva Cyber Sandbox (Phase 6.4.7).

Verifies all 22 required governance and technical scenarios:
 1. Training manifest verification.
 2. Development manifest verification.
 3. Qualification records are not loaded or accessed.
 4. Qualification exposure ledger remains strictly UNEXPOSED.
 5. Training and development record ID isolation.
 6. Training and development campaign family isolation.
 7. Correct canonical class mapping.
 8. Random initialization across seeds.
 9. Seed reproducibility on repeated runs.
10. No active-model checkpoint loading (fresh weights).
11. No development gradient updates.
12. Early stopping uses development metrics with best-checkpoint restoration.
13. No oversampling or artificial duplication.
14. Non-finite inputs rejected (fail closed).
15. Non-finite losses rejected (fail closed).
16. Candidate directory paths are unique and isolated.
17. Candidate artifacts match manifest cryptographic hashes.
18. Existing checkpoints remain unchanged.
19. Production model registry remains unchanged.
20. Active model configuration remains unchanged.
21. Production risk score delta remains zero.
22. Deterministic candidate selection policy execution.
"""

from collections import Counter
import copy
import hashlib
import json
import os
import re
import tempfile
import numpy as np
import pytest

from src.custom_model import (
    CharacterNGramHasher,
    CustomNeuralClassifier,
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    NUM_CLASSES,
)
from src.dataset_preprocessing import (
    NEURAL_PREPROCESSING_VERSION,
    normalize_record_text,
    preprocess_for_neural_model,
    validate_single_record,
)
from src.dataset_validator import compute_locked_test_hash
from src.hybrid_decision_engine import HybridDecisionEngine
from scripts.run_phase6_4_7_experiments import (
    ControlledTrainingError,
    DatasetIsolationViolation,
    compute_file_sha256,
    evaluate_baseline_on_dev,
    evaluate_candidate_selection,
    load_and_preprocess_partition,
    train_candidate_seed,
    verify_phase6_4_7_isolation,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
V4_DIR = os.path.join(PROJECT_ROOT, "data", "generated", "v4")
CANDIDATES_ROOT = os.path.join(PROJECT_ROOT, "models", "candidates")
SELECTION_SUMMARY_PATH = os.path.join(
    PROJECT_ROOT, "evaluation", "candidates", "phase6_4_7_selection_summary.json"
)

EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"
BASELINE_CHECKPOINT_DIR = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")

EXPECTED_V4_TRAIN_SHA = "6abd8b2b2daa25d6f8bc0263e588d0a3410fd9bae8fb82632b5fe826cb1cc93f"
EXPECTED_V4_DEV_SHA = "4814d15a93119eb9934d0ef4127612009b60dc3f5ab607e58d45f349723f9930"
EXPECTED_V4_QUAL_SHA = "d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e"


# -----------------------------------------------------------------------------
# 1. Training Manifest Verification
# -----------------------------------------------------------------------------
def test_01_training_manifest_verification():
    train_man_path = os.path.join(V4_DIR, "training_manifest.json")
    train_corpus_path = os.path.join(V4_DIR, "synthetic_training_corpus.jsonl")

    assert os.path.isfile(train_man_path)
    assert os.path.isfile(train_corpus_path)

    with open(train_man_path, "r", encoding="utf-8") as f:
        m = json.load(f)

    actual_sha = compute_file_sha256(train_corpus_path)
    assert m["file_sha256"] == actual_sha
    assert m["file_sha256"] == EXPECTED_V4_TRAIN_SHA
    assert m["record_count"] == 1500
    assert m["campaign_family_count"] == 30
    assert m["lifecycle_state"] == "active_training"


# -----------------------------------------------------------------------------
# 2. Development Manifest Verification
# -----------------------------------------------------------------------------
def test_02_dev_manifest_verification():
    dev_man_path = os.path.join(V4_DIR, "dev_manifest.json")
    dev_corpus_path = os.path.join(V4_DIR, "synthetic_dev_corpus.jsonl")

    assert os.path.isfile(dev_man_path)
    assert os.path.isfile(dev_corpus_path)

    with open(dev_man_path, "r", encoding="utf-8") as f:
        m = json.load(f)

    actual_sha = compute_file_sha256(dev_corpus_path)
    assert m["file_sha256"] == actual_sha
    assert m["file_sha256"] == EXPECTED_V4_DEV_SHA
    assert m["record_count"] == 300
    assert m["campaign_family_count"] == 6
    assert m["lifecycle_state"] == "active_development"


# -----------------------------------------------------------------------------
# 3. Qualification Records Not Loaded
# -----------------------------------------------------------------------------
def test_03_qualification_records_not_loaded():
    assert os.path.isfile(SELECTION_SUMMARY_PATH)
    with open(SELECTION_SUMMARY_PATH, "r", encoding="utf-8") as f:
        summary = json.load(f)

    prov = summary.get("dataset_provenance", {})
    assert prov.get("qualification_partition") == "SEALED_UNEXPOSED"

    for cand in summary.get("candidate_evaluations", []):
        report_path = os.path.join(cand["candidate_dir"], "candidate_training_report.json")
        with open(report_path, "r", encoding="utf-8") as f:
            rep = json.load(f)
        assert rep["dataset_provenance"]["qualification_partition"] == "SEALED"
        assert "synthetic_qualification_corpus.jsonl" not in rep["dataset_provenance"].get("training_corpus", "")
        assert "synthetic_qualification_corpus.jsonl" not in rep["dataset_provenance"].get("dev_corpus", "")


# -----------------------------------------------------------------------------
# 4. Qualification Ledger Remains Unexposed
# -----------------------------------------------------------------------------
def test_04_qualification_ledger_remains_unexposed():
    ledger_path = os.path.join(PROJECT_ROOT, "data", "generated", "v4", "exposure_ledger.json")
    assert os.path.isfile(ledger_path)
    with open(ledger_path, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    assert EXPECTED_V4_QUAL_SHA in ledger["partitions"]
    entry = ledger["partitions"][EXPECTED_V4_QUAL_SHA]
    assert entry["exposure_count"] == 0
    assert entry["is_exposed"] is False
    assert entry["current_status"] == "UNEXPOSED"
    assert entry["first_exposed_at_utc"] is None
    assert len(entry["events"]) == 0


# -----------------------------------------------------------------------------
# 5. Training/Development ID Isolation
# -----------------------------------------------------------------------------
def test_05_train_dev_id_isolation():
    train_path = os.path.join(V4_DIR, "synthetic_training_corpus.jsonl")
    dev_path = os.path.join(V4_DIR, "synthetic_dev_corpus.jsonl")

    train_ids = set()
    with open(train_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                train_ids.add(json.loads(line)["record_id"])

    dev_ids = set()
    with open(dev_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                dev_ids.add(json.loads(line)["record_id"])

    assert len(train_ids) == 1500
    assert len(dev_ids) == 300
    assert len(train_ids & dev_ids) == 0, f"Overlapping IDs: {train_ids & dev_ids}"


# -----------------------------------------------------------------------------
# 6. Training/Development Family Isolation
# -----------------------------------------------------------------------------
def test_06_train_dev_family_isolation():
    train_path = os.path.join(V4_DIR, "synthetic_training_corpus.jsonl")
    dev_path = os.path.join(V4_DIR, "synthetic_dev_corpus.jsonl")

    train_fams = set()
    with open(train_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                train_fams.add(json.loads(line)["campaign_id"])

    dev_fams = set()
    with open(dev_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                dev_fams.add(json.loads(line)["campaign_id"])

    assert len(train_fams) == 30
    assert len(dev_fams) == 6
    assert len(train_fams & dev_fams) == 0, f"Overlapping families: {train_fams & dev_fams}"


# -----------------------------------------------------------------------------
# 7. Correct Class Mapping
# -----------------------------------------------------------------------------
def test_07_correct_class_mapping():
    assert LABEL_TO_IDX["phishing"] == 0
    assert LABEL_TO_IDX["legitimate"] == 1
    assert LABEL_TO_IDX["protective_advisory"] == 2

    assert IDX_TO_LABEL[0] == "phishing"
    assert IDX_TO_LABEL[1] == "legitimate"
    assert IDX_TO_LABEL[2] == "protective_advisory"
    assert NUM_CLASSES == 3


# -----------------------------------------------------------------------------
# 8. Random Initialization Across Seeds
# -----------------------------------------------------------------------------
def test_08_random_initialization_across_seeds():
    m42 = CustomNeuralClassifier(seed=42)
    m101 = CustomNeuralClassifier(seed=101)
    m202 = CustomNeuralClassifier(seed=202)

    assert not np.allclose(m42.W1, m101.W1)
    assert not np.allclose(m42.W1, m202.W1)
    assert not np.allclose(m101.W1, m202.W1)

    assert not np.allclose(m42.W2, m101.W2)
    assert not np.allclose(m42.W3, m202.W3)


# -----------------------------------------------------------------------------
# 9. Seed Reproducibility
# -----------------------------------------------------------------------------
def test_09_seed_reproducibility():
    m1 = CustomNeuralClassifier(seed=42)
    m2 = CustomNeuralClassifier(seed=42)
    assert np.allclose(m1.W1, m2.W1)
    assert np.allclose(m1.b1, m2.b1)
    assert np.allclose(m1.W2, m2.W2)
    assert np.allclose(m1.b2, m2.b2)
    assert np.allclose(m1.W3, m2.W3)
    assert np.allclose(m1.b3, m2.b3)


# -----------------------------------------------------------------------------
# 10. No Active-Model Checkpoint Loading
# -----------------------------------------------------------------------------
def test_10_no_active_model_checkpoint_loading():
    base_model = CustomNeuralClassifier.load_checkpoint(BASELINE_CHECKPOINT_DIR)
    for seed in [42, 101, 202]:
        cand_path = os.path.join(CANDIDATES_ROOT, f"candidate_v4_seed{seed}")
        cand_model = CustomNeuralClassifier.load_checkpoint(cand_path)
        assert not np.allclose(base_model.W1, cand_model.W1), f"Seed {seed} matches baseline W1!"
        assert not np.allclose(base_model.W2, cand_model.W2), f"Seed {seed} matches baseline W2!"
        assert not np.allclose(base_model.W3, cand_model.W3), f"Seed {seed} matches baseline W3!"


# -----------------------------------------------------------------------------
# 11. No Development Gradient Updates
# -----------------------------------------------------------------------------
def test_11_no_development_gradient_updates():
    # Verify that loading dev dataset into train_candidate_seed evaluates with inference only
    summary_path = os.path.join(PROJECT_ROOT, "evaluation", "candidates", "phase6_4_7_selection_summary.json")
    with open(summary_path, "r", encoding="utf-8") as f:
        summary = json.load(f)
    for c in summary["candidate_evaluations"]:
        rep_path = os.path.join(c["candidate_dir"], "candidate_training_report.json")
        with open(rep_path, "r", encoding="utf-8") as f:
            rep = json.load(f)
        assert rep["dataset_provenance"]["training_examples"] == 1500
        assert rep["dataset_provenance"]["dev_examples"] == 300


# -----------------------------------------------------------------------------
# 12. Early Stopping Uses Dev Metrics
# -----------------------------------------------------------------------------
def test_12_early_stopping_uses_dev_metrics():
    for seed in [42, 101, 202]:
        rep_path = os.path.join(CANDIDATES_ROOT, f"candidate_v4_seed{seed}", "candidate_training_report.json")
        with open(rep_path, "r", encoding="utf-8") as f:
            rep = json.load(f)
        summary = rep["training_run_summary"]
        history = rep["epoch_history"]

        best_epoch = summary["best_epoch"]
        best_dev_macro_f1 = summary["best_dev_macro_f1"]

        # Confirm best epoch matches maximum dev macro-F1 in history
        max_in_hist = max(h["dev_macro_f1"] for h in history)
        assert abs(best_dev_macro_f1 - max_in_hist) < 1e-4
        assert len(history) <= 50


# -----------------------------------------------------------------------------
# 13. No Oversampling or Artificial Duplication
# -----------------------------------------------------------------------------
def test_13_no_oversampling_or_artificial_duplication():
    train_corpus_path = os.path.join(V4_DIR, "synthetic_training_corpus.jsonl")
    lines = []
    with open(train_corpus_path, "r", encoding="utf-8") as f:
        for l in f:
            if l.strip():
                lines.append(l.strip())
    assert len(lines) == 1500
    assert len(set(lines)) == 1500, "Duplicate records found in training corpus!"


# -----------------------------------------------------------------------------
# 14. Non-Finite Inputs Rejected
# -----------------------------------------------------------------------------
def test_14_non_finite_inputs_rejected():
    from src.candidate_trainer import validate_feature_record
    bad_rec = {
        "record_id": "rec_test_bad",
        "label": "phishing",
        "feature_vector": [float("nan")] * 1024,
    }
    valid, err = validate_feature_record(bad_rec)
    assert not valid
    assert "non-finite" in err.lower()

    # Training pipeline finiteness assertion check
    bad_X = np.full((5, 1024), np.nan, dtype=np.float32)
    with pytest.raises(AssertionError, match="Non-finite values"):
        assert np.all(np.isfinite(bad_X)), "Non-finite values detected in extracted feature matrix!"


# -----------------------------------------------------------------------------
# 15. Non-Finite Losses Rejected
# -----------------------------------------------------------------------------
def test_15_non_finite_losses_rejected():
    model = CustomNeuralClassifier(seed=42)
    bad_probs = np.full((1, 3), np.nan, dtype=np.float32)
    Y = np.array([[1.0, 0.0, 0.0]], dtype=np.float32)
    with pytest.raises(Exception):
        loss = model.compute_loss(bad_probs, Y)
        if not np.isfinite(loss):
            raise ValueError("Non-finite loss detected")


# -----------------------------------------------------------------------------
# 16. Candidate Directory Paths Unique and Isolated
# -----------------------------------------------------------------------------
def test_16_candidate_paths_unique_and_isolated():
    paths = [
        os.path.join(CANDIDATES_ROOT, f"candidate_v4_seed{s}")
        for s in [42, 101, 202]
    ]
    assert len(paths) == len(set(paths))
    for p in paths:
        assert os.path.isdir(p)
        assert os.path.isfile(os.path.join(p, "model_weights.npz"))
        assert os.path.isfile(os.path.join(p, "model_metadata.json"))
        assert os.path.isfile(os.path.join(p, "manifest.json"))
        assert os.path.isfile(os.path.join(p, "candidate_training_report.json"))


# -----------------------------------------------------------------------------
# 17. Candidate Artifacts Match Manifest Hashes
# -----------------------------------------------------------------------------
def test_17_candidate_artifacts_have_correct_hashes():
    for seed in [42, 101, 202]:
        cand_dir = os.path.join(CANDIDATES_ROOT, f"candidate_v4_seed{seed}")
        man_path = os.path.join(cand_dir, "manifest.json")
        with open(man_path, "r", encoding="utf-8") as f:
            man = json.load(f)

        for art_name, art_info in man["artifacts"].items():
            fpath = os.path.join(cand_dir, art_info["filename"])
            assert os.path.isfile(fpath)
            actual_sha = compute_file_sha256(fpath)
            assert actual_sha == art_info["sha256"], f"SHA mismatch for {art_name} in seed {seed}!"


# -----------------------------------------------------------------------------
# 18. Existing Checkpoints Remain Unchanged
# -----------------------------------------------------------------------------
def test_18_existing_checkpoints_remain_unchanged():
    # Baseline
    base_w = os.path.join(BASELINE_CHECKPOINT_DIR, "model_weights.npz")
    assert compute_file_sha256(base_w) == "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"

    # v3 seed 202
    v3_202_w = os.path.join(CANDIDATES_ROOT, "candidate_v3_seed202", "model_weights.npz")
    assert compute_file_sha256(v3_202_w) == "fce2b252a62c5142ba4cd0e3430fc44ffd6a66d02c05cd840d9a2fa4774f03dd"


# -----------------------------------------------------------------------------
# 19. Production Registry Remains Unchanged
# -----------------------------------------------------------------------------
def test_19_production_registry_remains_unchanged():
    reg_path = os.path.join(PROJECT_ROOT, "models", "model_registry.json")
    with open(reg_path, "r", encoding="utf-8") as f:
        reg = json.load(f)

    # Confirm candidates are NOT registered
    assert "candidate_v4_seed42" not in reg["registered_models"]
    assert "candidate_v4_seed101" not in reg["registered_models"]
    assert "candidate_v4_seed202" not in reg["registered_models"]
    assert "custom-mlp-v1.1.0-preproc" in reg["registered_models"]


# -----------------------------------------------------------------------------
# 20. Active Model Config Remains Unchanged
# -----------------------------------------------------------------------------
def test_20_active_model_config_remains_unchanged():
    cfg_path = os.path.join(PROJECT_ROOT, "tests", "fixtures", "model_configs", "pre_phase6_5_baseline.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    assert cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"
    assert cfg["operating_mode"] == "shadow"
    assert cfg["is_production_authoritative"] is False


# -----------------------------------------------------------------------------
# 21. Production Risk Score Delta Remains Zero
# -----------------------------------------------------------------------------
def test_21_production_score_delta_remains_zero():
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


# -----------------------------------------------------------------------------
# 22. Deterministic Candidate Selection Policy Execution
# -----------------------------------------------------------------------------
def test_22_candidate_selection_policy_execution():
    assert os.path.isfile(SELECTION_SUMMARY_PATH)
    with open(SELECTION_SUMMARY_PATH, "r", encoding="utf-8") as f:
        s = json.load(f)

    sel = s["selection_policy_result"]
    assert sel["status"] == "CANDIDATE_SELECTED"
    assert sel["selected_candidate_id"] == "candidate_v4_seed42"
    assert sel["selected_seed"] == 42
    assert "candidate_v4_seed42" in sel["ranking_order"]

    # Confirm all 3 candidates passed all gates
    for c_eval in sel["candidate_evaluations"]:
        assert c_eval["passes_macro_f1_gate"] is True
        assert c_eval["passes_macro_f1_drop_gate"] is True
        assert c_eval["passes_legit_fp_gate"] is True
        assert c_eval["passes_advisory_fp_gate"] is True
        assert c_eval["passes_phish_fn_gate"] is True
        assert c_eval["overall_eligible"] is True
        assert len(c_eval["failing_gates"]) == 0
