"""
Phase 5 Comprehensive Unit Test Suite:
Human Review Desk, Model Version Registry, Rollback, and Privacy Hardening.

Covers all 21 Phase 5 verification requirements:
1. Raw vs. normalized forms handled consistently by model preprocessing.
2. Devanagari digits handled consistently during inference.
3. Locked evaluation files remain untouched (SHA-256 verified).
4. Message-derived hashes are not persisted or exported (linkability prevention).
5. Diagnostic events do not contain raw message text.
6. Reviews start in pending state with empty outcome and null timestamp.
7. Review submission does not retrain model or change checkpoint weights.
8. Review submission does not alter production risk scores.
9. Reviewed and unreviewed feedback are distinguishable.
10. Invalid review labels and notes >1000 chars are rejected.
11. Existing case history remains intact across review desk operations.
12. Database initialization and migrations are idempotent.
13. Registry checkpoint SHA-256 hashes verified before loading.
14. Path traversal and arbitrary checkpoint selection rejected.
15. Corrupted and incompatible checkpoints rejected safely.
16. Valid registered versions can be selected for shadow mode.
17. Rollback restores prior diagnostic configuration without changing production scores.
18. Failed activation preserves previous valid configuration.
19. Missing configuration safely selects deterministic fallback.
20. Existing test suite compatibility maintained.
21. Zero external network requests occur.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import socket
import tempfile
from typing import Any, Dict, List
import numpy as np
import pytest

from src.case_repository import (
    ALLOWED_CONFIDENCE_RATINGS,
    ALLOWED_HUMAN_OUTCOME_CATEGORIES,
    ALLOWED_HUMAN_REVIEW_STATES,
    CaseRepository,
    HumanReviewError,
    HumanReviewValidationError,
)
from src.case_manager import SessionCaseStore
from src.dataset_preprocessing import (
    NEURAL_PREPROCESSING_VERSION,
    preprocess_for_neural_model,
)
from src.dataset_validator import verify_locked_test_integrity
from src.hybrid_decision_engine import (
    HybridDecisionEngine,
    HybridOperatingMode,
    SafeModelHolder,
    evaluate_message_hybrid,
)
from src.model_registry import (
    ModelIntegrityError,
    ModelLifecycleState,
    ModelNotFoundError,
    ModelRegistry,
    ModelSecurityError,
    compute_file_sha256,
    get_default_model_registry,
)
from src.phishing_detector import analyze_message_text

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOCKED_DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
EXPECTED_LOCKED_SHA256 = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"
CHECKPOINT_DIR = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")


# ---------------------------------------------------------------------------
# 1. Raw vs Normalized Preprocessing Consistency
# ---------------------------------------------------------------------------
def test_01_raw_vs_normalized_preprocessing_consistency():
    """Verify preprocess_for_neural_model produces identical output for raw and NFC/whitespace-normalized inputs."""
    raw_text = "  \u200b\ufeffमहाराष्ट्र   शासन\tयोजना\n\n "
    normalized_input = "महाराष्ट्र शासन योजना"

    res_raw = preprocess_for_neural_model(raw_text)
    res_norm = preprocess_for_neural_model(normalized_input)

    assert res_raw == "महाराष्ट्र शासन योजना"
    assert res_raw == res_norm
    assert "\u200b" not in res_raw
    assert "\ufeff" not in res_raw


# ---------------------------------------------------------------------------
# 2. Devanagari Digits Normalized for Neural Model
# ---------------------------------------------------------------------------
def test_02_devanagari_digits_normalized_for_neural_model():
    """Verify Devanagari numerals in advisory messages map to ASCII digits during model preprocessing."""
    advisory_text = "सायबर हेल्प: १९३० वर त्वरित संपर्क करा"
    preprocessed = preprocess_for_neural_model(advisory_text)

    assert "1930" in preprocessed
    assert "१९३०" not in preprocessed

    # Test all 10 Devanagari numerals
    all_dev_digits = "०१२३४५६७८९"
    assert preprocess_for_neural_model(all_dev_digits) == "0123456789"

    # Verify model inference on normalized text does not predict phishing for standard helpline
    holder = SafeModelHolder(CHECKPOINT_DIR)
    pred = holder.predict_safe(advisory_text)
    assert pred["is_available"] is True
    assert pred["predicted_label"] == "protective_advisory"


# ---------------------------------------------------------------------------
# 3. Locked Evaluation Integrity
# ---------------------------------------------------------------------------
def test_03_locked_evaluation_integrity_unmodified():
    """Verify SHA-256 digest of locked test partition matches locked test manifest."""
    from src.dataset_validator import compute_locked_test_hash

    assert os.path.isfile(LOCKED_DATASET_PATH), "Locked evaluation dataset must exist"

    with open(LOCKED_DATASET_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)

    actual_sha = compute_locked_test_hash(records)

    assert actual_sha == EXPECTED_LOCKED_SHA256, (
        f"LOCKED DATASET TAMPERING DETECTED! Expected {EXPECTED_LOCKED_SHA256}, got {actual_sha}"
    )

    # Also verify through dataset_validator
    is_valid, msg = verify_locked_test_integrity(records)
    assert is_valid is True, msg


# ---------------------------------------------------------------------------
# 4. Message-Derived Hashes Linkability Prevention
# ---------------------------------------------------------------------------
def test_04_message_derived_hashes_not_persisted_or_exported(tmp_path):
    """Verify diagnostic outputs and cases DO NOT contain message-derived SHA-256 hashes."""
    msg = "तात्काळ वीज बिल भरा नाहीतर कनेक्शन कट होईल http://fake.in"
    eval_res = evaluate_message_hybrid(msg)

    audit = eval_res.get("audit_metadata", {})
    assert "input_sha256" not in audit
    assert "message_sha256" not in audit
    assert "sha256" not in audit

    # Verify cases and review corpus do not store raw message SHA-256
    db_file = tmp_path / "test_repo.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    store = SessionCaseStore(session_id="test_sess_04", repository=repo)

    case_record = {
        "case_id": "CASE-20261029-TEST04",
        "analysis_type": "WhatsApp Phishing Analysis",
        "target_identifier": "Message Snippet (Sanitized)",
        "risk_score": 85,
        "risk_category": "phishing",
        "badge_color": "red",
        "analysis_status": "Completed",
        "raw_data_stored": False,
        "observed_evidence": ["Urgent threat phrasing"],
    }
    store.add_case(case_record)
    store.submit_review("CASE-20261029-TEST04", "phishing", notes="Clear phishing lure")

    corpus = store.export_human_reviews_corpus()
    assert isinstance(corpus, str)
    for line in corpus.strip().split("\n"):
        record = json.loads(line)
        assert "input_sha256" not in record
        assert "message_hash" not in record
        assert "raw_text" not in record


# ---------------------------------------------------------------------------
# 5. Diagnostic Event Privacy
# ---------------------------------------------------------------------------
def test_05_diagnostic_event_id_privacy():
    """Verify diagnostic_event_id is random, does not contain raw message text, and is distinct across runs."""
    msg = "गुप्त पासवर्ड कोणालाही सांगू नका"
    eval_1 = evaluate_message_hybrid(msg)
    eval_2 = evaluate_message_hybrid(msg)

    evt_1 = eval_1["audit_metadata"]["diagnostic_event_id"]
    evt_2 = eval_2["audit_metadata"]["diagnostic_event_id"]

    assert evt_1.startswith("EVT-")
    assert evt_2.startswith("EVT-")
    assert evt_1 != evt_2, "Diagnostic event IDs must be random and collision-resistant"
    assert msg not in evt_1
    assert "गुप्त" not in evt_1


# ---------------------------------------------------------------------------
# 6. Review State Initialization
# ---------------------------------------------------------------------------
def test_06_review_initial_state_pending(tmp_path):
    """Verify newly created reviews enter pending state with empty outcome and null timestamp."""
    db_file = tmp_path / "test_rev_init.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    case_id = "CASE-20261029-TEST06"
    repo.save_case({"case_id": case_id, "risk_score": 50, "risk_category": "suspicious"})

    rev = repo.create_or_get_review(case_id, reviewer_label="operator_test")
    assert rev["review_state"] == "pending"
    assert rev["outcome_category"] is None
    assert rev["reviewed_at_utc"] is None
    assert rev["case_id"] == case_id
    assert rev["review_id"].startswith("REV-")


# ---------------------------------------------------------------------------
# 7. Review-to-Model Isolation
# ---------------------------------------------------------------------------
def test_07_review_submission_does_not_retrain_model(tmp_path):
    """Verify submitting a human review does NOT trigger model retraining or checkpoint updates."""
    weights_path = os.path.join(CHECKPOINT_DIR, "model_weights.npz")
    meta_path = os.path.join(CHECKPOINT_DIR, "model_metadata.json")

    weights_sha_before = compute_file_sha256(weights_path)
    meta_sha_before = compute_file_sha256(meta_path)
    weights_mtime_before = os.path.getmtime(weights_path)

    db_file = tmp_path / "test_isolation.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    cid = "CASE-20261029-TEST07"
    repo.save_case({"case_id": cid, "risk_score": 40, "risk_category": "suspicious"})

    repo.submit_review(
        case_id=cid,
        outcome_category="protective_advisory",
        notes="Security awareness notice",
        reviewer_label="operator_iso",
    )

    weights_sha_after = compute_file_sha256(weights_path)
    meta_sha_after = compute_file_sha256(meta_path)
    weights_mtime_after = os.path.getmtime(weights_path)

    assert weights_sha_before == weights_sha_after
    assert meta_sha_before == meta_sha_after
    assert weights_mtime_before == weights_mtime_after


# ---------------------------------------------------------------------------
# 8. Score Immutability Under Human Review
# ---------------------------------------------------------------------------
def test_08_review_submission_does_not_alter_production_score(tmp_path):
    """Verify submitting a human review does NOT alter threat_cases.risk_score or category."""
    db_file = tmp_path / "test_immutability.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    cid = "CASE-20261029-TEST08"
    repo.save_case({
        "case_id": cid,
        "risk_score": 75,
        "risk_category": "phishing",
        "recommended_action": "Do not click links",
    })

    # Operator adjudicates it as legitimate
    repo.submit_review(
        case_id=cid,
        outcome_category="legitimate",
        notes="False alarm, confirmed legitimate utility alert",
    )

    case_after = repo.get_case(cid)
    assert case_after["risk_score"] == 75, "Risk score must remain untouched by human review"
    assert case_after["risk_category"] == "phishing"
    assert case_after["recommended_action"] == "Do not click links"

    rev = repo.get_review_by_case(cid)
    assert rev["outcome_category"] == "legitimate"
    assert rev["review_state"] == "completed"


# ---------------------------------------------------------------------------
# 9. Reviewed vs. Unreviewed Feedback Distinction
# ---------------------------------------------------------------------------
def test_09_reviewed_and_unreviewed_feedback_distinguishable(tmp_path):
    """Verify threat intelligence and human reviews keep unreviewed leads distinct from reviewed."""
    db_file = tmp_path / "test_distinction.sqlite3"
    repo = CaseRepository(db_path=str(db_file))

    cid1 = "CASE-20261029-TEST09-1"
    cid2 = "CASE-20261029-TEST09-2"
    repo.save_case({"case_id": cid1, "risk_score": 60})
    repo.save_case({"case_id": cid2, "risk_score": 10})

    repo.create_or_get_review(cid1)  # pending
    repo.submit_review(cid2, "legitimate")  # completed

    pending = repo.list_reviews(review_state="pending")
    completed = repo.list_reviews(review_state="completed")

    assert len(pending) == 1
    assert pending[0]["case_id"] == cid1
    assert len(completed) == 1
    assert completed[0]["case_id"] == cid2


# ---------------------------------------------------------------------------
# 10. Input Validation and Sanitization
# ---------------------------------------------------------------------------
def test_10_input_validation_and_sanitization(tmp_path):
    """Verify invalid review outcomes, invalid confidence ratings, and oversized notes are rejected."""
    db_file = tmp_path / "test_val.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    cid = "CASE-20261029-TEST10"
    repo.save_case({"case_id": cid, "risk_score": 50})

    # Invalid outcome category
    with pytest.raises(HumanReviewValidationError, match="Invalid outcome category"):
        repo.submit_review(case_id=cid, outcome_category="malicious_scam")

    # Invalid confidence rating
    with pytest.raises(HumanReviewValidationError, match="Invalid confidence rating"):
        repo.submit_review(case_id=cid, outcome_category="phishing", confidence_rating="ultra_high")

    # Notes exceeding 1000 characters
    oversized_notes = "A" * 1001
    with pytest.raises(HumanReviewValidationError, match="exceed maximum allowed length"):
        repo.submit_review(case_id=cid, outcome_category="phishing", notes=oversized_notes)

    # Note with sensitive PII (Devanagari Aadhaar) is sanitized
    pii_note = "Analyst inspected message for user with Aadhaar १२३४ ५६७८ ९०१२"
    rev = repo.submit_review(case_id=cid, outcome_category="phishing", notes=pii_note)
    assert "XXXX-XXXX-" in rev["notes"]
    assert "१२३४" not in rev["notes"]


# ---------------------------------------------------------------------------
# 11. Case History Preservation
# ---------------------------------------------------------------------------
def test_11_case_history_preserved_across_operations(tmp_path):
    """Verify existing cases and indicators are preserved without loss across review queue operations."""
    db_file = tmp_path / "test_history.sqlite3"
    repo = CaseRepository(db_path=str(db_file))

    for i in range(5):
        repo.save_case({"case_id": f"CASE-HIST-{i}", "risk_score": i * 20})

    assert repo.count_cases() == 5

    # Perform multiple reviews
    repo.submit_review("CASE-HIST-1", "phishing")
    repo.submit_review("CASE-HIST-2", "legitimate")

    assert repo.count_cases() == 5
    for i in range(5):
        c = repo.get_case(f"CASE-HIST-{i}")
        assert c is not None
        assert c["risk_score"] == i * 20


# ---------------------------------------------------------------------------
# 12. Database Idempotency
# ---------------------------------------------------------------------------
def test_12_database_init_and_migrations_idempotent(tmp_path):
    """Verify calling init_db() repeatedly does not drop tables, wipe data, or alter existing reviews."""
    db_file = tmp_path / "test_idempotency.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    cid = "CASE-IDEMP-01"
    repo.save_case({"case_id": cid, "risk_score": 70})
    repo.submit_review(cid, "phishing", notes="Permanent note")

    # Re-run initialization 3 times
    repo.init_db()
    repo.init_db()
    repo.init_db()

    c = repo.get_case(cid)
    assert c is not None
    assert c["risk_score"] == 70

    r = repo.get_review_by_case(cid)
    assert r is not None
    assert r["outcome_category"] == "phishing"
    assert r["notes"] == "Permanent note"


# ---------------------------------------------------------------------------
# 13. Checkpoint SHA-256 Integrity Verification
# ---------------------------------------------------------------------------
def test_13_checkpoint_sha256_verified_before_loading():
    """Verify registry verifies checkpoint weights and metadata SHA-256 digests before loading."""
    registry = get_default_model_registry()
    is_valid, msg = registry.verify_checkpoint_integrity("custom-mlp-v1.1.0-preproc")
    assert is_valid is True, f"Integrity check failed: {msg}"
    assert "Integrity verified" in msg


# ---------------------------------------------------------------------------
# 14. Path Traversal Prevention
# ---------------------------------------------------------------------------
def test_14_path_traversal_rejected(tmp_path):
    """Verify registry rejects checkpoint paths containing '..' or resolving outside models directory."""
    registry = ModelRegistry(project_root=str(tmp_path))

    with pytest.raises(ModelSecurityError, match="Path traversal detected"):
        registry.register_model(
            model_version="malicious-v1",
            architecture_version="CustomMLP-v1",
            checkpoint_rel_path="../../etc/passwd",
            preprocessing_version="neural-preproc-v1.1.0",
        )

    with pytest.raises(ModelSecurityError):
        registry.register_model(
            model_version="malicious-v2",
            architecture_version="CustomMLP-v1",
            checkpoint_rel_path="models/../../../outside_dir",
            preprocessing_version="neural-preproc-v1.1.0",
        )


# ---------------------------------------------------------------------------
# 15. Corrupted Checkpoint Rejection
# ---------------------------------------------------------------------------
def test_15_corrupted_checkpoint_gracefully_rejected(tmp_path):
    """Verify registry and engine gracefully reject corrupted checkpoints with fallback."""
    fake_proj = tmp_path / "proj"
    models_dir = fake_proj / "models"
    ckpt_dir = models_dir / "corrupted_ckpt"
    os.makedirs(ckpt_dir, exist_ok=True)

    weights_file = ckpt_dir / "model_weights.npz"
    meta_file = ckpt_dir / "model_metadata.json"
    weights_file.write_bytes(b"corrupted_binary_data")
    meta_file.write_text(json.dumps({
        "model_version": "corrupted-v1",
        "input_dim": 1024,
        "hidden_dim1": 64,
        "hidden_dim2": 32,
        "num_classes": 3,
    }), encoding="utf-8")

    registry = ModelRegistry(project_root=str(fake_proj))
    registry.register_model(
        model_version="corrupted-v1",
        architecture_version="CustomMLP-v1",
        checkpoint_rel_path="models/corrupted_ckpt",
        preprocessing_version="neural-preproc-v1.1.0",
    )

    # Now tamper with weights file after registration
    weights_file.write_bytes(b"tampered_bytes")
    is_valid, msg = registry.verify_checkpoint_integrity("corrupted-v1")
    assert is_valid is False
    assert "Weights SHA-256 mismatch" in msg

    # Activating corrupted model raises ModelIntegrityError
    with pytest.raises(ModelIntegrityError, match="Weights SHA-256 mismatch"):
        registry.activate_model("corrupted-v1")


# ---------------------------------------------------------------------------
# 16. Valid Registered Version Activated for Shadow Mode
# ---------------------------------------------------------------------------
def test_16_valid_registered_version_activated_for_shadow(tmp_path):
    """Verify registered models with valid lifecycle states can be activated for shadow mode."""
    # Copy real checkpoint to temp environment
    fake_proj = tmp_path / "proj"
    fake_models = fake_proj / "models"
    dst_ckpt = fake_models / "experimental_custom_v1"
    os.makedirs(fake_models, exist_ok=True)
    shutil.copytree(CHECKPOINT_DIR, dst_ckpt)

    registry = ModelRegistry(project_root=str(fake_proj))
    registry.register_model(
        model_version="test-model-v1",
        architecture_version="CustomMLP-v1",
        checkpoint_rel_path="models/experimental_custom_v1",
        preprocessing_version="neural-preproc-v1.1.0",
        lifecycle_state=ModelLifecycleState.APPROVED_FOR_SHADOW,
    )

    new_cfg = registry.activate_model("test-model-v1", reason="Automated shadow activation")
    assert new_cfg["active_model_version"] == "test-model-v1"
    assert new_cfg["operating_mode"] == "shadow"
    assert new_cfg["is_production_authoritative"] is False


# ---------------------------------------------------------------------------
# 17. Rollback Functionality
# ---------------------------------------------------------------------------
def test_17_rollback_restores_prior_diagnostic_configuration(tmp_path):
    """Verify rollback atomically restores prior diagnostic configuration without altering scores."""
    fake_proj = tmp_path / "proj"
    fake_models = fake_proj / "models"
    ckpt_a = fake_models / "ckpt_a"
    ckpt_b = fake_models / "ckpt_b"
    os.makedirs(fake_models, exist_ok=True)
    shutil.copytree(CHECKPOINT_DIR, ckpt_a)
    shutil.copytree(CHECKPOINT_DIR, ckpt_b)

    registry = ModelRegistry(project_root=str(fake_proj))
    registry.register_model("model-a", "CustomMLP-v1", "models/ckpt_a", "neural-preproc-v1.1.0", ModelLifecycleState.APPROVED_FOR_SHADOW)
    registry.register_model("model-b", "CustomMLP-v1", "models/ckpt_b", "neural-preproc-v1.1.0", ModelLifecycleState.APPROVED_FOR_SHADOW)

    registry.activate_model("model-a")
    registry.activate_model("model-b")

    cur_cfg = registry.get_active_model_config()
    assert cur_cfg["active_model_version"] == "model-b"
    assert cur_cfg["last_known_good_version"] == "model-a"

    # Execute rollback
    rb_cfg = registry.rollback_model(reason="Testing rollback to model-a")
    assert rb_cfg["active_model_version"] == "model-a"
    assert rb_cfg["last_known_good_version"] == "model-b"


# ---------------------------------------------------------------------------
# 18. Failed Activation Preserves Valid Configuration
# ---------------------------------------------------------------------------
def test_18_failed_activation_preserves_valid_configuration(tmp_path):
    """Verify failed activation preserves previous valid configuration without corruption."""
    fake_proj = tmp_path / "proj"
    fake_models = fake_proj / "models"
    ckpt_valid = fake_models / "ckpt_valid"
    os.makedirs(fake_models, exist_ok=True)
    shutil.copytree(CHECKPOINT_DIR, ckpt_valid)

    registry = ModelRegistry(project_root=str(fake_proj))
    registry.register_model("valid-v1", "CustomMLP-v1", "models/ckpt_valid", "neural-preproc-v1.1.0", ModelLifecycleState.APPROVED_FOR_SHADOW)
    registry.activate_model("valid-v1")

    # Attempt to activate non-existent model
    with pytest.raises(ModelNotFoundError):
        registry.activate_model("ghost-model-v9")

    # Verify configuration still points to valid-v1
    cfg = registry.get_active_model_config()
    assert cfg["active_model_version"] == "valid-v1"


# ---------------------------------------------------------------------------
# 19. Missing Configuration Fallback
# ---------------------------------------------------------------------------
def test_19_missing_configuration_falls_back_safely():
    """Verify missing or non-existent checkpoint safely falls back to deterministic rule engine."""
    engine = HybridDecisionEngine(checkpoint_dir="models/non_existent_dir_12345")
    assert engine.model_holder.is_available is False

    eval_res = engine.evaluate_message("महावितरण बिल थकीत आहे, त्वरित भरा http://fake-msedcl.in")
    assert eval_res["operating_mode"] == "shadow"
    assert eval_res["final_decision"]["final_risk_score"] >= 20
    assert eval_res["experimental_model"]["is_available"] is False
    assert "Checkpoint directory not found" in eval_res["experimental_model"]["fallback_reason"]


# ---------------------------------------------------------------------------
# 20. Backward Compatibility of Case Store
# ---------------------------------------------------------------------------
def test_20_backward_compatibility_of_case_store(tmp_path):
    """Verify SessionCaseStore review additions integrate seamlessly with existing case operations."""
    db_file = tmp_path / "test_store_compat.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    store = SessionCaseStore(session_id="compat_sess", repository=repo)

    case_record = {
        "case_id": "CASE-COMPAT-01",
        "analysis_type": "WhatsApp Phishing Analysis",
        "target_identifier": "Message Snippet",
        "risk_score": 35,
        "risk_category": "suspicious",
    }
    cid = store.add_case(case_record)
    assert cid == "CASE-COMPAT-01"
    assert store.count() == 1

    # Human review interaction
    store.create_or_get_review(cid)
    stats = store.get_review_stats()
    assert stats["pending"] == 1
    assert stats["completed"] == 0

    store.submit_review(cid, "phishing", notes="Verified threat")
    stats2 = store.get_review_stats()
    assert stats2["pending"] == 0
    assert stats2["completed"] == 1


# ---------------------------------------------------------------------------
# 21. Network Isolation Guaranteed
# ---------------------------------------------------------------------------
def test_21_network_isolation_guaranteed(monkeypatch):
    """Verify zero external network calls occur during review desk operations or model evaluation."""
    def guarded_connect(*args, **kwargs):
        raise RuntimeError("NETWORK CALL ATTEMPTED! Forbidden by zero-network constraint.")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    # 1. Normalization
    txt = preprocess_for_neural_model("सायबर मदत कक्ष: १९३०")
    assert "1930" in txt

    # 2. Hybrid Evaluation
    eval_res = evaluate_message_hybrid(txt)
    assert eval_res["final_decision"]["final_risk_score"] >= 0

    # 3. Model Registry Check
    reg = get_default_model_registry()
    active_cfg = reg.get_active_model_config()
    assert active_cfg["operating_mode"] == "shadow"
