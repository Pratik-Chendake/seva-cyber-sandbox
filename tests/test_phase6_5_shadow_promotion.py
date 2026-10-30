"""
Automated Test Suite for Controlled Shadow-Mode Model Registration and Rollback.
Part of Seva Cyber Sandbox (Phase 6.5).

Verifies all 25 governance, integrity, safety, and operational rollback requirements:
 1. Candidate qualification evidence verification (Phase 6.4.8 PASS, all gates passed).
 2. Candidate checkpoint hash verification.
 3. Candidate metadata hash verification.
 4. Candidate manifest verification.
 5. Immutable candidate artifact preservation.
 6. Safe registry registration with full provenance.
 7. Existing version collision rejection (fails closed on overwrite attempt).
 8. Approved-for-shadow lifecycle enforcement (unapproved states cannot be activated).
 9. No production-authoritative status assigned.
10. Correct shadow-model configuration.
11. Deterministic risk scoring unchanged.
12. Production score delta remains exactly zero across all classes.
13. Shadow inference failure does not disrupt analysis.
14. Missing checkpoint fallback.
15. Corrupt checkpoint fallback.
16. Feature-schema mismatch handling.
17. Rollback to previous shadow model.
18. Invalid rollback target rejection (fails closed, preserves current valid config).
19. Atomic configuration writes via temporary file replacement.
20. Audit trail creation for all lifecycle events.
21. Privacy-safe diagnostics (coarse length bucket, event ID, non-linkable).
22. No raw text or PII in telemetry.
23. Shadow disable control (rules_only toggle preserves deterministic detection).
24. Existing deterministic rules remain fully functional.
25. Qualification dataset and exposure ledger remain sealed/unmodified.
"""

import copy
import hashlib
import json
import os
import shutil
import tempfile
import numpy as np
import pytest

from src.custom_model import (
    CustomNeuralClassifier,
    CharacterNGramHasher,
    IDX_TO_LABEL,
    LABEL_TO_IDX,
)
from src.dataset_preprocessing import preprocess_for_neural_model
from src.hybrid_decision_engine import (
    HybridDecisionEngine,
    HybridOperatingMode,
    SafeModelHolder,
)
from src.model_registry import (
    ModelRegistry,
    ModelLifecycleState,
    ModelRegistryError,
    ModelIntegrityError,
    ModelNotFoundError,
    ModelRegistryConflictError,
    get_default_model_registry,
    compute_file_sha256,
)
from src.rollback_controller import RollbackController
from src.shadow_controller import ShadowMonitorController

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CANDIDATE_ID = "candidate_v4_seed42"
CANDIDATE_DIR = os.path.join(PROJECT_ROOT, "models", "candidates", CANDIDATE_ID)
BASELINE_DIR = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")
QUAL_REPORT_PATH = os.path.join(PROJECT_ROOT, "docs", "PHASE_6_4_8_FINAL_QUALIFICATION_REPORT.md")
QUAL_JSON_PATH = os.path.join(PROJECT_ROOT, "evaluation", "qualification", f"{CANDIDATE_ID}_qualification.json")
EXPOSURE_LEDGER_PATH = os.path.join(PROJECT_ROOT, "evaluation", "qualification", "exposure_ledger_v4.json")
QUAL_CORPUS_PATH = os.path.join(PROJECT_ROOT, "data", "generated", "v4", "synthetic_qualification_corpus.jsonl")
LOCKED_MANIFEST_PATH = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
MODEL_REGISTRY_PATH = os.path.join(PROJECT_ROOT, "models", "model_registry.json")
ACTIVE_CONFIG_PATH = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")

EXPECTED_CANDIDATE_WEIGHTS_SHA = "3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f"
EXPECTED_CANDIDATE_META_SHA = "8bf388271453b805c148b17232972f6adbe1a4689370893159454b7fe61cafa3"
EXPECTED_CANDIDATE_REPORT_SHA = "c22d6021f15d66860549a2064d846bb44156bbb2cf7ff1d30a03abdf5a64e6c6"
EXPECTED_BASELINE_WEIGHTS_SHA = "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"
EXPECTED_BASELINE_META_SHA = "23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8"
EXPECTED_QUAL_SHA256 = "d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e"
EXPECTED_LOCKED_DIGEST = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"


# -----------------------------------------------------------------------------
# 1. Candidate Qualification Evidence Verification
# -----------------------------------------------------------------------------
def test_01_candidate_qualification_evidence_verification():
    assert os.path.isfile(QUAL_REPORT_PATH), f"Missing qualification report: {QUAL_REPORT_PATH}"
    assert os.path.isfile(QUAL_JSON_PATH), f"Missing qualification JSON: {QUAL_JSON_PATH}"

    with open(QUAL_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["qualification_verdict"] == "PASS"
    assert data["candidate_id"] == CANDIDATE_ID
    assert data["baseline_id"] == "custom-mlp-v1.1.0-preproc"

    # Verify gates
    gate_details = data["benchmark_policy_evaluation"]["gate_details"]
    for gate_name, gate_info in gate_details.items():
        assert gate_info["passed"] is True, f"Gate '{gate_name}' was not passed!"


# -----------------------------------------------------------------------------
# 2. Candidate Checkpoint Hash Verification
# -----------------------------------------------------------------------------
def test_02_candidate_checkpoint_hash_verification():
    weights_path = os.path.join(CANDIDATE_DIR, "model_weights.npz")
    assert os.path.isfile(weights_path)
    actual_sha = compute_file_sha256(weights_path)
    assert actual_sha == EXPECTED_CANDIDATE_WEIGHTS_SHA, f"Candidate weights SHA mismatch: {actual_sha}"


# -----------------------------------------------------------------------------
# 3. Candidate Metadata Hash Verification
# -----------------------------------------------------------------------------
def test_03_candidate_metadata_hash_verification():
    meta_path = os.path.join(CANDIDATE_DIR, "model_metadata.json")
    assert os.path.isfile(meta_path)
    actual_sha = compute_file_sha256(meta_path)
    assert actual_sha == EXPECTED_CANDIDATE_META_SHA, f"Candidate metadata SHA mismatch: {actual_sha}"


# -----------------------------------------------------------------------------
# 4. Candidate Manifest Verification
# -----------------------------------------------------------------------------
def test_04_candidate_manifest_verification():
    manifest_path = os.path.join(CANDIDATE_DIR, "manifest.json")
    assert os.path.isfile(manifest_path)
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["candidate_id"] == CANDIDATE_ID
    assert manifest["artifacts"]["model_weights"]["sha256"] == EXPECTED_CANDIDATE_WEIGHTS_SHA
    assert manifest["artifacts"]["model_metadata"]["sha256"] == EXPECTED_CANDIDATE_META_SHA
    assert manifest["artifacts"]["training_report"]["sha256"] == EXPECTED_CANDIDATE_REPORT_SHA


# -----------------------------------------------------------------------------
# 5. Immutable Candidate Artifact Preservation
# -----------------------------------------------------------------------------
def test_05_immutable_candidate_artifact_preservation():
    # Recompute all files in candidate dir to ensure no accidental mutations
    weights_sha = compute_file_sha256(os.path.join(CANDIDATE_DIR, "model_weights.npz"))
    meta_sha = compute_file_sha256(os.path.join(CANDIDATE_DIR, "model_metadata.json"))
    report_sha = compute_file_sha256(os.path.join(CANDIDATE_DIR, "candidate_training_report.json"))

    assert weights_sha == EXPECTED_CANDIDATE_WEIGHTS_SHA
    assert meta_sha == EXPECTED_CANDIDATE_META_SHA
    assert report_sha == EXPECTED_CANDIDATE_REPORT_SHA


# -----------------------------------------------------------------------------
# 6. Safe Registry Registration
# -----------------------------------------------------------------------------
def test_06_safe_registry_registration():
    reg = get_default_model_registry()
    entry = reg.get_model("custom-mlp-v4.0.0-seed42")

    assert entry["model_version"] == "custom-mlp-v4.0.0-seed42"
    assert entry["lifecycle_state"] == "approved_for_shadow"
    assert entry["weights_sha256"] == EXPECTED_CANDIDATE_WEIGHTS_SHA
    assert entry["metadata_sha256"] == EXPECTED_CANDIDATE_META_SHA
    assert entry["candidate_id"] == CANDIDATE_ID
    assert "PHASE_6_4_8_FINAL_QUALIFICATION_REPORT.md" in entry.get("qualification_report_ref", "")
    assert entry.get("qualification_provenance", {}).get("qualification_verdict") == "PASS"


# -----------------------------------------------------------------------------
# 7. Existing Version Collision Rejection
# -----------------------------------------------------------------------------
def test_07_existing_version_collision_rejection(tmp_path):
    # Setup temporary isolated registry
    temp_models_dir = tmp_path / "models"
    temp_models_dir.mkdir(parents=True)
    temp_ckpt_dir = temp_models_dir / "test_ckpt"
    temp_ckpt_dir.mkdir()

    # Create dummy checkpoint
    np.savez(temp_ckpt_dir / "model_weights.npz", W1=np.zeros((10, 5)), b1=np.zeros((1, 5)))
    (temp_ckpt_dir / "model_metadata.json").write_text(json.dumps({
        "model_version": "v1.0", "input_dim": 10, "hidden_dim1": 5, "hidden_dim2": 3, "num_classes": 3,
        "learning_rate": 0.01, "weight_decay": 0.0001, "seed": 42
    }), encoding="utf-8")

    reg = ModelRegistry(project_root=str(tmp_path), models_dir="models")
    reg.register_model(
        model_version="immutable-test-v1",
        architecture_version="test-arch",
        checkpoint_rel_path="models/test_ckpt",
        preprocessing_version="neural-preproc-v1.1.0",
    )

    # Modify checkpoint weights in a new dir to simulate differing collision
    other_ckpt_dir = temp_models_dir / "other_ckpt"
    other_ckpt_dir.mkdir()
    np.savez(other_ckpt_dir / "model_weights.npz", W1=np.ones((10, 5)), b1=np.ones((1, 5)))
    (other_ckpt_dir / "model_metadata.json").write_text(json.dumps({
        "model_version": "v1.0", "input_dim": 10, "hidden_dim1": 5, "hidden_dim2": 3, "num_classes": 3,
        "learning_rate": 0.01, "weight_decay": 0.0001, "seed": 42
    }), encoding="utf-8")

    with pytest.raises(ModelRegistryConflictError):
        reg.register_model(
            model_version="immutable-test-v1",
            architecture_version="test-arch",
            checkpoint_rel_path="models/other_ckpt",
            preprocessing_version="neural-preproc-v1.1.0",
        )


# -----------------------------------------------------------------------------
# 8. Approved-for-Shadow Lifecycle Enforcement
# -----------------------------------------------------------------------------
def test_08_approved_for_shadow_lifecycle_enforcement(tmp_path):
    temp_models_dir = tmp_path / "models"
    temp_models_dir.mkdir(parents=True)
    temp_ckpt_dir = temp_models_dir / "test_ckpt"
    temp_ckpt_dir.mkdir()

    np.savez(temp_ckpt_dir / "model_weights.npz", W1=np.zeros((10, 5)), b1=np.zeros((1, 5)))
    (temp_ckpt_dir / "model_metadata.json").write_text(json.dumps({
        "model_version": "v1.0", "input_dim": 10, "hidden_dim1": 5, "hidden_dim2": 3, "num_classes": 3,
        "learning_rate": 0.01, "weight_decay": 0.0001, "seed": 42
    }), encoding="utf-8")

    reg = ModelRegistry(project_root=str(tmp_path), models_dir="models")
    reg.register_model(
        model_version="retired-model-v1",
        architecture_version="test-arch",
        checkpoint_rel_path="models/test_ckpt",
        preprocessing_version="neural-preproc-v1.1.0",
        lifecycle_state=ModelLifecycleState.RETIRED,
    )

    with pytest.raises(ModelRegistryError, match="Cannot activate model"):
        reg.activate_model("retired-model-v1")


# -----------------------------------------------------------------------------
# 9. No Production-Authoritative Status Assigned
# -----------------------------------------------------------------------------
def test_09_no_production_authoritative_status():
    reg = get_default_model_registry()
    entry = reg.get_model("custom-mlp-v4.0.0-seed42")
    assert entry.get("is_production_authoritative") is False

    active_cfg = reg.get_active_model_config()
    assert active_cfg.get("is_production_authoritative") is False
    assert active_cfg.get("operating_mode") == "shadow"


# -----------------------------------------------------------------------------
# 10. Correct Shadow-Model Configuration
# -----------------------------------------------------------------------------
def test_10_correct_shadow_model_configuration():
    reg = get_default_model_registry()
    cfg = reg.get_active_model_config()

    assert cfg.get("active_model_version") == "custom-mlp-v4.0.0-seed42"
    assert cfg.get("last_known_good_version") == "custom-mlp-v1.1.0-preproc"
    assert cfg.get("operating_mode") == "shadow"
    assert "models/candidates/candidate_v4_seed42" in cfg.get("checkpoint_rel_path", "")
    assert cfg.get("is_production_authoritative") is False


# -----------------------------------------------------------------------------
# 11. Deterministic Risk Scoring Unchanged
# -----------------------------------------------------------------------------
def test_11_deterministic_risk_scoring_unchanged():
    engine = HybridDecisionEngine()
    test_message = "MSEDCL Alert: Light bill unpaid. Pay immediately or power cut at 9 PM: http://bit.ly/msedcl-fake"

    eval_result = engine.evaluate_message(test_message)
    rule_score = eval_result["rule_based_evidence"]["score"]
    final_score = eval_result["final_decision"]["final_risk_score"]

    assert final_score == rule_score
    assert eval_result["final_decision"]["authoritative_source"] == "deterministic_rules"


# -----------------------------------------------------------------------------
# 12. Production Score Delta Remains Exactly Zero
# -----------------------------------------------------------------------------
def test_12_production_score_delta_remains_zero():
    engine = HybridDecisionEngine()
    messages = [
        "आपले वीज बिल प्रलंबित आहे, आजच भरा.",
        "Bank of Maharashtra Alert: Update your PAN card to prevent account freeze: http://phish.xyz",
        "Official Police Notice: Cyber safety awareness regarding online arrest scams. Do not pay any fine via video call.",
        "Trade license renewal reminder for municipal ward 4.",
        "   ",  # Empty
    ]

    for msg in messages:
        res = engine.evaluate_message(msg)
        assert res["final_decision"]["production_score_difference"] == 0, (
            f"Production score delta non-zero for message: '{msg}'"
        )


# -----------------------------------------------------------------------------
# 13. Shadow Inference Failure Does Not Disrupt Analysis
# -----------------------------------------------------------------------------
def test_13_shadow_inference_failure_does_not_disrupt_analysis(monkeypatch):
    engine = HybridDecisionEngine()

    def mock_predict_safe(text):
        return {
            "is_enabled": True,
            "is_available": False,
            "predicted_label": None,
            "predicted_index": None,
            "confidence": 0.0,
            "confidence_scores": None,
            "model_version": None,
            "fallback_reason": "Simulated hardware error",
            "confidence_warning": "Fallback to rules applied.",
        }

    monkeypatch.setattr(engine.model_holder, "predict_safe", mock_predict_safe)
    res = engine.evaluate_message("Test message under mocked model failure.")

    assert res["final_decision"]["final_risk_score"] is not None
    assert any("GR-07" in g for g in res["final_decision"]["guardrails_applied"])
    assert res["final_decision"]["production_score_difference"] == 0


# -----------------------------------------------------------------------------
# 14. Missing Checkpoint Fallback
# -----------------------------------------------------------------------------
def test_14_missing_checkpoint_fallback():
    holder = SafeModelHolder(checkpoint_dir="models/non_existent_directory_99999")
    pred = holder.predict_safe("Test input")

    assert pred["is_available"] is False
    assert pred["predicted_label"] is None
    assert "missing" in pred["fallback_reason"].lower() or "not found" in pred["fallback_reason"].lower() or "security" in pred["fallback_reason"].lower()


# -----------------------------------------------------------------------------
# 15. Corrupt Checkpoint Fallback
# -----------------------------------------------------------------------------
def test_15_corrupt_checkpoint_fallback(tmp_path):
    corrupt_dir = tmp_path / "models" / "corrupt_ckpt"
    corrupt_dir.mkdir(parents=True)
    (corrupt_dir / "model_weights.npz").write_text("NOT_A_VALID_NPZ_FILE", encoding="utf-8")
    (corrupt_dir / "model_metadata.json").write_text(json.dumps({
        "model_version": "corrupt-v1", "input_dim": 1024, "hidden_dim1": 64, "hidden_dim2": 32, "num_classes": 3
    }), encoding="utf-8")

    holder = SafeModelHolder(checkpoint_dir=str(corrupt_dir))
    pred = holder.predict_safe("Test message")

    assert pred["is_available"] is False
    assert pred["predicted_label"] is None


# -----------------------------------------------------------------------------
# 16. Feature-Schema Mismatch Handling
# -----------------------------------------------------------------------------
def test_16_feature_schema_mismatch_handling(tmp_path):
    mismatch_dir = tmp_path / "models" / "mismatch_ckpt"
    mismatch_dir.mkdir(parents=True)

    # Save weights with 512 dimensions instead of 1024
    np.savez(mismatch_dir / "model_weights.npz",
             W1=np.zeros((512, 64)), b1=np.zeros((1, 64)),
             W2=np.zeros((64, 32)), b2=np.zeros((1, 32)),
             W3=np.zeros((32, 3)), b3=np.zeros((1, 3)))
    (mismatch_dir / "model_metadata.json").write_text(json.dumps({
        "model_version": "mismatch-v1", "input_dim": 512, "hidden_dim1": 64, "hidden_dim2": 32, "num_classes": 3,
        "learning_rate": 0.01, "weight_decay": 0.0001, "dropout_rate": 0.2, "leaky_relu_alpha": 0.01, "seed": 42
    }), encoding="utf-8")

    holder = SafeModelHolder(checkpoint_dir=str(mismatch_dir))
    pred = holder.predict_safe("Test message")
    # Should catch mismatch during loading or self-test
    assert pred["is_available"] is False or pred["predicted_label"] is None


# -----------------------------------------------------------------------------
# 17. Rollback to Previous Shadow Model
# -----------------------------------------------------------------------------
def test_17_rollback_to_previous_shadow_model(tmp_path):
    # Use isolated test directory to guarantee live workspace config is never mutated
    temp_models_dir = tmp_path / "models"
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(temp_models_dir))
    reg = ModelRegistry(project_root=str(tmp_path))
    rbc = RollbackController(registry=reg)
    status = rbc.get_rollback_status()

    assert status["can_rollback"] is True
    assert status["target_rollback_version"] == "custom-mlp-v1.1.0-preproc"

    # Execute rollback in isolated directory
    rb_cfg = rbc.execute_rollback(operator_label="test_suite", reason="Unit test rollback")
    assert rb_cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"
    assert rb_cfg["last_known_good_version"] == "custom-mlp-v4.0.0-seed42"

    # Verify live active_model_config.json was NOT mutated
    live_cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    with open(live_cfg_path, "r", encoding="utf-8") as f:
        live_cfg = json.load(f)
    assert live_cfg["active_model_version"] == "custom-mlp-v4.0.0-seed42"
    assert live_cfg["operating_mode"] == "shadow"


# -----------------------------------------------------------------------------
# 18. Invalid Rollback Target Rejection
# -----------------------------------------------------------------------------
def test_18_invalid_rollback_target_rejection(tmp_path):
    temp_models_dir = tmp_path / "models"
    temp_models_dir.mkdir(parents=True)

    reg = ModelRegistry(project_root=str(tmp_path), models_dir="models")
    # Active config with non-existent LKG target
    cfg = {
        "active_model_version": "active-v1",
        "last_known_good_version": "ghost-model-v999",
        "operating_mode": "shadow",
        "checkpoint_rel_path": "models/active_v1",
        "is_production_authoritative": False,
    }
    reg._save_json_atomic(reg.active_config_path, cfg)

    rbc = RollbackController(registry=reg)
    status = rbc.get_rollback_status()
    assert status["can_rollback"] is False
    assert "not registered" in status["validation_message"]

    with pytest.raises(ModelRegistryError):
        rbc.execute_rollback()

    # Verify active config was NOT corrupted or overwritten
    cur_cfg = reg.get_active_model_config()
    assert cur_cfg["active_model_version"] == "active-v1"


# -----------------------------------------------------------------------------
# 19. Atomic Rollback Configuration Writes
# -----------------------------------------------------------------------------
def test_19_atomic_rollback_configuration_writes(tmp_path):
    test_json = tmp_path / "atomic_test.json"
    reg = get_default_model_registry()

    data = {"test_key": "initial_value", "version": 1}
    reg._save_json_atomic(str(test_json), data)

    with open(test_json, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["test_key"] == "initial_value"

    # Update atomically
    data["test_key"] = "updated_value"
    reg._save_json_atomic(str(test_json), data)

    with open(test_json, "r", encoding="utf-8") as f:
        loaded2 = json.load(f)
    assert loaded2["test_key"] == "updated_value"


# -----------------------------------------------------------------------------
# 20. Audit Trail Creation
# -----------------------------------------------------------------------------
def test_20_audit_trail_creation():
    reg = get_default_model_registry()
    log = reg.get_audit_log(limit=50)

    actions = {e["action"] for e in log}
    assert "REGISTER_MODEL" in actions
    assert "ACTIVATE_DIAGNOSTIC_MODEL" in actions


# -----------------------------------------------------------------------------
# 21. Privacy-Safe Diagnostics
# -----------------------------------------------------------------------------
def test_21_privacy_safe_diagnostics():
    engine = HybridDecisionEngine()
    sensitive_msg = "Aadhaar 1234-5678-9012 OTP 987654 sent to phone 9876543210. Pay fine immediately."
    eval_res = engine.evaluate_message(sensitive_msg)

    audit = eval_res["audit_metadata"]
    assert "diagnostic_event_id" in audit
    assert audit["diagnostic_event_id"].startswith("EVT-")
    assert "length_bucket" in audit
    assert "medium" in audit["length_bucket"] or "short" in audit["length_bucket"]

    # Telemetry should NOT contain raw strings
    audit_str = json.dumps(audit)
    assert "1234-5678-9012" not in audit_str
    assert "987654" not in audit_str
    assert "9876543210" not in audit_str


# -----------------------------------------------------------------------------
# 22. No Raw Text in Telemetry
# -----------------------------------------------------------------------------
def test_22_no_raw_text_in_telemetry(tmp_path):
    smc = ShadowMonitorController(metrics_file_path=str(tmp_path / "test_metrics.json"))
    engine = HybridDecisionEngine()

    sensitive_text = "CONFIDENTIAL_CITIZEN_COMPLAINT_TEXT_SECRET_XYZ"
    res = engine.evaluate_message(sensitive_text)
    smc.record_inference_telemetry(res)

    with open(smc.metrics_path, "r", encoding="utf-8") as f:
        metrics_content = f.read()

    assert sensitive_text not in metrics_content
    assert "SECRET" not in metrics_content


# -----------------------------------------------------------------------------
# 23. Shadow Disable Control
# -----------------------------------------------------------------------------
def test_23_shadow_disable_control(tmp_path):
    # Use isolated test directory to guarantee live workspace config is never mutated
    temp_models_dir = tmp_path / "models"
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(temp_models_dir))
    temp_metrics = tmp_path / "shadow_metrics.json"
    reg = ModelRegistry(project_root=str(tmp_path))
    smc = ShadowMonitorController(registry=reg, metrics_file_path=str(temp_metrics))

    # Disable shadow diagnostics in isolated configuration
    new_cfg = smc.disable_shadow_inference(operator_label="test_suite")
    assert new_cfg["operating_mode"] == "rules_only"

    # Evaluate message while disabled using isolated registry
    engine = HybridDecisionEngine(model_registry=reg)
    res = engine.evaluate_message("Test message while shadow disabled.")
    assert res["operating_mode"] == "rules_only"
    assert res["experimental_model"]["is_enabled"] is False
    assert res["final_decision"]["final_risk_score"] is not None

    # Re-enable shadow diagnostics
    re_cfg = smc.enable_shadow_inference(operator_label="test_suite")
    assert re_cfg["operating_mode"] == "shadow"

    # Verify live active_model_config.json was NOT mutated
    live_cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    with open(live_cfg_path, "r", encoding="utf-8") as f:
        live_cfg = json.load(f)
    assert live_cfg["active_model_version"] == "custom-mlp-v4.0.0-seed42"
    assert live_cfg["operating_mode"] == "shadow"


# -----------------------------------------------------------------------------
# 24. Existing Deterministic Rules Remain Functional
# -----------------------------------------------------------------------------
def test_24_existing_deterministic_rules_remain_functional():
    engine = HybridDecisionEngine()

    # Rule 1: High severity impersonation / urgent phishing
    scam_msg = "MSEDCL Alert: Light bill unpaid. Immediate power cut tonight. Pay bill at: http://bit.ly/pay-msedcl"
    res1 = engine.evaluate_message(scam_msg)
    assert res1["rule_based_evidence"]["score"] >= 20

    # Rule 2: Legitimate civic message
    legit_msg = "Gram Panchayat water supply maintenance schedule for ward 3 tomorrow."
    res2 = engine.evaluate_message(legit_msg)
    assert res2["rule_based_evidence"]["rule_label"] == "legitimate"


# -----------------------------------------------------------------------------
# 25. Qualification Dataset Not Accessed or Modified
# -----------------------------------------------------------------------------
def test_25_qualification_dataset_not_accessed_or_modified():
    assert os.path.isfile(QUAL_CORPUS_PATH)
    actual_qual_sha = compute_file_sha256(QUAL_CORPUS_PATH)
    assert actual_qual_sha == EXPECTED_QUAL_SHA256, "Qualification partition corpus was modified!"

    with open(EXPOSURE_LEDGER_PATH, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    entry = ledger["partitions"][EXPECTED_QUAL_SHA256]
    assert entry["current_status"] == "EVALUATION_COMPLETED"
    assert entry["exposure_count"] == 1
    assert entry["is_exposed"] is True
