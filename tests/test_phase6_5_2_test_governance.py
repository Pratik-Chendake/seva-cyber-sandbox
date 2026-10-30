"""
Automated Test Suite for Historical Test Isolation and Regression Governance Hardening.
Part of Seva Cyber Sandbox (Phase 6.5.2).

Verifies all governance, test isolation, hermetic execution, and integrity requirements:
 1. Current registered candidate version and provenance (custom-mlp-v4.0.0-seed42).
 2. Current candidate lifecycle state (approved_for_shadow).
 3. Current active configuration operating mode (shadow).
 4. Production-authoritative flag is false (is_production_authoritative == False).
 5. Last-known-good model identity (custom-mlp-v1.1.0-preproc).
 6. Candidate artifact cryptographic integrity (weights and metadata SHA-256).
 7. Deterministic rule scoring authoritativeness and score invariance (score delta = 0.00).
 8. Shadow disable control preserves deterministic detection (rules_only mode).
 9. Rollback controller restores intended previous shadow model in isolated test fixture.
10. Historical fixtures exact assertions isolated from live workspace state.
11. Temporary registry and active configuration isolation via tmp_path.
12. Test-induced production mutation prevention (live configs unmodified across operations).
13. Random telemetry diagnostic event ID verification (EVT-XXXXXXXXXXXX, non-message derived).
14. Corrupt and invalid configuration fail-closed fallback safety.
15. Model artifacts cryptographic preservation across all versions.
16. Locked evaluation manifest digest preservation.
"""

import hashlib
import json
import os
import shutil
import uuid
import pytest
import numpy as np

from src.hybrid_decision_engine import (
    HybridDecisionEngine,
    HybridOperatingMode,
    parse_operating_mode,
)
from src.model_registry import (
    ModelRegistry,
    get_default_model_registry,
    ModelLifecycleState,
    compute_file_sha256,
)
from src.rollback_controller import RollbackController
from src.shadow_controller import ShadowMonitorController

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "tests", "fixtures", "model_configs")

EXPECTED_CANDIDATE_VERSION = "custom-mlp-v4.0.0-seed42"
EXPECTED_BASELINE_VERSION = "custom-mlp-v1.1.0-preproc"
EXPECTED_LKG_VERSION = "custom-mlp-v1.1.0-preproc"

EXPECTED_CANDIDATE_WEIGHTS_SHA = "3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f"
EXPECTED_CANDIDATE_META_SHA = "8bf388271453b805c148b17232972f6adbe1a4689370893159454b7fe61cafa3"
EXPECTED_BASELINE_WEIGHTS_SHA = "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"
EXPECTED_BASELINE_META_SHA = "23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8"

EXPECTED_LOCKED_TEST_HASH = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"


# -----------------------------------------------------------------------------
# 1. Current Registered Candidate Version and Provenance
# -----------------------------------------------------------------------------
def test_01_current_registered_candidate_version_and_provenance():
    reg_path = os.path.join(PROJECT_ROOT, "models", "model_registry.json")
    with open(reg_path, "r", encoding="utf-8") as f:
        reg = json.load(f)

    assert EXPECTED_CANDIDATE_VERSION in reg["registered_models"]
    cand = reg["registered_models"][EXPECTED_CANDIDATE_VERSION]
    assert cand["model_version"] == EXPECTED_CANDIDATE_VERSION
    assert cand["lifecycle_state"] == ModelLifecycleState.APPROVED_FOR_SHADOW.value
    assert cand["is_production_authoritative"] is False
    assert cand["checkpoint_rel_path"] == "models/candidates/candidate_v4_seed42"
    assert cand["preprocessing_version"] == "neural-preproc-v1.1.0"
    assert cand["weights_sha256"] == EXPECTED_CANDIDATE_WEIGHTS_SHA
    assert cand["metadata_sha256"] == EXPECTED_CANDIDATE_META_SHA


# -----------------------------------------------------------------------------
# 2. Current Lifecycle State
# -----------------------------------------------------------------------------
def test_02_current_lifecycle_state():
    reg = get_default_model_registry()
    entry = reg.get_model(EXPECTED_CANDIDATE_VERSION)
    assert entry["lifecycle_state"] == ModelLifecycleState.APPROVED_FOR_SHADOW.value


# -----------------------------------------------------------------------------
# 3. Active Shadow Operating Mode
# -----------------------------------------------------------------------------
def test_03_active_shadow_operating_mode():
    cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    assert cfg["active_model_version"] == EXPECTED_CANDIDATE_VERSION
    assert cfg["operating_mode"] == "shadow"


# -----------------------------------------------------------------------------
# 4. Production-Authoritative Flag is False
# -----------------------------------------------------------------------------
def test_04_production_authoritative_flag_is_false():
    cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    assert cfg["is_production_authoritative"] is False

    reg_path = os.path.join(PROJECT_ROOT, "models", "model_registry.json")
    with open(reg_path, "r", encoding="utf-8") as f:
        reg = json.load(f)
    for model_name, info in reg["registered_models"].items():
        assert info.get("is_production_authoritative") is False, f"Model {model_name} has authoritative flag set!"


# -----------------------------------------------------------------------------
# 5. Last-Known-Good Model Identity
# -----------------------------------------------------------------------------
def test_05_last_known_good_model_identity():
    cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    assert cfg["last_known_good_version"] == EXPECTED_LKG_VERSION


# -----------------------------------------------------------------------------
# 6. Candidate Artifact Cryptographic Integrity
# -----------------------------------------------------------------------------
def test_06_candidate_artifact_hashes():
    cand_dir = os.path.join(PROJECT_ROOT, "models", "candidates", "candidate_v4_seed42")
    w_path = os.path.join(cand_dir, "model_weights.npz")
    m_path = os.path.join(cand_dir, "model_metadata.json")

    assert compute_file_sha256(w_path) == EXPECTED_CANDIDATE_WEIGHTS_SHA
    assert compute_file_sha256(m_path) == EXPECTED_CANDIDATE_META_SHA


# -----------------------------------------------------------------------------
# 7. Deterministic Rule Primacy and Score Invariance
# -----------------------------------------------------------------------------
def test_07_deterministic_rules_authoritative_and_score_invariance():
    engine = HybridDecisionEngine()
    test_cases = [
        ("MSEDCL: Your electricity will be disconnected tonight. Pay immediately at http://msedcl-bill.fake", "phishing"),
        ("Namaskar, your monthly bank account statement is ready for review.", "legitimate"),
        ("Cyber Police Advisory: Do not attend Skype video calls claiming digital arrest or CBI warrant.", "protective_advisory"),
    ]

    for text, expected_category in test_cases:
        res = engine.evaluate_message(text)

        # Production scoring delta must be exactly 0.00
        assert res["final_decision"]["production_score_difference"] == 0
        assert "deterministic_rules" in res["final_decision"]["authoritative_source"]
        assert res["operating_mode"] == "shadow"
        assert res["experimental_model"]["is_enabled"] is True


# -----------------------------------------------------------------------------
# 8. Shadow Disable Preserves Deterministic Detection
# -----------------------------------------------------------------------------
def test_08_shadow_disable_preserves_deterministic_detection(tmp_path):
    temp_models_dir = tmp_path / "models"
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(temp_models_dir))
    reg = ModelRegistry(project_root=str(tmp_path))
    smc = ShadowMonitorController(registry=reg, metrics_file_path=str(tmp_path / "metrics.json"))

    # Disable shadow mode
    new_cfg = smc.disable_shadow_inference(operator_label="gov_test")
    assert new_cfg["operating_mode"] == "rules_only"

    # Evaluate with rules_only mode
    engine = HybridDecisionEngine(model_registry=reg)
    res = engine.evaluate_message("MSEDCL: Light bill unpaid. Pay at http://fake.com")
    assert res["operating_mode"] == "rules_only"
    assert res["experimental_model"]["is_enabled"] is False
    assert res["final_decision"]["final_risk_score"] > 0.0


# -----------------------------------------------------------------------------
# 9. Rollback Restores Intended Previous Shadow Model
# -----------------------------------------------------------------------------
def test_09_rollback_restores_intended_previous_shadow_model(tmp_path):
    temp_models_dir = tmp_path / "models"
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(temp_models_dir))
    reg = ModelRegistry(project_root=str(tmp_path))
    rbc = RollbackController(registry=reg)

    status = rbc.get_rollback_status()
    assert status["can_rollback"] is True
    assert status["target_rollback_version"] == EXPECTED_BASELINE_VERSION

    rb_res = rbc.execute_rollback(operator_label="gov_test", reason="Testing governance rollback")
    assert rb_res["active_model_version"] == EXPECTED_BASELINE_VERSION
    assert rb_res["last_known_good_version"] == EXPECTED_CANDIDATE_VERSION
    assert rb_res["operating_mode"] == "shadow"
    assert rb_res["is_production_authoritative"] is False


# -----------------------------------------------------------------------------
# 10. Historical Fixtures Exact Assertions Isolated
# -----------------------------------------------------------------------------
def test_10_historical_fixtures_exact_assertions_isolated():
    baseline_fixture = os.path.join(FIXTURES_DIR, "pre_phase6_5_baseline.json")
    with open(baseline_fixture, "r", encoding="utf-8") as f:
        base_cfg = json.load(f)

    assert base_cfg["active_model_version"] == EXPECTED_BASELINE_VERSION
    assert base_cfg["operating_mode"] == "shadow"
    assert base_cfg["is_production_authoritative"] is False

    candidate_fixture = os.path.join(FIXTURES_DIR, "phase6_5_shadow_candidate.json")
    with open(candidate_fixture, "r", encoding="utf-8") as f:
        cand_cfg = json.load(f)

    assert cand_cfg["active_model_version"] == EXPECTED_CANDIDATE_VERSION
    assert cand_cfg["last_known_good_version"] == EXPECTED_BASELINE_VERSION
    assert cand_cfg["operating_mode"] == "shadow"
    assert cand_cfg["is_production_authoritative"] is False


# -----------------------------------------------------------------------------
# 11. Temporary Registry and Active Configuration Isolation
# -----------------------------------------------------------------------------
def test_11_temporary_registry_and_active_config_isolation(tmp_path):
    temp_models_dir = tmp_path / "models"
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(temp_models_dir))
    reg = ModelRegistry(project_root=str(tmp_path))

    assert str(tmp_path) in reg.models_dir
    assert str(tmp_path) in reg.active_config_path
    assert str(tmp_path) in reg.registry_path


# -----------------------------------------------------------------------------
# 12. Test-Induced Production Mutation Prevention
# -----------------------------------------------------------------------------
def test_12_test_induced_mutation_prevention(tmp_path):
    live_cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    live_reg_path = os.path.join(PROJECT_ROOT, "models", "model_registry.json")

    live_cfg_sha_before = compute_file_sha256(live_cfg_path)
    live_reg_sha_before = compute_file_sha256(live_reg_path)

    # Perform mutations strictly in isolated temp directory
    temp_models_dir = tmp_path / "models"
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(temp_models_dir))
    reg = ModelRegistry(project_root=str(tmp_path))
    rbc = RollbackController(registry=reg)

    rbc.execute_rollback(operator_label="test_isolation")
    reg.disable_shadow_inference(operator_label="test_isolation")
    reg.enable_shadow_inference(operator_label="test_isolation")

    # Verify live production files are 100% byte-for-byte unmodified
    assert compute_file_sha256(live_cfg_path) == live_cfg_sha_before
    assert compute_file_sha256(live_reg_path) == live_reg_sha_before


# -----------------------------------------------------------------------------
# 13. Random Telemetry Diagnostic Event ID Verification
# -----------------------------------------------------------------------------
def test_13_random_telemetry_event_id_verification():
    engine = HybridDecisionEngine()
    identical_msg = "Repeated test message for diagnostic event id entropy verification."

    res1 = engine.evaluate_message(identical_msg)
    res2 = engine.evaluate_message(identical_msg)

    evt1 = res1["audit_metadata"]["diagnostic_event_id"]
    evt2 = res2["audit_metadata"]["diagnostic_event_id"]

    assert evt1.startswith("EVT-")
    assert evt2.startswith("EVT-")
    assert len(evt1) == 16  # "EVT-" + 12 hex chars
    assert len(evt2) == 16

    # Critical entropy verification: Identical messages MUST produce distinct event IDs
    # proving the ID is generated via random uuid rather than derived from message contents
    assert evt1 != evt2


# -----------------------------------------------------------------------------
# 14. Corrupt and Invalid Configuration Fail-Closed Fallback
# -----------------------------------------------------------------------------
def test_14_corrupt_config_fallback_safety(monkeypatch):
    corrupt_fixture = os.path.join(FIXTURES_DIR, "corrupt_config.json")
    monkeypatch.setenv("SEVA_ACTIVE_CONFIG_PATH", corrupt_fixture)

    # Hybrid engine should fail safe to shadow mode with fallback if config is corrupt
    engine = HybridDecisionEngine()
    res = engine.evaluate_message("Test message under corrupted active config.")

    assert res["final_decision"]["final_risk_score"] is not None
    # Deterministic rule detection must still succeed
    assert "rule_based_evidence" in res


# -----------------------------------------------------------------------------
# 15. Model Artifacts Cryptographic Preservation
# -----------------------------------------------------------------------------
def test_15_model_artifacts_cryptographic_preservation():
    base_w = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1", "model_weights.npz")
    base_m = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1", "model_metadata.json")
    cand_w = os.path.join(PROJECT_ROOT, "models", "candidates", "candidate_v4_seed42", "model_weights.npz")
    cand_m = os.path.join(PROJECT_ROOT, "models", "candidates", "candidate_v4_seed42", "model_metadata.json")

    assert compute_file_sha256(base_w) == EXPECTED_BASELINE_WEIGHTS_SHA
    assert compute_file_sha256(base_m) == EXPECTED_BASELINE_META_SHA
    assert compute_file_sha256(cand_w) == EXPECTED_CANDIDATE_WEIGHTS_SHA
    assert compute_file_sha256(cand_m) == EXPECTED_CANDIDATE_META_SHA


# -----------------------------------------------------------------------------
# 16. Locked Evaluation Manifest Digest Preservation
# -----------------------------------------------------------------------------
def test_16_locked_evaluation_digest_preservation():
    manifest_path = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["sha256_checksum"] == EXPECTED_LOCKED_TEST_HASH
