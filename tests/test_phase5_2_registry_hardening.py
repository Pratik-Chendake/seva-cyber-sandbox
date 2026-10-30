"""
Phase 5.2 Unit Test Suite: Model Registry Hardening & Cold-Start Integrity.

Verifies all requirements for SEC-05-02 and SEC-05-03:
1. Valid registered checkpoint and metadata load successfully.
2. Modified checkpoint weights rejected during cold-start.
3. Modified metadata descriptor rejected during cold-start.
4. Missing checkpoint weights file falls back safely to deterministic rules.
5. Missing metadata descriptor falls back safely to deterministic rules.
6. Unregistered or invalid active model version falls back safely.
7. Unsafe artifact path traversal is rejected.
8. Failed integrity verification preserves previously valid active configuration.
9. Exact idempotent re-registration does not mutate registry entry.
10. Rejected registry overwrite does not mutate original entry.
11. Lifecycle state transitions preserve immutable artifact identity.
12. Shadow-mode operation guarantees zero production score delta.
13. Cold-start loading re-checks disk files and rejects offline tampering.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import tempfile
from typing import Any, Dict
import numpy as np
import pytest

from src.hybrid_decision_engine import (
    HybridDecisionEngine,
    HybridOperatingMode,
    SafeModelHolder,
)
from src.model_registry import (
    ModelIntegrityError,
    ModelLifecycleState,
    ModelNotFoundError,
    ModelRegistry,
    ModelRegistryConflictError,
    ModelSecurityError,
    compute_file_sha256,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASE_CHECKPOINT_DIR = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1")


def _setup_isolated_registry_env(tmp_path):
    """Helper to create an isolated project environment with valid registered model."""
    proj = tmp_path / "proj"
    models_dir = proj / "models"
    ckpt_dir = models_dir / "test_ckpt"
    os.makedirs(ckpt_dir, exist_ok=True)

    # Copy real weights and metadata
    shutil.copyfile(os.path.join(BASE_CHECKPOINT_DIR, "model_weights.npz"), ckpt_dir / "model_weights.npz")
    shutil.copyfile(os.path.join(BASE_CHECKPOINT_DIR, "model_metadata.json"), ckpt_dir / "model_metadata.json")

    reg = ModelRegistry(project_root=str(proj))
    reg.register_model(
        model_version="test-model-v1",
        architecture_version="3-layer-mlp-ngram-v1",
        checkpoint_rel_path="models/test_ckpt",
        preprocessing_version="neural-preproc-v1.1.0",
        lifecycle_state=ModelLifecycleState.APPROVED_FOR_SHADOW,
    )
    reg.activate_model("test-model-v1", reason="Initial test activation")
    return proj, reg, ckpt_dir


# ---------------------------------------------------------------------------
# 1. Valid registered checkpoint and metadata load successfully
# ---------------------------------------------------------------------------
def test_01_valid_registered_checkpoint_loads_successfully(tmp_path):
    """Valid registered checkpoint and metadata pass integrity verification and load finite weights."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    engine = HybridDecisionEngine(model_registry=reg)
    assert engine.model_holder.is_available is True
    assert engine.model_holder.load_error is None

    res = engine.evaluate_message("तातडीने महावितरण वीज बिल भरा http://msedcl-fake.in")
    assert res["operating_mode"] == "shadow"
    assert res["experimental_model"]["is_available"] is True
    assert res["final_decision"]["production_score_difference"] == 0


# ---------------------------------------------------------------------------
# 2. Modified checkpoint weights rejected during cold-start
# ---------------------------------------------------------------------------
def test_02_modified_checkpoint_weights_rejected_during_cold_start(tmp_path):
    """Tampering with model_weights.npz bytes on disk triggers integrity rejection on cold start."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    # Simulate offline tampering with weights archive
    weights_path = ckpt_dir / "model_weights.npz"
    weights_path.write_bytes(b"tampered_weights_binary_payload")

    # Cold restart
    engine = HybridDecisionEngine(model_registry=reg)
    assert engine.model_holder.is_available is False
    assert "weights SHA-256 mismatch" in engine.model_holder.load_error

    # Evaluates safely using deterministic rules
    res = engine.evaluate_message("तातडीने वीज बिल भरा http://msedcl-fake.in")
    assert res["experimental_model"]["is_available"] is False
    assert res["final_decision"]["final_risk_score"] >= 20
    assert any("GR-07" in g for g in res["final_decision"]["guardrails_applied"])


# ---------------------------------------------------------------------------
# 3. Modified metadata descriptor rejected during cold-start
# ---------------------------------------------------------------------------
def test_03_modified_metadata_rejected_during_cold_start(tmp_path):
    """Tampering with model_metadata.json on disk triggers integrity rejection on cold start."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    # Tamper with metadata JSON
    meta_path = ckpt_dir / "model_metadata.json"
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    meta["learning_rate"] = 0.99999  # Unauthorized modification
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f)

    # Cold restart
    engine = HybridDecisionEngine(model_registry=reg)
    assert engine.model_holder.is_available is False
    assert "metadata SHA-256 mismatch" in engine.model_holder.load_error

    res = engine.evaluate_message("तातडीने वीज बिल भरा http://msedcl-fake.in")
    assert res["experimental_model"]["is_available"] is False
    assert res["final_decision"]["final_risk_score"] >= 20


# ---------------------------------------------------------------------------
# 4. Missing checkpoint weights falls back safely
# ---------------------------------------------------------------------------
def test_04_missing_checkpoint_weights_falls_back_safely(tmp_path):
    """Missing model_weights.npz file causes graceful rule-based fallback without crash."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    weights_path = ckpt_dir / "model_weights.npz"
    os.remove(weights_path)

    engine = HybridDecisionEngine(model_registry=reg)
    assert engine.model_holder.is_available is False
    assert "Weights archive missing" in engine.model_holder.load_error

    res = engine.evaluate_message("महावितरण बिल भरा")
    assert res["experimental_model"]["is_available"] is False
    assert res["final_decision"]["final_risk_score"] >= 0


# ---------------------------------------------------------------------------
# 5. Missing metadata descriptor falls back safely
# ---------------------------------------------------------------------------
def test_05_missing_metadata_falls_back_safely(tmp_path):
    """Missing model_metadata.json causes graceful rule-based fallback without crash."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    meta_path = ckpt_dir / "model_metadata.json"
    os.remove(meta_path)

    engine = HybridDecisionEngine(model_registry=reg)
    assert engine.model_holder.is_available is False
    assert "Metadata descriptor missing" in engine.model_holder.load_error

    res = engine.evaluate_message("महावितरण बिल भरा")
    assert res["experimental_model"]["is_available"] is False
    assert res["final_decision"]["final_risk_score"] >= 0


# ---------------------------------------------------------------------------
# 6. Unregistered active version falls back safely
# ---------------------------------------------------------------------------
def test_06_unregistered_active_version_falls_back_safely(tmp_path):
    """If active_model_config.json references an unregistered version, fail closed to rules."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    cfg_path = proj / "models" / "active_model_config.json"
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["active_model_version"] = "phantom-unregistered-model-v9"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    engine = HybridDecisionEngine(model_registry=reg)
    assert engine.model_holder.is_available is False
    assert "is not registered in model registry" in engine.model_holder.load_error

    res = engine.evaluate_message("महावितरण बिल भरा http://fake.in")
    assert res["experimental_model"]["is_available"] is False
    assert res["final_decision"]["final_risk_score"] >= 20


# ---------------------------------------------------------------------------
# 7. Unsafe artifact path traversal is rejected
# ---------------------------------------------------------------------------
def test_07_unsafe_artifact_path_traversal_rejected(tmp_path):
    """Path traversal in configuration or explicit checkpoint path is rejected."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    # 1. Path traversal in explicit path
    holder_traversal = SafeModelHolder(checkpoint_dir="models/../../secret", registry=reg)
    assert holder_traversal.is_available is False
    assert "path traversal" in holder_traversal.load_error.lower()

    # 2. Path traversal in active_model_config.json
    cfg_path = proj / "models" / "active_model_config.json"
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["checkpoint_rel_path"] = "models/../../secret"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    engine_traversal = HybridDecisionEngine(model_registry=reg)
    assert engine_traversal.model_holder.is_available is False
    assert "mismatch" in engine_traversal.model_holder.load_error.lower() or "security" in engine_traversal.model_holder.load_error.lower()


# ---------------------------------------------------------------------------
# 8. Failed integrity verification preserves valid active config
# ---------------------------------------------------------------------------
def test_08_failed_integrity_verification_preserves_valid_active_config(tmp_path):
    """When activating a model fails integrity verification, existing active configuration is untouched."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    # Active model is test-model-v1
    cur_cfg = reg.get_active_model_config()
    assert cur_cfg["active_model_version"] == "test-model-v1"

    # Register corrupt model
    corrupt_dir = proj / "models" / "corrupt_ckpt"
    os.makedirs(corrupt_dir, exist_ok=True)
    (corrupt_dir / "model_weights.npz").write_bytes(b"initial_weights")
    (corrupt_dir / "model_metadata.json").write_text(json.dumps({"model_version": "corrupt-v1", "input_dim": 1024, "hidden_dim1": 64, "hidden_dim2": 32, "num_classes": 3}), encoding="utf-8")

    reg.register_model("corrupt-v1", "CustomMLP-v1", "models/corrupt_ckpt", "neural-preproc-v1.1.0", ModelLifecycleState.APPROVED_FOR_SHADOW)

    # Tamper with weights
    (corrupt_dir / "model_weights.npz").write_bytes(b"tampered_after_registration")

    # Activation must raise ModelIntegrityError
    with pytest.raises(ModelIntegrityError):
        reg.activate_model("corrupt-v1")

    # Verify active configuration is strictly preserved
    cfg_after = reg.get_active_model_config()
    assert cfg_after["active_model_version"] == "test-model-v1"
    assert cfg_after["last_known_good_version"] is None


# ---------------------------------------------------------------------------
# 9. Exact idempotent re-registration does not mutate registry
# ---------------------------------------------------------------------------
def test_09_exact_idempotent_registration_does_not_mutate_registry(tmp_path):
    """Registering an existing model version with identical immutable attributes is idempotent and safe."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    reg_file = proj / "models" / "model_registry.json"
    sha_before = compute_file_sha256(str(reg_file))
    audit_count_before = len(reg.get_audit_log())

    # Call register_model again with identical immutable attributes
    entry = reg.register_model(
        model_version="test-model-v1",
        architecture_version="3-layer-mlp-ngram-v1",
        checkpoint_rel_path="models/test_ckpt",
        preprocessing_version="neural-preproc-v1.1.0",
        lifecycle_state=ModelLifecycleState.APPROVED_FOR_SHADOW,
    )

    assert entry["model_version"] == "test-model-v1"
    sha_after = compute_file_sha256(str(reg_file))
    audit_count_after = len(reg.get_audit_log())

    # File was not rewritten or mutated
    assert sha_before == sha_after
    assert audit_count_before == audit_count_after


# ---------------------------------------------------------------------------
# 10. Rejected registry overwrite does not mutate original entry
# ---------------------------------------------------------------------------
def test_10_rejected_registry_overwrite_does_not_mutate_original_entry(tmp_path):
    """Attempting to overwrite a registered version with different weights raises ModelRegistryConflictError."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    orig_entry = reg.get_model("test-model-v1")
    orig_weights_sha = orig_entry["weights_sha256"]

    # Create a different checkpoint with altered weights
    alt_dir = proj / "models" / "alt_ckpt"
    os.makedirs(alt_dir, exist_ok=True)
    (alt_dir / "model_weights.npz").write_bytes(b"completely_different_weights_bytes")
    shutil.copyfile(os.path.join(BASE_CHECKPOINT_DIR, "model_metadata.json"), alt_dir / "model_metadata.json")

    # Attempt to overwrite test-model-v1 with different weights
    with pytest.raises(ModelRegistryConflictError) as exc_info:
        reg.register_model(
            model_version="test-model-v1",
            architecture_version="3-layer-mlp-ngram-v1",
            checkpoint_rel_path="models/alt_ckpt",
            preprocessing_version="neural-preproc-v1.1.0",
        )

    assert "Cannot overwrite immutable model version 'test-model-v1'" in str(exc_info.value)
    assert "A changed model must receive a new distinct version identifier" in str(exc_info.value)

    # Verify original entry remains unchanged
    entry_after = reg.get_model("test-model-v1")
    assert entry_after["weights_sha256"] == orig_weights_sha
    assert entry_after["checkpoint_rel_path"] == "models/test_ckpt"


# ---------------------------------------------------------------------------
# 11. Lifecycle state transitions preserve immutable artifact identity
# ---------------------------------------------------------------------------
def test_11_lifecycle_state_transition_preserves_immutable_artifact_identity(tmp_path):
    """set_lifecycle_state updates state and audits transition while preserving artifact hashes."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    orig_entry = reg.get_model("test-model-v1")

    # Transition to retired
    updated = reg.set_lifecycle_state("test-model-v1", ModelLifecycleState.RETIRED, reason="End of evaluation cycle")
    assert updated["lifecycle_state"] == "retired"

    # Immutable artifact identities are strictly preserved
    assert updated["weights_sha256"] == orig_entry["weights_sha256"]
    assert updated["metadata_sha256"] == orig_entry["metadata_sha256"]
    assert updated["checkpoint_rel_path"] == orig_entry["checkpoint_rel_path"]
    assert updated["architecture_version"] == orig_entry["architecture_version"]

    # Verify audit event logged
    recent_audit = reg.get_audit_log()[0]
    assert recent_audit["action"] == "UPDATE_LIFECYCLE_STATE"
    assert recent_audit["prior_state"] == "approved_for_shadow"
    assert recent_audit["new_state"] == "retired"


# ---------------------------------------------------------------------------
# 12. Shadow-mode operation guarantees zero production score delta
# ---------------------------------------------------------------------------
def test_12_shadow_mode_produces_zero_production_score_delta(tmp_path):
    """In shadow mode, production risk score is strictly determined by rules and threat intelligence."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    engine = HybridDecisionEngine(model_registry=reg)

    test_messages = [
        "महावितरण: आपले वीज बिल थकीत आहे. आजच भरा नाहीतर वीज तोडली जाईल http://msedcl-bill.xyz",
        "सायबर हेल्पलाइन १९३०: कधीही कोणाशीही OTP किंवा पासवर्ड शेअर करू नका.",
        "ग्रामपंचायत मासिक बैठक उद्या दुपारी २ वाजता होणार आहे.",
    ]

    for msg in test_messages:
        res = engine.evaluate_message(msg)
        assert res["operating_mode"] == "shadow"
        assert res["final_decision"]["production_score_difference"] == 0
        assert res["final_decision"]["final_risk_score"] == res["rule_based_evidence"]["score"]


# ---------------------------------------------------------------------------
# 13. Cold-start loading re-checks disk files and rejects offline tampering
# ---------------------------------------------------------------------------
def test_13_cold_start_loading_verifies_files_from_disk_each_time(tmp_path):
    """Cold start model holder does not trust prior activation; it re-hashes disk files each time."""
    proj, reg, ckpt_dir = _setup_isolated_registry_env(tmp_path)

    # First startup: valid
    h1 = SafeModelHolder(registry=reg)
    assert h1.is_available is True

    # Tamper with file on disk while process is stopped
    weights_path = ckpt_dir / "model_weights.npz"
    weights_path.write_bytes(b"tampered_bytes_after_cold_shutdown")

    # Second startup (cold start): must re-calculate hash from disk and reject
    h2 = SafeModelHolder(registry=reg)
    assert h2.is_available is False
    assert "weights SHA-256 mismatch" in h2.load_error
