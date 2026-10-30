"""
Model Version Registry and Rollback Management Module.
Part of Seva Cyber Sandbox (Phase 5).

DESIGN & SECURITY ARCHITECTURE:
1. Strict Local-First & Zero Pretrained Weights:
   - Tracks only purpose-built local neural models trained from randomly initialized weights.
   - Operates strictly offline without external network calls or remote model downloads.
2. Cryptographic Integrity Verification:
   - Checkpoint weights (.npz) and metadata (.json) SHA-256 digests are verified prior
     to model registration, activation, or inference loading.
   - Modified, corrupted, or tampered artifacts are rejected immediately.
3. Path Traversal & Security Boundaries:
   - Checkpoint paths must resolve strictly within the project's trusted 'models/' directory.
   - Arbitrary user-supplied paths, absolute paths, or paths with '..' traversal are rejected.
4. Explicit Rollback & Provenance:
   - Operator actions to activate or roll back diagnostic models are recorded in an audit trail.
   - Atomic configuration persistence guarantees rollback safety.
   - Last known-good diagnostic configuration is preserved; rollback can restore prior state.
5. Strict Isolation from Production Risk Scoring:
   - The registered models operate strictly in 'shadow' or diagnostic mode.
   - Model activation or rollback NEVER alters production risk scores, alerts, or rule verdicts.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

REGISTRY_SCHEMA_VERSION = "1.0.0"
DEFAULT_MODELS_DIR = "models"
REGISTRY_FILE_NAME = "model_registry.json"
ACTIVE_CONFIG_FILE_NAME = "active_model_config.json"


class ModelLifecycleState(str, Enum):
    """Lifecycle states for registered custom neural models."""
    EXPERIMENTAL = "experimental"
    APPROVED_FOR_SHADOW = "approved_for_shadow"
    INACTIVE = "inactive"
    RETIRED = "retired"


class ModelRegistryError(Exception):
    """Base exception for model registry operations."""
    pass


class ModelNotFoundError(ModelRegistryError):
    """Raised when a requested model version is not registered."""
    pass


class ModelIntegrityError(ModelRegistryError):
    """Raised when checkpoint weights or metadata fail SHA-256 integrity verification."""
    pass


class ModelSecurityError(ModelRegistryError):
    """Raised when path traversal or unauthorized directory access is detected."""
    pass


class ModelRegistryConflictError(ModelRegistryError):
    """Raised when an attempt is made to overwrite an existing immutable model version."""
    pass


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 digest of a local file safely in 64 KB chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class ModelRegistry:
    """
    Manages model registration, cryptographic verification, activation,
    and atomic rollback for diagnostic neural models.
    """

    def __init__(
        self,
        project_root: Optional[str] = None,
        models_dir: Optional[str] = None,
    ):
        if project_root is None:
            self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        else:
            self.project_root = os.path.abspath(project_root)

        self.models_dir = os.path.abspath(os.path.join(self.project_root, models_dir or DEFAULT_MODELS_DIR))
        self.registry_path = os.path.join(self.models_dir, REGISTRY_FILE_NAME)
        self.active_config_path = os.path.join(self.models_dir, ACTIVE_CONFIG_FILE_NAME)

        os.makedirs(self.models_dir, exist_ok=True)
        self._ensure_initialized()

    def _validate_safe_path(self, rel_path: str) -> str:
        """
        Validates that rel_path resolves strictly inside self.models_dir.
        Rejects path traversal ('..'), absolute outside paths, or invalid characters.
        """
        if not rel_path or not isinstance(rel_path, str):
            raise ModelSecurityError("Checkpoint path must be a non-empty string.")

        # Clean slashes
        clean_rel = os.path.normpath(rel_path).strip()
        if clean_rel.startswith("..") or ".." in clean_rel.split(os.sep):
            raise ModelSecurityError(f"Path traversal detected in checkpoint path: '{rel_path}'")

        abs_path = os.path.abspath(os.path.join(self.project_root, clean_rel))
        # Ensure it falls within models_dir
        if not abs_path.startswith(self.models_dir):
            raise ModelSecurityError(
                f"Security violation: Checkpoint path '{rel_path}' resolves outside trusted models directory."
            )

        return abs_path

    def _ensure_initialized(self) -> None:
        """Initializes empty registry manifest and active config if not present."""
        if not os.path.exists(self.registry_path):
            initial_reg = {
                "registry_schema_version": REGISTRY_SCHEMA_VERSION,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "registered_models": {},
                "audit_log": [],
            }
            self._save_json_atomic(self.registry_path, initial_reg)

        if not os.path.exists(self.active_config_path):
            initial_cfg = {
                "active_model_version": None,
                "last_known_good_version": None,
                "operating_mode": "shadow",
                "activated_at_utc": None,
                "activated_by": "system",
                "activation_reason": "Initial default configuration",
                "is_production_authoritative": False,
            }
            self._save_json_atomic(self.active_config_path, initial_cfg)

    def _load_json(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise ModelRegistryError(f"Failed to read registry artifact at '{path}': {e}") from e

    def _save_json_atomic(self, path: str, data: Dict[str, Any]) -> None:
        """Atomically saves JSON data using a temporary file in the same directory."""
        dir_name = os.path.dirname(path)
        os.makedirs(dir_name, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_reg_", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            shutil.move(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            raise

    # -------------------------------------------------------------------------
    # REGISTRATION API
    # -------------------------------------------------------------------------

    def register_model(
        self,
        model_version: str,
        architecture_version: str,
        checkpoint_rel_path: str,
        preprocessing_version: str,
        lifecycle_state: Union[str, ModelLifecycleState] = ModelLifecycleState.EXPERIMENTAL,
        label_mapping: Optional[Dict[str, int]] = None,
        hyperparameters: Optional[Dict[str, Any]] = None,
        training_corpus_id: str = "synthetic_training_v2",
        training_corpus_digest: Optional[str] = None,
        validation_corpus_id: str = "synthetic_validation_v2",
        validation_corpus_digest: Optional[str] = None,
        validation_metrics: Optional[Dict[str, Any]] = None,
        operator_label: str = "local_operator",
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Registers a custom neural model checkpoint in the version registry.
        Computes and records SHA-256 digests for model_weights.npz and model_metadata.json.
        """
        abs_ckpt = self._validate_safe_path(checkpoint_rel_path)

        weights_file = os.path.join(abs_ckpt, "model_weights.npz")
        meta_file = os.path.join(abs_ckpt, "model_metadata.json")

        if not os.path.isfile(weights_file):
            raise ModelRegistryError(f"Missing weights archive: {weights_file}")
        if not os.path.isfile(meta_file):
            raise ModelRegistryError(f"Missing metadata descriptor: {meta_file}")

        # Compute integrity digests
        weights_sha = compute_file_sha256(weights_file)
        meta_sha = compute_file_sha256(meta_file)

        # Read metadata for dimensions validation
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        now_utc = datetime.now(timezone.utc).isoformat()
        state_val = (
            lifecycle_state.value if isinstance(lifecycle_state, ModelLifecycleState) else str(lifecycle_state)
        )

        entry = {
            "model_version": model_version,
            "architecture_version": architecture_version,
            "checkpoint_rel_path": os.path.normpath(checkpoint_rel_path).replace("\\", "/"),
            "weights_sha256": weights_sha,
            "metadata_sha256": meta_sha,
            "preprocessing_version": preprocessing_version,
            "label_mapping": label_mapping or meta.get("label_to_index", {"phishing": 0, "legitimate": 1, "protective_advisory": 2}),
            "hyperparameters": hyperparameters or {
                "input_dim": meta.get("input_dim", 1024),
                "hidden_dim1": meta.get("hidden_dim1", 64),
                "hidden_dim2": meta.get("hidden_dim2", 32),
                "num_classes": meta.get("num_classes", 3),
                "learning_rate": meta.get("learning_rate", 0.005),
                "weight_decay": meta.get("weight_decay", 0.0001),
                "seed": meta.get("seed", 42),
            },
            "training_corpus_id": training_corpus_id,
            "training_corpus_digest": training_corpus_digest,
            "validation_corpus_id": validation_corpus_id,
            "validation_corpus_digest": validation_corpus_digest,
            "validation_metrics": validation_metrics or {
                "accuracy": meta.get("training_metadata", {}).get("final_val_accuracy"),
                "macro_f1": meta.get("training_metadata", {}).get("final_val_macro_f1"),
                "note": "Evaluated on synthetic candidate corpus. Metrics do NOT establish certified real-world accuracy.",
            },
            "registered_at_utc": now_utc,
            "registered_by": operator_label[:64],
            "lifecycle_state": state_val,
            "is_production_authoritative": False,
            "notes": notes[:500],
        }

        registry = self._load_json(self.registry_path)
        existing_entry = registry.get("registered_models", {}).get(model_version)

        if existing_entry is not None:
            clean_ckpt = os.path.normpath(checkpoint_rel_path).replace("\\", "/")
            existing_ckpt = os.path.normpath(existing_entry.get("checkpoint_rel_path", "")).replace("\\", "/")

            mismatches = []
            if existing_entry.get("weights_sha256") != weights_sha:
                mismatches.append(f"weights_sha256 mismatch (existing: {existing_entry.get('weights_sha256')}, new: {weights_sha})")
            if existing_entry.get("metadata_sha256") != meta_sha:
                mismatches.append(f"metadata_sha256 mismatch (existing: {existing_entry.get('metadata_sha256')}, new: {meta_sha})")
            if existing_ckpt != clean_ckpt:
                mismatches.append(f"checkpoint_rel_path mismatch (existing: '{existing_ckpt}', new: '{clean_ckpt}')")
            if existing_entry.get("architecture_version") != architecture_version:
                mismatches.append(f"architecture_version mismatch (existing: '{existing_entry.get('architecture_version')}', new: '{architecture_version}')")
            if existing_entry.get("preprocessing_version") != preprocessing_version:
                mismatches.append(f"preprocessing_version mismatch (existing: '{existing_entry.get('preprocessing_version')}', new: '{preprocessing_version}')")

            if mismatches:
                raise ModelRegistryConflictError(
                    f"Cannot overwrite immutable model version '{model_version}'. "
                    f"Existing registered model version has differing immutable attributes: {'; '.join(mismatches)}. "
                    f"A changed model must receive a new distinct version identifier."
                )

            # Identical registration: idempotent, return existing entry without rewriting
            logger.info("Model version '%s' is already registered with identical immutable artifacts. Skipping rewrite (idempotent).", model_version)
            return existing_entry

        registry["registered_models"][model_version] = entry

        audit_entry = {
            "timestamp_utc": now_utc,
            "action": "REGISTER_MODEL",
            "model_version": model_version,
            "operator_label": operator_label[:64],
            "lifecycle_state": state_val,
            "weights_sha256": weights_sha,
        }
        registry.setdefault("audit_log", []).append(audit_entry)
        self._save_json_atomic(self.registry_path, registry)

        logger.info("Successfully registered model version '%s' in registry.", model_version)
        return entry

    # -------------------------------------------------------------------------
    # LOOKUP & INTEGRITY VERIFICATION
    # -------------------------------------------------------------------------

    def list_models(self) -> List[Dict[str, Any]]:
        """Returns a list of all registered models."""
        reg = self._load_json(self.registry_path)
        return list(reg.get("registered_models", {}).values())

    def get_model(self, model_version: str) -> Dict[str, Any]:
        """Retrieves entry for a specific model version."""
        reg = self._load_json(self.registry_path)
        models = reg.get("registered_models", {})
        if model_version not in models:
            raise ModelNotFoundError(f"Model version '{model_version}' is not registered.")
        return models[model_version]

    def verify_checkpoint_integrity(self, model_version: str) -> Tuple[bool, str]:
        """
        Verifies that on-disk weights and metadata match registered SHA-256 digests.
        Returns (is_valid, message).
        """
        entry = self.get_model(model_version)
        rel_path = entry["checkpoint_rel_path"]

        try:
            abs_ckpt = self._validate_safe_path(rel_path)
        except ModelSecurityError as e:
            return False, f"Path security violation: {e}"

        weights_file = os.path.join(abs_ckpt, "model_weights.npz")
        meta_file = os.path.join(abs_ckpt, "model_metadata.json")

        if not os.path.isfile(weights_file):
            return False, f"Weights file missing at '{weights_file}'"
        if not os.path.isfile(meta_file):
            return False, f"Metadata file missing at '{meta_file}'"

        actual_weights_sha = compute_file_sha256(weights_file)
        if actual_weights_sha != entry["weights_sha256"]:
            return False, f"Weights SHA-256 mismatch! Registered: {entry['weights_sha256']}, Actual: {actual_weights_sha}"

        actual_meta_sha = compute_file_sha256(meta_file)
        if actual_meta_sha != entry["metadata_sha256"]:
            return False, f"Metadata SHA-256 mismatch! Registered: {entry['metadata_sha256']}, Actual: {actual_meta_sha}"

        return True, "Integrity verified: Checkpoint weights and metadata match registered digests."

    def set_lifecycle_state(
        self,
        model_version: str,
        new_state: Union[str, ModelLifecycleState],
        operator_label: str = "local_operator",
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Updates the lifecycle state of a registered model (e.g. approved_for_shadow, retired).
        Strictly preserves immutable artifact identities and paths; audits the transition.
        """
        entry = self.get_model(model_version)
        state_val = new_state.value if isinstance(new_state, ModelLifecycleState) else str(new_state)
        valid_states = {s.value for s in ModelLifecycleState}
        if state_val not in valid_states:
            raise ModelRegistryError(f"Invalid lifecycle state '{state_val}'. Must be one of {valid_states}.")

        prior_state = entry["lifecycle_state"]
        if prior_state == state_val:
            return entry

        registry = self._load_json(self.registry_path)
        registry["registered_models"][model_version]["lifecycle_state"] = state_val
        now_utc = datetime.now(timezone.utc).isoformat()

        audit_entry = {
            "timestamp_utc": now_utc,
            "action": "UPDATE_LIFECYCLE_STATE",
            "model_version": model_version,
            "operator_label": operator_label[:64],
            "prior_state": prior_state,
            "new_state": state_val,
            "reason": reason[:256] or f"Transitioned from {prior_state} to {state_val}",
        }
        registry.setdefault("audit_log", []).append(audit_entry)
        self._save_json_atomic(self.registry_path, registry)
        logger.info("Updated model '%s' lifecycle state from '%s' to '%s'.", model_version, prior_state, state_val)
        return registry["registered_models"][model_version]

    def verify_active_model_for_loading(self) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Validates active model configuration and cryptographic checkpoint integrity
        during cold application startup or model loading (SEC-05-02).
        """
        try:
            active_cfg = self.get_active_model_config()
        except Exception as e:
            return False, f"Failed to load active model configuration: {e}", None

        active_version = active_cfg.get("active_model_version")
        if not active_version:
            return False, "No active model version specified in configuration.", None

        # Check model exists in registry
        try:
            entry = self.get_model(active_version)
        except ModelNotFoundError:
            return False, f"Active model version '{active_version}' is not registered in model registry.", None
        except Exception as e:
            return False, f"Registry lookup error for active model '{active_version}': {e}", None

        # Lifecycle gate
        allowed_states = {ModelLifecycleState.APPROVED_FOR_SHADOW.value, ModelLifecycleState.EXPERIMENTAL.value}
        if entry.get("lifecycle_state") not in allowed_states:
            return False, f"Active model '{active_version}' has unpermitted lifecycle state '{entry.get('lifecycle_state')}'.", None

        # Path traversal and path consistency checks
        rel_path = active_cfg.get("checkpoint_rel_path") or entry.get("checkpoint_rel_path")
        if not rel_path:
            return False, f"Active model '{active_version}' has no checkpoint path configured.", None

        reg_rel_path = entry.get("checkpoint_rel_path")
        if reg_rel_path and os.path.normpath(rel_path).replace("\\", "/") != os.path.normpath(reg_rel_path).replace("\\", "/"):
            return False, f"Active configuration checkpoint path mismatch with registry for model '{active_version}'.", None

        try:
            abs_ckpt = self._validate_safe_path(rel_path)
        except ModelSecurityError as e:
            return False, f"Path security violation for active model '{active_version}': {e}", None

        # Verify on-disk file existence
        weights_file = os.path.join(abs_ckpt, "model_weights.npz")
        meta_file = os.path.join(abs_ckpt, "model_metadata.json")

        if not os.path.isfile(weights_file):
            return False, f"Weights archive missing for active model '{active_version}' at '{rel_path}/model_weights.npz'", None
        if not os.path.isfile(meta_file):
            return False, f"Metadata descriptor missing for active model '{active_version}' at '{rel_path}/model_metadata.json'", None

        # Re-compute and compare file SHA-256
        actual_weights_sha = compute_file_sha256(weights_file)
        if actual_weights_sha != entry.get("weights_sha256"):
            return False, f"Integrity check failed: weights SHA-256 mismatch for model '{active_version}'.", None

        actual_meta_sha = compute_file_sha256(meta_file)
        if actual_meta_sha != entry.get("metadata_sha256"):
            return False, f"Integrity check failed: metadata SHA-256 mismatch for model '{active_version}'.", None

        return True, f"Integrity verified for active model '{active_version}'.", entry

    def verify_checkpoint_for_loading(
        self,
        checkpoint_dir: str,
        expected_version: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Validates checkpoint at arbitrary relative or absolute path against registry
        prior to loading (SEC-05-02).
        """
        clean_norm = os.path.normpath(str(checkpoint_dir)).replace("\\", "/")
        if clean_norm.startswith("..") or ".." in clean_norm.split("/"):
            return False, f"Security violation: path traversal detected in checkpoint path: '{checkpoint_dir}'", None

        if not os.path.exists(checkpoint_dir):
            return False, f"Checkpoint directory not found: {checkpoint_dir}", None

        try:
            abs_ckpt = self._validate_safe_path(checkpoint_dir)
        except ModelSecurityError as e:
            return False, f"Path security violation: {e}", None

        weights_file = os.path.join(abs_ckpt, "model_weights.npz")
        meta_file = os.path.join(abs_ckpt, "model_metadata.json")

        if not os.path.isfile(weights_file):
            return False, f"Weights archive missing: {weights_file}", None
        if not os.path.isfile(meta_file):
            return False, f"Metadata descriptor missing: {meta_file}", None

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception as e:
            return False, f"Malformed metadata descriptor: {e}", None

        model_version = meta.get("model_version")
        if not model_version:
            return False, "Metadata missing 'model_version' identifier.", None

        if expected_version and model_version != expected_version:
            return False, f"Metadata model_version '{model_version}' does not match expected '{expected_version}'.", None

        try:
            entry = self.get_model(model_version)
        except ModelNotFoundError:
            return False, f"Model version '{model_version}' is not registered in version registry.", None
        except Exception as e:
            return False, f"Registry lookup error for model '{model_version}': {e}", None

        allowed_states = {ModelLifecycleState.APPROVED_FOR_SHADOW.value, ModelLifecycleState.EXPERIMENTAL.value}
        if entry.get("lifecycle_state") not in allowed_states:
            return False, f"Model version '{model_version}' has unpermitted lifecycle state '{entry.get('lifecycle_state')}'.", None

        is_valid, msg = self.verify_checkpoint_integrity(model_version)
        if not is_valid:
            return False, f"Checkpoint integrity verification failed: {msg}", None

        return True, f"Model '{model_version}' verified successfully for loading.", entry

    # -------------------------------------------------------------------------
    # ACTIVATION & ATOMIC ROLLBACK
    # -------------------------------------------------------------------------

    def get_active_model_config(self) -> Dict[str, Any]:
        """Returns the current active diagnostic model configuration."""
        return self._load_json(self.active_config_path)

    def activate_model(
        self,
        model_version: str,
        operator_label: str = "local_operator",
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Activates a registered model version for shadow-mode diagnostics.
        1. Verifies that the model is registered and in an allowed lifecycle state.
        2. Cryptographically verifies weights and metadata SHA-256 digests.
        3. Preserves current active model as last_known_good_version for rollback.
        4. Atomically updates active_model_config.json.
        """
        entry = self.get_model(model_version)

        # Lifecycle gate
        allowed_states = {ModelLifecycleState.APPROVED_FOR_SHADOW.value, ModelLifecycleState.EXPERIMENTAL.value}
        if entry["lifecycle_state"] not in allowed_states:
            raise ModelRegistryError(
                f"Cannot activate model '{model_version}' with lifecycle state '{entry['lifecycle_state']}'. "
                f"Must be one of {allowed_states}."
            )

        # Integrity verification
        valid, msg = self.verify_checkpoint_integrity(model_version)
        if not valid:
            self._record_audit_event(
                action="ACTIVATION_FAILED",
                model_version=model_version,
                operator_label=operator_label,
                reason=f"Integrity check failed: {msg}",
            )
            raise ModelIntegrityError(f"Model activation aborted: {msg}")

        # Current configuration
        cur_cfg = self.get_active_model_config()
        prior_active = cur_cfg.get("active_model_version")

        now_utc = datetime.now(timezone.utc).isoformat()
        new_cfg = {
            "active_model_version": model_version,
            "last_known_good_version": prior_active if prior_active != model_version else cur_cfg.get("last_known_good_version"),
            "operating_mode": "shadow",
            "activated_at_utc": now_utc,
            "activated_by": operator_label[:64],
            "activation_reason": reason[:256] or "Operator activation",
            "checkpoint_rel_path": entry["checkpoint_rel_path"],
            "preprocessing_version": entry["preprocessing_version"],
            "is_production_authoritative": False,
        }

        self._save_json_atomic(self.active_config_path, new_cfg)
        self._record_audit_event(
            action="ACTIVATE_DIAGNOSTIC_MODEL",
            model_version=model_version,
            operator_label=operator_label,
            reason=reason or f"Activated {model_version} for shadow diagnostics",
            details={"prior_version": prior_active, "checkpoint": entry["checkpoint_rel_path"]},
        )

        logger.info("Activated model version '%s' for shadow diagnostics.", model_version)
        return new_cfg

    def rollback_model(
        self,
        operator_label: str = "local_operator",
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Rolls back the active diagnostic model to the last known-good configuration atomically.
        """
        cur_cfg = self.get_active_model_config()
        target_version = cur_cfg.get("last_known_good_version")
        current_version = cur_cfg.get("active_model_version")

        if not target_version:
            raise ModelRegistryError("Cannot rollback: No prior last_known_good_version recorded.")

        if target_version == current_version:
            raise ModelRegistryError(f"Target rollback version '{target_version}' is already active.")

        # Activate target version with rollback audit
        entry = self.get_model(target_version)
        valid, msg = self.verify_checkpoint_integrity(target_version)
        if not valid:
            raise ModelIntegrityError(f"Rollback aborted: Prior version '{target_version}' failed integrity: {msg}")

        now_utc = datetime.now(timezone.utc).isoformat()
        new_cfg = {
            "active_model_version": target_version,
            "last_known_good_version": current_version,  # Swap allows roll-forward if needed
            "operating_mode": "shadow",
            "activated_at_utc": now_utc,
            "activated_by": operator_label[:64],
            "activation_reason": f"Rollback from {current_version}: {reason[:200]}",
            "checkpoint_rel_path": entry["checkpoint_rel_path"],
            "preprocessing_version": entry["preprocessing_version"],
            "is_production_authoritative": False,
        }

        self._save_json_atomic(self.active_config_path, new_cfg)
        self._record_audit_event(
            action="ROLLBACK_DIAGNOSTIC_MODEL",
            model_version=target_version,
            operator_label=operator_label,
            reason=f"Rolled back from {current_version} to {target_version}. {reason}",
            details={"rolled_back_from": current_version, "rolled_back_to": target_version},
        )

        logger.info("Successfully rolled back diagnostic model from '%s' to '%s'.", current_version, target_version)
        return new_cfg

    def _record_audit_event(
        self,
        action: str,
        model_version: Optional[str] = None,
        operator_label: str = "local_operator",
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Appends an event to the registry audit trail."""
        registry = self._load_json(self.registry_path)
        audit_entry = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "model_version": model_version,
            "operator_label": operator_label[:64],
            "reason": reason[:256],
            "details": details or {},
        }
        registry.setdefault("audit_log", []).append(audit_entry)
        self._save_json_atomic(self.registry_path, registry)

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent audit log entries in reverse chronological order."""
        registry = self._load_json(self.registry_path)
        entries = registry.get("audit_log", [])
        return list(reversed(entries))[:limit]


# =============================================================================
# DEFAULT INITIALIZATION HELPER
# =============================================================================

_DEFAULT_REGISTRY_INSTANCE: Optional[ModelRegistry] = None


def get_default_model_registry(project_root: Optional[str] = None) -> ModelRegistry:
    """Returns singleton model registry instance."""
    global _DEFAULT_REGISTRY_INSTANCE
    if _DEFAULT_REGISTRY_INSTANCE is None:
        _DEFAULT_REGISTRY_INSTANCE = ModelRegistry(project_root=project_root)
    return _DEFAULT_REGISTRY_INSTANCE
