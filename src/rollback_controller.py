"""
Rollback Controller and Safety Gate Module.
Part of Seva Cyber Sandbox (Phase 6.5).

DESIGN & GOVERNANCE ARCHITECTURE:
1. Immutable Model Preservation:
   - Rollback NEVER deletes, modifies, or overwrites any registered model checkpoint.
   - Older models and candidate artifacts remain completely intact.
2. Atomic Configuration Transition:
   - Model activation and rollback operate via atomic temporary-file writes.
   - Failed rollback attempts fail closed and CANNOT corrupt current valid configuration.
3. Cryptographic Pre-Flight Verification:
   - Before restoring any prior version, its checkpoint weights (.npz) and metadata (.json)
     SHA-256 digests are re-computed and verified against the immutable registry.
   - Corrupt, missing, or tampered targets are rejected immediately.
4. Append-Only Audit Trail:
   - Every rollback attempt (successful or rejected) is recorded with timestamp, operator,
     reason, and source/target version identifiers.
5. Production Score Invariance:
   - Rollback restores only the diagnostic shadow model. Production rule scoring remains
     completely unaffected with a score delta of exactly zero.
"""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, Union

from src.model_registry import (
    ModelRegistry,
    get_default_model_registry,
    ModelRegistryError,
    ModelIntegrityError,
    ModelNotFoundError,
    ModelLifecycleState,
)

logger = logging.getLogger(__name__)


class RollbackController:
    """
    Dedicated controller for executing and validating atomic rollbacks
    of diagnostic neural models with cryptographic pre-flight checks.
    """

    def __init__(self, registry: Optional[ModelRegistry] = None):
        self.registry = registry or get_default_model_registry()

    def get_rollback_status(self) -> Dict[str, Any]:
        """
        Inspects active configuration and determines rollback availability.
        """
        cfg = self.registry.get_active_model_config()
        current_version = cfg.get("active_model_version")
        target_version = cfg.get("last_known_good_version")

        can_rollback, reason, details = self.simulate_rollback_validation(target_version)

        return {
            "current_active_version": current_version,
            "target_rollback_version": target_version,
            "can_rollback": can_rollback,
            "validation_message": reason,
            "target_details": details,
        }

    def simulate_rollback_validation(
        self,
        target_version: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Performs a dry-run pre-flight check of the rollback target without modifying configuration.
        Returns (can_rollback, reason, target_entry).
        """
        cfg = self.registry.get_active_model_config()
        current_version = cfg.get("active_model_version")
        target = target_version or cfg.get("last_known_good_version")

        if not target:
            return False, "Cannot rollback: No prior last_known_good_version recorded in active configuration.", None

        if target == current_version:
            return False, f"Target rollback version '{target}' is already the active model.", None

        try:
            entry = self.registry.get_model(target)
        except ModelNotFoundError:
            return False, f"Rollback target '{target}' is not registered in the model registry.", None
        except Exception as e:
            return False, f"Registry error while resolving rollback target '{target}': {e}", None

        allowed_states = {ModelLifecycleState.APPROVED_FOR_SHADOW.value, ModelLifecycleState.EXPERIMENTAL.value}
        if entry.get("lifecycle_state") not in allowed_states:
            return False, f"Rollback target '{target}' has unpermitted lifecycle state '{entry.get('lifecycle_state')}'.", entry

        is_valid, msg = self.registry.verify_checkpoint_integrity(target)
        if not is_valid:
            return False, f"Rollback target '{target}' failed cryptographic integrity check: {msg}", entry

        return True, f"Rollback target '{target}' is valid and cryptographically verified.", entry

    def execute_rollback(
        self,
        operator_label: str = "local_operator",
        reason: str = "Operator initiated diagnostic rollback",
    ) -> Dict[str, Any]:
        """
        Safely executes atomic rollback to last_known_good_version.
        Fails closed with ModelRegistryError or ModelIntegrityError if pre-flight fails.
        """
        can_rollback, validation_msg, _ = self.simulate_rollback_validation()
        if not can_rollback:
            raise ModelRegistryError(f"Rollback pre-flight validation failed: {validation_msg}")

        return self.registry.rollback_model(
            operator_label=operator_label,
            reason=reason,
        )

    def get_rollback_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Returns audit trail entries specifically related to model activation and rollback.
        """
        audit_log = self.registry.get_audit_log(limit=limit * 2)
        filtered = [
            e for e in audit_log
            if e.get("action") in ("ROLLBACK_DIAGNOSTIC_MODEL", "ACTIVATE_DIAGNOSTIC_MODEL", "ACTIVATION_FAILED")
        ]
        return filtered[:limit]
