"""
Shadow Mode Controller and Diagnostic Monitoring Module.
Part of Seva Cyber Sandbox (Phase 6.5).

DESIGN & GOVERNANCE ARCHITECTURE:
1. Strict Offline Execution & ₹0 Budget:
   - 100% local CPU operation. Zero remote APIs, telemetry endpoints, or external networks.
2. Rule Primacy Invariance:
   - Disabling shadow inference disables only experimental neural model loading.
   - Deterministic rule-based phishing detection remains 100% authoritative and uninterrupted.
3. Privacy-Preserving Diagnostic Telemetry & Correlation Boundaries:
   - Stores only aggregate integer counters and coarse categorical metrics.
   - STRICTLY PROHIBITS retaining raw text, sanitized text, phone numbers, Aadhaar numbers,
     OTPs, reviewer notes, HMAC fingerprints, or case IDs.
   - Diagnostic event IDs (EVT-XXXXXXXXXXXX) are pseudorandom (uuid.uuid4()) and non-message-derived;
     they must not be characterized as inherently non-linkable or anonymous if correlated
     alongside input messages within local process logs. Local operational log retention
     must be restricted to the minimum necessary period. Zero external telemetry endpoints.
4. Auditable Rollback Coordination:
   - Works with ModelRegistry to provide operator controls for viewing status, disabling
     shadow diagnostics, and restoring previous shadow configurations.
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

METRICS_FILE_NAME = "shadow_metrics.json"


class ShadowMonitorController:
    """
    Local operator controller for monitoring shadow neural models,
    tracking diagnostic statistics with strict privacy controls,
    and managing safe shadow enable/disable and rollback operations.
    """

    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        metrics_file_path: Optional[str] = None,
    ):
        self.registry = registry or get_default_model_registry()
        self.project_root = self.registry.project_root
        self.models_dir = self.registry.models_dir
        self.metrics_path = metrics_file_path or os.path.join(self.models_dir, METRICS_FILE_NAME)
        self._ensure_metrics_initialized()

    def _ensure_metrics_initialized(self) -> None:
        """Initializes empty aggregate metrics store if not present."""
        if not os.path.exists(self.metrics_path):
            initial_metrics = {
                "metrics_schema_version": "1.0.0",
                "initialized_at_utc": datetime.now(timezone.utc).isoformat(),
                "last_updated_utc": datetime.now(timezone.utc).isoformat(),
                "aggregate_counts": {
                    "total_evaluations": 0,
                    "model_available_evaluations": 0,
                    "model_fallback_evaluations": 0,
                    "phishing_predictions": 0,
                    "legitimate_predictions": 0,
                    "protective_advisory_predictions": 0,
                    "agreements": 0,
                    "disagreements": 0,
                },
                "disagreement_breakdown": {
                    "rule_phish_model_legit": 0,
                    "rule_phish_model_advisory": 0,
                    "rule_legit_model_phish": 0,
                    "rule_legit_model_advisory": 0,
                    "rule_advisory_model_phish": 0,
                    "rule_advisory_model_legit": 0,
                },
            }
            self.registry._save_json_atomic(self.metrics_path, initial_metrics)

    def _load_metrics(self) -> Dict[str, Any]:
        """Safely loads metrics JSON."""
        try:
            return self.registry._load_json(self.metrics_path)
        except Exception:
            self._ensure_metrics_initialized()
            return self.registry._load_json(self.metrics_path)

    # -------------------------------------------------------------------------
    # OPERATOR STATUS INTERFACES
    # -------------------------------------------------------------------------

    def get_current_shadow_version(self) -> Optional[str]:
        """Returns the currently configured active shadow model version."""
        cfg = self.registry.get_active_model_config()
        return cfg.get("active_model_version")

    def get_shadow_load_status(self) -> Dict[str, Any]:
        """
        Inspects active configuration, cryptographic integrity, and load readiness.
        Returns a complete health and diagnostic status descriptor.
        """
        cfg = self.registry.get_active_model_config()
        active_version = cfg.get("active_model_version")
        operating_mode = cfg.get("operating_mode", "shadow")
        last_known_good = cfg.get("last_known_good_version")

        status_info = {
            "active_model_version": active_version,
            "operating_mode": operating_mode,
            "is_enabled": operating_mode != "rules_only",
            "is_available": False,
            "integrity_verified": False,
            "lifecycle_state": None,
            "checkpoint_dir": cfg.get("checkpoint_rel_path"),
            "last_known_good_version": last_known_good,
            "load_error": None,
            "is_production_authoritative": False,
            "status_label": "UNAVAILABLE",
        }

        if operating_mode == "rules_only":
            status_info["status_label"] = "DISABLED_BY_OPERATOR"
            status_info["load_error"] = "Shadow inference is disabled in rules_only mode."
            return status_info

        if not active_version:
            status_info["status_label"] = "NO_ACTIVE_MODEL"
            status_info["load_error"] = "No active model version specified in active_model_config.json."
            return status_info

        try:
            entry = self.registry.get_model(active_version)
            status_info["lifecycle_state"] = entry.get("lifecycle_state")
            status_info["checkpoint_dir"] = entry.get("checkpoint_rel_path")
        except ModelNotFoundError:
            status_info["status_label"] = "NOT_REGISTERED"
            status_info["load_error"] = f"Model version '{active_version}' is not registered in model_registry.json."
            return status_info

        # Verify cryptographic integrity
        is_valid, msg = self.registry.verify_checkpoint_integrity(active_version)
        if not is_valid:
            status_info["status_label"] = "INTEGRITY_FAILED"
            status_info["load_error"] = f"Cryptographic integrity failed: {msg}"
            return status_info

        status_info["integrity_verified"] = True

        # Lifecycle gate
        allowed_states = {ModelLifecycleState.APPROVED_FOR_SHADOW.value, ModelLifecycleState.EXPERIMENTAL.value}
        if entry.get("lifecycle_state") not in allowed_states:
            status_info["status_label"] = "LIFECYCLE_UNPERMITTED"
            status_info["load_error"] = f"Unpermitted lifecycle state: '{entry.get('lifecycle_state')}'."
            return status_info

        status_info["is_available"] = True
        status_info["status_label"] = "HEALTHY_SHADOW"
        return status_info

    # -------------------------------------------------------------------------
    # PRIVACY-SAFE TELEMETRY AGGREGATION
    # -------------------------------------------------------------------------

    def record_inference_telemetry(self, eval_result: Dict[str, Any]) -> None:
        """
        Extracts aggregate metrics from an evaluation result and updates counters.
        CRITICAL PRIVACY RULE: Zero raw message strings, zero sanitized text,
        zero user identifiers, and zero hashes are stored.
        """
        metrics = self._load_metrics()
        counts = metrics.setdefault("aggregate_counts", {})
        breakdown = metrics.setdefault("disagreement_breakdown", {})

        counts["total_evaluations"] = counts.get("total_evaluations", 0) + 1

        exp_model = eval_result.get("experimental_model", {})
        if exp_model.get("is_available"):
            counts["model_available_evaluations"] = counts.get("model_available_evaluations", 0) + 1
            pred_label = exp_model.get("predicted_label")
            if pred_label == "phishing":
                counts["phishing_predictions"] = counts.get("phishing_predictions", 0) + 1
            elif pred_label == "legitimate":
                counts["legitimate_predictions"] = counts.get("legitimate_predictions", 0) + 1
            elif pred_label == "protective_advisory":
                counts["protective_advisory_predictions"] = counts.get("protective_advisory_predictions", 0) + 1
        else:
            counts["model_fallback_evaluations"] = counts.get("model_fallback_evaluations", 0) + 1

        concordance = eval_result.get("concordance", {})
        status = concordance.get("status")
        if status == "AGREEMENT":
            counts["agreements"] = counts.get("agreements", 0) + 1
        elif status == "DISAGREEMENT":
            counts["disagreements"] = counts.get("disagreements", 0) + 1
            rule_lbl = concordance.get("rule_label")
            model_lbl = concordance.get("model_label")
            key = f"rule_{rule_lbl}_model_{model_lbl}"
            if key in breakdown:
                breakdown[key] = breakdown.get(key, 0) + 1

        metrics["last_updated_utc"] = datetime.now(timezone.utc).isoformat()
        self.registry._save_json_atomic(self.metrics_path, metrics)

    def get_aggregate_prediction_counts(self) -> Dict[str, int]:
        """Returns coarse aggregate prediction counts."""
        metrics = self._load_metrics()
        return dict(metrics.get("aggregate_counts", {}))

    def get_disagreement_counts(self) -> Dict[str, Any]:
        """Returns rule-to-model disagreement summary."""
        metrics = self._load_metrics()
        return {
            "agreements": metrics.get("aggregate_counts", {}).get("agreements", 0),
            "disagreements": metrics.get("aggregate_counts", {}).get("disagreements", 0),
            "breakdown": dict(metrics.get("disagreement_breakdown", {})),
        }

    def reset_metrics(self) -> None:
        """Resets all aggregate diagnostic counters."""
        if os.path.exists(self.metrics_path):
            try:
                os.remove(self.metrics_path)
            except Exception:
                pass
        self._ensure_metrics_initialized()

    # -------------------------------------------------------------------------
    # OPERATOR CONTROL ACTIONS
    # -------------------------------------------------------------------------

    def disable_shadow_inference(
        self,
        operator_label: str = "local_operator",
        reason: str = "Operator disabled shadow diagnostics",
    ) -> Dict[str, Any]:
        """
        Disables shadow model inference by setting operating_mode to 'rules_only'.
        Preserves deterministic production rules and active model identity.
        """
        return self.registry.disable_shadow_inference(operator_label=operator_label, reason=reason)

    def enable_shadow_inference(
        self,
        operator_label: str = "local_operator",
        reason: str = "Operator enabled shadow diagnostics",
    ) -> Dict[str, Any]:
        """
        Re-enables shadow model inference by setting operating_mode to 'shadow'.
        """
        return self.registry.enable_shadow_inference(operator_label=operator_label, reason=reason)

    def restore_previous_shadow_model(
        self,
        operator_label: str = "local_operator",
        reason: str = "Operator initiated rollback to previous shadow model",
    ) -> Dict[str, Any]:
        """
        Safely rolls back the shadow model configuration to the last known-good version.
        """
        return self.registry.rollback_model(operator_label=operator_label, reason=reason)
