"""
Hybrid Decision Engine and Safety Guardrails.
Part of Seva Cyber Sandbox (Phase 4).

ARCHITECTURE & DESIGN PRINCIPLES:
1. Additive Hybrid Architecture:
   Combines three complementary evidence layers:
   - Layer 1: Deterministic Vernacular Pattern Rules & Capability Safeguards (Authoritative).
   - Layer 2: Reviewed Threat Intelligence Indicators (Corroborating Evidence).
   - Layer 3: Custom Neural Model with Randomly Initialized Weights (Diagnostic / Experimental).
2. Operating Modes:
   - Mode A: 'shadow' (Default)
     Existing rule-based detection remains fully authoritative. The custom neural
     model runs locally in parallel as an additional diagnostic. Model predictions
     do NOT alter production risk scores, severity levels, or automated alerts.
     The production score delta is strictly zero.
   - Mode B: 'rules_only'
     Completely disables experimental neural model loading and inference. Runs
     strictly deterministic rules and threat intelligence.
   - Mode C: 'advisory'
     Separately testable policy that proposes explanatory advisory guidance based
     on model and rule evidence, but CANNOT automatically mark a message as verified
     fraud, clear a strong warning, or alter production risk scores.
3. Decision Guardrails (Non-Negotiable Boundaries):
   - GR-01: Rule Primacy in Shadow Mode — Model predictions cannot change production risk scores.
   - GR-02: Non-Suppression — Strong deterministic rules (score >= 50 or high-severity)
            cannot be suppressed by a benign model prediction.
   - GR-03: No Uncorroborated Fraud — A model prediction alone cannot establish confirmed fraud.
   - GR-04: Threat Intelligence Tiering — Only reviewed indicators contribute corroborating risk.
            Unreviewed leads remain investigative and do NOT increase trusted risk scores.
   - GR-05: Protective Advisory Grounding — Genuine security awareness alerts cannot be
            overridden as fraud without strong deterministic attack indicators.
   - GR-06: No Keyword Overreaction — Benign mentions of OTP, UPI, or URLs do not trigger fraud.
   - GR-07: Safe Checkpoint Validation & Fallback — Missing, corrupted, or non-finite outputs
            safely fall back to rule-based decisions without crashing.
   - GR-08: Zero Raw Data Retention — Diagnostics and audit records store only non-sensitive metrics.
   - GR-09: Strict Score Bounds — Risk scores are strictly bounded in [0, 100].
   - GR-10: Configuration Fail-Safe — Invalid or malformed modes fall back to 'shadow'.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid
import numpy as np

from src.dataset_preprocessing import preprocess_for_neural_model, NEURAL_PREPROCESSING_VERSION
from src.phishing_detector import analyze_message_text
from src.risk_scorer import apply_threat_intelligence_to_score, score_message_analysis
from src.custom_model import (
    IDX_TO_LABEL,
    LABEL_TO_IDX,
    NUM_CLASSES,
    CharacterNGramHasher,
    CustomNeuralClassifier,
    load_custom_model,
)

logger = logging.getLogger(__name__)

ENGINE_VERSION = "hybrid-engine-v1.0.0"
DEFAULT_CHECKPOINT_DIR = "models/experimental_custom_v1"
ENV_OPERATING_MODE_KEY = "HYBRID_ENGINE_MODE"


class HybridOperatingMode(str, Enum):
    """Supported operating modes for the hybrid decision engine."""
    SHADOW = "shadow"
    RULES_ONLY = "rules_only"
    ADVISORY = "advisory"


def parse_operating_mode(mode_val: Optional[Union[str, HybridOperatingMode]]) -> HybridOperatingMode:
    """
    Parses and validates the operating mode.
    Checks explicit parameter, environment variable, active configuration file,
    and fails safe to SHADOW if missing, invalid, or malformed.
    """
    if mode_val is None:
        if ENV_OPERATING_MODE_KEY in os.environ:
            mode_val = os.environ.get(ENV_OPERATING_MODE_KEY, "").strip().lower()
        else:
            active_cfg_path = os.environ.get("SEVA_ACTIVE_CONFIG_PATH") or os.path.join("models", "active_model_config.json")
            if os.path.isfile(active_cfg_path):
                try:
                    with open(active_cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                    mode_val = cfg.get("operating_mode")
                except Exception:
                    mode_val = "shadow"
            else:
                mode_val = "shadow"

    if isinstance(mode_val, HybridOperatingMode):
        return mode_val

    clean_str = str(mode_val).strip().lower()
    for valid_mode in HybridOperatingMode:
        if clean_str == valid_mode.value:
            return valid_mode

    # Fail-safe default
    logger.warning(
        "Invalid hybrid engine mode '%s' requested. Failing safe to default '%s'.",
        mode_val,
        HybridOperatingMode.SHADOW.value,
    )
    return HybridOperatingMode.SHADOW


class SafeModelHolder:
    """
    Safe lifecycle manager for the experimental custom neural model.
    Ensures safe loading, caching, tensor validation, and graceful fallback.
    """

    def __init__(
        self,
        checkpoint_dir: Optional[str] = None,
        registry: Optional[Any] = None,
    ):
        self.explicit_checkpoint_dir = checkpoint_dir
        self.registry = registry
        if checkpoint_dir is None:
            if registry is not None and hasattr(registry, "get_active_model_config"):
                try:
                    cfg = registry.get_active_model_config()
                    checkpoint_dir = cfg.get("checkpoint_rel_path") or DEFAULT_CHECKPOINT_DIR
                except Exception:
                    checkpoint_dir = DEFAULT_CHECKPOINT_DIR
            else:
                active_cfg_path = os.environ.get("SEVA_ACTIVE_CONFIG_PATH") or os.path.join("models", "active_model_config.json")
                if os.path.isfile(active_cfg_path):
                    try:
                        with open(active_cfg_path, "r", encoding="utf-8") as f:
                            cfg = json.load(f)
                        checkpoint_dir = cfg.get("checkpoint_rel_path") or DEFAULT_CHECKPOINT_DIR
                    except Exception:
                        checkpoint_dir = DEFAULT_CHECKPOINT_DIR
                else:
                    checkpoint_dir = DEFAULT_CHECKPOINT_DIR
        self.checkpoint_dir = checkpoint_dir
        self._model: Optional[CustomNeuralClassifier] = None
        self._hasher: Optional[CharacterNGramHasher] = None
        self._metadata: Optional[Dict[str, Any]] = None
        self._load_attempted: bool = False
        self._load_error: Optional[str] = None

    @property
    def is_available(self) -> bool:
        """Returns True if the model loaded successfully and passed validation."""
        self._ensure_loaded()
        return self._model is not None and self._load_error is None

    @property
    def load_error(self) -> Optional[str]:
        """Returns the fallback reason or error string if model is unavailable."""
        self._ensure_loaded()
        return self._load_error

    @property
    def metadata(self) -> Optional[Dict[str, Any]]:
        self._ensure_loaded()
        return self._metadata

    def _ensure_loaded(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True

        from src.model_registry import get_default_model_registry, ModelSecurityError
        registry = self.registry or get_default_model_registry()

        # Step 1: Pre-loading cryptographic verification and path bounds check (SEC-05-02)
        if self.explicit_checkpoint_dir is None:
            is_valid, msg, entry = registry.verify_active_model_for_loading()
            if not is_valid or entry is None:
                self._load_error = f"Active model loading failed integrity verification: {msg}"
                return
            try:
                resolved_ckpt = registry._validate_safe_path(entry["checkpoint_rel_path"])
            except ModelSecurityError as e:
                self._load_error = f"Path security violation: {e}"
                return
            self.checkpoint_dir = entry["checkpoint_rel_path"]
        else:
            is_valid, msg, entry = registry.verify_checkpoint_for_loading(self.explicit_checkpoint_dir)
            if not is_valid:
                self._load_error = msg
                return
            try:
                resolved_ckpt = registry._validate_safe_path(self.explicit_checkpoint_dir)
            except ModelSecurityError as e:
                self._load_error = f"Path security violation: {e}"
                return
            self.checkpoint_dir = self.explicit_checkpoint_dir

        weights_file = os.path.join(resolved_ckpt, "model_weights.npz")
        meta_file = os.path.join(resolved_ckpt, "model_metadata.json")

        if not os.path.isfile(weights_file):
            self._load_error = f"Weights archive missing: {weights_file}"
            return
        if not os.path.isfile(meta_file):
            self._load_error = f"Metadata descriptor missing: {meta_file}"
            return

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)

            # Validate metadata structure
            required_meta_keys = {"model_version", "input_dim", "hidden_dim1", "hidden_dim2", "num_classes"}
            if not required_meta_keys.issubset(set(meta.keys())):
                self._load_error = f"Malformed metadata: missing keys {required_meta_keys - set(meta.keys())}"
                return

            # Load model checkpoint safely with allow_pickle=False
            model = CustomNeuralClassifier.load_checkpoint(resolved_ckpt)

            # Test inference on empty and dummy input to verify finite outputs
            test_vec = np.zeros((1, model.input_dim), dtype=np.float32)
            test_probs = model.predict_proba(test_vec)
            if not np.all(np.isfinite(test_probs)):
                self._load_error = "Model self-test failed: non-finite output probabilities detected."
                return

            self._model = model
            self._hasher = model.hasher
            self._metadata = meta

        except Exception as e:
            self._load_error = f"Failed to load checkpoint safely: {str(e)}"
            self._model = None
            self._hasher = None
            self._metadata = None

    def predict_safe(self, text: str) -> Dict[str, Any]:
        """
        Executes inference on text with complete exception handling and finite-value guarantees.
        """
        self._ensure_loaded()
        if not self.is_available or self._model is None:
            return {
                "is_enabled": True,
                "is_available": False,
                "predicted_label": None,
                "predicted_index": None,
                "confidence": 0.0,
                "confidence_scores": None,
                "is_calibrated": False,
                "model_version": None,
                "checkpoint_dir": self.checkpoint_dir,
                "fallback_reason": self._load_error or "Model unavailable",
                "confidence_warning": "Model inference failed; rule-based detection was used as fallback.",
            }

        try:
            norm_text = preprocess_for_neural_model(text)
            pred = self._model.predict_one(norm_text, self._hasher)
            probs = pred.get("probabilities", {})

            # Validate that all probability values are finite numbers between 0 and 1
            for k, v in probs.items():
                if not isinstance(v, (int, float)) or not np.isfinite(v) or v < 0.0 or v > 1.0:
                    return {
                        "is_enabled": True,
                        "is_available": False,
                        "predicted_label": None,
                        "predicted_index": None,
                        "confidence": 0.0,
                        "confidence_scores": None,
                        "is_calibrated": False,
                        "model_version": self._model.model_version,
                        "checkpoint_dir": self.checkpoint_dir,
                        "fallback_reason": f"Non-finite or out-of-bounds probability for class '{k}': {v}",
                        "confidence_warning": "Rejected non-finite model output; using rule-based fallback.",
                    }

            return {
                "is_enabled": True,
                "is_available": True,
                "predicted_label": pred["predicted_label"],
                "predicted_index": pred["predicted_index"],
                "confidence": pred["confidence"],
                "confidence_scores": pred["probabilities"],
                "is_calibrated": False,
                "model_version": pred["model_version"],
                "preprocessing_version": NEURAL_PREPROCESSING_VERSION,
                "checkpoint_dir": self.checkpoint_dir,
                "fallback_reason": None,
                "confidence_warning": (
                    "Softmax scores are uncalibrated cross-entropy estimates from an experimental model. "
                    "Do not interpret as certified Bayesian probabilities."
                ),
            }

        except Exception as e:
            return {
                "is_enabled": True,
                "is_available": False,
                "predicted_label": None,
                "predicted_index": None,
                "confidence": 0.0,
                "confidence_scores": None,
                "is_calibrated": False,
                "model_version": self._model.model_version if self._model else None,
                "checkpoint_dir": self.checkpoint_dir,
                "fallback_reason": f"Inference execution error: {str(e)}",
                "confidence_warning": "Model execution error; rule-based fallback applied.",
            }


class HybridDecisionEngine:
    """
    Additive Hybrid Decision Engine combining deterministic rules,
    reviewed threat intelligence, and experimental neural models with strict safety guardrails.
    """

    def __init__(
        self,
        operating_mode: Optional[Union[str, HybridOperatingMode]] = None,
        checkpoint_dir: Optional[str] = None,
        case_repository: Optional[Any] = None,
        model_registry: Optional[Any] = None,
    ):
        if operating_mode is None and model_registry is not None and hasattr(model_registry, "get_active_model_config"):
            try:
                active_cfg = model_registry.get_active_model_config()
                operating_mode = active_cfg.get("operating_mode")
            except Exception:
                operating_mode = None
        self.operating_mode = parse_operating_mode(operating_mode)
        self.model_registry = model_registry
        self.model_holder = SafeModelHolder(checkpoint_dir, registry=model_registry)
        self.checkpoint_dir = checkpoint_dir or self.model_holder.checkpoint_dir
        self.case_repo = case_repository

    def set_operating_mode(self, mode: Union[str, HybridOperatingMode]) -> None:
        """Dynamically updates the operating mode with safe validation."""
        self.operating_mode = parse_operating_mode(mode)

    def evaluate_message(
        self,
        message_text: str,
        rule_analysis: Optional[Dict[str, Any]] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
        mode_override: Optional[Union[str, HybridOperatingMode]] = None,
    ) -> Dict[str, Any]:
        """
        Executes hybrid evaluation of a text message across rules, intelligence, and neural model.

        SAFETY BOUNDARY:
        - In 'shadow' mode, production risk score is strictly determined by rules and reviewed intel.
          The custom model's score difference is guaranteed to be zero.
        - In 'rules_only' mode, model inference is completely disabled.
        - In 'advisory' mode, advisory notes are generated without altering production risk scores.
        """
        active_mode = parse_operating_mode(mode_override) if mode_override is not None else self.operating_mode
        timestamp_utc = datetime.now(timezone.utc).isoformat()
        clean_text = message_text.strip() if isinstance(message_text, str) else ""

        # ---------------------------------------------------------------------
        # 1. Deterministic Rule-Based Analysis (Authoritative Core)
        # ---------------------------------------------------------------------
        if rule_analysis is None:
            rule_analysis = analyze_message_text(clean_text)

        scored_rules = score_message_analysis(rule_analysis)
        base_rule_score = int(scored_rules["score"])

        # Determine semantic rule label
        if rule_analysis.get("is_empty"):
            rule_label = "empty"
        elif rule_analysis.get("protective_advisory_detected"):
            rule_label = "protective_advisory"
        elif base_rule_score >= 20 or len(rule_analysis.get("findings", [])) > 0:
            rule_label = "phishing"
        else:
            rule_label = "legitimate"

        rule_based_evidence = {
            "score": base_rule_score,
            "risk_level": scored_rules["risk_level"],
            "badge_color": scored_rules["badge_color"],
            "rule_label": rule_label,
            "findings_count": len(rule_analysis.get("findings", [])),
            "findings": [
                {
                    "id": f["id"],
                    "category": f["category"],
                    "severity": f["severity"],
                    "matched_text": f["matched_text"],
                }
                for f in rule_analysis.get("findings", [])
            ],
            "protective_advisory_detected": bool(rule_analysis.get("protective_advisory_detected")),
            "context_only_suppressed": bool(rule_analysis.get("context_only_suppressed")),
            "extracted_urls": list(rule_analysis.get("extracted_urls", [])),
            "script_detected": rule_analysis.get("script_detected", "unknown"),
        }

        # ---------------------------------------------------------------------
        # 2. Threat Intelligence Integration (Reviewed vs. Unreviewed)
        # ---------------------------------------------------------------------
        # If threat_intel wasn't supplied but a case repository is attached, query it
        if threat_intel is None and self.case_repo is not None and hasattr(self.case_repo, "match_indicators"):
            try:
                observables = {
                    "urls": rule_analysis.get("extracted_urls", []),
                    "domains": [],
                    "phone_numbers": [],
                    "apk_hashes": [],
                }
                threat_intel = self.case_repo.match_indicators(observables)
            except Exception as e:
                logger.warning("Threat intelligence lookup failed safely: %s", e)
                threat_intel = None

        intel_summary = {
            "has_matches": False,
            "trusted_matches_count": 0,
            "unreviewed_leads_count": 0,
            "highest_severity": None,
            "highest_confidence": 0,
            "trusted_matches": [],
            "unreviewed_leads": [],
        }

        production_score = base_rule_score
        scored_production = scored_rules

        if threat_intel and threat_intel.get("has_matches"):
            trusted_count = int(threat_intel.get("trusted_matches_count", 0))
            unreviewed_count = int(threat_intel.get("unreviewed_leads_count", 0))

            intel_summary = {
                "has_matches": True,
                "trusted_matches_count": trusted_count,
                "unreviewed_leads_count": unreviewed_count,
                "highest_severity": threat_intel.get("highest_severity"),
                "highest_confidence": int(threat_intel.get("highest_confidence", 0)),
                "trusted_matches": [
                    {
                        "indicator_id": m.get("indicator_id"),
                        "indicator_type": m.get("indicator_type"),
                        "severity": m.get("severity"),
                        "confidence_score": m.get("confidence_score"),
                    }
                    for m in threat_intel.get("trusted_matches", [])
                ],
                "unreviewed_leads": [
                    {
                        "indicator_id": m.get("indicator_id"),
                        "indicator_type": m.get("indicator_type"),
                        "severity": m.get("severity"),
                        "confidence_score": m.get("confidence_score"),
                    }
                    for m in threat_intel.get("unreviewed_leads", [])
                ],
            }

            # GR-04: Only reviewed indicators adjust production score
            scored_production = apply_threat_intelligence_to_score(scored_rules, threat_intel)
            production_score = int(scored_production["score"])

        # ---------------------------------------------------------------------
        # 3. Experimental Neural Model Inference
        # ---------------------------------------------------------------------
        if active_mode == HybridOperatingMode.RULES_ONLY or rule_analysis.get("is_empty"):
            experimental_model = {
                "is_enabled": False,
                "is_available": False,
                "predicted_label": None,
                "predicted_index": None,
                "confidence": 0.0,
                "confidence_scores": None,
                "is_calibrated": False,
                "model_version": None,
                "checkpoint_dir": self.checkpoint_dir,
                "fallback_reason": "Disabled by rules_only operating mode" if active_mode == HybridOperatingMode.RULES_ONLY else "Input is empty",
                "confidence_warning": "Model inference is disabled in rules_only mode.",
            }
        else:
            experimental_model = self.model_holder.predict_safe(clean_text)

        # ---------------------------------------------------------------------
        # 4. Concordance & Disagreement Analysis
        # ---------------------------------------------------------------------
        model_label = experimental_model.get("predicted_label")

        if not experimental_model.get("is_available") or model_label is None or rule_label == "empty":
            concordance_status = "NOT_APPLICABLE"
            disagreement_details = None
        elif rule_label == model_label:
            concordance_status = "AGREEMENT"
            disagreement_details = None
        else:
            concordance_status = "DISAGREEMENT"
            disagreement_details = (
                f"Rule-based detection classified input as '{rule_label}' (score {production_score}), "
                f"while experimental neural model predicted '{model_label}' "
                f"(uncalibrated confidence: {experimental_model.get('confidence', 0.0):.4f})."
            )

        # ---------------------------------------------------------------------
        # 5. Guardrail Application & Final Decision
        # ---------------------------------------------------------------------
        guardrails_applied: List[str] = []
        decision_reasons: List[str] = []
        advisory_notes: List[str] = []

        # Start with production score and badge
        final_score = production_score
        final_risk_level = scored_production["risk_level"]
        final_badge_color = scored_production["badge_color"]

        # Action verdict mapping
        if rule_analysis.get("is_empty"):
            action_verdict = "NO_INPUT"
            decision_reasons.append("Empty or whitespace-only input received.")
        elif final_score >= 50:
            action_verdict = "HIGH_RISK_BLOCK"
            decision_reasons.append("High-risk phishing indicators or verified threat intelligence detected.")
        elif final_score >= 20:
            action_verdict = "SUSPICIOUS_REVIEW"
            decision_reasons.append("Potentially suspicious patterns found. Independent verification recommended.")
        else:
            action_verdict = "INFORMATIONAL_SAFE"
            decision_reasons.append("No strong phishing indicators detected by deterministic rules.")

        # GR-01: Rule Primacy in Shadow Mode
        if active_mode == HybridOperatingMode.SHADOW:
            guardrails_applied.append(
                "GR-01 (Rule Primacy): Production score determined strictly by deterministic rules. "
                "Experimental model predictions do NOT alter risk scores or verdict."
            )

        # GR-02: Non-Suppression of Strong Rule Evidence
        if base_rule_score >= 50 and model_label in ("legitimate", "protective_advisory"):
            guardrails_applied.append(
                "GR-02 (Non-Suppression): High-severity deterministic rule findings cannot be suppressed "
                "by a benign or advisory neural model prediction."
            )

        # GR-03: No Fraud on Model Prediction Alone
        if base_rule_score < 20 and model_label == "phishing" and intel_summary["trusted_matches_count"] == 0:
            guardrails_applied.append(
                "GR-03 (No Fraud on Model Alone): Experimental neural model predicted 'phishing', "
                "but deterministic rules found no scam indicators. Model prediction alone cannot establish fraud."
            )

        # GR-04: Unreviewed Threat Leads Non-Scoring
        if intel_summary["unreviewed_leads_count"] > 0:
            guardrails_applied.append(
                f"GR-04 (Threat Intelligence Tiering): {intel_summary['unreviewed_leads_count']} unreviewed lead(s) "
                "recorded for investigation but excluded from trusted risk scoring."
            )

        # GR-05: Protective Advisory Grounding
        if rule_label == "protective_advisory" and model_label == "phishing":
            guardrails_applied.append(
                "GR-05 (Protective Advisory Grounding): Legitimate security awareness message preserved. "
                "Model phishing prediction rejected due to protective phrasing."
            )

        # GR-06: No Keyword Overreaction
        if rule_based_evidence.get("context_only_suppressed"):
            guardrails_applied.append(
                "GR-06 (Context Safeguard): Mention of utility/bank without scam indicators preserved as safe."
            )

        # GR-07: Safe Fallback
        if active_mode != HybridOperatingMode.RULES_ONLY and not experimental_model.get("is_available"):
            guardrails_applied.append(
                f"GR-07 (Safe Checkpoint Fallback): Model unavailable ({experimental_model.get('fallback_reason')}). "
                "Failing safe to deterministic rule-based evaluation."
            )

        # GR-09: Score Bounds Guarantee
        final_score = int(max(0, min(100, final_score)))
        guardrails_applied.append("GR-09 (Score Bounds): Risk score mathematically verified in [0, 100].")

        # Advisory Mode Policy Guidance (Mode C)
        if active_mode == HybridOperatingMode.ADVISORY:
            guardrails_applied.append(
                "Mode C (Advisory Policy Active): Providing dual explanatory guidance. "
                "Risk score remains strictly bound to production rules."
            )
            if concordance_status == "AGREEMENT":
                advisory_notes.append(
                    f"Consensus: Rules and neural model agree on '{rule_label}'. Confidence: {experimental_model.get('confidence', 0.0):.2%} (uncalibrated)."
                )
            elif concordance_status == "DISAGREEMENT":
                advisory_notes.append(
                    f"Investigative Disagreement: Rules indicate '{rule_label}', whereas experimental model suggests '{model_label}' "
                    f"({experimental_model.get('confidence', 0.0):.2%}). Analyst verification recommended."
                )

        # Diagnostic audit metadata (Zero Raw Data & Non-Linkable Hashes - GR-08)
        # Coarse length bucket prevents precise character-count fingerprinting
        txt_len = len(clean_text)
        if txt_len == 0:
            len_bucket = "empty (0)"
        elif txt_len < 100:
            len_bucket = "short (<100)"
        elif txt_len <= 300:
            len_bucket = "medium (100-300)"
        else:
            len_bucket = "long (>300)"

        # Random non-message-derived event ID for safe ephemeral log correlation.
        # Governance note: Pseudorandom IDs must not be characterized as inherently anonymous
        # if correlated with local process logs; local operational logs should be purged after
        # the minimum necessary operational period.
        diagnostic_event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"

        audit_metadata = {
            "diagnostic_event_id": diagnostic_event_id,
            "length_bucket": len_bucket,
            "script_type": rule_based_evidence.get("script_detected", "unknown"),
            "extracted_urls_count": len(rule_based_evidence.get("extracted_urls", [])),
            "findings_count": rule_based_evidence.get("findings_count", 0),
            "has_threat_intel_matches": intel_summary["has_matches"],
            "model_evaluated": bool(experimental_model.get("is_available")),
            "concordance_status": concordance_status,
            "preprocessing_version": experimental_model.get("preprocessing_version", NEURAL_PREPROCESSING_VERSION),
            "timestamp_utc": timestamp_utc,
        }
        guardrails_applied.append("GR-08 (Privacy Hardening): Telemetry records non-sensitive coarse metrics only (zero raw text, zero message hashes).")

        # ---------------------------------------------------------------------
        # 6. Structured Output Packaging
        # ---------------------------------------------------------------------
        return {
            "engine_version": ENGINE_VERSION,
            "operating_mode": active_mode.value,
            "rule_based_evidence": rule_based_evidence,
            "threat_intelligence": intel_summary,
            "experimental_model": experimental_model,
            "concordance": {
                "status": concordance_status,
                "rule_label": rule_label,
                "model_label": model_label,
                "disagreement_details": disagreement_details,
            },
            "final_decision": {
                "authoritative_source": "deterministic_rules" if active_mode != HybridOperatingMode.ADVISORY else "deterministic_rules_with_advisory",
                "final_risk_score": final_score,
                "risk_level": final_risk_level,
                "badge_color": final_badge_color,
                "action_verdict": action_verdict,
                "decision_reasons": decision_reasons,
                "guardrails_applied": guardrails_applied,
                "production_score_difference": final_score - production_score,
            },
            "advisory_notes": advisory_notes,
            "audit_metadata": audit_metadata,
        }

    def evaluate_batch(
        self,
        messages: List[str],
        mode_override: Optional[Union[str, HybridOperatingMode]] = None,
    ) -> List[Dict[str, Any]]:
        """Evaluates a batch of text messages sequentially."""
        return [self.evaluate_message(m, mode_override=mode_override) for m in messages]


# =============================================================================
# TOP-LEVEL FUNCTIONAL CONVENIENCE INTERFACES
# =============================================================================

_DEFAULT_ENGINE_INSTANCE: Optional[HybridDecisionEngine] = None


def get_default_engine(
    mode: Optional[Union[str, HybridOperatingMode]] = None,
    checkpoint_dir: Optional[str] = None,
    case_repo: Optional[Any] = None,
    model_registry: Optional[Any] = None,
) -> HybridDecisionEngine:
    """Returns or initializes the singleton default hybrid decision engine."""
    global _DEFAULT_ENGINE_INSTANCE
    if _DEFAULT_ENGINE_INSTANCE is None:
        _DEFAULT_ENGINE_INSTANCE = HybridDecisionEngine(
            operating_mode=mode,
            checkpoint_dir=checkpoint_dir,
            case_repository=case_repo,
            model_registry=model_registry,
        )
    elif mode is not None:
        _DEFAULT_ENGINE_INSTANCE.set_operating_mode(mode)
    return _DEFAULT_ENGINE_INSTANCE


def evaluate_message_hybrid(
    message_text: str,
    rule_analysis: Optional[Dict[str, Any]] = None,
    threat_intel: Optional[Dict[str, Any]] = None,
    operating_mode: Optional[Union[str, HybridOperatingMode]] = None,
    checkpoint_dir: Optional[str] = None,
    model_registry: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Main top-level API function for hybrid message evaluation.
    """
    engine = HybridDecisionEngine(
        operating_mode=operating_mode,
        checkpoint_dir=checkpoint_dir,
        model_registry=model_registry,
    )
    return engine.evaluate_message(
        message_text=message_text,
        rule_analysis=rule_analysis,
        threat_intel=threat_intel,
    )
