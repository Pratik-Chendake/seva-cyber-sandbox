"""
Model Disagreement Detection and Human-in-the-Loop Analysis Engine.
Part of Seva Cyber Sandbox (Phase 6.6).

DESIGN & GOVERNANCE ARCHITECTURE:
1. Strict Rule Primacy & Zero Score Delta:
   - Disagreement detection operates strictly in parallel for diagnostic and learning purposes.
   - Authoritative production risk scores and action verdicts are 100% determined by deterministic rules.
   - Production risk score difference is guaranteed to be exactly 0.00 across all categories.
2. Privacy-Preserving Event Architecture:
   - Stores ZERO raw message text, zero sanitized text, zero URLs, and zero direct citizen identifiers.
   - Diagnostic event IDs (EVT-XXXXXXXXXXXX) are pseudorandom (uuid.uuid4()) and non-message-derived.
3. Explicit Consent Curation Gate:
   - Only when affirmative user consent is given (consent_given == True), text is sanitized for local
     training, converted to abstract 1024-dimensional character n-gram feature vectors, and hashed
     with dedicated SEVA_FEEDBACK_HMAC_KEY for future offline training curation.
   - When consent is False, feature extraction is strictly skipped.
4. Unambiguous Decision Mapping:
   - Compares deterministic rule outcomes and neural predictions across the canonical classes:
     {'phishing', 'legitimate', 'protective_advisory'}.
   - If outputs are unclassifiable, missing, empty, or from rules-only mode, classifies as 'non_comparable'
     rather than fabricating an artificial disagreement.
"""

from datetime import datetime, timezone
from enum import Enum
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from src.case_repository import (
    CaseRepository,
    get_default_case_repository,
    get_utc_now_iso,
)

logger = logging.getLogger(__name__)


class DisagreementEventType(str, Enum):
    """Canonical event classifications between deterministic rules and neural shadow predictions."""
    RULE_PHISHING_MODEL_LEGITIMATE = "rule_phishing_model_legitimate"
    RULE_PHISHING_MODEL_ADVISORY = "rule_phishing_model_advisory"
    RULE_LEGITIMATE_MODEL_PHISHING = "rule_legitimate_model_phishing"
    RULE_LEGITIMATE_MODEL_ADVISORY = "rule_legitimate_model_advisory"
    RULE_ADVISORY_MODEL_PHISHING = "rule_advisory_model_phishing"
    RULE_ADVISORY_MODEL_LEGITIMATE = "rule_advisory_model_legitimate"
    AGREEMENT = "agreement"
    NON_COMPARABLE = "non_comparable"


class ReviewOutcome(str, Enum):
    """Canonical human adjudication outcomes."""
    PHISHING = "phishing"
    LEGITIMATE = "legitimate"
    PROTECTIVE_ADVISORY = "protective_advisory"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ReviewerAssessment(str, Enum):
    """Structured operator comparative assessments."""
    RULES_CORRECT = "rules_correct"
    MODEL_CORRECT = "model_correct"
    BOTH_INVESTIGATE = "both_investigate"
    NEITHER_SUFFICIENT = "neither_sufficient"


class ReviewState(str, Enum):
    """Lifecycle state of an operator review."""
    PENDING = "pending"
    IN_REVIEW = "in_review"
    COMPLETED = "completed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SUPERSEDED = "superseded"
    REJECTED = "rejected"


DEVANAGARI_RANGE = re.compile(r"[\u0900-\u097F]")
LATIN_RANGE = re.compile(r"[A-Za-z]")


def detect_script_and_language_category(text: str) -> Tuple[str, str]:
    """
    Infers coarse script and language categories without persisting raw text.
    Returns (script_category, language_category).
    """
    if not text or not isinstance(text, str) or not text.strip():
        return "unknown", "unknown"

    has_dev = bool(DEVANAGARI_RANGE.search(text))
    has_lat = bool(LATIN_RANGE.search(text))

    if has_dev and has_lat:
        script = "mixed"
        lang = "mr-en"
    elif has_dev:
        script = "devanagari"
        lang = "marathi"
    elif has_lat:
        script = "latin"
        # Coarse heuristic: vernacular tokens indicate Romanized Marathi
        lower_t = text.lower()
        vernacular_tokens = ["aapan", "aaple", "ahe", "kara", "krupaya", "shasan", "pan", "yojna", "yojana"]
        if any(w in lower_t for w in vernacular_tokens):
            lang = "mr-Latn"
        else:
            lang = "english"
    else:
        script = "unknown"
        lang = "unknown"

    return script, lang


class DisagreementEngine:
    """
    Autonomous engine for detecting, categorizing, recording, and coordinating
    human-in-the-loop review of model-rule disagreements.
    """

    def __init__(self, repository: Optional[CaseRepository] = None):
        self.repository = repository or get_default_case_repository()

    def classify_evaluation(
        self,
        evaluation_result: Dict[str, Any],
        raw_text_for_metadata_only: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Classifies concordance between deterministic rules and experimental neural model.

        SAFETY BOUNDARY:
        - Never alters final_decision, risk scores, or production verdicts.
        - Emits 'non_comparable' when model inference is disabled, missing, failed, or rule label is ambiguous.
        - Emits random non-message-derived event ID.
        """
        op_mode = evaluation_result.get("operating_mode", "shadow")
        rule_evidence = evaluation_result.get("rule_based_evidence", {})
        rule_label = rule_evidence.get("rule_label")
        rule_score = rule_evidence.get("score")

        exp_model = evaluation_result.get("experimental_model", {})
        model_available = bool(exp_model.get("is_available"))
        model_enabled = bool(exp_model.get("is_enabled"))
        model_label = exp_model.get("predicted_label")
        model_version = exp_model.get("model_version")
        model_confidence = exp_model.get("confidence")

        # Determine Coarse Buckets
        if rule_score is not None:
            if rule_score >= 50:
                rule_score_bucket = "high (>=50)"
            elif rule_score >= 20:
                rule_score_bucket = "suspicious (20-49)"
            else:
                rule_score_bucket = "low (<20)"
        else:
            rule_score_bucket = "unknown"

        if model_confidence is not None and model_available:
            if model_confidence >= 0.80:
                model_conf_bucket = "high (>=0.8)"
            elif model_confidence >= 0.50:
                model_conf_bucket = "medium (0.5-0.8)"
            else:
                model_conf_bucket = "low (<0.5)"
        else:
            model_conf_bucket = "none"

        # Determine Script and Length Buckets from audit metadata or text length
        audit_meta = evaluation_result.get("audit_metadata", {})
        length_bucket = audit_meta.get("length_bucket", "short (<100)")

        if raw_text_for_metadata_only:
            script_cat, lang_cat = detect_script_and_language_category(raw_text_for_metadata_only)
        else:
            script_desc = rule_evidence.get("script_detected", "")
            if "Devanagari" in script_desc:
                script_cat, lang_cat = "devanagari", "marathi"
            elif "Romanized" in script_desc:
                script_cat, lang_cat = "latin", "mr-Latn"
            elif "Latin" in script_desc:
                script_cat, lang_cat = "latin", "english"
            else:
                script_cat, lang_cat = "unknown", "unknown"

        # ---------------------------------------------------------------------
        # Unambiguous Concordance & Disagreement Logic
        # ---------------------------------------------------------------------
        non_comp_reasons: List[str] = []

        if op_mode == "rules_only" or not model_enabled:
            event_type = DisagreementEventType.NON_COMPARABLE.value
            non_comp_reasons.append("Operating mode is rules_only; neural model inference was disabled.")
        elif not model_available or model_label is None:
            event_type = DisagreementEventType.NON_COMPARABLE.value
            fallback_reason = exp_model.get("fallback_reason") or "Model output unavailable"
            non_comp_reasons.append(f"Model unavailable or failed inference: {fallback_reason}")
        elif rule_label in (None, "empty", "unknown", "unclassified"):
            event_type = DisagreementEventType.NON_COMPARABLE.value
            non_comp_reasons.append(f"Deterministic rule outcome '{rule_label}' is non-comparable.")
        elif rule_label == model_label:
            event_type = DisagreementEventType.AGREEMENT.value
        else:
            # Map canonical pairwise disagreements
            mapping = {
                ("phishing", "legitimate"): DisagreementEventType.RULE_PHISHING_MODEL_LEGITIMATE.value,
                ("phishing", "protective_advisory"): DisagreementEventType.RULE_PHISHING_MODEL_ADVISORY.value,
                ("legitimate", "phishing"): DisagreementEventType.RULE_LEGITIMATE_MODEL_PHISHING.value,
                ("legitimate", "protective_advisory"): DisagreementEventType.RULE_LEGITIMATE_MODEL_ADVISORY.value,
                ("protective_advisory", "phishing"): DisagreementEventType.RULE_ADVISORY_MODEL_PHISHING.value,
                ("protective_advisory", "legitimate"): DisagreementEventType.RULE_ADVISORY_MODEL_LEGITIMATE.value,
            }
            event_type = mapping.get((rule_label, model_label), DisagreementEventType.NON_COMPARABLE.value)

        # Generate Random Diagnostic Event Identifier
        event_id = audit_meta.get("diagnostic_event_id") or f"EVT-{uuid.uuid4().hex[:12].upper()}"

        return {
            "event_id": event_id,
            "event_type": event_type,
            "is_disagreement": event_type.startswith("rule_"),
            "is_agreement": event_type == DisagreementEventType.AGREEMENT.value,
            "is_non_comparable": event_type == DisagreementEventType.NON_COMPARABLE.value,
            "rule_decision": rule_label or "unclassified",
            "model_prediction": model_label,
            "model_version": model_version,
            "rule_engine_version": evaluation_result.get("engine_version", "hybrid-engine-v1.0.0"),
            "model_confidence": model_confidence,
            "model_confidence_bucket": model_conf_bucket,
            "rule_score": rule_score,
            "rule_score_bucket": rule_score_bucket,
            "language_category": lang_cat,
            "script_category": script_cat,
            "message_length_bucket": length_bucket,
            "review_state": ReviewState.PENDING.value,
            "created_at_utc": get_utc_now_iso(),
            "non_comparable_reasons": non_comp_reasons,
            "structural_observations": {
                "findings_count": rule_evidence.get("findings_count", 0),
                "extracted_urls_count": len(rule_evidence.get("extracted_urls", [])),
                "protective_advisory_detected": rule_evidence.get("protective_advisory_detected", False),
                "context_only_suppressed": rule_evidence.get("context_only_suppressed", False),
            },
        }

    def process_and_record(
        self,
        message_text: str,
        evaluation_result: Dict[str, Any],
        consent_given: bool = False,
        case_id: Optional[str] = None,
        repository: Optional[CaseRepository] = None,
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes classification and records event in SQLite if consent-appropriate.

        CRITICAL PRIVACY GUARANTEE:
        - NEVER stores raw message_text or sanitized text in the database.
        - If consent_given is True, safely derives 1024-dim features using local sanitizer,
          stores feature record with SEVA_FEEDBACK_HMAC_KEY, and links feature_record_id.
        - If consent_given is False, persists event metadata only with feature_record_id=None.
        """
        repo = repository or self.repository
        clean_text = message_text.strip() if isinstance(message_text, str) else ""

        # Step 1: Classify disagreement event
        event = self.classify_evaluation(evaluation_result, raw_text_for_metadata_only=clean_text)

        # Step 2: Persist Disagreement Event first so case anchor exists in SQLite
        persisted_id = repo.record_disagreement_event(
            event_data=event,
            consent_given=consent_given,
            feature_record_id=None,
            case_id=case_id,
        )
        event["event_id"] = persisted_id

        # Step 3: Consent-Gated Feature Extraction (Phase 6.1.1 pipeline integration)
        feature_record_id: Optional[str] = None
        if consent_given and clean_text:
            from src.dataset_preprocessing import extract_derived_training_features

            success, feat_vec, fingerprint, err = extract_derived_training_features(
                raw_text=clean_text,
                secret=secret,
            )

            if success and feat_vec is not None and fingerprint is not None:
                try:
                    linked_case_id = case_id or persisted_id
                    feat_record = repo.record_training_features(
                        case_id=linked_case_id,
                        feature_vector=feat_vec,
                        dedup_fingerprint=fingerprint,
                        consent_given=True,
                        metadata={
                            "event_id": persisted_id,
                            "event_type": event["event_type"],
                            "rule_decision": event["rule_decision"],
                            "model_prediction": event["model_prediction"],
                        },
                    )
                    feature_record_id = feat_record["feature_record_id"]
                    # Update event with feature_record_id
                    with repo.get_connection() as conn:
                        conn.execute(
                            "UPDATE model_disagreement_events SET feature_record_id = ? WHERE event_id = ?;",
                            (feature_record_id, persisted_id),
                        )
                except Exception as exc:
                    logger.warning("Feature record persistence failed safely: %s", exc)
                    feature_record_id = None
            else:
                logger.info("Feature extraction failed or blocked by privacy gate: %s", err)
                feature_record_id = None

        event["consent_given"] = bool(consent_given)
        event["feature_record_id"] = feature_record_id
        return event

    def submit_review(
        self,
        event_id: str,
        outcome_label: str,
        reviewer_assessment: str,
        confidence_rating: str = "medium",
        reviewer_label: str = "local_operator_unauthenticated",
        notes: str = "",
        supersede_existing: bool = False,
        reason: str = "",
        repository: Optional[CaseRepository] = None,
    ) -> Dict[str, Any]:
        """Coordinates review submission through the repository."""
        repo = repository or self.repository
        return repo.submit_disagreement_review(
            event_id=event_id,
            outcome_label=outcome_label,
            reviewer_assessment=reviewer_assessment,
            confidence_rating=confidence_rating,
            reviewer_label=reviewer_label,
            notes=notes,
            supersede_existing=supersede_existing,
            reason=reason,
        )
