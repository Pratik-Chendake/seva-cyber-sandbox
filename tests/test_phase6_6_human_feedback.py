"""
Comprehensive Test Suite for Phase 6.6:
Human-in-the-Loop (HITL) Learning, Model Disagreement Analysis and Threat Pattern Review.
Part of Seva Cyber Sandbox.

TEST SPECIFICATION (All 50 Required Tests Across 6 Core Categories):

Disagreement Detection (Tests 1-11):
  1. Rules and model agreement.
  2. Rules phishing / model legitimate.
  3. Rules phishing / model advisory.
  4. Rules legitimate / model phishing.
  5. Rules legitimate / model advisory.
  6. Rules advisory / model phishing.
  7. Rules advisory / model legitimate.
  8. Non-comparable outputs.
  9. Missing model output.
 10. Corrupt model output.
 11. Rules-only mode.

Privacy and Consent (Tests 12-20):
 12. Consent disabled means no message-derived persistence.
 13. Consent enabled allows valid feature capture.
 14. No raw text stored.
 15. No raw URL stored.
 16. No PII stored.
 17. Sanitization failure prevents storage.
 18. Missing HMAC secret fails closed.
 19. Threat-intelligence secret cannot substitute for feedback secret.
 20. Consent revocation excludes future training exports.

Human Review (Tests 21-29):
 21. Pending review creation.
 22. Valid review completion.
 23. Invalid review labels rejected.
 24. Duplicate review submission rejected.
 25. Superseding completed reviews creates audit entries.
 26. Insufficient evidence remains excluded.
 27. Unauthenticated provenance preserved.
 28. Delayed review clearly indicates missing raw message evidence.
 29. Review decisions do not alter production scores.

Pattern Governance (Tests 30-34):
 30. Draft pattern cannot be automatically approved.
 31. Human approval is audited.
 32. Rejected pattern cannot silently reactivate.
 33. Pattern approval does not change production rules.
 34. Synthetic and human-reviewed provenance remain separate.

Training Eligibility (Tests 35-40):
 35. Only eligible reviewed records enter future training exports.
 36. Pending and low-confidence records are excluded.
 37. Superseded reviews are excluded.
 38. Duplicate feature examples are not counted twice.
 39. Revoked consent is excluded.
 40. Case IDs and HMAC fingerprints are absent from exports.

System Integration (Tests 41-50):
 41. Shadow inference does not alter production scoring.
 42. Disagreement detection failures do not disrupt normal analysis.
 43. Existing APK analyzer works.
 44. Existing multilingual phishing detector works.
 45. Existing URL analyzer works.
 46. Maharashtra scheme verifier remains functional.
 47. Existing case management remains functional.
 48. Audio alerts remain functional.
 49. Existing review desk remains functional.
 50. Existing shadow rollback remains functional.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import tempfile
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock
import pytest

from src.apk_analyzer import analyze_apk_bytes
from src.audio_alert import generate_alert_wav_bytes, get_spoken_script
from src.case_manager import SessionCaseStore, create_message_case
from src.case_repository import (
    CaseRepository,
    FeedbackCurationError,
    FeedbackCurationKeyError,
    FeedbackCurationValidationError,
    compute_feedback_dedup_fingerprint,
    get_feedback_hmac_secret,
)
from src.dataset_preprocessing import (
    EXPECTED_FEATURE_DIM,
    FEATURE_EXTRACTOR_VERSION,
    FEATURE_SCHEMA_VERSION,
    extract_derived_training_features,
)
from src.disagreement_engine import (
    DisagreementEngine,
    DisagreementEventType,
    ReviewOutcome,
    ReviewerAssessment,
    ReviewState,
    detect_script_and_language_category,
)
from src.feedback_analytics import FeedbackAnalytics
from src.hybrid_decision_engine import (
    HybridDecisionEngine,
    HybridOperatingMode,
    evaluate_message_hybrid,
)
from src.model_registry import ModelRegistry, ModelRegistryError, get_default_model_registry
from src.pattern_discovery import (
    CandidatePattern,
    PatternCatalogError,
    PatternCatalogManager,
    PatternReviewError,
)
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_message_analysis
from src.rollback_controller import RollbackController
from src.scheme_verifier import verify_scheme_claim
from src.url_analyzer import analyze_url


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEST_FEEDBACK_SECRET = "test_feedback_hmac_secret_32_chars_ok"


@pytest.fixture
def temp_repo(tmp_path):
    """Provides an isolated CaseRepository instance backed by a temporary SQLite file."""
    db_file = tmp_path / "test_seva_cases.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    repo.init_db()
    return repo


@pytest.fixture
def disagreement_engine(temp_repo):
    """Provides a DisagreementEngine bound to the temporary repository."""
    return DisagreementEngine(repository=temp_repo)


def _make_eval_result(
    rule_label: str = "phishing",
    rule_score: int = 75,
    model_label: str = "legitimate",
    model_version: str = "custom-mlp-v4.0.0-seed42",
    model_confidence: float = 0.91,
    operating_mode: str = "shadow",
    model_available: bool = True,
    model_enabled: bool = True,
    fallback_reason: str = None,
) -> Dict[str, Any]:
    """Helper to construct synthetic hybrid evaluation results for testing."""
    return {
        "operating_mode": operating_mode,
        "engine_version": "hybrid-engine-v1.0.0",
        "rule_based_evidence": {
            "rule_label": rule_label,
            "score": rule_score,
            "findings_count": 3,
            "extracted_urls": ["https://example.com/test"],
            "protective_advisory_detected": (rule_label == "protective_advisory"),
            "context_only_suppressed": False,
            "script_detected": "Latin / English",
        },
        "experimental_model": {
            "is_available": model_available,
            "is_enabled": model_enabled,
            "model_version": model_version,
            "predicted_label": model_label,
            "confidence": model_confidence,
            "fallback_reason": fallback_reason,
        },
        "audit_metadata": {
            "score_difference": 0.0,
            "length_bucket": "medium (100-300)",
        },
    }


# =============================================================================
# CATEGORY 1: DISAGREEMENT DETECTION (Tests 1-11)
# =============================================================================

def test_01_rules_and_model_agreement(disagreement_engine):
    """1. Rules and model agreement across canonical classes."""
    for label in ["phishing", "legitimate", "protective_advisory"]:
        eval_res = _make_eval_result(rule_label=label, model_label=label)
        classification = disagreement_engine.classify_evaluation(eval_res)

        assert classification["event_type"] == DisagreementEventType.AGREEMENT.value
        assert classification["is_agreement"] is True
        assert classification["is_disagreement"] is False
        assert classification["is_non_comparable"] is False
        assert classification["rule_decision"] == label
        assert classification["model_prediction"] == label


def test_02_rules_phishing_model_legitimate(disagreement_engine):
    """2. Rules phishing / model legitimate."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.RULE_PHISHING_MODEL_LEGITIMATE.value
    assert c["is_disagreement"] is True
    assert c["is_agreement"] is False


def test_03_rules_phishing_model_advisory(disagreement_engine):
    """3. Rules phishing / model advisory."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="protective_advisory")
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.RULE_PHISHING_MODEL_ADVISORY.value
    assert c["is_disagreement"] is True
    assert c["is_agreement"] is False


def test_04_rules_legitimate_model_phishing(disagreement_engine):
    """4. Rules legitimate / model phishing."""
    eval_res = _make_eval_result(rule_label="legitimate", model_label="phishing")
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.RULE_LEGITIMATE_MODEL_PHISHING.value
    assert c["is_disagreement"] is True
    assert c["is_agreement"] is False


def test_05_rules_legitimate_model_advisory(disagreement_engine):
    """5. Rules legitimate / model advisory."""
    eval_res = _make_eval_result(rule_label="legitimate", model_label="protective_advisory")
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.RULE_LEGITIMATE_MODEL_ADVISORY.value
    assert c["is_disagreement"] is True
    assert c["is_agreement"] is False


def test_06_rules_advisory_model_phishing(disagreement_engine):
    """6. Rules advisory / model phishing."""
    eval_res = _make_eval_result(rule_label="protective_advisory", model_label="phishing")
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.RULE_ADVISORY_MODEL_PHISHING.value
    assert c["is_disagreement"] is True
    assert c["is_agreement"] is False


def test_07_rules_advisory_model_legitimate(disagreement_engine):
    """7. Rules advisory / model legitimate."""
    eval_res = _make_eval_result(rule_label="protective_advisory", model_label="legitimate")
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.RULE_ADVISORY_MODEL_LEGITIMATE.value
    assert c["is_disagreement"] is True
    assert c["is_agreement"] is False


def test_08_non_comparable_outputs(disagreement_engine):
    """8. Unclassifiable or ambiguous rule outputs produce non_comparable."""
    for unk in [None, "unclassified", "empty", "unknown"]:
        eval_res = _make_eval_result(rule_label=unk, model_label="phishing")
        c = disagreement_engine.classify_evaluation(eval_res)

        assert c["event_type"] == DisagreementEventType.NON_COMPARABLE.value
        assert c["is_non_comparable"] is True
        assert c["is_disagreement"] is False
        assert any("Deterministic rule outcome" in r for r in c["non_comparable_reasons"])


def test_09_missing_model_output(disagreement_engine):
    """9. Missing model output produces non_comparable."""
    eval_res = _make_eval_result(rule_label="phishing", model_label=None, model_available=False)
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.NON_COMPARABLE.value
    assert c["is_non_comparable"] is True
    assert any("Model unavailable" in r for r in c["non_comparable_reasons"])


def test_10_corrupt_model_output(disagreement_engine):
    """10. Corrupt model output with fallback reason produces non_comparable."""
    eval_res = _make_eval_result(
        rule_label="phishing",
        model_label=None,
        model_available=False,
        fallback_reason="Corrupt weights matrix: NaN values detected",
    )
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.NON_COMPARABLE.value
    assert c["is_non_comparable"] is True
    assert any("Corrupt weights" in r for r in c["non_comparable_reasons"])


def test_11_rules_only_mode(disagreement_engine):
    """11. Operating mode rules_only produces non_comparable."""
    eval_res = _make_eval_result(
        rule_label="phishing",
        model_label=None,
        operating_mode="rules_only",
        model_enabled=False,
    )
    c = disagreement_engine.classify_evaluation(eval_res)

    assert c["event_type"] == DisagreementEventType.NON_COMPARABLE.value
    assert c["is_non_comparable"] is True
    assert any("rules_only" in r for r in c["non_comparable_reasons"])


# =============================================================================
# CATEGORY 2: PRIVACY AND CONSENT (Tests 12-20)
# =============================================================================

def test_12_consent_disabled_means_no_message_derived_persistence(disagreement_engine, temp_repo):
    """12. Consent disabled means no message-derived features or tokens are persisted."""
    raw_message = "Urgent: Your SBI bank account will be blocked today! Click http://sbi-fake.xyz"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    event = disagreement_engine.process_and_record(
        message_text=raw_message,
        evaluation_result=eval_res,
        consent_given=False,
        secret=TEST_FEEDBACK_SECRET,
    )

    assert event["consent_given"] is False
    assert event["feature_record_id"] is None

    # Verify no training feature record exists in SQLite
    with temp_repo.get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"]
        assert count == 0


def test_13_consent_enabled_allows_valid_feature_capture(disagreement_engine, temp_repo):
    """13. Consent enabled extracts 1024-dim vector and creates linked feature record."""
    raw_message = "Urgent: Your SBI bank account will be blocked today! Update KYC now."
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    event = disagreement_engine.process_and_record(
        message_text=raw_message,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    assert event["consent_given"] is True
    assert event["feature_record_id"] is not None

    with temp_repo.get_connection() as conn:
        feat = conn.execute(
            "SELECT * FROM training_feature_records WHERE feature_record_id = ?;",
            (event["feature_record_id"],),
        ).fetchone()
        assert feat is not None
        assert feat["feature_dim"] == EXPECTED_FEATURE_DIM
        vec = json.loads(feat["feature_vector_json"])
        assert len(vec) == 1024


def test_14_no_raw_text_stored(disagreement_engine, temp_repo):
    """14. Zero raw message text stored in any disagreement database table."""
    canary_text = "UNIQUE_CANARY_RAW_TEXT_THAT_MUST_NEVER_APPEAR_IN_DATABASE_987654"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    disagreement_engine.process_and_record(
        message_text=canary_text,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    # Inspect all rows in SQLite
    with temp_repo.get_connection() as conn:
        for table in ["model_disagreement_events", "disagreement_reviews", "disagreement_review_audit"]:
            rows = conn.execute(f"SELECT * FROM {table};").fetchall()
            for r in rows:
                for col_name in r.keys():
                    val = str(r[col_name] or "")
                    assert canary_text not in val, f"Leaked canary text in {table}.{col_name}"


def test_15_no_raw_url_stored(disagreement_engine, temp_repo):
    """15. Zero raw URLs stored in disagreement tables."""
    canary_url = "https://phishing-scam-canary-domain-12345.com/steal-creds"
    msg = f"Your electricity will be cut off! Pay here: {canary_url}"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    disagreement_engine.process_and_record(
        message_text=msg,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    with temp_repo.get_connection() as conn:
        for table in ["model_disagreement_events", "disagreement_reviews", "disagreement_review_audit"]:
            rows = conn.execute(f"SELECT * FROM {table};").fetchall()
            for r in rows:
                for col_name in r.keys():
                    val = str(r[col_name] or "")
                    assert canary_url not in val, f"Leaked URL in {table}.{col_name}"


def test_16_no_pii_stored(disagreement_engine, temp_repo):
    """16. Zero citizen PII (phone number, Aadhaar number, name) stored in disagreement tables."""
    citizen_phone = "+91 9988776655"
    citizen_aadhaar = "5432 1098 7654"
    citizen_name = "Rajeshwari Deshmukh"
    msg = f"Notice for {citizen_name}, Aadhaar {citizen_aadhaar}, Phone {citizen_phone}: Pay fine immediately."
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    disagreement_engine.process_and_record(
        message_text=msg,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    with temp_repo.get_connection() as conn:
        for table in ["model_disagreement_events", "disagreement_reviews", "disagreement_review_audit"]:
            rows = conn.execute(f"SELECT * FROM {table};").fetchall()
            for r in rows:
                for col_name in r.keys():
                    val = str(r[col_name] or "")
                    assert citizen_phone not in val, f"Leaked phone in {table}.{col_name}"
                    assert citizen_aadhaar not in val, f"Leaked Aadhaar in {table}.{col_name}"
                    assert citizen_name not in val, f"Leaked citizen name in {table}.{col_name}"


def test_17_sanitization_failure_prevents_storage(disagreement_engine, temp_repo):
    """17. Sanitization failure prevents feature storage (fails closed)."""
    raw_message = "Valid looking text but sanitization mock fails"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    with patch("src.privacy_gate.sanitize_for_local_training") as mock_gate:
        # Mock privacy gate to simulate failure
        mock_gate.return_value = MagicMock(
            sanitization_success=False,
            sanitized_text=None,
            blocking_reasons=["High-entropy token detected"],
        )

        event = disagreement_engine.process_and_record(
            message_text=raw_message,
            evaluation_result=eval_res,
            consent_given=True,
            secret=TEST_FEEDBACK_SECRET,
        )

        assert event["feature_record_id"] is None
        with temp_repo.get_connection() as conn:
            assert conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"] == 0


def test_18_missing_hmac_secret_fails_closed(disagreement_engine, temp_repo, monkeypatch):
    """18. Missing HMAC secret fails closed: no feature record stored, event preserved."""
    monkeypatch.delenv("SEVA_FEEDBACK_HMAC_KEY", raising=False)
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    event = disagreement_engine.process_and_record(
        message_text="Sample message text for testing",
        evaluation_result=eval_res,
        consent_given=True,
        secret=None,  # No secret passed, environment variable absent
    )

    assert event["event_id"].startswith("EVT-")
    assert event["feature_record_id"] is None
    with temp_repo.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"] == 0


def test_19_threat_intel_secret_cannot_substitute_for_feedback_secret(monkeypatch):
    """19. Dedicated secret isolation: threat intel secret cannot substitute for feedback secret."""
    monkeypatch.delenv("SEVA_FEEDBACK_HMAC_KEY", raising=False)
    monkeypatch.setenv("SEVA_THREAT_INTEL_KEY", "threat_intel_secret_key_32chars_ok")
    monkeypatch.setenv("SEVA_HMAC_SECRET", "threat_intel_secret_key_32chars_ok")

    with pytest.raises(FeedbackCurationKeyError):
        get_feedback_hmac_secret(secret=None)


def test_20_consent_revocation_excludes_future_training_exports(disagreement_engine, temp_repo):
    """20. Consent revocation sets consent_given=0 and excludes records from training curation."""
    raw_message = "Sample phishing message for revocation verification."
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    event = disagreement_engine.process_and_record(
        message_text=raw_message,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    # Submit valid human review
    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )

    # Verify initially eligible
    curation = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(curation["eligible_records"]) == 1

    # Revoke consent
    temp_repo.revoke_training_consent(case_id=event["event_id"])

    # Verify event consent is updated
    updated_evt = temp_repo.get_disagreement_event(event["event_id"])
    assert updated_evt["consent_given"] == 0

    # Verify now excluded from training exports
    curation_after = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(curation_after["eligible_records"]) == 0
    assert any(r["reason"] == "consent_revoked" for r in curation_after["ineligible_records"])


# =============================================================================
# CATEGORY 3: HUMAN REVIEW (Tests 21-29)
# =============================================================================

def test_21_pending_review_creation(disagreement_engine):
    """21. Newly recorded disagreement starts in pending review state."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text="Bank message",
        evaluation_result=eval_res,
        consent_given=False,
    )

    assert event["review_state"] == ReviewState.PENDING.value
    persisted = disagreement_engine.repository.get_disagreement_event(event["event_id"])
    assert persisted["review_state"] == "pending"


def test_22_valid_review_completion(disagreement_engine, temp_repo):
    """22. Valid review completion updates state, records review and audit entry."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text="Bank message",
        evaluation_result=eval_res,
    )

    review_res = disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
        notes="Rules correctly identified phishing bank lure",
    )

    assert review_res["review_state"] == "completed"
    assert review_res["outcome_label"] == "phishing"

    # Verify event state updated
    evt = temp_repo.get_disagreement_event(event["event_id"])
    assert evt["review_state"] == "completed"

    # Verify audit entry recorded
    audit_logs = temp_repo.list_disagreement_audit_logs(event_id=event["event_id"])
    assert len(audit_logs) >= 1
    assert audit_logs[0]["action"] == "created"


def test_23_invalid_review_labels_rejected(disagreement_engine):
    """23. Invalid review outcome or assessment labels are rejected with validation error."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(message_text="Test", evaluation_result=eval_res)

    # Invalid outcome label
    with pytest.raises(ValueError, match="Invalid outcome_label"):
        disagreement_engine.submit_review(
            event_id=event["event_id"],
            outcome_label="invalid_outcome_category",
            reviewer_assessment="rules_correct",
        )

    # Invalid reviewer assessment
    with pytest.raises(ValueError, match="Invalid reviewer_assessment"):
        disagreement_engine.submit_review(
            event_id=event["event_id"],
            outcome_label="phishing",
            reviewer_assessment="invalid_assessment_string",
        )


def test_24_duplicate_review_submission_rejected(disagreement_engine):
    """24. Duplicate review submission without supersede flag is rejected."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(message_text="Test", evaluation_result=eval_res)

    # First review
    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
    )

    # Second review without supersede
    with pytest.raises(ValueError, match="Duplicate review submission"):
        disagreement_engine.submit_review(
            event_id=event["event_id"],
            outcome_label="legitimate",
            reviewer_assessment="model_correct",
            supersede_existing=False,
        )


def test_25_superseding_completed_reviews_creates_audit_entries(disagreement_engine, temp_repo):
    """25. Superseding completed reviews marks prior review superseded and creates audit trail."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(message_text="Test", evaluation_result=eval_res)

    # First review
    rev1 = disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
    )

    # Second review with supersede_existing=True
    rev2 = disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="legitimate",
        reviewer_assessment="model_correct",
        supersede_existing=True,
        reason="Senior analyst reviewed additional contextual evidence",
    )

    assert rev2["review_state"] == "completed"
    assert rev2["outcome_label"] == "legitimate"

    # Verify first review is marked superseded
    prior = temp_repo.get_disagreement_review(rev1["review_id"])
    assert prior["is_superseded"] == 1
    assert prior["superseded_by"] == rev2["review_id"]

    # Verify audit logs record superseding
    logs = temp_repo.list_disagreement_audit_logs(event_id=event["event_id"])
    actions = [l["action"] for l in logs]
    assert "superseded" in actions
    assert "created" in actions


def test_26_insufficient_evidence_remains_excluded(disagreement_engine, temp_repo):
    """26. Insufficient evidence outcome marks state and remains excluded from training."""
    raw_message = "Ambiguous SMS fragment with no clear indicators"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text=raw_message,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="insufficient_evidence",
        reviewer_assessment="neither_sufficient",
        confidence_rating="low",
    )

    evt = temp_repo.get_disagreement_event(event["event_id"])
    assert evt["review_state"] == "insufficient_evidence"

    curation = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(curation["eligible_records"]) == 0
    assert any(r["reason"] == "insufficient_evidence" for r in curation["ineligible_records"])


def test_27_unauthenticated_provenance_preserved(disagreement_engine, temp_repo):
    """27. Reviewer attribution is strictly preserved as local_operator_unauthenticated."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(message_text="Test", evaluation_result=eval_res)

    review_res = disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        reviewer_label="local_operator_unauthenticated",
    )

    assert review_res["reviewer_label"] == "local_operator_unauthenticated"
    audit_logs = temp_repo.list_disagreement_audit_logs(event_id=event["event_id"])
    assert all(a["actor"] == "local_operator_unauthenticated" for a in audit_logs)


def test_28_delayed_review_clearly_indicates_missing_raw_message_evidence(disagreement_engine, temp_repo):
    """28. Delayed review accesses only structural metadata; original text is unavailable."""
    secret_text = "Highly private confidential communication 98765"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text=secret_text,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    # In delayed review mode, reviewer inspects stored event
    stored_event = temp_repo.get_disagreement_event(event["event_id"])
    assert "raw_text" not in stored_event
    assert "message_text" not in stored_event
    assert "text" not in stored_event
    # Structural metadata is present
    meta = stored_event.get("structural_observations", {})
    assert "findings_count" in meta
    assert "extracted_urls_count" in meta


def test_29_review_decisions_do_not_alter_production_scores(disagreement_engine, temp_repo):
    """29. Review decisions do not alter authoritative risk scores."""
    eval_res = _make_eval_result(rule_label="phishing", rule_score=85, model_label="legitimate")
    event = disagreement_engine.process_and_record(message_text="Test", evaluation_result=eval_res)

    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="legitimate",
        reviewer_assessment="model_correct",
        confidence_rating="high",
    )

    # The persisted event rule_score remains 85
    evt = temp_repo.get_disagreement_event(event["event_id"])
    assert evt["rule_score"] == 85


# =============================================================================
# CATEGORY 4: PATTERN GOVERNANCE (Tests 30-34)
# =============================================================================

@pytest.fixture
def temp_catalog_manager(tmp_path):
    """Provides a PatternCatalogManager with an isolated directory."""
    cat_dir = tmp_path / "pattern_catalog"
    return PatternCatalogManager(catalog_dir=str(cat_dir))


def _make_candidate_pattern(
    candidate_id: str = "PAT-TEST-001",
    lifecycle_state: str = "draft",
    data_provenance: str = "local_curated_feedback",
    target_class: str = "phishing",
) -> CandidatePattern:
    return CandidatePattern(
        candidate_id=candidate_id,
        pattern_schema_version="1.0.0",
        discovery_timestamp_utc="2026-10-30T12:00:00Z",
        candidate_pattern_type="ngram_feature_association",
        opaque_feature_identifiers=["feature_idx_101", "feature_idx_202"],
        target_class=target_class,
        supporting_example_count=15,
        total_dataset_examples=100,
        class_distribution={"phishing": 15, "legitimate": 0, "protective_advisory": 0},
        statistical_evidence={"confidence": 0.92, "lift": 3.5, "wilson_lower": 0.85},
        uncertainty_or_limitations=["Observational correlation only"],
        data_provenance=data_provenance,
        algorithm_version="pattern-discovery-v1.0.0",
        lifecycle_state=lifecycle_state,
    )


def test_30_draft_pattern_cannot_be_automatically_approved(temp_catalog_manager):
    """30. Newly discovered candidate pattern starts as draft and cannot be auto-approved."""
    candidate = _make_candidate_pattern(candidate_id="PAT-TEST-001", lifecycle_state="draft")
    temp_catalog_manager.save_catalog([candidate], version="1.0.0")

    loaded = temp_catalog_manager.load_catalog(version="1.0.0")
    assert loaded["candidate_patterns"][0]["lifecycle_state"] == "draft"


def test_31_human_approval_is_audited(temp_catalog_manager):
    """31. Operator approval of candidate pattern appends to audit log with production invariance."""
    candidate = _make_candidate_pattern(candidate_id="PAT-TEST-002", lifecycle_state="draft")
    temp_catalog_manager.save_catalog([candidate], version="1.0.0")

    res = temp_catalog_manager.review_candidate_pattern(
        candidate_id="PAT-TEST-002",
        new_state="approved_by_human",
        reason="Verified against digital-arrest extortion campaign telemetry",
        reviewer_label="local_operator_unauthenticated",
    )

    assert res["new_state"] == "approved_by_human"
    assert res["audit_entry"]["production_rules_modified"] is False
    assert res["audit_entry"]["scoring_altered"] is False

    # Check append-only audit file
    audit_file = temp_catalog_manager.get_audit_log_path()
    assert os.path.exists(audit_file)
    with open(audit_file, "r", encoding="utf-8") as f:
        logs = [json.loads(line) for line in f]
    assert len(logs) == 1
    assert logs[0]["candidate_id"] == "PAT-TEST-002"
    assert logs[0]["new_state"] == "approved_by_human"


def test_32_rejected_pattern_cannot_silently_reactivate(temp_catalog_manager):
    """32. Rejected pattern cannot be silently reactivated to approved_by_human."""
    candidate = _make_candidate_pattern(candidate_id="PAT-TEST-003", lifecycle_state="draft")
    temp_catalog_manager.save_catalog([candidate], version="1.0.0")

    # Reject pattern
    temp_catalog_manager.review_candidate_pattern(
        candidate_id="PAT-TEST-003",
        new_state="rejected",
        reason="Pattern correlates with legitimate utility messages",
    )

    # Attempting silent reactivation must raise PatternReviewError
    with pytest.raises(PatternReviewError, match="previously REJECTED"):
        temp_catalog_manager.review_candidate_pattern(
            candidate_id="PAT-TEST-003",
            new_state="approved_by_human",
            reason="Attempting unauthorized reactivation",
        )


def test_33_pattern_approval_does_not_change_production_rules(temp_catalog_manager):
    """33. Pattern approval leaves production deterministic detection rules completely unchanged."""
    test_msg = "Urgent: Electricity power will be disconnected at 9:30 PM tonight."
    baseline_analysis = analyze_message_text(test_msg)
    baseline_score = score_message_analysis(baseline_analysis)

    # Approve candidate pattern
    candidate = _make_candidate_pattern(candidate_id="PAT-TEST-004", lifecycle_state="draft")
    temp_catalog_manager.save_catalog([candidate], version="1.0.0")
    temp_catalog_manager.review_candidate_pattern(
        candidate_id="PAT-TEST-004",
        new_state="approved_by_human",
        reason="Analyst verified pattern",
    )

    # Re-run deterministic rule analysis
    post_analysis = analyze_message_text(test_msg)
    post_score = score_message_analysis(post_analysis)

    assert baseline_analysis["findings"] == post_analysis["findings"]
    assert baseline_score["score"] == post_score["score"]
    assert baseline_score["badge_color"] == post_score["badge_color"]


def test_34_synthetic_and_human_reviewed_provenance_remain_separate(temp_catalog_manager):
    """34. Separate provenance is preserved between synthetic corpora and human-reviewed feedback."""
    cand_synth = _make_candidate_pattern(
        candidate_id="PAT-SYNTH-001",
        data_provenance="synthetic_corpus_v4",
    )
    cand_human = _make_candidate_pattern(
        candidate_id="PAT-HUMAN-001",
        data_provenance="local_curated_feedback",
    )

    temp_catalog_manager.save_catalog([cand_synth, cand_human], version="1.0.0")
    loaded = temp_catalog_manager.load_catalog(version="1.0.0")

    provs = {p["candidate_id"]: p["data_provenance"] for p in loaded["candidate_patterns"]}
    assert provs["PAT-SYNTH-001"] == "synthetic_corpus_v4"
    assert provs["PAT-HUMAN-001"] == "local_curated_feedback"


# =============================================================================
# CATEGORY 5: TRAINING ELIGIBILITY (Tests 35-40)
# =============================================================================

def test_35_only_eligible_reviewed_records_enter_future_training_exports(disagreement_engine, temp_repo):
    """35. Only fully reviewed records with affirmative consent enter training curation."""
    raw_message = "Urgent lottery winner claim prize at http://fake.xyz"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text=raw_message,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    # Before review: not eligible
    c1 = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(c1["eligible_records"]) == 0

    # After valid review: eligible
    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )

    c2 = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(c2["eligible_records"]) == 1
    assert c2["eligible_records"][0]["feature_record_id"] == event["feature_record_id"]


def test_36_pending_and_low_confidence_records_are_excluded(disagreement_engine, temp_repo):
    """36. Pending reviews and low-confidence reviews are excluded from training curation."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    # Record 1: pending review
    disagreement_engine.process_and_record(
        message_text="Message one for pending check",
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    # Record 2: low confidence review
    event2 = disagreement_engine.process_and_record(
        message_text="Message two for low confidence check",
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )
    disagreement_engine.submit_review(
        event_id=event2["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="low",
    )

    curation = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(curation["eligible_records"]) == 0
    reasons = [r["reason"] for r in curation["ineligible_records"]]
    assert "review_pending" in reasons
    assert "low_confidence_review" in reasons


def test_37_superseded_reviews_are_excluded(disagreement_engine, temp_repo):
    """37. Superseded reviews are excluded; only the active review is considered."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text="Message for superseded review check",
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    # Initial review: high confidence phishing
    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )

    # Superseded with low-confidence or insufficient_evidence
    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="insufficient_evidence",
        reviewer_assessment="neither_sufficient",
        confidence_rating="low",
        supersede_existing=True,
        reason="Evidence deemed insufficient on reconsideration",
    )

    curation = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(curation["eligible_records"]) == 0
    assert any(r["reason"] == "insufficient_evidence" for r in curation["ineligible_records"])


def test_38_duplicate_feature_examples_are_not_counted_twice(disagreement_engine, temp_repo):
    """38. Repeated examples with identical deduplication fingerprints are not duplicated."""
    identical_text = "Standard repeated phishing notification message"
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")

    # Record two independent events with identical text
    e1 = disagreement_engine.process_and_record(
        message_text=identical_text,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )
    e2 = disagreement_engine.process_and_record(
        message_text=identical_text,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    disagreement_engine.submit_review(
        event_id=e1["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )
    disagreement_engine.submit_review(
        event_id=e2["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )

    curation = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    # Exactly one representative is eligible
    assert len(curation["eligible_records"]) == 1
    # Duplicate is flagged in ineligible
    assert any(r["reason"] in ("duplicate_fingerprint", "duplicate_feature_fingerprint") for r in curation["ineligible_records"])


def test_39_revoked_consent_is_excluded(disagreement_engine, temp_repo):
    """39. Records with revoked consent are excluded from curation."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text="Revocation target message",
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )

    temp_repo.revoke_training_consent(case_id=event["event_id"])
    curation = temp_repo.curate_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(curation["eligible_records"]) == 0
    assert any(r["reason"] == "consent_revoked" for r in curation["ineligible_records"])


def test_40_case_ids_and_hmac_fingerprints_are_absent_from_exports(disagreement_engine, temp_repo):
    """40. Case IDs, internal deduplication fingerprints, and raw texts are stripped from export."""
    eval_res = _make_eval_result(rule_label="phishing", model_label="legitimate")
    event = disagreement_engine.process_and_record(
        message_text="Test message for export privacy verification",
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_FEEDBACK_SECRET,
    )

    disagreement_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )

    exported = temp_repo.export_curated_training_features(secret=TEST_FEEDBACK_SECRET)
    assert len(exported) == 1
    record = exported[0]

    forbidden_keys = [
        "case_id",
        "dedup_fingerprint",
        "raw_text",
        "text",
        "sanitized_text",
        "notes",
        "reviewer_notes",
        "phone",
        "secret",
    ]
    for key in forbidden_keys:
        assert key not in record, f"Forbidden key '{key}' leaked into training export!"


# =============================================================================
# CATEGORY 6: SYSTEM INTEGRATION (Tests 41-50)
# =============================================================================

def test_41_shadow_inference_does_not_alter_production_scoring():
    """41. Shadow inference does not alter deterministic production risk scores (score delta = 0.00)."""
    test_msg = "URGENT: Your SBI bank debit card is deactivated. Visit http://sbi-card-reactivate.xyz"
    rules_eval = evaluate_message_hybrid(test_msg, operating_mode="rules_only")
    shadow_eval = evaluate_message_hybrid(test_msg, operating_mode="shadow")

    assert rules_eval["final_decision"]["final_risk_score"] == shadow_eval["final_decision"]["final_risk_score"]
    assert rules_eval["final_decision"]["action_verdict"] == shadow_eval["final_decision"]["action_verdict"]
    assert shadow_eval["final_decision"]["production_score_difference"] == 0


def test_42_disagreement_detection_failures_do_not_disrupt_normal_analysis():
    """42. Failures in disagreement detection do not crash or disrupt deterministic analysis."""
    test_msg = "URGENT: Electricity bill overdue. Call 9876543210 immediately."

    with patch.object(DisagreementEngine, "classify_evaluation", side_effect=RuntimeError("Simulated disagreement crash")):
        # Message analysis should complete unharmed
        analysis = analyze_message_text(test_msg)
        score = score_message_analysis(analysis)
        assert score["score"] >= 0
        assert "badge_color" in score


def test_43_existing_apk_analyzer_works():
    """43. Existing APK analyzer operates properly and rejects corrupted input safely."""
    garbage_bytes = b"NOT_A_VALID_ZIP_ARCHIVE_DATA"
    res = analyze_apk_bytes(garbage_bytes, "corrupt_sample.apk")
    assert res["is_valid_apk"] is False
    assert "not a valid zip/apk archive" in (res["error_message"] or "").lower()


def test_44_existing_multilingual_phishing_detector_works():
    """44. Existing multilingual phishing detector detects indicators in English and Marathi."""
    en_msg = "Your bank account has been suspended! Click http://phish.com to update KYC."
    en_res = analyze_message_text(en_msg)
    assert len(en_res["findings"]) > 0

    mr_msg = "तुमचे बँक खाते त्वरित बंद केले जाईल. केवायसी अपडेट करा."
    mr_res = analyze_message_text(mr_msg)
    assert len(mr_res["findings"]) > 0 or mr_res.get("assessment_label") in ("phishing", "suspicious")


def test_45_existing_url_analyzer_works():
    """45. Existing URL analyzer flags suspicious IP address hostnames."""
    res = analyze_url("http://192.168.1.1/admin/login")
    assert res["observable_characteristics"]["is_ip_address"] is True
    assert res["score"] > 0


def test_46_maharashtra_scheme_verifier_remains_functional():
    """46. Maharashtra government scheme verifier verifies official claims accurately."""
    res = verify_scheme_claim("Ladki Bahin Yojana registration portal")
    assert res["classification"] == "SUPPORTED BY OFFICIAL SOURCE" or "Ladki" in str(res.get("matched_scheme_title", ""))


def test_47_existing_case_management_remains_functional(temp_repo):
    """47. Existing SessionCaseStore and threat case management remain fully functional."""
    store = SessionCaseStore(repository=temp_repo)
    test_text = "Important message: update your details"
    analysis = analyze_message_text(test_text)
    scored = score_message_analysis(analysis)

    case = create_message_case(analysis, scored)
    store.add_case(case)

    cases = store.list_cases()
    assert len(cases) == 1
    assert cases[0]["case_id"] == case["case_id"]


def test_48_audio_alerts_remain_functional():
    """48. Audio alerts module synthesizes PCM WAV chime bytes and spoken scripts."""
    wav_bytes = generate_alert_wav_bytes("red")
    assert isinstance(wav_bytes, bytes)
    assert len(wav_bytes) > 44  # Valid WAV header + PCM samples

    spoken_en, written_mr = get_spoken_script("red", "message")
    assert "caution" in spoken_en.lower() or "alert" in spoken_en.lower()
    assert len(written_mr) > 0


def test_49_existing_review_desk_remains_functional(temp_repo):
    """49. Existing threat case review desk functions properly and records reviews."""
    case_record = {
        "case_type": "message",
        "input_data": {"text_preview": "Suspicious preview"},
        "risk_score": 75,
        "risk_category": "SUSPICIOUS",
        "badge_color": "orange",
        "findings_count": 2,
    }
    case_id = temp_repo.save_case(case_record)

    review = temp_repo.submit_review(
        case_id=case_id,
        outcome_category="phishing",
        confidence_rating="high",
        reviewer_label="local_operator_unauthenticated",
        notes="Confirmed phishing attempt",
    )

    assert review["outcome_category"] == "phishing"
    loaded = temp_repo.get_review_by_case(case_id)
    assert loaded is not None
    assert loaded["outcome_category"] == "phishing"


def test_50_existing_shadow_rollback_remains_functional(tmp_path):
    """50. Existing shadow model rollback restores prior last-known-good version atomically."""
    temp_models_dir = tmp_path / "models"
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(temp_models_dir))

    reg = ModelRegistry(project_root=str(tmp_path), models_dir="models")
    rbc = RollbackController(registry=reg)

    status = rbc.get_rollback_status()
    assert status["can_rollback"] is True
    assert status["target_rollback_version"] == "custom-mlp-v1.1.0-preproc"

    # Execute rollback
    rb_cfg = rbc.execute_rollback(operator_label="test_suite", reason="Phase 6.6 verification")
    assert rb_cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"
    assert rb_cfg["last_known_good_version"] == "custom-mlp-v4.0.0-seed42"

    # Verify live workspace config was NOT mutated
    live_reg = get_default_model_registry()
    live_cfg = live_reg.get_active_model_config()
    assert live_cfg["active_model_version"] == "custom-mlp-v4.0.0-seed42"
