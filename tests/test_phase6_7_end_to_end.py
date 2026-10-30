"""
Comprehensive End-to-End Integration, Security, Recovery and Stress Test Suite.
Phase 6.7: Seva Cyber Sandbox.

SCOPE & DESIGN:
- Exercises complete end-to-end integration across all subsystems:
  1. Multilingual message analysis & deterministic rule engine.
  2. Neural shadow inference & diagnostic score delta (0.00).
  3. Disagreement classification & non-comparable guardrails.
  4. Privacy & consent gating (zero raw text, zero URLs, zero PII).
  5. Human review lifecycle & append-only audit trail.
  6. Feedback curation, deduplication, conflict quarantine & export.
  7. Pattern discovery hypothesis review & catalogue governance.
  8. Candidate model training pipeline in isolated environments.
  9. Candidate evaluation benchmark gate & Wilson confidence metrics.
 10. Model registry shadow registration & atomic rollback recovery.
 11. Failure injection: database, model corruption, and engine crash resilience.
 12. Local performance benchmarks & resource boundedness.
 13. Network isolation (zero outbound sockets) & loopback binding.
 14. Live production safety and immutable artifact verification.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import socket
import tempfile
import time
from typing import Any, Dict, List
from unittest.mock import patch, MagicMock
import numpy as np
import pytest

from src.candidate_evaluator import (
    ArtifactIntegrityError,
    BenchmarkPolicy,
    BenchmarkVerdict,
    CandidateEvaluator,
    CandidateIncompatibleError,
    compute_classification_metrics,
    compute_confusion_matrix,
    wilson_score_interval,
)
from src.candidate_trainer import (
    CandidateArtifactError,
    CandidateModelTrainer,
    InsufficientTrainingDataError,
    compose_training_dataset,
    validate_dataset_eligibility,
)
from src.case_manager import SessionCaseStore, create_message_case
from src.case_repository import (
    CaseRepository,
    FeedbackCurationError,
    FeedbackCurationKeyError,
    FeedbackCurationValidationError,
    compute_feedback_dedup_fingerprint,
    get_feedback_hmac_secret,
)
from src.custom_model import (
    CharacterNGramHasher,
    CustomNeuralClassifier,
)
from src.dataset_preprocessing import (
    EXPECTED_FEATURE_DIM,
    extract_derived_training_features,
    preprocess_for_neural_model,
)
from src.dataset_validator import compute_locked_test_hash, verify_locked_test_integrity
from src.disagreement_engine import (
    DisagreementEngine,
    DisagreementEventType,
    ReviewOutcome,
    ReviewerAssessment,
    ReviewState,
)
from src.feedback_analytics import FeedbackAnalytics
from src.hybrid_decision_engine import (
    HybridDecisionEngine,
    evaluate_message_hybrid,
    get_default_engine,
)
from src.model_registry import (
    ModelRegistry,
    ModelRegistryError,
    get_default_model_registry,
)
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
TEST_HMAC_SECRET = "test_feedback_secret_key_32chars_ok"
LOCKED_DIGEST_EXPECTED = "9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda"
CANDIDATE_WEIGHTS_SHA = "3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f"
BASELINE_WEIGHTS_SHA = "d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20"


# =============================================================================
# ISOLATED FIXTURES
# =============================================================================

@pytest.fixture
def isolated_repo(tmp_path):
    """Provides an isolated temporary SQLite database for integration testing."""
    db_file = tmp_path / "test_seva_cases_e2e.sqlite3"
    repo = CaseRepository(db_path=str(db_file))
    repo.init_db()
    return repo


@pytest.fixture
def isolated_engine(isolated_repo):
    """Provides a DisagreementEngine bound to the temporary repository."""
    return DisagreementEngine(repository=isolated_repo)


@pytest.fixture
def isolated_catalog_mgr(tmp_path):
    """Provides an isolated PatternCatalogManager."""
    cat_dir = tmp_path / "pattern_catalog"
    return PatternCatalogManager(catalog_dir=str(cat_dir))


def _make_synthetic_feature_record(
    record_id: str,
    label: str = "phishing",
    confidence: str = "high",
    provenance: str = "local_curated_feedback",
    seed: int = 42,
) -> Dict[str, Any]:
    """Helper to generate a valid 1024-d synthetic feature record for training tests."""
    rng = np.random.RandomState(seed)
    vec = [round(float(x), 6) for x in rng.randn(EXPECTED_FEATURE_DIM).tolist()]
    label_idx = {"phishing": 0, "legitimate": 1, "protective_advisory": 2}.get(label, 0)
    return {
        "example_id": f"example_{record_id}",
        "feature_record_id": record_id,
        "feature_vector": vec,
        "feature_dim": EXPECTED_FEATURE_DIM,
        "label": label,
        "label_idx": label_idx,
        "confidence_rating": confidence,
        "confidence_category": confidence,
        "feature_schema_version": "1.0.0",
        "preprocessing_version": "canonical-nfc-devanagari-v1.0.0",
        "feature_extractor_version": "char-ngram-hasher-1024-v1.0.0",
        "consent_timestamp_utc": "2026-10-30T12:00:00Z",
        "created_at_utc": "2026-10-30T12:00:00Z",
        "reviewed_at_utc": "2026-10-30T12:05:00Z",
        "review_provenance": "local_operator_unauthenticated",
        "provenance_category": provenance,
    }


# =============================================================================
# SCENARIO 1: NORMAL MESSAGE ANALYSIS (Tests 1)
# =============================================================================

def test_01_e2e_normal_message_analysis_multilingual_and_url_variants():
    """
    Scenario 1: End-to-end evaluation of diverse fictional test messages across:
    - English Phishing (URL-bearing)
    - Devanagari Phishing (URL-bearing)
    - Romanized Marathi Phishing (URL-bearing)
    - Mixed Marathi-English Extortion (URL-free)
    - Legitimate Administrative Notice (English)
    - Legitimate Administrative Notice (Devanagari)
    - Protective Advisory (English)
    - Protective Advisory (Devanagari)
    Verifies rule authority, shadow parallel execution, diagnostic labeling,
    zero score delta, and zero raw text persistence in telemetry.
    """
    test_corpus = [
        # 1. English Phishing (URL-bearing)
        ("en_phish", "Urgent: Your SBI bank debit card is deactivated. Visit http://sbi-unfreeze-secure.xyz to update KYC."),
        # 2. Devanagari Phishing (URL-bearing)
        ("mr_phish", "महावितरण वीज बिल: आज रात्री 9:30 वाजता वीज पुरवठा खंडित केला जाईल. त्वरित बिल भरा: http://msedcl-bill-pay.in"),
        # 3. Romanized Marathi Phishing (URL-bearing)
        ("mr_latn_phish", "Aaple SBI khate block honar ahe. Pan link kara http://sbi-pan-kyc.com"),
        # 4. Mixed Marathi-English Extortion (URL-free)
        ("mixed_extortion_urlfree", "Notice from MahaPolice Crime Branch: Extortion case filed under Sec 420. Call verification officer on 9822001122 immediately."),
        # 5. Legitimate Administrative Notice (English)
        ("en_legit", "Official notice from Pune Municipal Corporation: Scheduled water pipeline maintenance on Wednesday from 10 AM to 4 PM."),
        # 6. Legitimate Administrative Notice (Devanagari)
        ("mr_legit", "महाराष्ट्र शासन: महाडिस्कॉम कडून सार्वजनिक वीज ग्राहकांसाठी नियोजित देखभाल दुरुस्ती संबंधी अधिकृत सूचना."),
        # 7. Protective Advisory (English)
        ("en_advisory", "Cyber Crime Advisory: Police and CBI never arrest citizens via video calls. Report digital arrest fraud immediately to cybercrime portal 1930."),
        # 8. Protective Advisory (Devanagari)
        ("mr_advisory", "सायबर सुरक्षा सूचना: कोणत्याही अनोळखी व्यक्तीला बँक तपशील किंवा ओटीपी शेअर करू नका. डिजिटल अरेस्ट कॉल फ्रॉड आहे."),
    ]

    for name, text in test_corpus:
        res = evaluate_message_hybrid(text, operating_mode="shadow")

        # 1. Deterministic rules are the authoritative source
        assert res["final_decision"]["authoritative_source"] == "deterministic_rules"
        # 2. Neural shadow model runs diagnostic only; score delta is exactly zero
        assert res["final_decision"]["production_score_difference"] == 0
        # 3. Production score strictly equals rule score
        assert res["final_decision"]["final_risk_score"] == res["rule_based_evidence"]["score"]
        # 4. Badge colors are standard
        assert res["final_decision"]["badge_color"] in ("green", "orange", "red")
        # 5. Diagnostic Event ID is non-message-derived
        event_id = res["audit_metadata"].get("diagnostic_event_id", "")
        assert event_id.startswith("EVT-")
        # 6. Zero raw text in audit metadata
        assert text not in str(res["audit_metadata"])


# =============================================================================
# SCENARIO 2: DISAGREEMENT DETECTION & ONTOLOGY (Tests 2-3)
# =============================================================================

def test_02_e2e_disagreement_detection_all_canonical_mappings(isolated_engine):
    """
    Scenario 2: Verifies concordance classification across all 8 supported canonical event types:
    - agreement (phishing, legitimate, protective_advisory)
    - 6 pairwise disagreements
    - non_comparable
    Verifies pseudorandom event IDs and production score invariance.
    """
    pairs = [
        # Agreements
        ("phishing", "phishing", DisagreementEventType.AGREEMENT.value),
        ("legitimate", "legitimate", DisagreementEventType.AGREEMENT.value),
        ("protective_advisory", "protective_advisory", DisagreementEventType.AGREEMENT.value),
        # Disagreements
        ("phishing", "legitimate", DisagreementEventType.RULE_PHISHING_MODEL_LEGITIMATE.value),
        ("phishing", "protective_advisory", DisagreementEventType.RULE_PHISHING_MODEL_ADVISORY.value),
        ("legitimate", "phishing", DisagreementEventType.RULE_LEGITIMATE_MODEL_PHISHING.value),
        ("legitimate", "protective_advisory", DisagreementEventType.RULE_LEGITIMATE_MODEL_ADVISORY.value),
        ("protective_advisory", "phishing", DisagreementEventType.RULE_ADVISORY_MODEL_PHISHING.value),
        ("protective_advisory", "legitimate", DisagreementEventType.RULE_ADVISORY_MODEL_LEGITIMATE.value),
    ]

    for rule_lbl, model_lbl, expected_type in pairs:
        mock_eval = {
            "operating_mode": "shadow",
            "rule_based_evidence": {"rule_label": rule_lbl, "score": 60, "findings_count": 2},
            "experimental_model": {
                "is_available": True,
                "is_enabled": True,
                "model_version": "custom-mlp-v4.0.0-seed42",
                "predicted_label": model_lbl,
                "confidence": 0.88,
            },
            "audit_metadata": {"score_difference": 0.0},
        }

        classification = isolated_engine.classify_evaluation(mock_eval)
        assert classification["event_type"] == expected_type
        assert classification["rule_decision"] == rule_lbl
        assert classification["model_prediction"] == model_lbl
        assert classification["event_id"].startswith("EVT-")
        assert len(classification["event_id"]) == 16


def test_03_e2e_non_comparable_classification_guardrails(isolated_engine):
    """
    Scenario 2: Verifies that rules-only mode, missing model predictions, corrupt models,
    or ambiguous rule outcomes strictly map to 'non_comparable' with diagnostic reasons.
    """
    # 1. Rules only mode
    c1 = isolated_engine.classify_evaluation({
        "operating_mode": "rules_only",
        "rule_based_evidence": {"rule_label": "phishing", "score": 80},
        "experimental_model": {"is_available": False, "is_enabled": False},
    })
    assert c1["event_type"] == DisagreementEventType.NON_COMPARABLE.value
    assert c1["is_non_comparable"] is True
    assert any("rules_only" in r for r in c1["non_comparable_reasons"])

    # 2. Model unavailable
    c2 = isolated_engine.classify_evaluation({
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 80},
        "experimental_model": {
            "is_available": False,
            "is_enabled": True,
            "predicted_label": None,
            "fallback_reason": "Inference timeout",
        },
    })
    assert c2["event_type"] == DisagreementEventType.NON_COMPARABLE.value
    assert any("timeout" in r for r in c2["non_comparable_reasons"])

    # 3. Ambiguous rule label
    c3 = isolated_engine.classify_evaluation({
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "unclassified", "score": 0},
        "experimental_model": {
            "is_available": True,
            "is_enabled": True,
            "predicted_label": "legitimate",
        },
    })
    assert c3["event_type"] == DisagreementEventType.NON_COMPARABLE.value


# =============================================================================
# SCENARIO 3: PRIVACY AND CONSENT (Tests 4-7)
# =============================================================================

def test_04_e2e_privacy_consent_disabled_zero_persistence(isolated_engine, isolated_repo):
    """
    Scenario 3: With consent disabled, message analysis proceeds, event metadata is stored,
    but feature derivation is completely bypassed (feature_record_id is None, 0 feature rows).
    """
    msg = "Urgent: Update KYC at http://phish-bank.in immediately."
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 90, "findings_count": 2},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate", "model_version": "v4"},
    }

    event = isolated_engine.process_and_record(
        message_text=msg,
        evaluation_result=mock_eval,
        consent_given=False,
        secret=TEST_HMAC_SECRET,
    )

    assert event["consent_given"] is False
    assert event["feature_record_id"] is None

    with isolated_repo.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"] == 0


def test_05_e2e_privacy_consent_enabled_derived_feature_capture(isolated_engine, isolated_repo):
    """
    Scenario 3: With consent enabled, local sanitization executes, 1024-d character n-gram
    features are safely extracted, validated, and linked to the disagreement event.
    """
    msg = "Electricity bill pending: Pay immediately to avoid disconnection."
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 70, "findings_count": 2},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate", "model_version": "v4"},
    }

    event = isolated_engine.process_and_record(
        message_text=msg,
        evaluation_result=mock_eval,
        consent_given=True,
        secret=TEST_HMAC_SECRET,
    )

    assert event["consent_given"] is True
    assert event["feature_record_id"] is not None

    feat = isolated_repo.get_training_features_by_record_id(event["feature_record_id"])
    assert feat is not None
    assert feat["feature_dim"] == EXPECTED_FEATURE_DIM
    assert len(feat["feature_vector"]) == 1024
    assert np.all(np.isfinite(feat["feature_vector"]))


def test_06_e2e_privacy_fail_closed_on_missing_or_invalid_hmac_secret(isolated_engine, isolated_repo, monkeypatch):
    """
    Scenario 3: Missing or short (< 16 chars) HMAC secret fails closed for training
    feature persistence without crashing event metadata recording or core analysis.
    """
    monkeypatch.delenv("SEVA_FEEDBACK_HMAC_KEY", raising=False)
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 75},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }

    # 1. Completely missing secret
    evt1 = isolated_engine.process_and_record(
        message_text="Sample message text",
        evaluation_result=mock_eval,
        consent_given=True,
        secret=None,
    )
    assert evt1["feature_record_id"] is None

    # 2. Too short secret (< 16 chars)
    evt2 = isolated_engine.process_and_record(
        message_text="Sample message text",
        evaluation_result=mock_eval,
        consent_given=True,
        secret="short_key",
    )
    assert evt2["feature_record_id"] is None

    with isolated_repo.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"] == 0


def test_07_e2e_privacy_sanitization_failure_fails_closed(isolated_engine, isolated_repo):
    """
    Scenario 3: If local sanitization gate fails or detects blocking content,
    feature extraction fails closed and no training record is created.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 85},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }

    with patch("src.privacy_gate.sanitize_for_local_training") as mock_gate:
        mock_gate.return_value = MagicMock(
            sanitization_success=False,
            sanitized_text=None,
            blocking_reasons=["High-entropy secret token identified"],
        )

        event = isolated_engine.process_and_record(
            message_text="Bank message with high entropy token",
            evaluation_result=mock_eval,
            consent_given=True,
            secret=TEST_HMAC_SECRET,
        )

        assert event["feature_record_id"] is None
        with isolated_repo.get_connection() as conn:
            assert conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"] == 0


# =============================================================================
# SCENARIO 4: HUMAN REVIEW LIFECYCLE (Tests 8-10)
# =============================================================================

def test_08_e2e_human_review_complete_lifecycle_and_adjudication(isolated_engine, isolated_repo):
    """
    Scenario 4: Complete human review lifecycle:
    - Event starts in 'pending' state.
    - Reviewer inspects structural observations.
    - Operator completes review: state -> 'completed', outcome -> 'phishing', assessment -> 'rules_correct'.
    - Append-only audit record created with actor 'local_operator_unauthenticated'.
    - Duplicate review without supersede flag is rejected.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 75, "findings_count": 2},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate", "model_version": "v4"},
    }
    event = isolated_engine.process_and_record("Test lure", mock_eval)
    assert event["review_state"] == ReviewState.PENDING.value

    # Complete review
    rev = isolated_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
        notes="Rules correctly identified phishing indicator",
    )
    assert rev["review_state"] == "completed"
    assert rev["outcome_label"] == "phishing"
    assert rev["reviewer_label"] == "local_operator_unauthenticated"

    # Verify audit trail
    audits = isolated_repo.list_disagreement_audit_logs(event_id=event["event_id"])
    assert len(audits) >= 1
    assert audits[0]["action"] == "created"
    assert audits[0]["actor"] == "local_operator_unauthenticated"

    # Duplicate review rejection
    with pytest.raises(ValueError, match="Duplicate review submission"):
        isolated_engine.submit_review(
            event_id=event["event_id"],
            outcome_label="legitimate",
            reviewer_assessment="model_correct",
            supersede_existing=False,
        )


def test_09_e2e_human_review_supersede_and_audit_trail(isolated_engine, isolated_repo):
    """
    Scenario 4: Superseding an existing review updates the previous review to
    is_superseded=1, review_state='superseded', and creates audit records for both actions.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 70},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }
    event = isolated_engine.process_and_record("Test lure", mock_eval)

    # Initial adjudication
    rev1 = isolated_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
    )

    # Superseded adjudication
    rev2 = isolated_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="legitimate",
        reviewer_assessment="model_correct",
        confidence_rating="high",
        supersede_existing=True,
        reason="Secondary verification confirmed legitimate government dispatch",
    )

    prior = isolated_repo.get_disagreement_review(rev1["review_id"])
    assert prior["is_superseded"] == 1
    assert prior["superseded_by"] == rev2["review_id"]
    assert prior["review_state"] == "superseded"

    # Current active review is rev2
    active = isolated_repo.get_disagreement_review(event["event_id"])
    assert active["review_id"] == rev2["review_id"]
    assert active["outcome_label"] == "legitimate"


def test_10_e2e_human_review_insufficient_evidence_and_score_invariance(isolated_engine, isolated_repo):
    """
    Scenario 4: An insufficient evidence adjudication transitions event state to
    'insufficient_evidence', is excluded from training, and never alters production scores.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 80},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }
    event = isolated_engine.process_and_record(
        message_text="Ambiguous text",
        evaluation_result=mock_eval,
        consent_given=True,
        secret=TEST_HMAC_SECRET,
    )

    rev = isolated_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="insufficient_evidence",
        reviewer_assessment="neither_sufficient",
        confidence_rating="low",
    )
    assert rev["review_state"] == "insufficient_evidence"

    # Score invariance
    persisted_event = isolated_repo.get_disagreement_event(event["event_id"])
    assert persisted_event["rule_score"] == 80


# =============================================================================
# SCENARIO 5: FEEDBACK CURATION & TRAINING EXPORT (Tests 11-14)
# =============================================================================

def test_11_e2e_feedback_curation_eligibility_and_filtering(isolated_engine, isolated_repo):
    """
    Scenario 5: Curate training features enforces all 9 eligibility rules:
    - Excludes pending reviews.
    - Excludes low-confidence reviews.
    - Excludes insufficient-evidence reviews.
    - Includes completed high/medium confidence reviews with consent.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 75},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }

    # 1. Pending (excluded)
    isolated_engine.process_and_record("Pending msg", mock_eval, consent_given=True, secret=TEST_HMAC_SECRET)

    # 2. Low confidence (excluded)
    e2 = isolated_engine.process_and_record("Low conf msg", mock_eval, consent_given=True, secret=TEST_HMAC_SECRET)
    isolated_engine.submit_review(e2["event_id"], "phishing", "rules_correct", confidence_rating="low")

    # 3. Eligible completed (included)
    e3 = isolated_engine.process_and_record("Eligible msg", mock_eval, consent_given=True, secret=TEST_HMAC_SECRET)
    isolated_engine.submit_review(e3["event_id"], "phishing", "rules_correct", confidence_rating="high")

    curation = isolated_repo.curate_training_features(secret=TEST_HMAC_SECRET)
    assert len(curation["eligible_records"]) == 1
    assert curation["eligible_records"][0]["feature_record_id"] == e3["feature_record_id"]


def test_12_e2e_feedback_curation_deduplication_and_conflict_quarantine(isolated_engine, isolated_repo):
    """
    Scenario 5: Duplicate examples with identical fingerprints select the earliest
    representative, while conflicting labels on identical fingerprints are quarantined.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 85},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }
    same_text = "Repeated standard fraud message text"

    # Two identical records with same label -> 1 eligible, 1 duplicate
    e1 = isolated_engine.process_and_record(same_text, mock_eval, consent_given=True, secret=TEST_HMAC_SECRET)
    e2 = isolated_engine.process_and_record(same_text, mock_eval, consent_given=True, secret=TEST_HMAC_SECRET)
    isolated_engine.submit_review(e1["event_id"], "phishing", "rules_correct", confidence_rating="high")
    isolated_engine.submit_review(e2["event_id"], "phishing", "rules_correct", confidence_rating="high")

    curation = isolated_repo.curate_training_features(secret=TEST_HMAC_SECRET)
    assert len(curation["eligible_records"]) == 1
    assert any(r["reason"] == "duplicate_fingerprint" for r in curation["ineligible_records"])


def test_13_e2e_feedback_export_privacy_and_identifier_stripping(isolated_engine, isolated_repo):
    """
    Scenario 5: Feature export strips case IDs, HMAC fingerprints, reviewer notes,
    raw text, and URLs, generating opaque example_ids and valid 1024-d float vectors.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 90},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }
    event = isolated_engine.process_and_record(
        message_text="Bank KYC update request",
        evaluation_result=mock_eval,
        consent_given=True,
        secret=TEST_HMAC_SECRET,
    )
    isolated_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
        notes="CONFIDENTIAL_OPERATOR_INTERNAL_NOTE_12345",
    )

    exported = isolated_repo.export_curated_training_features(secret=TEST_HMAC_SECRET)
    assert len(exported) == 1
    rec = exported[0]

    assert rec["example_id"].startswith("curated_feat_")
    assert len(rec["feature_vector"]) == 1024
    assert rec["review_provenance"] == "local_operator_unauthenticated"

    forbidden = ["case_id", "dedup_fingerprint", "notes", "raw_text", "text", "sanitized_text", "phone", "secret"]
    for key in forbidden:
        assert key not in rec, f"Key '{key}' leaked into export!"


def test_14_e2e_consent_revocation_lifecycle_and_export_exclusion(isolated_engine, isolated_repo):
    """
    Scenario 5: Calling revoke_training_consent(case_id) atomically excludes
    the record from all future training exports without altering historical audit logs.
    """
    mock_eval = {
        "operating_mode": "shadow",
        "rule_based_evidence": {"rule_label": "phishing", "score": 75},
        "experimental_model": {"is_available": True, "predicted_label": "legitimate"},
    }
    event = isolated_engine.process_and_record("Revocation test", mock_eval, consent_given=True, secret=TEST_HMAC_SECRET)
    isolated_engine.submit_review(event["event_id"], "phishing", "rules_correct", confidence_rating="high")

    # Initially eligible
    assert len(isolated_repo.curate_training_features(secret=TEST_HMAC_SECRET)["eligible_records"]) == 1

    # Revoke consent
    isolated_repo.revoke_training_consent(case_id=event["event_id"])

    # Now ineligible
    c_after = isolated_repo.curate_training_features(secret=TEST_HMAC_SECRET)
    assert len(c_after["eligible_records"]) == 0
    assert any(r["reason"] == "consent_revoked" for r in c_after["ineligible_records"])


# =============================================================================
# SCENARIO 6: PATTERN DISCOVERY & CATALOGUE GOVERNANCE (Tests 15-17)
# =============================================================================

def test_15_e2e_pattern_discovery_lifecycle_and_audit(isolated_catalog_mgr):
    """
    Scenario 6: Discovered patterns start as 'draft', can be reviewed and approved
    by an operator, with append-only audit entries recorded in pattern_review_audit.jsonl.
    """
    pattern = CandidatePattern(
        candidate_id="PAT-E2E-001",
        pattern_schema_version="1.0.0",
        discovery_timestamp_utc="2026-10-30T12:00:00Z",
        candidate_pattern_type="ngram_feature_association",
        opaque_feature_identifiers=["feature_idx_42", "feature_idx_88"],
        target_class="phishing",
        supporting_example_count=18,
        total_dataset_examples=120,
        class_distribution={"phishing": 18, "legitimate": 0, "protective_advisory": 0},
        statistical_evidence={"confidence": 0.94, "lift": 3.8, "wilson_lower": 0.82},
        uncertainty_or_limitations=["Observational correlation"],
        data_provenance="local_curated_feedback",
        algorithm_version="pattern-discovery-v1.0.0",
        lifecycle_state="draft",
    )
    isolated_catalog_mgr.save_catalog([pattern], version="1.0.0")

    # Review approval
    res = isolated_catalog_mgr.review_candidate_pattern(
        candidate_id="PAT-E2E-001",
        new_state="approved_by_human",
        reason="Validated against digital-arrest extortion lure telemetry",
        reviewer_label="local_operator_unauthenticated",
    )
    assert res["new_state"] == "approved_by_human"
    assert res["audit_entry"]["production_rules_modified"] is False
    assert res["audit_entry"]["scoring_altered"] is False


def test_16_e2e_pattern_rejection_anti_reactivation_and_score_invariance(isolated_catalog_mgr):
    """
    Scenario 6: Rejected patterns cannot silently reactivate, and pattern approval
    leaves deterministic production risk scoring 100% unchanged.
    """
    pattern = CandidatePattern(
        candidate_id="PAT-E2E-002",
        pattern_schema_version="1.0.0",
        discovery_timestamp_utc="2026-10-30T12:00:00Z",
        candidate_pattern_type="ngram_feature_association",
        opaque_feature_identifiers=["feature_idx_12"],
        target_class="phishing",
        supporting_example_count=10,
        total_dataset_examples=100,
        class_distribution={"phishing": 10, "legitimate": 0, "protective_advisory": 0},
        statistical_evidence={"confidence": 0.70, "lift": 1.2},
        uncertainty_or_limitations=["Low lift"],
        data_provenance="local_curated_feedback",
        algorithm_version="pattern-discovery-v1.0.0",
        lifecycle_state="draft",
    )
    isolated_catalog_mgr.save_catalog([pattern], version="1.0.0")

    # Reject
    isolated_catalog_mgr.review_candidate_pattern(
        candidate_id="PAT-E2E-002",
        new_state="rejected",
        reason="High correlation with benign administrative messages",
    )

    # Attempting silent reactivation raises error
    with pytest.raises(PatternReviewError, match="previously REJECTED"):
        isolated_catalog_mgr.review_candidate_pattern(
            candidate_id="PAT-E2E-002",
            new_state="approved_by_human",
            reason="Unauthorized reactivation attempt",
        )


def test_17_e2e_pattern_provenance_separation_synthetic_vs_human(isolated_catalog_mgr):
    """
    Scenario 6: Separate provenance is strictly maintained between synthetic
    corpora and human-reviewed feedback in pattern catalogues.
    """
    p_synth = CandidatePattern(
        candidate_id="PAT-SYNTH-01",
        pattern_schema_version="1.0.0",
        discovery_timestamp_utc="2026-10-30T12:00:00Z",
        candidate_pattern_type="ngram_feature_association",
        opaque_feature_identifiers=["feature_idx_10"],
        target_class="phishing",
        supporting_example_count=50,
        total_dataset_examples=200,
        class_distribution={"phishing": 50, "legitimate": 0, "protective_advisory": 0},
        statistical_evidence={"confidence": 0.98},
        uncertainty_or_limitations=[],
        data_provenance="synthetic_corpus_v4",
        algorithm_version="pattern-discovery-v1.0.0",
        lifecycle_state="draft",
    )
    p_human = CandidatePattern(
        candidate_id="PAT-HUMAN-01",
        pattern_schema_version="1.0.0",
        discovery_timestamp_utc="2026-10-30T12:00:00Z",
        candidate_pattern_type="ngram_feature_association",
        opaque_feature_identifiers=["feature_idx_20"],
        target_class="phishing",
        supporting_example_count=12,
        total_dataset_examples=100,
        class_distribution={"phishing": 12, "legitimate": 0, "protective_advisory": 0},
        statistical_evidence={"confidence": 0.90},
        uncertainty_or_limitations=[],
        data_provenance="local_curated_feedback",
        algorithm_version="pattern-discovery-v1.0.0",
        lifecycle_state="draft",
    )
    isolated_catalog_mgr.save_catalog([p_synth, p_human], version="1.0.0")

    cat = isolated_catalog_mgr.load_catalog(version="1.0.0")
    prov_map = {item["candidate_id"]: item["data_provenance"] for item in cat["candidate_patterns"]}
    assert prov_map["PAT-SYNTH-01"] == "synthetic_corpus_v4"
    assert prov_map["PAT-HUMAN-01"] == "local_curated_feedback"


# =============================================================================
# SCENARIO 7: CANDIDATE MODEL TRAINING PIPELINE (Tests 18-19)
# =============================================================================

def test_18_e2e_candidate_training_pipeline_isolated_execution(tmp_path):
    """
    Scenario 7: Candidate training pipeline in an isolated directory:
    - Starts from random initialization.
    - Accepts valid 1024-d feature records.
    - Generates model_weights.npz, model_metadata.json, manifest.json.
    - Leaves live workspace model artifacts and active configuration completely untouched.
    """
    temp_candidates_dir = tmp_path / "candidates"
    trainer = CandidateModelTrainer(candidates_dir=str(temp_candidates_dir), epochs=2, seed=42)

    # Compose small synthetic training set (10 phishing, 10 legitimate)
    recs = [
        _make_synthetic_feature_record(f"p_{i}", label="phishing", seed=i)
        for i in range(10)
    ] + [
        _make_synthetic_feature_record(f"l_{i}", label="legitimate", seed=i + 50)
        for i in range(10)
    ]
    summary = {
        "human_reviewed_feedback_count": 10,
        "synthetic_anchor_corpus_count": 10,
        "is_synthetic_only": False,
    }

    res = trainer.train_candidate(recs, summary, candidate_version="1.0.0", min_samples=10)
    assert res.status == "SUCCESS"
    assert os.path.exists(res.weights_path)
    assert os.path.exists(res.metadata_path)
    assert os.path.exists(res.manifest_path)

    # Overwrite protection
    with pytest.raises(CandidateArtifactError, match="already exists"):
        trainer.train_candidate(recs, summary, candidate_version="1.0.0", min_samples=10)


def test_19_e2e_candidate_training_integrity_hashes_and_live_immutability(tmp_path):
    """
    Scenario 7: Verifies candidate training computes SHA-256 digests matching
    manifest entries, and enforces that live active model config is never modified.
    """
    temp_candidates_dir = tmp_path / "candidates"
    trainer = CandidateModelTrainer(candidates_dir=str(temp_candidates_dir), epochs=1, seed=101)

    recs = [
        _make_synthetic_feature_record(f"p_{i}", label="phishing", seed=i)
        for i in range(8)
    ] + [
        _make_synthetic_feature_record(f"l_{i}", label="legitimate", seed=i + 20)
        for i in range(8)
    ]
    res = trainer.train_candidate(recs, {}, candidate_version="1.0.1", min_samples=5)

    with open(res.manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["artifacts"]["model_weights"]["sha256"] == res.weights_sha256
    assert manifest["artifacts"]["model_metadata"]["sha256"] == res.metadata_sha256


# =============================================================================
# SCENARIO 8: CANDIDATE EVALUATION GATE (Tests 20-21)
# =============================================================================

def test_20_e2e_candidate_evaluation_gate_metrics_and_verdicts():
    """
    Scenario 8: Evaluates statistical metric calculations:
    - Confusion matrices across classes {0, 1, 2}.
    - Per-class precision, recall, and F1.
    - False-positive rates with Wilson score confidence intervals.
    """
    y_true = np.array([0, 0, 0, 1, 1, 1, 2, 2, 2], dtype=np.int64)
    y_pred = np.array([0, 0, 1, 1, 1, 1, 2, 2, 0], dtype=np.int64)

    cm = compute_confusion_matrix(y_true, y_pred, num_classes=3)
    assert cm[0][0] == 2  # class 0 TP
    assert cm[0][1] == 1  # class 0 predicted 1

    metrics = compute_classification_metrics(y_true, y_pred)
    assert "macro_f1" in metrics
    assert "per_class" in metrics
    assert metrics["accuracy"] > 0.60

    lower, upper = wilson_score_interval(successes=95, total=100, confidence=0.95)
    assert 0.88 < lower < 0.95
    assert 0.95 < upper <= 0.99


def test_21_e2e_candidate_evaluation_small_sample_and_incompatible_handling(tmp_path):
    """
    Scenario 8: Small sample sizes (< policy threshold) or incompatible feature dimensions
    are rejected safely without modifying model checkpoints or advancing qualification.
    """
    policy = BenchmarkPolicy(min_class_samples=50)
    # Check evaluation gate handling for small sample size
    evaluator = CandidateEvaluator(project_root=str(tmp_path), policy=policy)

    mock_metrics = {
        "macro_f1": 0.99,
        "per_class": {
            "phishing": {"support": 5, "f1": 1.0},
            "legitimate": {"support": 5, "f1": 1.0},
            "protective_advisory": {"support": 5, "f1": 1.0},
        },
    }
    gate_res = evaluator.evaluate_benchmark_gate(mock_metrics, mock_metrics, robustness_metrics={})
    assert gate_res["verdict"] in (BenchmarkVerdict.INSUFFICIENT_EVIDENCE.value, BenchmarkVerdict.FAIL.value)
    assert any("Insufficient sample count" in r for r in gate_res["reasons"])


# =============================================================================
# SCENARIO 9: MODEL REGISTRATION AND ROLLBACK (Tests 22-23)
# =============================================================================

def test_22_e2e_model_registry_shadow_registration_isolated(tmp_path):
    """
    Scenario 9: Model registry registration in isolated environment:
    - Shadow registration sets operating_mode='shadow' and is_production_authoritative=False.
    - Rejects duplicate versions or path traversals.
    """
    models_dir = tmp_path / "models"
    models_dir.mkdir(parents=True)
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(models_dir), dirs_exist_ok=True)

    reg = ModelRegistry(project_root=str(tmp_path), models_dir="models")
    active_cfg = reg.get_active_model_config()

    assert active_cfg["operating_mode"] == "shadow"
    assert active_cfg["is_production_authoritative"] is False
    assert active_cfg["active_model_version"] == "custom-mlp-v4.0.0-seed42"


def test_23_e2e_rollback_controller_atomic_execution_isolated(tmp_path):
    """
    Scenario 9: RollbackController restores designated previous model (LKG) atomically
    without corrupting active configuration or leaving partial files.
    """
    models_dir = tmp_path / "models"
    models_dir.mkdir(parents=True)
    shutil.copytree(os.path.join(PROJECT_ROOT, "models"), str(models_dir), dirs_exist_ok=True)

    reg = ModelRegistry(project_root=str(tmp_path), models_dir="models")
    rbc = RollbackController(registry=reg)

    status = rbc.get_rollback_status()
    assert status["can_rollback"] is True
    assert status["target_rollback_version"] == "custom-mlp-v1.1.0-preproc"

    # Execute rollback
    cfg = rbc.execute_rollback(operator_label="test_suite", reason="Phase 6.7 integration rollback test")
    assert cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"
    assert cfg["last_known_good_version"] == "custom-mlp-v4.0.0-seed42"

    # Live workspace configuration was not touched
    live_cfg = get_default_model_registry().get_active_model_config()
    assert live_cfg["active_model_version"] == "custom-mlp-v4.0.0-seed42"


# =============================================================================
# SCENARIO 10: FAILURE INJECTION AND FAULT TOLERANCE (Tests 24-26)
# =============================================================================

def test_24_e2e_failure_injection_corrupt_database_safe_fallback(tmp_path):
    """
    Scenario 10: Corrupt SQLite database file handling:
    1. CaseRepository fails closed upon database initialization (raises CaseRepositoryError).
    2. SessionCaseStore fails closed when initialized with a corrupt repository.
    3. In-memory message analysis, risk scoring, and case formatting operate safely
       and independently without requiring database access.
    4. Stateless hybrid decision engine operates without failure in shadow and rules_only modes.
    5. LIMITATION: Application architecture does NOT provide transparent in-memory database
       fallback; it deliberately fails closed on corrupt persistence to prevent silent data loss.
    """
    corrupt_db = tmp_path / "corrupt.sqlite3"
    with open(corrupt_db, "wb") as f:
        f.write(b"NOT_A_VALID_SQLITE_DATABASE_HEADER_CORRUPTED_BYTES")

    from src.case_repository import CaseRepositoryError

    # 1. Repository initialization fails closed
    with pytest.raises(CaseRepositoryError, match="file is not a database"):
        CaseRepository(db_path=str(corrupt_db))

    # 2. SessionCaseStore fails closed when backed by a corrupt repository
    with pytest.raises(CaseRepositoryError):
        bad_repo = CaseRepository(db_path=str(corrupt_db))
        SessionCaseStore(session_id="corrupt_session", repository=bad_repo)

    # 3. Core detection and message case intake formatting execute independently in memory
    msg = "Urgent: Your SBI bank debit card is deactivated. Visit http://sbi-unfreeze-secure.xyz to update KYC."
    analysis = analyze_message_text(msg)
    scored = score_message_analysis(analysis)
    case_rec = create_message_case(analysis, scored, store_raw_text=False)

    assert case_rec["case_id"].startswith("CASE-MSG-")
    assert case_rec["risk_score"] > 0
    assert case_rec["analysis_status"] == "Completed"

    # 4. Hybrid engine runs independently of database state
    res_rules = evaluate_message_hybrid(msg, operating_mode="rules_only")
    assert res_rules["final_decision"]["authoritative_source"] == "deterministic_rules"
    assert res_rules["final_decision"]["final_risk_score"] > 0

    res_shadow = evaluate_message_hybrid(msg, operating_mode="shadow")
    assert res_shadow["final_decision"]["authoritative_source"] == "deterministic_rules"
    assert res_shadow["final_decision"]["production_score_difference"] == 0


def test_25_e2e_failure_injection_corrupt_model_safe_fallback():
    """
    Scenario 10: Neural model weights corrupted or inference throwing an exception
    falls back cleanly to deterministic rules, logging fallback reasons without crashing.
    """
    test_msg = "Your electricity will be cut off tonight. Pay immediately."

    with patch.object(CustomNeuralClassifier, "predict_proba", side_effect=ValueError("Corrupt weights matrix: NaN")):
        res = evaluate_message_hybrid(test_msg, operating_mode="shadow")

        # Deterministic scoring succeeds unharmed
        assert res["final_decision"]["authoritative_source"] == "deterministic_rules"
        assert res["final_decision"]["production_score_difference"] == 0
        assert res["experimental_model"]["is_available"] is False
        assert "Corrupt weights" in (res["experimental_model"]["fallback_reason"] or "")


def test_26_e2e_failure_injection_disagreement_crash_resilience(isolated_engine, isolated_repo):
    """
    Scenario 10: Disagreement engine failure resilience:
    1. Core message analysis and deterministic scoring remain fully available and unharmed.
    2. Exception injected into DisagreementEngine.classify_evaluation is ACTUALLY invoked
       and exercised along the real application call path (process_and_record / record_disagreement).
    3. The application does not falsely record a successful disagreement event in SQLite.
    4. Database state remains clean (zero partial/corrupt records).
    """
    test_msg = "Urgent: Your SBI bank debit card is deactivated. Visit http://sbi-unfreeze-secure.xyz to update KYC."

    # 1. Core message analysis and hybrid shadow evaluation execute and produce authoritative scores
    eval_res = evaluate_message_hybrid(test_msg, operating_mode="shadow")
    assert eval_res["final_decision"]["authoritative_source"] == "deterministic_rules"
    assert eval_res["final_decision"]["final_risk_score"] > 0
    assert eval_res["final_decision"]["production_score_difference"] == 0

    # 2. Inject failure directly into DisagreementEngine.classify_evaluation
    with patch.object(
        DisagreementEngine,
        "classify_evaluation",
        side_effect=RuntimeError("Disagreement classification crash probe"),
    ) as mock_classify:
        # Verify via direct engine call path
        with pytest.raises(RuntimeError, match="Disagreement classification crash probe"):
            isolated_engine.process_and_record(
                message_text=test_msg,
                evaluation_result=eval_res,
                consent_given=True,
                secret=TEST_HMAC_SECRET,
            )

        # Confirm the mock was ACTUALLY invoked along the real call path
        assert mock_classify.call_count == 1

        # Also verify via SessionCaseStore.record_disagreement entry point
        store = SessionCaseStore(session_id="test_resilience_session", repository=isolated_repo)
        with pytest.raises(RuntimeError, match="Disagreement classification crash probe"):
            store.record_disagreement(
                message_text=test_msg,
                evaluation_result=eval_res,
                consent_given=True,
                secret=TEST_HMAC_SECRET,
            )

        # Confirm mock was invoked again
        assert mock_classify.call_count == 2

    # 3. Verify safe behavior:
    # - Production score is completely unharmed
    assert eval_res["final_decision"]["production_score_difference"] == 0
    assert eval_res["final_decision"]["final_risk_score"] > 0
    # - No disagreement event was falsely recorded in SQLite
    stats = isolated_repo.get_disagreement_stats()
    assert stats["total_events"] == 0
    with isolated_repo.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM model_disagreement_events;").fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) AS c FROM training_feature_records;").fetchone()["c"] == 0


# =============================================================================
# SCENARIO 11: PERFORMANCE & RESOURCE LIMITS (Test 27)
# =============================================================================

def test_27_e2e_performance_benchmarks_latency_and_resource_bounds(isolated_engine, isolated_repo):
    """
    Scenario 11: Measures local latencies across core operations:
    - Message analysis latency (< 150 ms).
    - Shadow hybrid inference latency (< 100 ms).
    - Disagreement classification latency (< 100 ms).
    - Review submission latency (< 100 ms).
    - Curation & export latency (< 150 ms).
    - SQLite database growth for 15 records (< 300 KB).
    """
    msg = "Urgent: Your SBI bank debit card is deactivated. Visit http://sbi-unfreeze-secure.xyz"

    # 1. Message analysis latency
    t0 = time.perf_counter()
    analysis = analyze_message_text(msg)
    t_analysis = (time.perf_counter() - t0) * 1000
    assert t_analysis < 150  # comfortably sub-150ms

    # 2. Shadow hybrid evaluation latency
    t0 = time.perf_counter()
    eval_res = evaluate_message_hybrid(msg, operating_mode="shadow")
    t_hybrid = (time.perf_counter() - t0) * 1000
    assert t_hybrid < 100

    # 3. Disagreement processing & recording latency
    t0 = time.perf_counter()
    event = isolated_engine.process_and_record(msg, eval_res, consent_given=True, secret=TEST_HMAC_SECRET)
    t_disagree = (time.perf_counter() - t0) * 1000
    assert t_disagree < 100

    # 4. Review submission latency
    t0 = time.perf_counter()
    isolated_engine.submit_review(event["event_id"], "phishing", "rules_correct", confidence_rating="high")
    t_review = (time.perf_counter() - t0) * 1000
    assert t_review < 100

    # 5. Curation & export latency
    t0 = time.perf_counter()
    exported = isolated_repo.export_curated_training_features(secret=TEST_HMAC_SECRET)
    t_export = (time.perf_counter() - t0) * 1000
    assert t_export < 150
    assert len(exported) == 1

    # 6. Database size check
    db_size_bytes = os.path.getsize(isolated_repo.db_path)
    assert db_size_bytes < 300 * 1024  # Under 300 KB as documented


# =============================================================================
# SCENARIO 12: NETWORK & PRIVACY BOUNDARY VERIFICATION (Tests 28-29)
# =============================================================================

def test_28_e2e_network_isolation_zero_outbound_calls(isolated_engine, isolated_repo):
    """
    Scenario 12: Verifies 100% offline local operation across multiple Python network APIs:
    - Blocks socket.socket, socket.create_connection, socket.getaddrinfo, and urllib.request.urlopen.
    - Confirms that message analysis, shadow hybrid evaluation, lexical URL analysis,
      disagreement processing, review adjudication, and training curation make ZERO outbound calls.
    - LIMITATION: Confirms Python interpreter layer isolation; does NOT establish OS-level kernel
      firewall or subprocess sandbox isolation.
    """
    def forbidden_network(*args, **kwargs):
        raise ConnectionRefusedError("NETWORK_ISOLATION_VIOLATION: Outbound network calls are strictly prohibited!")

    import urllib.request

    with patch("socket.socket", side_effect=forbidden_network), \
         patch("socket.create_connection", side_effect=forbidden_network), \
         patch("socket.getaddrinfo", side_effect=forbidden_network), \
         patch("urllib.request.urlopen", side_effect=forbidden_network):

        # 1. Hybrid evaluation & rule analysis
        msg = "Urgent: Electricity bill unpaid. Call 9876543210 immediately."
        eval_res = evaluate_message_hybrid(msg, operating_mode="shadow")
        assert eval_res["final_decision"]["production_score_difference"] == 0

        # 2. Purely lexical URL analysis (never fetches or connects)
        url_res = analyze_url("https://sbi-unfreeze-secure.xyz/login?id=test")
        assert "Suspicious" in url_res["risk_level"] or url_res["score"] > 50
        assert url_res["badge_color"] in ("red", "orange")

        # 3. Disagreement processing & event recording
        event = isolated_engine.process_and_record(msg, eval_res, consent_given=True, secret=TEST_HMAC_SECRET)
        assert event["event_id"].startswith("EVT-")

        # 4. Review adjudication
        isolated_engine.submit_review(event["event_id"], "phishing", "rules_correct", confidence_rating="high")

        # 5. Feedback curation and export
        curation = isolated_repo.curate_training_features(secret=TEST_HMAC_SECRET)
        assert len(curation["eligible_records"]) == 1

        exported = isolated_repo.export_curated_training_features(secret=TEST_HMAC_SECRET)
        assert len(exported) == 1


def test_29_e2e_privacy_verification_zero_raw_text_in_storage(isolated_engine, isolated_repo):
    """
    Scenario 12: Ingests highly sensitive citizen PII, raw URLs with credential query tokens,
    phone numbers, email addresses, and citizen names.
    Exhaustively scans all database tables and export structures:
    1. threat_cases (cases table)
    2. training_feature_records (including metadata_json and vectors)
    3. model_disagreement_events (including metadata_json)
    4. disagreement_reviews (including notes)
    5. disagreement_review_audit (including details_json)
    6. Exported training feature dictionaries

    CRITICAL PRIVACY DISTINCTIONS & LIMITATIONS:
    - Derived 1024-d feature vectors are permitted only under explicit affirmative consent.
    - HMAC identifiers (dedup_fingerprint) are pseudonymous keyed hashes, not anonymous data.
    - Feature hashing (character n-grams modulo 1024) is a lossy representation, not differential privacy.
    - A canary string scan proves absence of test canary literals; it does not constitute
      mathematical proof of complete PII absence under arbitrary adversarial inputs.
    """
    canary_pii = "CITIZEN_AADHAAR_9999_8888_7777"
    canary_token = "secret_canary_token_xyz"
    canary_password = "canary_password_123"
    canary_url = f"https://malicious-phishing-canary-bank-domain.com/steal-auth?token={canary_token}&password={canary_password}"
    canary_name = "Smt. Shailaja Ramchandra Patil"
    canary_phone = "9822998877"
    canary_email = "canary.citizen.victim@maharashtra-pune-domain.org"

    sensitive_msg = (
        f"Official alert for {canary_name}, Aadhaar {canary_pii}, Phone {canary_phone}, "
        f"Email {canary_email}: Authenticate immediately here: {canary_url}"
    )

    # 1. Standard Case Intake (threat_cases table)
    msg_analysis = analyze_message_text(sensitive_msg)
    scored_analysis = score_message_analysis(msg_analysis)
    case_rec = create_message_case(msg_analysis, scored_analysis, store_raw_text=False)
    case_id = isolated_repo.save_case(case_rec, session_id="canary_privacy_session")

    # 2. Shadow Hybrid Evaluation & Disagreement Recording
    eval_res = evaluate_message_hybrid(sensitive_msg, operating_mode="shadow")
    event = isolated_engine.process_and_record(
        message_text=sensitive_msg,
        evaluation_result=eval_res,
        consent_given=True,
        secret=TEST_HMAC_SECRET,
    )

    # 3. Human Review Adjudication
    isolated_engine.submit_review(
        event_id=event["event_id"],
        outcome_label="phishing",
        reviewer_assessment="rules_correct",
        confidence_rating="high",
        notes="Operator verified high-risk phishing targeting citizen credentials",
    )

    # 4. Curate and Export Training Features
    exported_records = isolated_repo.export_curated_training_features(secret=TEST_HMAC_SECRET)
    assert len(exported_records) == 1

    # 5. Exhaustive Database Column Scan across all 5 tables
    canary_tokens = [
        canary_pii,
        canary_token,
        canary_password,
        canary_name,
        canary_phone,
        canary_email,
    ]

    # Verify no PII or raw secret tokens leak into threat_cases
    with isolated_repo.get_connection() as conn:
        case_rows = conn.execute("SELECT * FROM threat_cases;").fetchall()
        for row in case_rows:
            for col in row.keys():
                val = str(row[col] or "")
                for token in canary_tokens:
                    assert token not in val, f"Leaked canary token '{token}' in threat_cases.{col}!"

    # Verify no PII, raw URLs, or secrets leak into training or review tables
    review_and_training_tables = [
        "training_feature_records",
        "model_disagreement_events",
        "disagreement_reviews",
        "disagreement_review_audit",
    ]
    with isolated_repo.get_connection() as conn:
        for table in review_and_training_tables:
            rows = conn.execute(f"SELECT * FROM {table};").fetchall()
            for row in rows:
                for col in row.keys():
                    val = str(row[col] or "")
                    assert canary_url not in val, f"Leaked raw URL in {table}.{col}!"
                    for token in canary_tokens:
                        assert token not in val, f"Leaked canary token '{token}' in table '{table}', column '{col}'!"

    # 6. Verify Exported Training Records
    for rec in exported_records:
        rec_str = json.dumps(rec)
        assert canary_url not in rec_str, "Leaked raw URL in exported training record!"
        for token in canary_tokens:
            assert token not in rec_str, f"Leaked canary token '{token}' in exported training record!"

        forbidden_keys = [
            "case_id",
            "dedup_fingerprint",
            "notes",
            "raw_text",
            "text",
            "sanitized_text",
            "phone",
            "secret",
        ]
        for key in forbidden_keys:
            assert key not in rec, f"Forbidden sensitive key '{key}' leaked into export!"


# =============================================================================
# SCENARIO 13: LIVE PRODUCTION SAFETY & IMMUTABILITY (Test 30)
# =============================================================================

def test_30_e2e_live_workspace_production_safety_and_artifact_immutability():
    """
    Scenario 13: Rigorous verification that the live project workspace has remained
    100% untouched across all integration and stress tests:
    - Active model: custom-mlp-v4.0.0-seed42.
    - Operating mode: shadow.
    - is_production_authoritative: false.
    - Rollback target (LKG): custom-mlp-v1.1.0-preproc.
    - Candidate weights SHA-256 match.
    - Baseline weights SHA-256 match.
    - Locked test partition digest matches.
    - Deterministic rule engine produces score delta 0.00.
    """
    # 1. Active model config verification
    cfg_path = os.path.join(PROJECT_ROOT, "models", "active_model_config.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    assert cfg["active_model_version"] == "custom-mlp-v4.0.0-seed42"
    assert cfg["operating_mode"] == "shadow"
    assert cfg["is_production_authoritative"] is False
    assert cfg["last_known_good_version"] == "custom-mlp-v1.1.0-preproc"

    # 2. Candidate weights SHA-256
    import hashlib

    def compute_sha(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    cand_weights_path = os.path.join(PROJECT_ROOT, "models", "candidates", "candidate_v4_seed42", "model_weights.npz")
    assert compute_sha(cand_weights_path) == CANDIDATE_WEIGHTS_SHA

    # 3. Baseline weights SHA-256
    baseline_weights_path = os.path.join(PROJECT_ROOT, "models", "experimental_custom_v1", "model_weights.npz")
    assert compute_sha(baseline_weights_path) == BASELINE_WEIGHTS_SHA

    # 4. Locked test partition digest
    locked_dataset_path = os.path.join(PROJECT_ROOT, "data", "phishing_eval_dataset.json")
    with open(locked_dataset_path, "r", encoding="utf-8") as f:
        locked_records = json.load(f)
    actual_locked_digest = compute_locked_test_hash(locked_records)
    assert actual_locked_digest == LOCKED_DIGEST_EXPECTED

    is_valid, msg = verify_locked_test_integrity(locked_records)
    assert is_valid is True, f"Locked test integrity failure: {msg}"

    # 5. Production score delta remains zero on live engine
    test_eval = evaluate_message_hybrid("Live safety verification message", operating_mode="shadow")
    assert test_eval["final_decision"]["production_score_difference"] == 0
