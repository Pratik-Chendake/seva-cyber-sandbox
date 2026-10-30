"""
Comprehensive Unit & Integration Test Suite for Phase 6.1:
Privacy-Preserving Feedback Feature Curation.

TEST SPECIFICATION:
1. Consent disabled means no feature storage.
2. Consent enabled stores valid derived features.
3. Raw text is never stored in feature records.
4. Sanitization occurs before feature extraction.
5. Invalid features are rejected (non-finite, NaN, Inf).
6. Invalid feature dimensions are rejected (!= 1024).
7. Missing secret fails closed.
8. Duplicate submissions are not duplicated in the training export.
9. Pending reviews are excluded.
10. Insufficient-evidence reviews are excluded.
11. Superseded outcomes are excluded correctly.
12. Low-confidence reviews are excluded.
13. Missing feature records are excluded.
14. Unauthenticated review provenance is preserved.
15. Existing review history remains intact.
16. Existing case-management behavior is unchanged.
17. Existing detector scores are unchanged.
18. Export contains no raw text, reviewer notes, or PII.
19. Existing training and evaluation interfaces still work.
20. Feature data cannot be accessed through unintended UI paths.
"""

import json
import math
import os
import tempfile
from typing import Any, Dict, List
import pytest

from src.case_repository import (
    CaseRepository,
    FeedbackCurationError,
    FeedbackCurationKeyError,
    FeedbackCurationValidationError,
    compute_feedback_dedup_fingerprint,
    get_feedback_hmac_secret,
)
from src.case_manager import SessionCaseStore, create_message_case
from src.dataset_preprocessing import (
    EXPECTED_FEATURE_DIM,
    FEATURE_EXTRACTOR_VERSION,
    FEATURE_SCHEMA_VERSION,
    extract_derived_training_features,
)
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_message_analysis


TEST_SECRET = "test-curation-secret-key-32chars-ok"


@pytest.fixture
def temp_db_path():
    """Provides an isolated temporary database path cleaned up after test."""
    path = tempfile.mktemp(suffix=".sqlite3")
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@pytest.fixture
def store(temp_db_path, monkeypatch):
    """Provides a SessionCaseStore backed by an isolated temporary database with configured HMAC key."""
    monkeypatch.setenv("SEVA_FEEDBACK_HMAC_KEY", TEST_SECRET)
    repo = CaseRepository(db_path=temp_db_path)
    return SessionCaseStore(session_id="test-session-61", repository=repo)


def _create_sample_case(store: SessionCaseStore, text: str) -> str:
    """Helper to analyze a message and persist a case."""
    msg_res = analyze_message_text(text)
    scored = score_message_analysis(msg_res)
    case_rec = create_message_case(msg_res, scored, store_raw_text=False)
    return store.add_case(case_rec)


# =============================================================================
# 1. CONSENT TESTS
# =============================================================================

def test_01_consent_disabled_means_no_feature_storage(store):
    """Verifies that when consent is False, no training features are captured or persisted."""
    raw_text = "कृपया आपले वीज बिल त्वरित भरा: https://msedcl.bill-update.in"
    case_id = _create_sample_case(store, raw_text)

    res = store.capture_training_features(case_id, raw_text, consent_given=False, secret=TEST_SECRET)
    assert res["captured"] is False
    assert res["reason"] == "Consent not granted"

    feat = store.get_training_features(case_id)
    assert feat is None

    # Verify underlying database table has zero rows for this case
    with store.repository.get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM training_feature_records WHERE case_id = ?;", (case_id,)).fetchone()[0]
        assert count == 0


def test_02_consent_enabled_stores_valid_derived_features(store):
    """Verifies that when consent is granted, valid 1024-d features are computed and stored."""
    raw_text = "कृपया आपले वीज बिल त्वरित भरा https://msedcl.bill-update.in"
    case_id = _create_sample_case(store, raw_text)

    res = store.capture_training_features(case_id, raw_text, consent_given=True, secret=TEST_SECRET)
    assert res["captured"] is True
    assert "feature_record_id" in res
    assert res["feature_dim"] == EXPECTED_FEATURE_DIM

    feat = store.get_training_features(case_id)
    assert feat is not None
    assert feat["feature_dim"] == 1024
    assert len(feat["feature_vector"]) == 1024
    assert feat["consent_given"] is True
    assert feat["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert feat["preprocessing_version"] == "neural-preproc-v1.1.0"
    assert feat["feature_extractor_version"] == FEATURE_EXTRACTOR_VERSION
    assert all(isinstance(x, float) and math.isfinite(x) for x in feat["feature_vector"])


# =============================================================================
# 2. PRIVACY & SANITIZATION TESTS
# =============================================================================

def test_03_raw_text_is_never_stored(store):
    """Ensures raw message text is nowhere stored in the database or feature record."""
    sensitive_text = "प्रिय नागरिक 9820098200 वर ओटीपी 4589 पाठवा"
    case_id = _create_sample_case(store, sensitive_text)

    res = store.capture_training_features(case_id, sensitive_text, consent_given=True, secret=TEST_SECRET)
    assert res["captured"] is True

    # Inspect the raw SQLite table columns and data
    with store.repository.get_connection() as conn:
        cols = [c[1] for c in conn.execute("PRAGMA table_info(training_feature_records);").fetchall()]
        assert "text" not in cols
        assert "raw_text" not in cols
        assert "sanitized_text" not in cols

        row = conn.execute("SELECT * FROM training_feature_records WHERE case_id = ?;", (case_id,)).fetchone()
        row_str = str(dict(row))
        assert "9820098200" not in row_str
        assert "4589" not in row_str
        assert "प्रिय नागरिक" not in row_str


def test_04_sanitization_occurs_before_feature_extraction(store):
    """Ensures input is sanitized (Aadhaar & phone redacted) before n-gram feature extraction."""
    text_with_pii = "आधार क्रमांक 2345 6789 0123 वर मोफत सोलर योजनेचा लाभ घ्या"
    case_id = _create_sample_case(store, text_with_pii)

    res = store.capture_training_features(case_id, text_with_pii, consent_given=True, secret=TEST_SECRET)
    assert res["captured"] is True

    feat = store.get_training_features(case_id)
    assert feat is not None
    # Verify fingerprint does not match raw Aadhaar
    assert "2345 6789 0123" not in json.dumps(feat)


# =============================================================================
# 3. VALIDATION & INTEGRITY TESTS
# =============================================================================

def test_05_invalid_features_are_rejected(store):
    """Verifies that non-finite values (NaN / Inf) are rejected before persistence."""
    case_id = _create_sample_case(store, "साधा संदेश")
    nan_vector = [0.0] * 1024
    nan_vector[42] = float("nan")
    valid_fingerprint = "a" * 64

    with pytest.raises(FeedbackCurationValidationError, match="Invalid non-finite"):
        store.repository.record_training_features(
            case_id=case_id,
            feature_vector=nan_vector,
            dedup_fingerprint=valid_fingerprint,
            consent_given=True,
        )


def test_06_invalid_feature_dimensions_are_rejected(store):
    """Verifies that vector dimensions differing from 1024 are rejected."""
    case_id = _create_sample_case(store, "साधा संदेश")
    short_vector = [0.0] * 512
    valid_fingerprint = "a" * 64

    with pytest.raises(FeedbackCurationValidationError, match="dimension mismatch"):
        store.repository.record_training_features(
            case_id=case_id,
            feature_vector=short_vector,
            dedup_fingerprint=valid_fingerprint,
            consent_given=True,
        )


def test_07_missing_secret_fails_closed(store, monkeypatch):
    """Verifies that feature extraction and curation fail closed if the HMAC secret is unconfigured."""
    monkeypatch.delenv("SEVA_FEEDBACK_HMAC_KEY", raising=False)
    monkeypatch.delenv("SEVA_THREAT_INTEL_KEY", raising=False)
    monkeypatch.delenv("SEVA_HMAC_SECRET", raising=False)

    ok, vec, fgp, err = extract_derived_training_features("काहीतरी मजकूर", secret=None)
    assert ok is False
    assert "HMAC secret key is not configured" in err

    with pytest.raises(FeedbackCurationKeyError):
        store.repository.curate_training_features(secret=None)

    # SEC-06-02: Setting only threat intel key must NOT satisfy feedback curation
    monkeypatch.setenv("SEVA_THREAT_INTEL_KEY", "another-valid-secret-key-32chars-ok")
    with pytest.raises(FeedbackCurationKeyError):
        get_feedback_hmac_secret(secret=None)


# =============================================================================
# 4. DEDUPLICATION TESTS
# =============================================================================

def test_08_duplicate_submissions_not_duplicated_in_export(store):
    """Verifies that repeated submissions of identical text produce identical fingerprints and are deduplicated."""
    msg = "महावितरण वीज बिल थकबाकी भरण्यासाठी येथे क्लिक करा: http://msedcl.pay.link"
    case_id_1 = _create_sample_case(store, msg)
    case_id_2 = _create_sample_case(store, msg)

    # Capture features for both with consent
    res1 = store.capture_training_features(case_id_1, msg, consent_given=True, secret=TEST_SECRET)
    res2 = store.capture_training_features(case_id_2, msg, consent_given=True, secret=TEST_SECRET)
    assert res1["captured"] is True
    assert res2["captured"] is True

    # Complete human reviews for both cases
    store.repository.submit_review(case_id_1, outcome_category="phishing", confidence_rating="high")
    store.repository.submit_review(case_id_2, outcome_category="phishing", confidence_rating="high")

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    assert curation["report"]["total_feature_records_evaluated"] == 2
    assert curation["report"]["eligible_training_examples_count"] == 1
    assert curation["report"]["ineligibility_reasons_breakdown"]["duplicate_fingerprint"] == 1

    # Verify exported list contains exactly 1 independent record and case_id is omitted
    exported = store.repository.export_curated_training_features(secret=TEST_SECRET)
    assert len(exported) == 1
    assert "case_id" not in exported[0]
    assert "example_id" in exported[0]


# =============================================================================
# 5. REVIEW ELIGIBILITY TESTS
# =============================================================================

def test_09_pending_reviews_are_excluded(store):
    """Verifies that feature records for unadjudicated (pending) cases are ineligible."""
    case_id = _create_sample_case(store, "प्रलंबित पुनरावलोकन चाचणी संदेश")
    store.capture_training_features(case_id, "प्रलंबित पुनरावलोकन चाचणी संदेश", consent_given=True, secret=TEST_SECRET)
    # Explicitly create pending review
    rev = store.repository.create_or_get_review(case_id)
    assert rev["review_state"] == "pending"

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    assert curation["report"]["eligible_training_examples_count"] == 0
    assert curation["report"]["ineligibility_reasons_breakdown"]["review_pending"] == 1


def test_09b_unreviewed_cases_are_excluded(store):
    """Verifies that cases without any review record are marked as unreviewed_case and excluded."""
    case_id = _create_sample_case(store, "अद्याप पुनरावलोकन न झालेला संदेश")
    store.capture_training_features(case_id, "अद्याप पुनरावलोकन न झालेला संदेश", consent_given=True, secret=TEST_SECRET)

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    assert curation["report"]["eligible_training_examples_count"] == 0
    assert curation["report"]["ineligibility_reasons_breakdown"]["unreviewed_case"] == 1


def test_10_insufficient_evidence_reviews_are_excluded(store):
    """Verifies that reviews marked as insufficient_evidence (inconclusive) are excluded."""
    case_id = _create_sample_case(store, "अस्पष्ट पुरावा असलेला संदेश")
    store.capture_training_features(case_id, "अस्पष्ट पुरावा असलेला संदेश", consent_given=True, secret=TEST_SECRET)

    store.repository.submit_review(
        case_id=case_id,
        outcome_category="insufficient_evidence",
        notes="Not enough context to determine fraud.",
    )

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    assert curation["report"]["eligible_training_examples_count"] == 0
    assert curation["report"]["ineligibility_reasons_breakdown"]["insufficient_evidence"] == 1


def test_11_superseded_outcomes_excluded_correctly(store):
    """Verifies that when a review outcome is superseded, only the latest outcome is evaluated."""
    case_id = _create_sample_case(store, "सुधारित पुनरावलोकन संदेश")
    store.capture_training_features(case_id, "सुधारित पुनरावलोकन संदेश", consent_given=True, secret=TEST_SECRET)

    # Initial adjudication: phishing (completed)
    store.repository.submit_review(case_id=case_id, outcome_category="phishing", confidence_rating="high")
    c1 = store.repository.curate_training_features(secret=TEST_SECRET)
    assert c1["report"]["eligible_training_examples_count"] == 1

    # Corrected / superseded adjudication: insufficient_evidence
    store.repository.submit_review(case_id=case_id, outcome_category="insufficient_evidence", confidence_rating="medium")
    c2 = store.repository.curate_training_features(secret=TEST_SECRET)
    assert c2["report"]["eligible_training_examples_count"] == 0
    assert c2["report"]["ineligibility_reasons_breakdown"]["insufficient_evidence"] == 1


def test_12_low_confidence_reviews_are_excluded(store):
    """Verifies that reviews marked with 'low' confidence are excluded from candidate training."""
    case_id = _create_sample_case(store, "कमी आत्मविश्वासाचा निकाल संदेश")
    store.capture_training_features(case_id, "कमी आत्मविश्वासाचा निकाल संदेश", consent_given=True, secret=TEST_SECRET)

    store.repository.submit_review(
        case_id=case_id,
        outcome_category="phishing",
        confidence_rating="low",
        notes="Unsure about intent.",
    )

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    assert curation["report"]["eligible_training_examples_count"] == 0
    assert curation["report"]["ineligibility_reasons_breakdown"]["low_confidence_review"] == 1


def test_13_missing_feature_records_are_excluded(store):
    """Verifies that completed reviews without feature records (opt-out cases) do not enter candidate training."""
    case_id = _create_sample_case(store, "संमती नसलेला पुनरावलोकन संदेश")
    # No feature capture (consent was False or omitted)

    store.repository.submit_review(case_id=case_id, outcome_category="legitimate", confidence_rating="high")

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    # The case should not appear in eligible records
    assert curation["report"]["eligible_training_examples_count"] == 0


# =============================================================================
# 6. PROVENANCE & GOVERNANCE TESTS
# =============================================================================

def test_14_unauthenticated_review_provenance_is_preserved(store):
    """Verifies that exported records reflect unauthenticated local operator provenance."""
    case_id = _create_sample_case(store, "स्थानिक ऑपरेटर चाचणी संदेश")
    store.capture_training_features(case_id, "स्थानिक ऑपरेटर चाचणी संदेश", consent_given=True, secret=TEST_SECRET)
    store.repository.submit_review(case_id=case_id, outcome_category="protective_advisory", confidence_rating="high")

    exported = store.repository.export_curated_training_features(secret=TEST_SECRET)
    assert len(exported) == 1
    rec = exported[0]
    assert rec["review_provenance"] == "local_operator_unauthenticated"
    assert rec["label"] == "protective_advisory"
    assert rec["label_idx"] == 2
    assert "NOT independently authenticated" in rec["disclaimer"]


def test_15_existing_review_history_remains_intact(store):
    """Verifies that existing human reviews and audit logs are preserved intact."""
    case_id = _create_sample_case(store, "ऑडिट लॉग चाचणी केस")
    rev = store.repository.create_or_get_review(case_id)
    assert rev["review_state"] == "pending"

    submitted = store.repository.submit_review(case_id, outcome_category="legitimate", confidence_rating="medium")
    assert submitted["review_state"] == "completed"

    audit_logs = store.repository.list_review_audit_logs(case_id=case_id)
    assert len(audit_logs) >= 2
    actions = [a["action"] for a in audit_logs]
    assert "CREATE" in actions
    assert "SUBMIT_REVIEW" in actions

    # Existing export remains unchanged and functional
    raw_exp = store.export_human_reviews_corpus()
    assert isinstance(raw_exp, str)


def test_16_existing_case_management_behavior_is_unchanged(store):
    """Verifies that standard case storage, retrieval, and listing remain unchanged."""
    case_id = _create_sample_case(store, "केस व्यवस्थापन चाचणी")
    case = store.get_case(case_id)
    assert case is not None
    assert case["case_id"] == case_id
    assert case["analysis_type"] == "WhatsApp Vernacular Phishing Analysis"


def test_17_existing_detector_scores_are_unchanged(store):
    """Verifies that deterministic rules produce identical scores whether consent is granted or not."""
    sample_text = "कृपया त्वरित आपला वीज बिलाचा भरणा करा नाहीतर रात्री वीज पुरवठा खंडित केला जाईल."
    res1 = analyze_message_text(sample_text)
    score1 = score_message_analysis(res1)

    case_id = _create_sample_case(store, sample_text)
    store.capture_training_features(case_id, sample_text, consent_given=True, secret=TEST_SECRET)

    res2 = analyze_message_text(sample_text)
    score2 = score_message_analysis(res2)

    assert score1["score"] == score2["score"]
    assert score1["risk_level"] == score2["risk_level"]


def test_18_export_contains_no_raw_text_or_reviewer_notes(store, tmp_path):
    """Verifies that the generated JSONL export contains zero raw text, notes, or credentials."""
    case_id = _create_sample_case(store, "गोपनीयतेची संपूर्ण तपासणी करणारा संदेश")
    store.capture_training_features(case_id, "गोपनीयतेची संपूर्ण तपासणी करणारा संदेश", consent_given=True, secret=TEST_SECRET)
    store.repository.submit_review(
        case_id=case_id,
        outcome_category="phishing",
        confidence_rating="high",
        notes="Reviewer note mentioning confidential operator details.",
    )

    export_file = str(tmp_path / "curated_export.jsonl")
    records = store.export_curated_training_features(export_path=export_file, secret=TEST_SECRET)

    assert len(records) == 1
    with open(export_file, "r", encoding="utf-8") as f:
        file_content = f.read()

    # Sensitive strings must be strictly absent
    assert "गोपनीयतेची संपूर्ण तपासणी" not in file_content
    assert "Reviewer note mentioning" not in file_content
    assert "dedup_fingerprint" not in file_content

    # Validate structure of exported JSON
    exported_data = json.loads(file_content.strip())
    assert "feature_vector" in exported_data
    assert len(exported_data["feature_vector"]) == 1024
    assert exported_data["label"] == "phishing"


def test_19_existing_training_and_evaluation_interfaces_still_work():
    """Verifies that previous phase custom model components remain operational and compatible."""
    from src.custom_model import CharacterNGramHasher, CustomNeuralClassifier
    hasher = CharacterNGramHasher(num_features=1024)
    vec = hasher.transform_text("काहीतरी चाचणी मजकूर")
    assert vec.shape == (1024,)

    model = CustomNeuralClassifier(input_dim=1024, seed=42)
    pred = model.predict_one("काहीतरी चाचणी मजकूर", hasher)
    assert "predicted_label" in pred
    assert "probabilities" in pred


def test_20_feature_data_cannot_be_accessed_through_unintended_ui_paths(store):
    """Verifies that standard CaseRecord wrapper does not expose training feature records."""
    case_id = _create_sample_case(store, "सुरक्षित ऍक्सेस चाचणी")
    store.capture_training_features(case_id, "सुरक्षित ऍक्सेस चाचणी", consent_given=True, secret=TEST_SECRET)

    case = store.get_case(case_id)
    case_dict = case if isinstance(case, dict) else case.to_dict()
    assert "feature_vector" not in case_dict
    assert "dedup_fingerprint" not in case_dict
    assert "training_features" not in case_dict


# =============================================================================
# 7. PHASE 6.1.1 PRIVACY & GOVERNANCE HARDENING TESTS
# =============================================================================

def test_21_sanitize_for_local_training_safe_to_send_strictly_false():
    """
    Verifies that sanitize_for_local_training() unconditionally returns safe_to_send=False,
    establishing an unbreachable privacy boundary between local feature extraction and
    external network authorization.
    """
    from src.privacy_gate import sanitize_for_local_training

    # Completely benign text with zero PII
    res_benign = sanitize_for_local_training("महाराष्ट्र शासन सामान्य माहिती")
    assert res_benign.safe_to_send is False
    assert res_benign.sanitization_success is True

    # Text with phone and Aadhaar
    res_pii = sanitize_for_local_training("माझा मोबाईल 9820098200 आणि आधार 2345 6789 0123 आहे")
    assert res_pii.safe_to_send is False
    assert res_pii.sanitization_success is True
    assert "9820098200" not in res_pii.sanitized_text
    assert "2345 6789 0123" not in res_pii.sanitized_text
    assert "[PHONE_REDACTED]" in res_pii.sanitized_text
    assert "[AADHAAR_REDACTED]" in res_pii.sanitized_text


def test_22_dedicated_feedback_hmac_secret_strict_enforcement(monkeypatch):
    """
    Verifies that feedback HMAC secret validation uses strictly SEVA_FEEDBACK_HMAC_KEY
    and fails closed without falling back to SEVA_THREAT_INTEL_KEY or SEVA_HMAC_SECRET.
    """
    monkeypatch.delenv("SEVA_FEEDBACK_HMAC_KEY", raising=False)
    monkeypatch.setenv("SEVA_THREAT_INTEL_KEY", "threat-intel-secret-key-32chars")
    monkeypatch.setenv("SEVA_HMAC_SECRET", "generic-secret-key-32chars-long")

    # Threat intel and generic keys present, but SEVA_FEEDBACK_HMAC_KEY absent -> MUST fail closed
    with pytest.raises(FeedbackCurationKeyError, match="SEVA_FEEDBACK_HMAC_KEY"):
        get_feedback_hmac_secret(secret=None)

    # Short feedback key (< 16 chars) -> MUST fail closed
    monkeypatch.setenv("SEVA_FEEDBACK_HMAC_KEY", "too-short-key")
    with pytest.raises(FeedbackCurationKeyError, match="at least 16 characters"):
        get_feedback_hmac_secret(secret=None)


def test_23_early_pending_duplicate_does_not_disqualify_later_completed(store):
    """
    Verifies that when an earlier duplicate submission is pending review, a later
    completed duplicate submission is eligible and NOT disqualified.
    """
    msg = "महावितरण वीज बिल भरणा करा http://msedcl-bill.click"
    case_id_1 = _create_sample_case(store, msg)
    case_id_2 = _create_sample_case(store, msg)

    # Capture features for both
    res1 = store.capture_training_features(case_id_1, msg, consent_given=True, secret=TEST_SECRET)
    res2 = store.capture_training_features(case_id_2, msg, consent_given=True, secret=TEST_SECRET)
    assert res1["captured"] and res2["captured"]

    # Case 1 is created first but left in pending review
    store.repository.create_or_get_review(case_id_1)

    # Case 2 is submitted later and completed
    store.repository.submit_review(case_id_2, outcome_category="phishing", confidence_rating="high")

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    assert curation["report"]["total_feature_records_evaluated"] == 2
    assert curation["report"]["eligible_training_examples_count"] == 1
    assert curation["report"]["ineligibility_reasons_breakdown"]["review_pending"] == 1

    eligible = curation["eligible_records"]
    assert len(eligible) == 1
    assert eligible[0]["case_id"] == case_id_2


def test_24_conflicting_duplicate_labels_quarantine_entire_group(store):
    """
    Verifies that when duplicate submissions receive conflicting human review labels,
    the entire duplicate group is quarantined with reason 'conflicting_duplicate_labels'.
    """
    msg = "महाराष्ट्र राज्य लॉटरी निकाल पहा http://lottery-win.in"
    case_id_1 = _create_sample_case(store, msg)
    case_id_2 = _create_sample_case(store, msg)

    res1 = store.capture_training_features(case_id_1, msg, consent_given=True, secret=TEST_SECRET)
    res2 = store.capture_training_features(case_id_2, msg, consent_given=True, secret=TEST_SECRET)
    assert res1["captured"] and res2["captured"]

    # Conflicting adjudications by operators: phishing vs legitimate
    store.repository.submit_review(case_id_1, outcome_category="phishing", confidence_rating="high")
    store.repository.submit_review(case_id_2, outcome_category="legitimate", confidence_rating="high")

    curation = store.repository.curate_training_features(secret=TEST_SECRET)
    assert curation["report"]["eligible_training_examples_count"] == 0
    assert curation["report"]["ineligibility_reasons_breakdown"]["conflicting_duplicate_labels"] == 2


def test_25_export_curated_training_features_strips_case_id(store, tmp_path):
    """
    Verifies that export_curated_training_features() strictly strips direct case_id identifiers
    from all exported records to prevent cross-correlation with stored case logs.
    """
    msg = "बँक खात्याचे केवायसी अपडेट करा http://bank-kyc.in"
    case_id = _create_sample_case(store, msg)
    store.capture_training_features(case_id, msg, consent_given=True, secret=TEST_SECRET)
    store.repository.submit_review(case_id, outcome_category="phishing", confidence_rating="high")

    export_path = str(tmp_path / "stripped_export.jsonl")
    records = store.export_curated_training_features(export_path=export_path, secret=TEST_SECRET)
    assert len(records) == 1
    rec = records[0]

    # Verify case_id is strictly omitted
    assert "case_id" not in rec
    assert "example_id" in rec
    assert rec["example_id"].startswith("curated_feat_")
    assert "feature_vector" in rec
    assert "label" in rec
    assert "review_provenance" in rec

    # Verify exported file on disk does not contain the case_id string
    with open(export_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert case_id not in content
    assert '"case_id"' not in content


def test_26_consent_revocation_excludes_from_export_without_deleting_history(store):
    """
    Verifies that revoking consent sets eligibility_state='consent_revoked', excludes
    the record from subsequent training exports, and preserves existing case and review records.
    """
    msg = "शेतकरी कर्जमाफी यादीत नाव तपासा http://karjamafi.in"
    case_id = _create_sample_case(store, msg)
    store.capture_training_features(case_id, msg, consent_given=True, secret=TEST_SECRET)
    store.repository.submit_review(case_id, outcome_category="legitimate", confidence_rating="high")

    # Initial curation should be eligible
    c1 = store.repository.curate_training_features(secret=TEST_SECRET)
    assert c1["report"]["eligible_training_examples_count"] == 1

    # Revoke consent for the case
    revoked_count = store.revoke_training_consent(case_id=case_id, reason="citizen_request")
    assert revoked_count == 1

    # Subsequent curation should exclude this record with reason 'consent_revoked'
    c2 = store.repository.curate_training_features(secret=TEST_SECRET)
    assert c2["report"]["eligible_training_examples_count"] == 0
    assert c2["report"]["ineligibility_reasons_breakdown"]["consent_revoked"] == 1

    # Ensure export contains 0 records
    exported = store.export_curated_training_features(secret=TEST_SECRET)
    assert len(exported) == 0

    # Ensure underlying case record is intact
    case = store.get_case(case_id)
    assert case is not None
    assert case["case_id"] == case_id

    # Ensure human review is intact
    rev = store.get_review(case_id)
    assert rev is not None
    assert rev["outcome_category"] == "legitimate"


def test_27_consent_revocation_by_feature_record_id(store):
    """Verifies that consent can be revoked directly using feature_record_id."""
    msg = "सोलर योजना अर्ज करा http://solar-yojana.in"
    case_id = _create_sample_case(store, msg)
    cap = store.capture_training_features(case_id, msg, consent_given=True, secret=TEST_SECRET)
    fid = cap["feature_record_id"]
    store.repository.submit_review(case_id, outcome_category="protective_advisory", confidence_rating="high")

    c1 = store.repository.curate_training_features(secret=TEST_SECRET)
    assert c1["report"]["eligible_training_examples_count"] == 1

    revoked_count = store.revoke_training_consent(feature_record_id=fid, reason="gdpr_article_17")
    assert revoked_count == 1

    c2 = store.repository.curate_training_features(secret=TEST_SECRET)
    assert c2["report"]["eligible_training_examples_count"] == 0
    assert c2["report"]["ineligibility_reasons_breakdown"]["consent_revoked"] == 1

