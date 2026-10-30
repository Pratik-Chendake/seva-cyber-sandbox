"""
Comprehensive Unit & Integration Test Suite for Phase 6.2:
Offline Autonomous Fraud Pattern Discovery Engine.

TEST SPECIFICATION (All 23 Requirements):
1. Valid eligible records can be mined.
2. Pending reviews are excluded.
3. Low-confidence reviews are excluded.
4. Insufficient-evidence records are excluded.
5. Conflicting duplicate labels are excluded.
6. Revoked consent records are excluded.
7. Repeated examples do not inflate support counts.
8. Invalid feature vectors are rejected.
9. NaN and infinity values are rejected.
10. Unsupported schema versions are rejected.
11. Synthetic and human-reviewed provenance remain separate.
12. No raw text is required or persisted.
13. No raw URLs are persisted.
14. No case IDs or HMAC fingerprints are exported in candidates.
15. Small samples produce needs_more_evidence state.
16. No pattern can be approved automatically.
17. Candidate decisions create audit events.
18. Rejected patterns cannot silently reactivate.
19. Catalogue writes do not overwrite previous versions.
20. Malformed catalogue files fail safely.
21. Existing detection results remain unchanged.
22. Existing threat-intelligence functionality remains unchanged.
23. Existing consent and review behavior remains unchanged.
"""

import json
import math
import os
import tempfile
from typing import Any, Dict, List
import pytest

from src.case_repository import (
    CaseRepository,
    FeedbackCurationKeyError,
    FeedbackCurationValidationError,
)
from src.case_manager import SessionCaseStore, create_message_case
from src.pattern_discovery import (
    AUDIT_LOG_FILENAME,
    CandidatePattern,
    PatternCatalogError,
    PatternCatalogManager,
    PatternDiscoveryEngine,
    PatternDiscoveryError,
    PatternReviewError,
    PatternValidationError,
    compute_feature_statistics,
    compute_wilson_lower_bound,
    mine_ngram_feature_associations,
    mine_ngram_feature_pairs,
    mine_structural_url_characteristics,
)
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_message_analysis


TEST_SECRET = "test-pattern-discovery-secret-32chars"


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
def temp_catalog_dir(tmp_path):
    """Provides an isolated temporary directory for catalog storage."""
    cat_dir = tmp_path / "pattern_catalog"
    cat_dir.mkdir(parents=True, exist_ok=True)
    return str(cat_dir)


@pytest.fixture
def store(temp_db_path, monkeypatch):
    """Provides a SessionCaseStore backed by an isolated temporary database with configured HMAC key."""
    monkeypatch.setenv("SEVA_FEEDBACK_HMAC_KEY", TEST_SECRET)
    repo = CaseRepository(db_path=temp_db_path)
    return SessionCaseStore(session_id="test-session-62", repository=repo)


def _seed_curated_cases(store: SessionCaseStore, count_per_class: int = 5) -> List[str]:
    """Helper to seed consented, reviewed cases across phishing, legitimate, and protective_advisory."""
    case_ids = []

    phish_texts = [
        f"कृपया आपले वीज बिल त्वरित भरा {i}: http://msedcl-bill-update-{i}.in/pay.apk"
        for i in range(count_per_class)
    ]
    legit_texts = [
        f"महाराष्ट्र शासन अधिकृत योजना माहिती क्रमांक {i}: https://maharashtra.gov.in"
        for i in range(count_per_class)
    ]
    adv_texts = [
        f"सावधान! महावितरण कधीही व्हॉट्सॲपवर एपीके फाईल पाठवत नाही {i}. सतर्क राहा."
        for i in range(count_per_class)
    ]

    for t in phish_texts:
        msg_res = analyze_message_text(t)
        scored = score_message_analysis(msg_res)
        cid = store.add_case(create_message_case(msg_res, scored, store_raw_text=False))
        store.capture_training_features(cid, t, consent_given=True, secret=TEST_SECRET)
        store.repository.submit_review(cid, outcome_category="phishing", confidence_rating="high")
        case_ids.append(cid)

    for t in legit_texts:
        msg_res = analyze_message_text(t)
        scored = score_message_analysis(msg_res)
        cid = store.add_case(create_message_case(msg_res, scored, store_raw_text=False))
        store.capture_training_features(cid, t, consent_given=True, secret=TEST_SECRET)
        store.repository.submit_review(cid, outcome_category="legitimate", confidence_rating="high")
        case_ids.append(cid)

    for t in adv_texts:
        msg_res = analyze_message_text(t)
        scored = score_message_analysis(msg_res)
        cid = store.add_case(create_message_case(msg_res, scored, store_raw_text=False))
        store.capture_training_features(cid, t, consent_given=True, secret=TEST_SECRET)
        store.repository.submit_review(cid, outcome_category="protective_advisory", confidence_rating="high")
        case_ids.append(cid)

    return case_ids


# =============================================================================
# 1. ELIGIBILITY & GATE EXCLUSION TESTS
# =============================================================================

def test_01_valid_eligible_records_can_be_mined(store, temp_catalog_dir):
    """Verifies that eligible, consented, reviewed records can be mined for pattern hypotheses."""
    _seed_curated_cases(store, count_per_class=5)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)

    res = engine.discover_patterns_from_curated_feedback(
        repository=store.repository,
        secret=TEST_SECRET,
        min_support=3,
    )

    assert res["status"] in ("PASS", "NEEDS_MORE_EVIDENCE")
    assert res["eligible_records_count"] == 15
    assert res["discovered_candidates_count"] > 0
    assert len(res["candidates"]) > 0

    # Ensure all candidates are valid CandidatePattern instances
    for cand in res["candidates"]:
        cand.validate()
        assert cand.data_provenance == "local_curated_feedback"


def test_02_pending_reviews_are_excluded(store, temp_catalog_dir):
    """Verifies that cases with review_state='pending' are excluded from discovery mining."""
    # Seed 3 pending cases
    for i in range(3):
        t = f"प्रलंबित पुनरावलोकन चाचणी {i}: http://pending.link"
        msg_res = analyze_message_text(t)
        scored = score_message_analysis(msg_res)
        cid = store.add_case(create_message_case(msg_res, scored, store_raw_text=False))
        store.capture_training_features(cid, t, consent_given=True, secret=TEST_SECRET)
        store.repository.create_or_get_review(cid)  # Leaves in 'pending'

    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    assert res["eligible_records_count"] == 0
    assert res["status"] == "INSUFFICIENT_EVIDENCE"


def test_03_low_confidence_reviews_are_excluded(store, temp_catalog_dir):
    """Verifies that reviews marked with low confidence are excluded from candidate mining."""
    for i in range(3):
        t = f"कमी आत्मविश्वासाचा निकाल संदेश {i}: http://low-conf.link"
        msg_res = analyze_message_text(t)
        scored = score_message_analysis(msg_res)
        cid = store.add_case(create_message_case(msg_res, scored, store_raw_text=False))
        store.capture_training_features(cid, t, consent_given=True, secret=TEST_SECRET)
        store.repository.submit_review(cid, outcome_category="phishing", confidence_rating="low")

    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    assert res["eligible_records_count"] == 0
    assert res["status"] == "INSUFFICIENT_EVIDENCE"


def test_04_insufficient_evidence_records_are_excluded(store, temp_catalog_dir):
    """Verifies that reviews marked with outcome 'insufficient_evidence' are excluded."""
    for i in range(3):
        t = f"अस्पष्ट पुरावा संदेश {i}: http://inconclusive.link"
        msg_res = analyze_message_text(t)
        scored = score_message_analysis(msg_res)
        cid = store.add_case(create_message_case(msg_res, scored, store_raw_text=False))
        store.capture_training_features(cid, t, consent_given=True, secret=TEST_SECRET)
        store.repository.submit_review(cid, outcome_category="insufficient_evidence")

    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    assert res["eligible_records_count"] == 0
    assert res["status"] == "INSUFFICIENT_EVIDENCE"


def test_05_conflicting_duplicate_labels_are_excluded(store, temp_catalog_dir):
    """Verifies that duplicate submissions with conflicting review labels are quarantined and excluded."""
    msg = "महावितरण वीज बिल तात्काळ भरा: http://msedcl-conflict.link"
    cid1 = store.add_case(create_message_case(analyze_message_text(msg), score_message_analysis(analyze_message_text(msg))))
    cid2 = store.add_case(create_message_case(analyze_message_text(msg), score_message_analysis(analyze_message_text(msg))))

    store.capture_training_features(cid1, msg, consent_given=True, secret=TEST_SECRET)
    store.capture_training_features(cid2, msg, consent_given=True, secret=TEST_SECRET)

    # Conflicting labels
    store.repository.submit_review(cid1, outcome_category="phishing", confidence_rating="high")
    store.repository.submit_review(cid2, outcome_category="legitimate", confidence_rating="high")

    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    assert res["eligible_records_count"] == 0


def test_06_revoked_consent_records_are_excluded(store, temp_catalog_dir):
    """Verifies that records where consent was revoked are excluded from pattern discovery."""
    _seed_curated_cases(store, count_per_class=3)

    # Revoke consent for all records
    with store.repository.get_connection() as conn:
        cases = [r[0] for r in conn.execute("SELECT case_id FROM threat_cases;").fetchall()]
    for cid in cases:
        store.revoke_training_consent(case_id=cid, reason="bulk_revocation_test")

    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    assert res["eligible_records_count"] == 0
    assert res["status"] == "INSUFFICIENT_EVIDENCE"


def test_07_repeated_examples_do_not_inflate_support_counts(store, temp_catalog_dir):
    """Verifies that duplicate submissions are deduplicated and do not inflate support counts."""
    msg = "महावितरण डुप्लिकेट चाचणी: http://msedcl.unique.link"
    # Create 3 duplicate submissions with identical review
    for _ in range(3):
        cid = store.add_case(create_message_case(analyze_message_text(msg), score_message_analysis(analyze_message_text(msg))))
        store.capture_training_features(cid, msg, consent_given=True, secret=TEST_SECRET)
        store.repository.submit_review(cid, outcome_category="phishing", confidence_rating="high")

    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    # Only 1 deduplicated record should be eligible
    assert res["eligible_records_count"] == 1


# =============================================================================
# 2. DATA VALIDATION & INTEGRITY TESTS
# =============================================================================

def test_08_invalid_feature_vectors_are_rejected():
    """Verifies that feature vectors with invalid dimensions or types fail validation."""
    short_record = {"feature_vector": [0.1] * 500, "label": "phishing"}
    candidates = mine_ngram_feature_associations([short_record], provenance="test", min_support=1)
    assert len(candidates) == 0


def test_09_nan_and_infinity_values_are_rejected():
    """Verifies that CandidatePattern validation rejects NaN or Inf in statistical evidence."""
    cand = CandidatePattern(
        candidate_id="PAT-CAND-001",
        pattern_schema_version="1.0.0",
        discovery_timestamp_utc="2026-10-30T12:00:00Z",
        candidate_pattern_type="ngram_feature_association",
        opaque_feature_identifiers=["feature_idx_42"],
        target_class="phishing",
        supporting_example_count=5,
        total_dataset_examples=10,
        class_distribution={"phishing": 5, "legitimate": 0, "protective_advisory": 0},
        statistical_evidence={"wilson_lower_bound": float("nan")},
        uncertainty_or_limitations=["test limit"],
        data_provenance="test",
        algorithm_version="pattern-discovery-v1.0.0",
        lifecycle_state="draft",
    )

    with pytest.raises(PatternValidationError, match="non-finite value"):
        cand.validate()

    # Also test Inf rejection
    cand.statistical_evidence["wilson_lower_bound"] = float("inf")
    with pytest.raises(PatternValidationError, match="non-finite value"):
        cand.validate()

    # Also test forbidden key rejection
    cand.statistical_evidence["wilson_lower_bound"] = 0.75
    cand.metadata["raw_text"] = "sensitive message"
    with pytest.raises(PatternValidationError, match="Forbidden sensitive key"):
        cand.validate()


def test_10_unsupported_schema_versions_are_rejected():
    """Verifies that CandidatePattern rejects invalid pattern_schema_version."""
    cand = CandidatePattern(
        candidate_id="PAT-CAND-002",
        pattern_schema_version="99.0.0",
        discovery_timestamp_utc="2026-10-30T12:00:00Z",
        candidate_pattern_type="ngram_feature_association",
        opaque_feature_identifiers=["feature_idx_42"],
        target_class="phishing",
        supporting_example_count=5,
        total_dataset_examples=10,
        class_distribution={"phishing": 5, "legitimate": 0, "protective_advisory": 0},
        statistical_evidence={},
        uncertainty_or_limitations=[],
        data_provenance="test",
        algorithm_version="pattern-discovery-v1.0.0",
        lifecycle_state="draft",
    )

    with pytest.raises(PatternValidationError, match="Unsupported pattern schema version"):
        cand.validate()


# =============================================================================
# 3. PRIVACY & PROVENANCE TESTS
# =============================================================================

def test_11_synthetic_and_human_reviewed_provenance_remain_separate(store, temp_catalog_dir):
    """Verifies that synthetic data mining is strictly segregated with synthetic provenance."""
    _seed_curated_cases(store, count_per_class=3)
    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))

    local_res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)
    assert local_res["provenance"] == "local_curated_feedback"

    # Attempting to mine the locked evaluation dataset MUST raise PatternDiscoveryError
    with pytest.raises(PatternDiscoveryError, match="Mining the locked evaluation dataset is strictly prohibited"):
        engine.discover_patterns_from_synthetic_corpus("data/phishing_eval_dataset.json")

    # Attempting to mine the validation corpus MUST raise PatternDiscoveryError
    with pytest.raises(PatternDiscoveryError, match="Mining the validation corpus is prohibited"):
        engine.discover_patterns_from_synthetic_corpus("data/generated/v2/synthetic_validation_corpus.jsonl")


def test_12_no_raw_text_is_required_or_persisted(store, temp_catalog_dir):
    """Verifies that candidate patterns and catalog files contain zero raw message text."""
    _seed_curated_cases(store, count_per_class=4)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)

    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)
    cat_path = cat_mgr.save_catalog(res["candidates"], version="1.0.0")

    with open(cat_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "कृपया आपले वीज बिल" not in content
    assert "महाराष्ट्र शासन अधिकृत" not in content
    assert "व्हॉट्सॲपवर एपीके फाईल" not in content


def test_13_no_raw_urls_are_persisted(store, temp_catalog_dir):
    """Verifies that no full raw URLs or target web addresses are stored in pattern catalogues."""
    _seed_curated_cases(store, count_per_class=4)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)

    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)
    cat_path = cat_mgr.save_catalog(res["candidates"], version="1.0.0")

    with open(cat_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "http://" not in content
    assert "https://" not in content
    assert "msedcl-bill-update" not in content


def test_14_no_case_ids_or_hmac_fingerprints_in_candidates(store, temp_catalog_dir):
    """Verifies that internal case_id and dedup_fingerprint are strictly absent from candidate patterns."""
    _seed_curated_cases(store, count_per_class=3)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)

    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)
    for cand in res["candidates"]:
        cand_dict = cand.to_dict()
        assert "case_id" not in cand_dict
        assert "dedup_fingerprint" not in cand_dict
        assert "secret" not in cand_dict


# =============================================================================
# 4. LIFECYCLE & HUMAN REVIEW TESTS
# =============================================================================

def test_15_small_samples_produce_needs_more_evidence_state():
    """Verifies that candidate patterns with small sample sizes start in 'needs_more_evidence'."""
    # 3 supporting phishing records and 3 legitimate baseline records
    dummy_records = [
        {"feature_vector": [0.2] + [0.0] * 1023, "label": "phishing"}
        for _ in range(3)
    ] + [
        {"feature_vector": [0.0] * 1024, "label": "legitimate"}
        for _ in range(3)
    ]
    candidates = mine_ngram_feature_associations(dummy_records, provenance="test", min_support=3)
    assert len(candidates) == 1
    assert candidates[0].lifecycle_state == "needs_more_evidence"
    assert any("SMALL_SAMPLE_SIZE" in lim for lim in candidates[0].uncertainty_or_limitations)


def test_16_no_pattern_can_be_approved_automatically(store, temp_catalog_dir):
    """Verifies that autonomous discovery NEVER sets approved_by_human."""
    _seed_curated_cases(store, count_per_class=5)
    engine = PatternDiscoveryEngine(catalog_manager=PatternCatalogManager(catalog_dir=temp_catalog_dir))
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    for cand in res["candidates"]:
        assert cand.lifecycle_state in ("draft", "needs_more_evidence")
        assert cand.lifecycle_state != "approved_by_human"


def test_17_candidate_decisions_create_audit_events(store, temp_catalog_dir):
    """Verifies that reviewing a candidate appends an audit event to pattern_review_audit.jsonl."""
    _seed_curated_cases(store, count_per_class=4)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)

    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)
    assert len(res["candidates"]) > 0
    cat_path = cat_mgr.save_catalog(res["candidates"], version="1.0.0")

    target_cid = res["candidates"][0].candidate_id
    rev_res = cat_mgr.review_candidate_pattern(
        candidate_id=target_cid,
        new_state="approved_by_human",
        reason="Operator verified campaign correlation",
        reviewer_label="operator_analyst_1",
        catalog_path=cat_path,
    )

    assert rev_res["new_state"] == "approved_by_human"

    audit_logs = cat_mgr.list_review_audit_logs()
    assert len(audit_logs) >= 1
    last_log = audit_logs[-1]
    assert last_log["candidate_id"] == target_cid
    assert last_log["new_state"] == "approved_by_human"
    assert last_log["reason"] == "Operator verified campaign correlation"
    assert last_log["production_rules_modified"] is False
    assert last_log["scoring_altered"] is False


def test_18_rejected_patterns_cannot_silently_reactivate(store, temp_catalog_dir):
    """Verifies that once a candidate is rejected, it cannot be silently reactivated to approved_by_human."""
    _seed_curated_cases(store, count_per_class=4)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)

    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)
    cat_path = cat_mgr.save_catalog(res["candidates"], version="1.0.0")
    target_cid = res["candidates"][0].candidate_id

    # Reject candidate
    cat_mgr.review_candidate_pattern(
        candidate_id=target_cid,
        new_state="rejected",
        reason="False positive correlation with generic punctuation",
        catalog_path=cat_path,
    )

    # Attempt to reactivate to approved_by_human -> MUST raise PatternReviewError
    with pytest.raises(PatternReviewError, match="Silent reactivation to approved_by_human is strictly prohibited"):
        cat_mgr.review_candidate_pattern(
            candidate_id=target_cid,
            new_state="approved_by_human",
            reason="Attempting unauthorized reactivation",
            catalog_path=cat_path,
        )


# =============================================================================
# 5. CATALOGUE VERSIONING & ROBUSTNESS TESTS
# =============================================================================

def test_19_catalogue_writes_do_not_overwrite_previous_versions(store, temp_catalog_dir):
    """Verifies that catalogue versions increment sequentially and do not overwrite previous versions."""
    _seed_curated_cases(store, count_per_class=4)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)

    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)

    v1_path = cat_mgr.save_catalog(res["candidates"], version="1.0.0")
    assert os.path.exists(v1_path)

    # Attempting to save version 1.0.0 again without overwrite MUST fail
    with pytest.raises(PatternCatalogError, match="already exists"):
        cat_mgr.save_catalog(res["candidates"], version="1.0.0", overwrite=False)

    # Next automatic version should be 1.0.1
    v2_path = cat_mgr.save_catalog(res["candidates"])
    assert "catalog_v1.0.1.json" in v2_path
    assert os.path.exists(v1_path)  # v1.0.0 preserved
    assert os.path.exists(v2_path)


def test_20_malformed_catalogue_files_fail_safely(temp_catalog_dir):
    """Verifies that corrupted JSON in a catalog directory raises PatternCatalogError cleanly."""
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    bad_file = os.path.join(temp_catalog_dir, "catalog_v9.9.9.json")
    with open(bad_file, "w", encoding="utf-8") as f:
        f.write("{ broken json ...")

    with pytest.raises(PatternCatalogError, match="corrupted or malformed"):
        cat_mgr.load_catalog(catalog_path=bad_file)


# =============================================================================
# 6. INVARIANCE & NON-INTERFERENCE TESTS
# =============================================================================

def test_21_existing_detection_results_remain_unchanged(store, temp_catalog_dir):
    """Verifies that discovering patterns and approving candidates has zero impact on deterministic detectors."""
    test_text = "कृपया आपले वीज बिल भरा http://msedcl-test.in"

    # Pre-discovery score
    pre_res = analyze_message_text(test_text)
    pre_score = score_message_analysis(pre_res)

    _seed_curated_cases(store, count_per_class=4)
    cat_mgr = PatternCatalogManager(catalog_dir=temp_catalog_dir)
    engine = PatternDiscoveryEngine(catalog_manager=cat_mgr)
    res = engine.discover_patterns_from_curated_feedback(repository=store.repository, secret=TEST_SECRET)
    cat_path = cat_mgr.save_catalog(res["candidates"], version="1.0.0")

    # Approve discovered candidates (testing approval workflow and scoring invariance)
    assert len(res["candidates"]) > 0
    for c in res["candidates"][:3]:
        cat_mgr.review_candidate_pattern(
            candidate_id=c.candidate_id,
            new_state="approved_by_human",
            reason="Testing scoring invariance",
            catalog_path=cat_path,
        )

    # Post-discovery score MUST be identical
    post_res = analyze_message_text(test_text)
    post_score = score_message_analysis(post_res)

    assert pre_score["score"] == post_score["score"]
    assert pre_score["risk_level"] == post_score["risk_level"]


def test_22_existing_threat_intelligence_functionality_remains_unchanged(store):
    """Verifies that threat indicator repository and phone HMAC operations remain unaffected."""
    from src.case_repository import compute_phone_indicator_hmac

    # Ensure phone indicator matching works as expected
    phone_hmac = compute_phone_indicator_hmac("9820098200", secret="threat-intel-secret-32chars-ok")
    assert phone_hmac.startswith("HMAC_")
    assert len(phone_hmac) == 69


def test_23_existing_consent_and_review_behavior_remains_unchanged(store):
    """Verifies that existing human reviews and case management interfaces continue to work identically."""
    msg = "मानक केस चाचणी संदेश"
    cid = store.add_case(create_message_case(analyze_message_text(msg), score_message_analysis(analyze_message_text(msg))))

    rev = store.repository.create_or_get_review(cid)
    assert rev["review_state"] == "pending"

    sub = store.repository.submit_review(cid, outcome_category="legitimate", confidence_rating="high")
    assert sub["review_state"] == "completed"

    stored_case = store.get_case(cid)
    assert stored_case is not None
    assert stored_case["case_id"] == cid
