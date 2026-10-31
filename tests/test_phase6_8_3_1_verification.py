"""
Phase 6.8.3.1 - Password Hashing Compliance, Evidence Trust and Dataset Segregation Verification Tests.

VERIFICATION COVERAGE:
1. Scrypt Configuration & OWASP Compliance (N=2^17=131072, r=8, p=1, maxmem=256MB).
2. Backward-Compatible Authentication & Multi-Generation Rehash-on-Success.
3. Reviewer Accountability & Role Separation (Submitter prohibition, Two-Person Rule, Audit History).
4. Evidence Poisoning Safeguards (Deduplication, Campaign Conflict Quarantine, Shared Infrastructure).
5. Strict Four-Tier Dataset Segregation (Direct testing of export_curated_training_features and export_evaluation_candidate_features).
6. Production Model Safety & Shadow Invariance (custom-mlp-v4.0.0-seed42, delta 0.00).
"""

import os
import json
import sqlite3
import tempfile
import hashlib
import hmac
import pytest
from typing import Generator

from src.operator_auth import (
    OperatorAuthService,
    hash_password,
    verify_password,
    verify_password_and_check_rehash,
    is_rehash_needed,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    SCRYPT_MAXMEM,
    PBKDF2_OWASP_ITERATIONS,
    PBKDF2_LEGACY_ITERATIONS,
    InvalidCredentialsError,
    AccountLockedError,
    UnauthorizedError,
)
from src.case_repository import (
    CaseRepository,
    EvidenceGovernanceError,
    EvidenceProvenanceError,
    InvalidStateTransitionError,
    CorroborationError,
    SelfApprovalProhibitedError,
    TamperedEvidenceError,
    TrainingEligibilityError,
    ALLOWED_VERIFICATION_METHODS,
    SHARED_INFRASTRUCTURE_DOMAINS,
)
from src.case_manager import SessionCaseStore
from src.database_migration import (
    migrate_to_evidence_governance_v2,
    migrate_to_evidence_trust_hardening_v3,
)
from src.hybrid_decision_engine import evaluate_message_hybrid
from src.model_registry import ModelRegistry


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def temp_db_path() -> Generator[str, None, None]:
    """Provides a fresh temporary SQLite database with all v3 migrations applied."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        path = f.name
    try:
        migrate_to_evidence_governance_v2(path)
        migrate_to_evidence_trust_hardening_v3(path)
        yield path
    finally:
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


@pytest.fixture
def auth_service(temp_db_path: str) -> OperatorAuthService:
    """Provides an OperatorAuthService instance backed by temp_db_path."""
    return OperatorAuthService(temp_db_path)


@pytest.fixture
def repo(temp_db_path: str) -> CaseRepository:
    """Provides a CaseRepository instance backed by temp_db_path."""
    return CaseRepository(db_path=temp_db_path)


# =============================================================================
# PART 1: SCRYPT CONFIGURATION & OWASP COMPLIANCE
# =============================================================================

def test_01_scrypt_owasp_parameters_and_format():
    """Verifies that default password hashing uses OWASP-recommended scrypt parameters (N=2^17=131072, r=8, p=1)."""
    assert SCRYPT_N == 131072  # 2^17
    assert SCRYPT_R == 8
    assert SCRYPT_P == 1
    assert SCRYPT_MAXMEM == 256 * 1024 * 1024  # 256 MiB

    pwd = "AuditVerifiedPassword2026!#"
    hash_str, salt_hex = hash_password(pwd, algorithm="scrypt")

    assert hash_str.startswith(f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}$")
    parts = hash_str.split("$")
    assert len(parts) == 6
    assert int(parts[1]) == 131072
    assert int(parts[2]) == 8
    assert int(parts[3]) == 1
    assert parts[4] == salt_hex
    assert len(parts[5]) == 128  # 64-byte key in hex

    # Verification must succeed and report no rehash needed
    is_valid, needs_rehash = verify_password_and_check_rehash(pwd, salt_hex, hash_str)
    assert is_valid is True
    assert needs_rehash is False


def test_02_scrypt_memory_headroom_avoids_msvc_long_overflow():
    """Confirms that scrypt maxmem calculation does not overflow Windows 32-bit signed long (2 GiB)."""
    pwd = "MemorySafeTestPassword2026!"
    hash_str, salt_hex = hash_password(pwd, algorithm="scrypt")

    # Verify that password verification completes successfully without OverflowError
    assert verify_password(pwd, salt_hex, hash_str) is True


# =============================================================================
# PART 2: MULTI-GENERATION ACCOUNT PRESERVATION & REHASH UPGRADE
# =============================================================================

def test_03_legacy_and_interim_hash_verification_compatibility(auth_service, temp_db_path):
    """
    Verifies transparent backward compatibility across:
    1. Phase 6.8.2 legacy PBKDF2 (raw 200k hex).
    2. Modern PBKDF2 (pbkdf2_sha256$600000$).
    3. Interim Scrypt (N=16384, r=8, p=1).
    All must verify properly and trigger rehash-on-success.
    """
    pwd = "CrossGenerationPassword2026!"
    salt = os.urandom(32)
    salt_hex = salt.hex()

    # 1. Phase 6.8.2 legacy PBKDF2 (200k)
    legacy_key = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, PBKDF2_LEGACY_ITERATIONS).hex()
    v1, r1 = verify_password_and_check_rehash(pwd, salt_hex, legacy_key)
    assert v1 is True
    assert r1 is True
    assert is_rehash_needed(legacy_key) is True

    # 2. Modern PBKDF2 (600k)
    modern_key = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, PBKDF2_OWASP_ITERATIONS).hex()
    modern_hash = f"pbkdf2_sha256${PBKDF2_OWASP_ITERATIONS}${salt_hex}${modern_key}"
    v2, r2 = verify_password_and_check_rehash(pwd, salt_hex, modern_hash)
    assert v2 is True
    assert r2 is True
    assert is_rehash_needed(modern_hash) is True

    # 3. Interim Scrypt (N=16384, r=8, p=1)
    interim_key = hashlib.scrypt(pwd.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=64*1024*1024).hex()
    interim_hash = f"scrypt$16384$8$1${salt_hex}${interim_key}"
    v3, r3 = verify_password_and_check_rehash(pwd, salt_hex, interim_hash)
    assert v3 is True
    assert r3 is True  # Parameter mismatch (16384 != 131072) triggers upgrade!
    assert is_rehash_needed(interim_hash) is True


def test_04_interim_scrypt_transparently_upgraded_to_owasp_on_login(auth_service, temp_db_path):
    """Verifies that an operator account created with N=16384 is upgraded to N=131072 on login."""
    auth_service.register_initial_operator(username="admin_super", password="InitialAdminPass123!", role="admin")

    # Manually insert an operator with N=16384
    salt = os.urandom(32)
    salt_hex = salt.hex()
    pwd = "InterimOperatorPass2026!"
    old_key = hashlib.scrypt(pwd.encode("utf-8"), salt=salt, n=16384, r=8, p=1, maxmem=64*1024*1024).hex()
    old_hash = f"scrypt$16384$8$1${salt_hex}${old_key}"

    with sqlite3.connect(temp_db_path) as conn:
        conn.execute(
            """
            INSERT INTO operator_accounts (
                username, password_hash, salt, role, created_at_utc,
                failed_login_count, is_active
            ) VALUES ('interim_operator', ?, ?, 'reviewer', '2026-10-31T00:00:00Z', 0, 1);
            """,
            (old_hash, salt_hex),
        )

    # Login should succeed and perform transparent upgrade
    res = auth_service.login("interim_operator", pwd)
    assert res["success"] is True
    assert res["rehashed_to_scrypt"] is True

    # Check updated hash in SQLite
    with sqlite3.connect(temp_db_path) as conn:
        cur = conn.execute("SELECT password_hash FROM operator_accounts WHERE username = 'interim_operator';")
        upgraded_hash = cur.fetchone()[0]

    assert upgraded_hash.startswith("scrypt$131072$8$1$")
    assert upgraded_hash != old_hash

    # Second login should not trigger rehash
    res2 = auth_service.login("interim_operator", pwd)
    assert res2["success"] is True
    assert res2["rehashed_to_scrypt"] is False


def test_05_zero_plaintext_password_retention_in_database(auth_service, temp_db_path):
    """Confirms that plaintext passwords never exist anywhere in SQLite database tables."""
    raw_pwd = "PlausiblySecretOperatorPassword2026!#"
    auth_service.register_initial_operator("root_user", raw_pwd, role="admin")

    with sqlite3.connect(temp_db_path) as conn:
        cur = conn.execute("SELECT * FROM operator_accounts WHERE username = 'root_user';")
        cols = [d[0] for d in cur.description]
        row = dict(zip(cols, cur.fetchone()))

    assert raw_pwd not in json.dumps(row)
    assert row["password_hash"].startswith("scrypt$131072$8$1$")


# =============================================================================
# PART 3: REVIEWER ACCOUNTABILITY & ROLE SEPARATION
# =============================================================================

def test_06_submitter_role_cannot_review_or_corroborate_evidence(repo, auth_service):
    """Confirms that an operator with role 'submitter' cannot transition evidence to review states."""
    auth_service.register_initial_operator("admin_lead", "LeadAdminPass123!", role="admin")
    admin_sess = auth_service.login("admin_lead", "LeadAdminPass123!")

    # Create submitter account using create_operator
    auth_service.create_operator(admin_sess["session_token"], "field_submitter", "SubmitterPass123!", role="submitter")

    # Ingest evidence
    ev = repo.register_evidence_provenance(
        case_id="CASE-SUBMIT-01",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        operator_username="field_submitter",
        submitted_by="field_submitter",
    )
    eid = ev["evidence_id"]

    repo.transition_evidence_status(eid, "awaiting_review", "system", "Queue for review")

    # Submitter attempts to transition to under_review -> REJECTED
    with pytest.raises(EvidenceGovernanceError) as exc_info:
        repo.transition_evidence_status(
            evidence_id=eid,
            to_status="under_review",
            operator_username="field_submitter",
            transition_reason="Submitter trying to review own item",
            operator_role="submitter",
        )
    assert "Submitters are not authorized to transition evidence" in str(exc_info.value)


def test_07_submitting_operator_cannot_independently_corroborate(repo):
    """Enforces Two-Person Rule: Submitter cannot independently corroborate their own submission."""
    ev = repo.register_evidence_provenance(
        case_id="CASE-2P-01",
        evidence_origin="analyst_submitted",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        operator_username="analyst_vikram",
        submitted_by="analyst_vikram",
    )
    eid = ev["evidence_id"]

    repo.transition_evidence_status(eid, "awaiting_review", "system", "Queue")
    repo.transition_evidence_status(eid, "under_review", "analyst_vikram", "Triage review")

    # Submitter attempts independent corroboration -> MUST RAISE SelfApprovalProhibitedError
    with pytest.raises(SelfApprovalProhibitedError) as exc_info:
        repo.corroborate_evidence(
            evidence_id=eid,
            operator_username="analyst_vikram",
            rationale="I verified this myself and it is definitely malicious.",
            conclusion="phishing",
            verification_method="technical_indicator_correlation",
            supporting_references=["IND-MALICIOUS-PAYMENT"],
            require_independent=True,
        )
    assert "Self-approval prohibited" in str(exc_info.value)


def test_08_primary_reviewer_cannot_independently_corroborate(repo):
    """Enforces Two-Person Rule: Primary reviewer cannot corroborate as distinct second reviewer."""
    ev = repo.register_evidence_provenance(
        case_id="CASE-2P-02",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="citizen_mobile_app",
    )
    eid = ev["evidence_id"]

    repo.transition_evidence_status(eid, "awaiting_review", "system", "Queue")
    repo.transition_evidence_status(eid, "under_review", "reviewer_amit", "Primary triage", reviewer_classification="phishing")

    with pytest.raises(SelfApprovalProhibitedError) as exc_info:
        repo.corroborate_evidence(
            evidence_id=eid,
            operator_username="reviewer_amit",  # Same reviewer!
            rationale="Confirming my own prior review.",
            conclusion="phishing",
            verification_method="official_gazette_scheme_crosscheck",
            supporting_references=["GR-MAHA-2024-FINANCE"],
            require_independent=True,
        )
    assert "Self-approval prohibited" in str(exc_info.value)


def test_09_single_operator_mode_recorded_honestly_as_self_reviewed(repo):
    """Confirms single-operator mode honestly records self_reviewed and never independently_corroborated."""
    ev = repo.register_evidence_provenance(
        case_id="CASE-SOLO-99",
        evidence_origin="analyst_submitted",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        operator_username="solo_officer",
        submitted_by="solo_officer",
    )
    eid = ev["evidence_id"]

    repo.transition_evidence_status(eid, "awaiting_review", "solo_officer", "Queue")
    repo.transition_evidence_status(eid, "under_review", "solo_officer", "Review")

    res = repo.corroborate_evidence(
        evidence_id=eid,
        operator_username="solo_officer",
        rationale="Verified single-officer analysis of fake lottery domain.",
        conclusion="phishing",
        verification_method="domain_dns_lexical_analysis",
        supporting_references=["DNS-PUNYCODE-CHECK"],
        require_independent=False,  # Single-operator mode
    )

    assert res["lifecycle_status"] == "corroborated"
    assert res["verification_level"] == "self_reviewed"
    assert res["corroborated_by"] is None  # Not independently corroborated


def test_10_two_distinct_operators_achieve_independent_corroboration(repo):
    """Confirms two distinct human operators confer independently_corroborated status."""
    ev = repo.register_evidence_provenance(
        case_id="CASE-DUAL-01",
        evidence_origin="user_reported",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="citizen_reporter",
    )
    eid = ev["evidence_id"]

    repo.transition_evidence_status(eid, "awaiting_review", "triage_bot", "Triage")
    repo.transition_evidence_status(eid, "under_review", "reviewer_1", "First review", reviewer_classification="phishing")

    res = repo.corroborate_evidence(
        evidence_id=eid,
        operator_username="senior_reviewer_2",
        rationale="Second independent review confirmed credential harvesting form on domain.",
        conclusion="phishing",
        verification_method="technical_indicator_correlation",
        supporting_references=["CERT-IN-ADVISORY-2026-08"],
        operator_role="senior_reviewer",
        require_independent=True,
    )

    assert res["lifecycle_status"] == "corroborated"
    assert res["verification_level"] == "independently_corroborated"
    assert res["reviewed_by"] == "reviewer_1"
    assert res["corroborated_by"] == "senior_reviewer_2"


def test_11_audit_trail_immutably_records_all_reviewer_transitions(repo):
    """Confirms that all lifecycle state transitions create an immutable append-only audit trail."""
    ev = repo.register_evidence_provenance(
        case_id="CASE-AUDIT-01",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="citizen_intake",
    )
    eid = ev["evidence_id"]

    repo.transition_evidence_status(eid, "awaiting_review", "op_triage", "Queued for investigation")
    repo.transition_evidence_status(eid, "under_review", "op_analyst", "Analyst assigned")
    repo.corroborate_evidence(
        evidence_id=eid,
        operator_username="op_senior",
        rationale="Corroborated phishing using heuristic rule validation.",
        conclusion="phishing",
        verification_method="heuristic_rule_validation",
        supporting_references=["RULE-PHISH-01"],
        operator_role="senior_reviewer",
        require_independent=True,
    )

    history = repo.get_evidence_lifecycle_history(eid)
    assert len(history) == 4  # submitted, awaiting_review, under_review, corroborated
    statuses = [h["to_status"] for h in history]
    assert statuses == ["submitted", "awaiting_review", "under_review", "corroborated"]

    # Verify operators recorded
    operators = [h["operator_username"] for h in history]
    assert "op_triage" in operators
    assert "op_analyst" in operators
    assert "op_senior" in operators


# =============================================================================
# PART 4: EVIDENCE POISONING SAFEGUARDS
# =============================================================================

def test_12_repeated_identical_submissions_never_count_as_independent_verification(repo):
    """Confirms repeated user submissions do NOT bypass review or grant corroboration."""
    # Submit 5 identical reports
    eids = []
    for i in range(5):
        ev = repo.register_evidence_provenance(
            case_id=f"CASE-SPAM-{i}",
            evidence_origin="user_reported",
            evidence_type="url",
            consent_given=True,
            sanitization_status="passed",
            submitted_by=f"spammer_bot_{i}",
        )
        eids.append(ev["evidence_id"])

    # All remain in 'submitted' status with 'unverified' level
    for eid in eids:
        rec = repo.get_evidence_provenance(eid)
        assert rec["lifecycle_status"] == "submitted"
        assert rec["verification_level"] == "unverified"
        assert rec["corroborated_by"] is None

        # Training eligibility must be false
        elig = repo.check_training_eligibility(eid)
        assert elig["is_eligible"] is False
        assert elig["eligibility_tier"] == "eligible_exploratory_review"


def test_13_conflicting_classifications_quarantine_entire_campaign(repo):
    """
    Confirms anti-poisoning safeguard: Conflicting human labels within a campaign
    automatically set quarantined_from_training = 1 and disqualify all campaign evidence.
    """
    camp = repo.create_or_get_campaign_cluster(cluster_type="domain", cluster_key="suspicious-bank-login.xyz")
    camp_id = camp["campaign_id"]

    # Item 1: Labeled phishing
    repo.save_case({"case_id": "CASE-CAMP-01", "analysis_type": "URL Analysis"}, source_type="web_simulator")
    ev1 = repo.register_evidence_provenance(
        case_id="CASE-CAMP-01",
        evidence_origin="user_reported",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        campaign_id=camp_id,
        submitted_by="user_a",
    )
    repo.record_training_features("CASE-CAMP-01", [0.05]*1024, hashlib.sha256(b"camp1").hexdigest(), consent_given=True)
    repo.submit_review("CASE-CAMP-01", "phishing", confidence_rating="high")
    repo.transition_evidence_status(ev1["evidence_id"], "awaiting_review", "op1", "Triage")
    repo.transition_evidence_status(ev1["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev1["evidence_id"], "op2", "Confirmed phishing link targeting bank users.",
        "phishing", "domain_dns_lexical_analysis", ["DNS-REPORT-01"], require_independent=True,
    )

    # Pre-conflict: ev1 is eligible
    assert repo.check_training_eligibility(ev1["evidence_id"])["is_eligible"] is True

    # Item 2: Maliciously or mistakenly labeled legitimate in same campaign
    repo.save_case({"case_id": "CASE-CAMP-02", "analysis_type": "URL Analysis"}, source_type="web_simulator")
    ev2 = repo.register_evidence_provenance(
        case_id="CASE-CAMP-02",
        evidence_origin="user_reported",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        campaign_id=camp_id,
        submitted_by="user_b",
    )
    repo.record_training_features("CASE-CAMP-02", [0.05]*1024, hashlib.sha256(b"camp2").hexdigest(), consent_given=True)
    repo.submit_review("CASE-CAMP-02", "legitimate", confidence_rating="high")
    repo.transition_evidence_status(ev2["evidence_id"], "awaiting_review", "op3", "Triage")
    repo.transition_evidence_status(ev2["evidence_id"], "under_review", "op3", "Review")
    repo.corroborate_evidence(
        ev2["evidence_id"], "op4", "Reviewer claims portal is legitimate bank partner.",
        "legitimate", "technical_indicator_correlation", ["BANK-PARTNER-ASSERTION"], require_independent=True,
    )

    # Campaign conflict status
    conflict = repo.get_campaign_conflict_status(camp_id)
    assert conflict["is_conflict"] is True
    assert conflict["is_quarantined"] is True
    assert set(conflict["conflicting_labels"]) == {"phishing", "legitimate"}

    # BOTH items in the campaign must now FAIL training eligibility
    elig1 = repo.check_training_eligibility(ev1["evidence_id"])
    assert elig1["is_eligible"] is False
    assert elig1["eligibility_tier"] == "not_eligible"
    assert elig1["checks"]["conflict_resolved"] is False

    elig2 = repo.check_training_eligibility(ev2["evidence_id"])
    assert elig2["is_eligible"] is False
    assert elig2["eligibility_tier"] == "not_eligible"
    assert elig2["checks"]["conflict_resolved"] is False


def test_14_shared_infrastructure_domains_suppress_false_campaign_conflicts(repo):
    """Confirms shared infrastructure domains (e.g. tinyurl.com) are flagged and do not force false campaign groupings."""
    for domain in ["tinyurl.com", "bit.ly", "github.io", "storage.googleapis.com"]:
        cluster = repo.create_or_get_campaign_cluster(cluster_type="domain", cluster_key=domain)
        assert cluster["is_shared_infrastructure"] is True
        assert cluster["relationship_strength"] == "weak_similarity"


# =============================================================================
# PART 5: FOUR-TIER DATASET SEGREGATION & EXPORT VERIFICATION
# =============================================================================

def test_15_strict_dataset_segregation_in_export_functions(repo):
    """
    Directly tests export_curated_training_features and export_evaluation_candidate_features:
    - Tier 4 (Independently Corroborated Evaluation Candidates) strictly excluded from training export.
    - Only Tier 4 included in evaluation export.
    - Tier 3 included in training export, excluded from evaluation export.
    """
    secret = "TestFeedbackSecretKey2026!Min16Chars"
    dummy_vec = [0.05] * 1024

    # 1. Setup Tier 3 Item: Single-reviewed consented evidence
    repo.save_case({"case_id": "CASE-T3-EXPORT", "analysis_type": "SMS Message"}, source_type="web_simulator")
    repo.record_training_features("CASE-T3-EXPORT", dummy_vec, hashlib.sha256(b"t3_fingerprint").hexdigest(), consent_given=True)
    repo.submit_review("CASE-T3-EXPORT", "phishing", confidence_rating="high")
    ev_t3 = repo.register_evidence_provenance(
        case_id="CASE-T3-EXPORT",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="user_t3",
    )
    repo.transition_evidence_status(ev_t3["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev_t3["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev_t3["evidence_id"], "op1", "Single-operator verification of phishing scheme.",
        "phishing", "heuristic_rule_validation", ["RULE-PHISH-T3"], require_independent=False,
    )
    elig_t3 = repo.check_training_eligibility(ev_t3["evidence_id"])
    assert elig_t3["eligibility_tier"] == "eligible_supervised_candidate_training"

    # 2. Setup Tier 4 Item: Independently corroborated dual-reviewed evidence
    repo.save_case({"case_id": "CASE-T4-EXPORT", "analysis_type": "SMS Message"}, source_type="web_simulator")
    repo.record_training_features("CASE-T4-EXPORT", dummy_vec, hashlib.sha256(b"t4_fingerprint").hexdigest(), consent_given=True)
    repo.submit_review("CASE-T4-EXPORT", "phishing", confidence_rating="high")
    ev_t4 = repo.register_evidence_provenance(
        case_id="CASE-T4-EXPORT",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="user_t4",
    )
    repo.transition_evidence_status(ev_t4["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev_t4["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev_t4["evidence_id"], "senior_op2", "Dual-analyst verified Maharashtra lottery phishing.",
        "phishing", "multi_analyst_independent_review", ["ANALYST-AUDIT-T4"],
        operator_role="senior_reviewer", require_independent=True,
    )
    elig_t4 = repo.check_training_eligibility(ev_t4["evidence_id"])
    assert elig_t4["eligibility_tier"] == "independently_corroborated_evaluation_candidate"

    # 3. Execute Training Feature Export
    training_export = repo.export_curated_training_features(secret=secret)
    # Tier 4 item must NOT be in training export
    assert len(training_export) == 1
    assert "curated_feat_" in training_export[0]["example_id"]
    assert training_export[0]["consent_state"] == "opted_in"

    # 4. Execute Evaluation Candidate Export
    eval_export = repo.export_evaluation_candidate_features(secret=secret)
    assert len(eval_export) == 1
    assert "eval_feat_" in eval_export[0]["example_id"]
    assert eval_export[0]["review_provenance"] == "independently_corroborated_dual_reviewer"
    assert eval_export[0]["verification_level"] == "independently_corroborated"


def test_16_withdrawn_evidence_strictly_excluded_from_future_exports(repo):
    """Confirms that withdrawing evidence immediately revokes consent and excludes it from exports."""
    secret = "TestFeedbackSecretKey2026!Min16Chars"
    dummy_vec = [0.05] * 1024

    repo.save_case({"case_id": "CASE-WITHDRAW-01", "analysis_type": "SMS Message"}, source_type="web_simulator")
    repo.record_training_features("CASE-WITHDRAW-01", dummy_vec, hashlib.sha256(b"w_fp").hexdigest(), consent_given=True)
    repo.submit_review("CASE-WITHDRAW-01", "phishing", confidence_rating="high")
    ev = repo.register_evidence_provenance(
        case_id="CASE-WITHDRAW-01",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="user_w",
    )
    eid = ev["evidence_id"]
    repo.transition_evidence_status(eid, "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(eid, "under_review", "op1", "Review")
    repo.corroborate_evidence(
        eid, "op1", "Initial corroboration.",
        "phishing", "heuristic_rule_validation", ["RULE-W"], require_independent=False,
    )

    # Initial export has 1 record
    assert len(repo.export_curated_training_features(secret=secret)) == 1

    # User exercises right to withdraw
    repo.withdraw_evidence(eid, "op1", "User requested evidence deletion under privacy rights")

    # Re-export must be completely empty
    training_reexport = repo.export_curated_training_features(secret=secret)
    assert len(training_reexport) == 0

    eval_reexport = repo.export_evaluation_candidate_features(secret=secret)
    assert len(eval_reexport) == 0


def test_17_disputed_and_synthetic_evidence_excluded_from_exports(repo):
    """Confirms that synthetic data and disputed evidence never enter training or evaluation datasets."""
    secret = "TestFeedbackSecretKey2026!Min16Chars"
    dummy_vec = [0.05] * 1024

    # 1. Synthetic data
    repo.save_case({"case_id": "CASE-SYNTH-01", "analysis_type": "Synthetic"}, source_type="web_simulator")
    repo.record_training_features("CASE-SYNTH-01", dummy_vec, hashlib.sha256(b"synth_fp").hexdigest(), consent_given=True)
    ev_synth = repo.register_evidence_provenance(
        case_id="CASE-SYNTH-01",
        evidence_origin="synthetic_test_data",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
    )

    elig_synth = repo.check_training_eligibility(ev_synth["evidence_id"])
    assert elig_synth["is_eligible"] is False
    assert elig_synth["eligibility_tier"] == "not_eligible"

    # 2. Disputed evidence (tamper detected)
    repo.save_case({"case_id": "CASE-DISPUTE-01", "analysis_type": "URL Analysis"}, source_type="web_simulator")
    repo.record_training_features("CASE-DISPUTE-01", dummy_vec, hashlib.sha256(b"disp_fp").hexdigest(), consent_given=True)
    ev_disp = repo.register_evidence_provenance(
        case_id="CASE-DISPUTE-01",
        evidence_origin="user_reported",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        artifact_sha256=hashlib.sha256(b"original").hexdigest(),
    )

    # Trigger tamper detection
    with pytest.raises(TamperedEvidenceError):
        repo.verify_evidence_integrity(ev_disp["evidence_id"], artifact_content=b"tampered_content")

    disp_rec = repo.get_evidence_provenance(ev_disp["evidence_id"])
    assert disp_rec["lifecycle_status"] == "disputed"
    assert disp_rec["verification_level"] == "disputed"

    elig_disp = repo.check_training_eligibility(ev_disp["evidence_id"])
    assert elig_disp["is_eligible"] is False
    assert elig_disp["eligibility_tier"] == "not_eligible"

    # Verify export exclusion
    assert len(repo.export_curated_training_features(secret=secret)) == 0
    assert len(repo.export_evaluation_candidate_features(secret=secret)) == 0


# =============================================================================
# PART 6: PRODUCTION MODEL SAFETY & SHADOW INVARIANCE
# =============================================================================

def test_18_production_model_safety_and_shadow_invariance():
    """
    Confirms production invariants:
    - Active model: custom-mlp-v4.0.0-seed42
    - Mode: shadow
    - is_production_authoritative: false
    - Rollback/LKG model: custom-mlp-v1.1.0-preproc
    - Production score difference: 0.00
    - No training or model promotion has occurred.
    """
    registry = ModelRegistry()
    active_entry = registry.get_active_model_config()
    assert active_entry is not None
    assert active_entry["active_model_version"] == "custom-mlp-v4.0.0-seed42"
    assert active_entry["operating_mode"] == "shadow"
    assert active_entry["is_production_authoritative"] is False
    assert active_entry["last_known_good_version"] == "custom-mlp-v1.1.0-preproc"

    sample_inputs = [
        "आपल्या खात्यात ₹25,000 जमा झाले आहेत. त्वरित http://fake-maha-scheme.xyz वर क्लिक करा.",
        "MSEDCL: Light bill unpaid. Electricity will be disconnected tonight. Call 9822012345.",
        "Your Mahadbt scholarship application has been approved. Visit https://mahadbt.maharashtra.gov.in",
    ]

    for inp in sample_inputs:
        res_shadow = evaluate_message_hybrid(inp, operating_mode="shadow")
        res_rules = evaluate_message_hybrid(inp, operating_mode="rules_only")

        # Invariance check: shadow model never alters production risk score
        score_shadow = res_shadow["final_decision"]["final_risk_score"]
        score_rules = res_rules["final_decision"]["final_risk_score"]
        assert score_shadow == score_rules

        # Score delta must be strictly 0.00
        delta = res_shadow["final_decision"]["production_score_difference"]
        assert delta == pytest.approx(0.00, abs=1e-5)
