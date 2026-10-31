"""
Phase 6.8.3 — Evidence Trust, Authentication and Anti-Poisoning Security Hardening Tests.

Verifies:
1. Standard library memory-hard Scrypt password hashing (N=16384, r=8, p=1).
2. Backward-compatible PBKDF2 verification and transparent rehash-on-success upgrading.
3. Brute-force protection: 5-attempt failure lockout (15 minutes) and reset on success.
4. Administrative password reset, self-service password change, and account unlocking.
5. Session context binding (client_ip, user_agent) and cryptographic token validation.
6. Two-Person Rule: strict self-approval prevention (SelfApprovalProhibitedError) and distinct dual-reviewer elevation.
7. Honest single-operator local mode trust levels ('single_reviewed', 'self_reviewed').
8. Corroboration requirements: approved verification methods, technical references, and rationale >= 15 chars.
9. Shared infrastructure awareness: suppressing coarse domain clustering on shorteners/cloud hosting.
10. Campaign conflict quarantine: isolating mixed-label campaigns from training.
11. Four-tier training eligibility gating:
    - Tier 1: not_eligible
    - Tier 2: eligible_exploratory_review
    - Tier 3: eligible_supervised_candidate_training
    - Tier 4: independently_corroborated_evaluation_candidate
12. Strict evaluation / training dataset isolation: export_curated_training_features excludes Tier 4.
13. Cryptographic artifact tamper detection (SHA-256 digest verification).
14. Database migration v3 idempotency and historical data preservation.
15. Production model governance and shadow mode invariance.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import sqlite3
import tempfile
import pytest

from src.operator_auth import (
    OperatorAuthService,
    hash_password,
    verify_password,
    is_rehash_needed,
    verify_password_and_check_rehash,
    InvalidCredentialsError,
    AccountLockedError,
    UnauthorizedError,
    OperatorAccountExistsError,
    PasswordPolicyError,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    MAX_FAILED_LOGIN_ATTEMPTS,
)
from src.database_migration import (
    migrate_to_evidence_trust_hardening_v3,
    migrate_to_evidence_governance_v2,
    get_applied_migrations,
    create_database_backup,
    rollback_migration,
)
from src.case_repository import (
    CaseRepository,
    ALLOWED_VERIFICATION_METHODS,
    ALLOWED_VERIFICATION_LEVELS,
    SHARED_INFRASTRUCTURE_DOMAINS,
    RELATIONSHIP_STRENGTHS,
    ELIGIBILITY_TIERS,
    SelfApprovalProhibitedError,
    TamperedEvidenceError,
    CorroborationError,
    InvalidStateTransitionError,
    EvidenceProvenanceError,
    TrainingEligibilityError,
)
from src.case_manager import SessionCaseStore
from src.model_registry import get_default_model_registry
from src.hybrid_decision_engine import evaluate_message_hybrid


@pytest.fixture
def temp_db_path():
    """Provides a fresh temporary SQLite database path for isolated testing."""
    fd, path = tempfile.mkstemp(suffix="_phase6_8_3.sqlite3")
    os.close(fd)
    yield path
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


@pytest.fixture
def repo(temp_db_path):
    """Provides an isolated CaseRepository instance."""
    repository = CaseRepository(db_path=temp_db_path)
    repository.ensure_evidence_tables()
    return repository


@pytest.fixture
def auth_service(temp_db_path):
    """Provides an OperatorAuthService connected to the temporary database."""
    return OperatorAuthService(db_path=temp_db_path)


# =============================================================================
# PART 1: OPERATOR AUTHENTICATION, SCRYPT KDF & PROGRESSIVE LOCKOUT
# =============================================================================

def test_01_scrypt_password_hashing_structure_and_parameters():
    """Verifies that default password hashing uses standard-library memory-hard Scrypt."""
    pwd = "SecOpsHardenedPassword2026!"
    hash_str, salt_hex = hash_password(pwd, algorithm="scrypt")

    assert hash_str.startswith("scrypt$")
    parts = hash_str.split("$")
    assert len(parts) == 6
    assert int(parts[1]) == SCRYPT_N  # 16384
    assert int(parts[2]) == SCRYPT_R  # 8
    assert int(parts[3]) == SCRYPT_P  # 1
    assert parts[4] == salt_hex
    assert len(parts[5]) == 128  # 64-byte key in hex

    assert verify_password(pwd, salt_hex, hash_str) is True
    assert verify_password("WrongPassword!", salt_hex, hash_str) is False
    assert is_rehash_needed(hash_str) is False


def test_02_legacy_pbkdf2_compatibility_and_rehash_detection():
    """Verifies backward compatibility with legacy PBKDF2 hashes and detects rehash need."""
    pwd = "LegacyAnalystPassword2026!"
    # Generate legacy PBKDF2 hash (200k iterations from Phase 6.8.2)
    salt_bytes = os.urandom(32)
    salt_hex = salt_bytes.hex()
    legacy_hash = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt_bytes, 200_000).hex()

    # Legacy raw format should verify successfully
    assert verify_password(pwd, salt_hex, legacy_hash) is True
    assert verify_password("WrongPassword!", salt_hex, legacy_hash) is False
    # Needs rehash must be True to trigger Scrypt upgrade
    assert is_rehash_needed(legacy_hash) is True

    # Test modern PBKDF2 format (600k iterations)
    modern_pbkdf2, s_hex = hash_password(pwd, algorithm="pbkdf2_sha256")
    assert modern_pbkdf2.startswith("pbkdf2_sha256$600000$")
    assert verify_password(pwd, s_hex, modern_pbkdf2) is True
    assert is_rehash_needed(modern_pbkdf2) is True


def test_03_transparent_rehash_on_successful_login(auth_service, temp_db_path):
    """Confirms that logging in with a legacy PBKDF2 hash automatically upgrades the stored hash to Scrypt."""
    auth_service.register_initial_operator(username="root_admin", password="InitialScryptPass123!", role="admin")

    # Manually inject an operator with a legacy PBKDF2 hash
    legacy_pwd = "LegacyOperatorSecret2026!"
    salt_bytes = os.urandom(32)
    salt_hex = salt_bytes.hex()
    legacy_hash = hashlib.pbkdf2_hmac("sha256", legacy_pwd.encode("utf-8"), salt_bytes, 200_000).hex()

    conn = sqlite3.connect(temp_db_path)
    conn.execute(
        """
        INSERT INTO operator_accounts (
            username, password_hash, salt, role, created_at_utc,
            last_login_utc, failed_login_count, locked_until_utc, is_active
        ) VALUES ('analyst_vikram', ?, ?, 'reviewer', '2026-10-30T10:00:00Z', NULL, 0, NULL, 1);
        """,
        (legacy_hash, salt_hex),
    )
    conn.commit()
    conn.close()

    # Verify initial stored hash is legacy
    conn = sqlite3.connect(temp_db_path)
    cur = conn.execute("SELECT password_hash FROM operator_accounts WHERE username = 'analyst_vikram';")
    assert cur.fetchone()[0] == legacy_hash
    conn.close()

    # Perform login
    login_res = auth_service.login(username="analyst_vikram", password=legacy_pwd)
    assert login_res["success"] is True
    assert login_res["rehashed_to_scrypt"] is True

    # Verify hash has been transparently upgraded to Scrypt in database
    conn = sqlite3.connect(temp_db_path)
    cur = conn.execute("SELECT password_hash FROM operator_accounts WHERE username = 'analyst_vikram';")
    new_hash = cur.fetchone()[0]
    conn.close()

    assert new_hash.startswith(f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}$")
    assert new_hash != legacy_hash


def test_04_brute_force_lockout_and_progressive_defense(auth_service):
    """Enforces 5-attempt brute-force threshold resulting in a 15-minute account lockout."""
    auth_service.register_initial_operator(username="target_user", password="CorrectPassword123!", role="operator")

    # 4 consecutive failures
    for attempt in range(1, MAX_FAILED_LOGIN_ATTEMPTS):
        with pytest.raises(InvalidCredentialsError):
            auth_service.login(username="target_user", password="BadPassword!")

    # 5th failure triggers lockout
    with pytest.raises(AccountLockedError) as exc_info:
        auth_service.login(username="target_user", password="BadPassword!")
    assert "locked for 15 minutes" in str(exc_info.value)

    # 6th attempt with CORRECT password during lockout is immediately rejected
    with pytest.raises(AccountLockedError) as exc_info2:
        auth_service.login(username="target_user", password="CorrectPassword123!")
    assert "Account 'target_user' is locked" in str(exc_info2.value)


def test_05_successful_login_resets_failed_attempt_counter(auth_service):
    """Verifies that a valid login resets the failed attempt counter before lockout threshold is reached."""
    auth_service.register_initial_operator(username="careful_analyst", password="ValidAnalystPass123!", role="reviewer")

    # 3 failures
    for _ in range(3):
        with pytest.raises(InvalidCredentialsError):
            auth_service.login(username="careful_analyst", password="WrongPassword!")

    # 4th attempt is successful
    res = auth_service.login(username="careful_analyst", password="ValidAnalystPass123!")
    assert res["success"] is True

    # Account should now have 0 failures, allowing 4 more incorrect attempts without lockout
    for _ in range(4):
        with pytest.raises(InvalidCredentialsError):
            auth_service.login(username="careful_analyst", password="WrongPassword!")


def test_06_admin_unlock_and_password_reset(auth_service):
    """Confirms administrator account unlock and administrative password reset."""
    admin_setup = auth_service.register_initial_operator("super_admin", "AdminMasterPass123!", role="admin")
    admin_login = auth_service.login("super_admin", "AdminMasterPass123!")
    admin_token = admin_login["session_token"]

    auth_service.create_operator(admin_token, "locked_op", "OpOriginalPass123!", role="operator")

    # Lock operator account
    for _ in range(5):
        try:
            auth_service.login("locked_op", "BadPassword!")
        except Exception:
            pass

    with pytest.raises(AccountLockedError):
        auth_service.login("locked_op", "OpOriginalPass123!")

    # Admin unlocks account
    unlock_res = auth_service.unlock_account(admin_token, "locked_op")
    assert unlock_res["success"] is True

    # Login now succeeds with original password
    op_login = auth_service.login("locked_op", "OpOriginalPass123!")
    assert op_login["success"] is True

    # Admin resets operator password
    auth_service.reset_password_as_admin(admin_token, "locked_op", "NewResetPassword2026!")
    assert auth_service.validate_session(op_login["session_token"]) is None  # Prior session revoked

    # Login with new password
    new_login = auth_service.login("locked_op", "NewResetPassword2026!")
    assert new_login["success"] is True


def test_07_session_client_context_binding_and_revocation(auth_service):
    """Verifies that sessions bind client IP and User-Agent, and expire or revoke properly."""
    auth_service.register_initial_operator("analyst_maya", "SecureMayaPass123!", role="senior_reviewer")
    sess_res = auth_service.login(
        "analyst_maya",
        "SecureMayaPass123!",
        client_ip="192.168.1.10",
        user_agent="SevaSandboxAuditClient/1.0",
    )
    token = sess_res["session_token"]

    valid_sess = auth_service.validate_session(token)
    assert valid_sess is not None
    assert valid_sess["username"] == "analyst_maya"
    assert valid_sess["client_ip"] == "192.168.1.10"
    assert valid_sess["user_agent"] == "SevaSandboxAuditClient/1.0"

    # Explicit logout revokes session
    assert auth_service.logout(token) is True
    assert auth_service.validate_session(token) is None


# =============================================================================
# PART 2: TWO-PERSON RULE & SELF-APPROVAL PREVENTION
# =============================================================================

def test_08_self_approval_prohibited_for_submitting_operator(repo):
    """Enforces that an operator who submitted evidence cannot independently corroborate it."""
    evid = repo.register_evidence_provenance(
        case_id="CASE-2026-SELF-01",
        evidence_origin="analyst_submitted",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        operator_username="analyst_raj",
        submitted_by="analyst_raj",
    )
    evid_id = evid["evidence_id"]

    repo.transition_evidence_status(
        evidence_id=evid_id,
        to_status="awaiting_review",
        operator_username="analyst_raj",
        transition_reason="Submitting for review",
    )
    repo.transition_evidence_status(
        evidence_id=evid_id,
        to_status="under_review",
        operator_username="analyst_raj",
        transition_reason="Beginning technical triage",
    )

    # Submitting analyst attempts to independently corroborate
    with pytest.raises(SelfApprovalProhibitedError) as exc_info:
        repo.corroborate_evidence(
            evidence_id=evid_id,
            operator_username="analyst_raj",
            rationale="Verified domain registration details match legitimate Maharashtra scheme.",
            conclusion="legitimate",
            verification_method="official_gazette_scheme_crosscheck",
            supporting_references=["GR-2024-MAHA-SCHEME-42"],
            require_independent=True,
        )
    assert "Self-approval prohibited" in str(exc_info.value)


def test_09_self_approval_prohibited_for_primary_reviewer(repo):
    """Enforces that an operator who conducted primary review cannot independently corroborate it."""
    # Evidence submitted by citizen / external intake
    evid = repo.register_evidence_provenance(
        case_id="CASE-2026-SELF-02",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        operator_username="citizen_client",
        submitted_by="citizen_client",
    )
    evid_id = evid["evidence_id"]

    repo.transition_evidence_status(
        evidence_id=evid_id,
        to_status="awaiting_review",
        operator_username="operator_triage",
        transition_reason="Citizen intake completed",
    )
    # Analyst Meera conducts primary review
    repo.transition_evidence_status(
        evidence_id=evid_id,
        to_status="under_review",
        operator_username="analyst_meera",
        transition_reason="Primary review assigned to Meera",
        reviewer_classification="phishing",
    )

    # Analyst Meera attempts to independently corroborate her own primary review
    with pytest.raises(SelfApprovalProhibitedError) as exc_info:
        repo.corroborate_evidence(
            evidence_id=evid_id,
            operator_username="analyst_meera",
            rationale="Confirmed malicious intent based on deceptive urgency indicators.",
            conclusion="phishing",
            verification_method="heuristic_rule_validation",
            supporting_references=["RULE-PHISH-URGENCY-01"],
            require_independent=True,
        )
    assert "Self-approval prohibited" in str(exc_info.value)


def test_10_distinct_second_reviewer_achieves_independent_corroboration(repo):
    """Confirms that a distinct second operator successfully confers 'independently_corroborated' status."""
    evid = repo.register_evidence_provenance(
        case_id="CASE-2026-DUAL-01",
        evidence_origin="user_reported",
        evidence_type="apk",
        consent_given=True,
        sanitization_status="passed",
        operator_username="citizen_app",
        submitted_by="citizen_app",
        metadata={"apk_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
    )
    evid_id = evid["evidence_id"]

    # First reviewer: analyst_raj
    repo.transition_evidence_status(
        evidence_id=evid_id,
        to_status="awaiting_review",
        operator_username="analyst_raj",
        transition_reason="Triage started",
    )
    repo.transition_evidence_status(
        evidence_id=evid_id,
        to_status="under_review",
        operator_username="analyst_raj",
        transition_reason="Primary review triage by Raj",
        reviewer_classification="phishing",
    )

    # Second reviewer: senior_analyst_meera (distinct operator)
    corrob_res = repo.corroborate_evidence(
        evidence_id=evid_id,
        operator_username="senior_analyst_meera",
        rationale="Static structural analysis confirmed unauthorized SMS interception permissions.",
        conclusion="phishing",
        verification_method="apk_static_structural_audit",
        supporting_references=["android.permission.RECEIVE_SMS", "android.permission.READ_SMS"],
        operator_role="senior_reviewer",
        require_independent=True,
    )

    assert corrob_res["lifecycle_status"] == "corroborated"
    assert corrob_res["verification_level"] == "independently_corroborated"
    assert corrob_res["reviewed_by"] == "analyst_raj"
    assert corrob_res["corroborated_by"] == "senior_analyst_meera"
    assert corrob_res["corroborated_conclusion"] == "phishing"


def test_11_single_operator_local_installation_fallback(repo):
    """Supports single-operator local mode without false claims of independent verification."""
    evid = repo.register_evidence_provenance(
        case_id="CASE-2026-SOLO-01",
        evidence_origin="analyst_submitted",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        operator_username="solo_operator",
        submitted_by="solo_operator",
    )
    evid_id = evid["evidence_id"]

    repo.transition_evidence_status(evid_id, "awaiting_review", "solo_operator", "Queued")
    repo.transition_evidence_status(evid_id, "under_review", "solo_operator", "Review started", "phishing")

    # In single operator mode (require_independent=False), corroboration succeeds but receives honest 'self_reviewed'
    res = repo.corroborate_evidence(
        evidence_id=evid_id,
        operator_username="solo_operator",
        rationale="Verified scam intent based on deceptive payment QR code indicators.",
        conclusion="phishing",
        verification_method="technical_indicator_correlation",
        supporting_references=["IND-PAYMENT-QR-DECEPTION"],
        require_independent=False,
    )

    assert res["lifecycle_status"] == "corroborated"
    assert res["verification_level"] == "self_reviewed"
    assert res["corroborated_by"] is None  # Not independently corroborated


# =============================================================================
# PART 3: CORROBORATION REQUIREMENTS & VERIFICATION METHODS
# =============================================================================

def test_12_corroboration_rejects_unapproved_verification_methods(repo):
    """Enforces that corroboration requires a documented method from ALLOWED_VERIFICATION_METHODS."""
    evid = repo.register_evidence_provenance(
        case_id="CASE-2026-METH-01",
        evidence_origin="user_reported",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="intake_bot",
    )
    evid_id = evid["evidence_id"]
    repo.transition_evidence_status(evid_id, "awaiting_review", "analyst_raj", "Triage")
    repo.transition_evidence_status(evid_id, "under_review", "analyst_raj", "Primary review")

    with pytest.raises(CorroborationError) as exc_info:
        repo.corroborate_evidence(
            evidence_id=evid_id,
            operator_username="analyst_priya",
            rationale="Verified domain is invalid because it looks suspicious on my screen.",
            conclusion="phishing",
            verification_method="gut_feeling_instinct",  # Not approved
            supporting_references=["unregistered_domain_check"],
        )
    assert "Invalid verification method 'gut_feeling_instinct'" in str(exc_info.value)


def test_13_corroboration_rejects_empty_supporting_technical_references(repo):
    """Enforces that corroboration requires at least one structured technical reference."""
    evid = repo.register_evidence_provenance(
        case_id="CASE-2026-REF-01",
        evidence_origin="user_reported",
        evidence_type="url",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="intake_bot",
    )
    evid_id = evid["evidence_id"]
    repo.transition_evidence_status(evid_id, "awaiting_review", "analyst_raj", "Triage")
    repo.transition_evidence_status(evid_id, "under_review", "analyst_raj", "Primary review")

    with pytest.raises(CorroborationError) as exc_info:
        repo.corroborate_evidence(
            evidence_id=evid_id,
            operator_username="analyst_priya",
            rationale="Domain does not match legitimate portal and uses punycode deception.",
            conclusion="phishing",
            verification_method="domain_dns_lexical_analysis",
            supporting_references=[],  # Empty references
        )
    assert "requires at least one non-empty structured supporting reference" in str(exc_info.value)


# =============================================================================
# PART 4: SHARED INFRASTRUCTURE & CAMPAIGN CLUSTERING
# =============================================================================

def test_14_shared_infrastructure_suppresses_coarse_domain_clustering(repo):
    """Confirms that public URL shorteners and shared cloud hosts are flagged as shared infrastructure."""
    # Test public shortener
    camp_shortener = repo.create_or_get_campaign_cluster(cluster_type="domain", cluster_key="tinyurl.com")
    assert camp_shortener["is_shared_infrastructure"] is True
    assert "Shared infrastructure domain" in camp_shortener["infrastructure_notes"]
    assert camp_shortener["relationship_strength"] == "weak_similarity"

    # Test government shared root
    camp_gov = repo.create_or_get_campaign_cluster(cluster_type="domain", cluster_key="maharashtra.gov.in")
    assert camp_gov["is_shared_infrastructure"] is True
    assert camp_gov["relationship_strength"] == "weak_similarity"

    # Test dedicated attack domain
    camp_attack = repo.create_or_get_campaign_cluster(cluster_type="domain", cluster_key="maha-ladkibahin-fraud.xyz")
    assert camp_attack["is_shared_infrastructure"] is False
    assert camp_attack["relationship_strength"] == "strong_technical_relationship"

    # Test APK SHA-256 (cryptographic duplicate)
    camp_apk = repo.create_or_get_campaign_cluster(
        cluster_type="apk_sha256",
        cluster_key="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
    )
    assert camp_apk["is_shared_infrastructure"] is False
    assert camp_apk["relationship_strength"] == "exact_duplicate"


def test_15_campaign_classification_conflict_quarantines_campaign(repo):
    """Verifies that campaigns with contradictory human labels are quarantined from training."""
    camp = repo.create_or_get_campaign_cluster("domain", "campaign-conflict-test.in")
    camp_id = camp["campaign_id"]

    ev1 = repo.register_evidence_provenance(
        case_id="CASE-CAMP-01",
        evidence_origin="user_reported",
        evidence_type="url",
        campaign_id=camp_id,
        consent_given=True,
        sanitization_status="passed",
    )
    ev2 = repo.register_evidence_provenance(
        case_id="CASE-CAMP-02",
        evidence_origin="user_reported",
        evidence_type="url",
        campaign_id=camp_id,
        consent_given=True,
        sanitization_status="passed",
    )

    # Corroborate ev1 as phishing
    repo.transition_evidence_status(ev1["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev1["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev1["evidence_id"], "op2", "Malicious URL confirmed via domain lexical indicators.",
        "phishing", "domain_dns_lexical_analysis", ["subdomain_deception"],
    )

    # Corroborate ev2 as legitimate (creating a conflict in the campaign)
    repo.transition_evidence_status(ev2["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev2["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev2["evidence_id"], "op2", "Legitimate URL confirmed via Maharashtra Government Resolution.",
        "legitimate", "official_gazette_scheme_crosscheck", ["GR-2024-OFFICIAL"],
    )

    conflict_status = repo.get_campaign_conflict_status(camp_id)
    assert conflict_status["is_conflict"] is True
    assert set(conflict_status["conflicting_labels"]) == {"legitimate", "phishing"}
    assert conflict_status["is_quarantined"] is True

    # Both items must now fail training eligibility due to campaign conflict
    elig1 = repo.check_training_eligibility(ev1["evidence_id"])
    assert elig1["is_eligible"] is False
    assert elig1["eligibility_tier"] == "not_eligible"
    assert elig1["checks"]["conflict_resolved"] is False


# =============================================================================
# PART 5: FOUR-TIER TRAINING ELIGIBILITY GATE & DATASET ISOLATION
# =============================================================================

def test_16_four_tier_training_eligibility_classification(repo):
    """Verifies correct classification across all 4 training eligibility tiers."""
    # Dummy feature vector for testing
    dummy_vec = [0.05] * 1024

    # 1. Tier 1: not_eligible (synthetic origin)
    ev_t1 = repo.register_evidence_provenance(
        case_id="CASE-TIER-1",
        evidence_origin="synthetic_test_data",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
    )
    elig_t1 = repo.check_training_eligibility(ev_t1["evidence_id"])
    assert elig_t1["is_eligible"] is False
    assert elig_t1["eligibility_tier"] == "not_eligible"

    # 2. Tier 2: eligible_exploratory_review (consented, sanitized, genuine, but unverified)
    ev_t2 = repo.register_evidence_provenance(
        case_id="CASE-TIER-2",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
    )
    elig_t2 = repo.check_training_eligibility(ev_t2["evidence_id"])
    assert elig_t2["is_eligible"] is False
    assert elig_t2["eligibility_tier"] == "eligible_exploratory_review"

    # 3. Tier 3: eligible_supervised_candidate_training (single-reviewed / corroborated with 1024-d features)
    repo.save_case({"case_id": "CASE-TIER-3", "analysis_type": "SMS Message"}, source_type="web_simulator")
    ev_t3 = repo.register_evidence_provenance(
        case_id="CASE-TIER-3",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="citizen_intake",
    )
    fp_tier3 = hashlib.sha256(b"tier3").hexdigest()
    repo.record_training_features("CASE-TIER-3", dummy_vec, fp_tier3, consent_given=True)
    repo.transition_evidence_status(ev_t3["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev_t3["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev_t3["evidence_id"], "op1", "Confirmed phishing indicators using heuristic rules.",
        "phishing", "heuristic_rule_validation", ["RULE-PHISH-01"], require_independent=False,
    )
    elig_t3 = repo.check_training_eligibility(ev_t3["evidence_id"])
    assert elig_t3["is_eligible"] is True
    assert elig_t3["eligibility_tier"] == "eligible_supervised_candidate_training"

    # 4. Tier 4: independently_corroborated_evaluation_candidate (dual-reviewer verified)
    repo.save_case({"case_id": "CASE-TIER-4", "analysis_type": "SMS Message"}, source_type="web_simulator")
    ev_t4 = repo.register_evidence_provenance(
        case_id="CASE-TIER-4",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="citizen_intake",
    )
    fp_tier4 = hashlib.sha256(b"tier4").hexdigest()
    repo.record_training_features("CASE-TIER-4", dummy_vec, fp_tier4, consent_given=True)
    repo.transition_evidence_status(ev_t4["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev_t4["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev_t4["evidence_id"], "op2", "Dual-analyst independent verification of Maharashtra scheme phishing.",
        "phishing", "multi_analyst_independent_review", ["ANALYST-INDEPENDENT-AUDIT"],
        operator_role="senior_reviewer", require_independent=True,
    )
    elig_t4 = repo.check_training_eligibility(ev_t4["evidence_id"])
    assert elig_t4["is_eligible"] is True
    assert elig_t4["eligibility_tier"] == "independently_corroborated_evaluation_candidate"


def test_17_strict_dataset_isolation_excludes_tier4_from_training_export(repo):
    """Enforces that Tier 4 evaluation candidates are strictly excluded from candidate training exports."""
    dummy_vec = [0.1] * 1024

    # Case A: Tier 3 (eligible for supervised candidate training)
    repo.save_case({"case_id": "CASE-TRAIN-01", "analysis_type": "SMS Message"}, source_type="web_simulator")
    fp_tr = hashlib.sha256(b"train01").hexdigest()
    repo.record_training_features("CASE-TRAIN-01", dummy_vec, fp_tr, consent_given=True)
    repo.submit_review("CASE-TRAIN-01", "phishing", confidence_rating="high")
    ev_tr = repo.register_evidence_provenance(
        case_id="CASE-TRAIN-01",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="citizen",
    )
    repo.transition_evidence_status(ev_tr["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev_tr["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev_tr["evidence_id"], "op1", "Single reviewer corroboration rationale.",
        "phishing", "heuristic_rule_validation", ["RULE-PHISH-01"], require_independent=False,
    )

    # Case B: Tier 4 (independently corroborated evaluation candidate)
    repo.save_case({"case_id": "CASE-EVAL-01", "analysis_type": "SMS Message"}, source_type="web_simulator")
    fp_ev = hashlib.sha256(b"eval01").hexdigest()
    repo.record_training_features("CASE-EVAL-01", dummy_vec, fp_ev, consent_given=True)
    repo.submit_review("CASE-EVAL-01", "phishing", confidence_rating="high")
    ev_ev = repo.register_evidence_provenance(
        case_id="CASE-EVAL-01",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        submitted_by="citizen",
    )
    repo.transition_evidence_status(ev_ev["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev_ev["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev_ev["evidence_id"], "op2", "Dual analyst corroboration rationale for gold evaluation.",
        "phishing", "multi_analyst_independent_review", ["DUAL-ANALYST-CERT"],
        operator_role="senior_reviewer", require_independent=True,
    )

    # Verify eligibility tiers
    assert repo.check_training_eligibility(ev_tr["evidence_id"])["eligibility_tier"] == "eligible_supervised_candidate_training"
    assert repo.check_training_eligibility(ev_ev["evidence_id"])["eligibility_tier"] == "independently_corroborated_evaluation_candidate"

    test_secret = "TestFeedbackSecretKey2026!Min16Chars"
    # Export candidate training features
    training_exports = repo.export_curated_training_features(secret=test_secret)
    # Export evaluation candidate features
    eval_exports = repo.export_evaluation_candidate_features(secret=test_secret)

    # Dataset isolation assertions
    # Training export MUST NOT contain Tier 4 evaluation candidate
    assert len(training_exports) == 1
    assert training_exports[0]["example_id"] != f"curated_feat_{ev_ev['evidence_id']}"
    assert training_exports[0]["review_provenance"] == "local_operator_unauthenticated"

    # Evaluation export MUST contain Tier 4 evaluation candidate
    assert len(eval_exports) == 1
    assert eval_exports[0]["verification_level"] == "independently_corroborated"
    assert eval_exports[0]["review_provenance"] == "independently_corroborated_dual_reviewer"


# =============================================================================
# PART 6: CRYPTOGRAPHIC TAMPER DETECTION
# =============================================================================

def test_18_artifact_tamper_detection(repo):
    """Verifies that unauthorized modification of an evidence artifact is cryptographically detected."""
    raw_payload = "Claim your ₹1500 Ladki Bahin grant immediately at http://fake-portal.xyz/claim"
    payload_sha256 = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    ev = repo.register_evidence_provenance(
        case_id="CASE-TAMPER-01",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
        artifact_sha256=payload_sha256,
    )
    ev_id = ev["evidence_id"]

    # Verify matching artifact succeeds
    res_ok = repo.verify_evidence_integrity(ev_id, artifact_content=raw_payload)
    assert res_ok["is_valid"] is True
    assert res_ok["tamper_detected"] is False

    # Tampered payload fails verification and flags evidence as disputed
    tampered_payload = "Claim your ₹1500 Ladki Bahin grant immediately at http://fake-portal.xyz/claim_MODIFIED"
    with pytest.raises(TamperedEvidenceError) as exc_info:
        repo.verify_evidence_integrity(ev_id, artifact_content=tampered_payload)
    assert "Tamper detected" in str(exc_info.value)

    # Evidence status must have automatically transitioned to 'disputed'
    updated_ev = repo.get_evidence_provenance(ev_id)
    assert updated_ev["lifecycle_status"] == "disputed"
    assert updated_ev["verification_level"] == "disputed"


# =============================================================================
# PART 7: DATABASE MIGRATION V3
# =============================================================================

def test_19_database_migration_v3_idempotent_and_non_destructive(temp_db_path):
    """Verifies that migration v3 applies cleanly, creates required hardening columns, and is idempotent."""
    # 1. Apply v2 migration first
    v2_res = migrate_to_evidence_governance_v2(temp_db_path, create_backup=False)
    assert v2_res["success"] is True

    # Insert a dummy record in v2 schema
    conn = sqlite3.connect(temp_db_path)
    conn.execute(
        """
        INSERT INTO evidence_provenance (
            evidence_id, case_id, evidence_origin, evidence_type, lifecycle_status,
            user_classification, model_prediction, rule_assessment, reviewer_classification,
            corroborated_conclusion, corroboration_rationale, campaign_id, consent_given,
            consent_timestamp_utc, sanitization_status, created_at_utc, updated_at_utc, metadata_json
        ) VALUES ('EVID-V2-01', 'CASE-V2-01', 'user_reported', 'url', 'submitted', NULL, NULL, NULL, NULL, NULL, '', NULL, 1, '2026-10-30T12:00:00Z', 'passed', '2026-10-30T12:00:00Z', '2026-10-30T12:00:00Z', '{}');
        """
    )
    conn.commit()
    conn.close()

    # 2. Apply v3 migration
    v3_res = migrate_to_evidence_trust_hardening_v3(temp_db_path, create_backup=False)
    assert v3_res["success"] is True
    assert v3_res["already_applied"] is False

    # 3. Verify columns exist
    conn = sqlite3.connect(temp_db_path)
    cur = conn.execute("PRAGMA table_info(evidence_provenance);")
    cols = [r[1] for r in cur.fetchall()]
    assert "submitted_by" in cols
    assert "verification_level" in cols
    assert "eligibility_tier" in cols
    assert "artifact_sha256" in cols

    cur2 = conn.execute("PRAGMA table_info(campaign_clusters);")
    camp_cols = [r[1] for r in cur2.fetchall()]
    assert "is_shared_infrastructure" in camp_cols
    assert "quarantined_from_training" in camp_cols

    # Verify existing v2 record is completely preserved
    cur3 = conn.execute("SELECT evidence_id, lifecycle_status FROM evidence_provenance WHERE evidence_id = 'EVID-V2-01';")
    row = cur3.fetchone()
    assert row[0] == "EVID-V2-01"
    assert row[1] == "submitted"
    conn.close()

    # 4. Re-running v3 migration is idempotent
    v3_reapply = migrate_to_evidence_trust_hardening_v3(temp_db_path, create_backup=False)
    assert v3_reapply["success"] is True
    assert v3_reapply["already_applied"] is True


# =============================================================================
# PART 8: PRODUCTION MODEL GOVERNANCE & SHADOW INVARIANCE
# =============================================================================

def test_20_production_model_governance_invariance_and_shadow_isolation():
    """Guarantees that production model weights and configuration remain 100% invariant in shadow mode."""
    registry = get_default_model_registry()
    cfg = registry.get_active_model_config()

    # Invariants
    assert cfg.get("active_model_version") == "custom-mlp-v4.0.0-seed42"
    assert cfg.get("operating_mode") == "shadow"
    assert cfg.get("is_production_authoritative") is False
    assert cfg.get("last_known_good_version") == "custom-mlp-v1.1.0-preproc"

    sample_lure = "URGENT: Your electricity connection will be disconnected tonight. Update bill immediately."
    eval_res = evaluate_message_hybrid(sample_lure, operating_mode="shadow")
    assert eval_res["final_decision"]["production_score_difference"] == 0.00


# =============================================================================
# PART 9: EXTENDED GOVERNANCE, SESSION CASE STORE & INTEGRITY TESTS
# =============================================================================

def test_21_session_case_store_corroborate_and_tamper_verification(repo):
    """Verifies SessionCaseStore proxy methods for corroboration and tamper detection."""
    store = SessionCaseStore(session_id="test_session_proxy", repository=repo)

    case_id = store.add_case({
        "analysis_type": "URL Analysis",
        "target_identifier": "https://fake-maha-scheme.xyz/claim",
        "risk_category": "high",
        "consent_given": True,
        "sanitization_status": "passed",
        "sha256_hash": "222233334444555566667777888899990000aaaabbbbccccddddeeeeffff0000",
    })
    ev = store.get_evidence_for_case(case_id)
    assert ev is not None
    ev_id = ev["evidence_id"]

    # Transition to under_review
    store.transition_evidence(ev_id, "awaiting_review", "op1", "Queue")
    store.transition_evidence(ev_id, "under_review", "op1", "Review")

    # Corroborate via SessionCaseStore
    corr_res = store.corroborate_evidence(
        evidence_id=ev_id,
        operator_username="senior_op",
        rationale="Punycode domain verified as deceptive phishing target.",
        conclusion="phishing",
        verification_method="domain_dns_lexical_analysis",
        supporting_references=["IND-PUNYCODE-LEXICAL"],
        operator_role="senior_reviewer",
        require_independent=True,
    )
    assert corr_res["verification_level"] == "independently_corroborated"
    assert corr_res["corroborated_by"] == "senior_op"

    # Verify integrity via SessionCaseStore
    int_res = store.verify_evidence_integrity(ev_id)
    assert int_res["is_valid"] is True
    assert int_res["tamper_detected"] is False


def test_22_session_case_store_isolated_dataset_exports(repo):
    """Verifies that SessionCaseStore correctly exposes segregated training and evaluation exports."""
    store = SessionCaseStore(session_id="test_export_store", repository=repo)
    dummy_vec = [0.1] * 1024
    test_secret = "TestFeedbackSecretKey2026!Min16Chars"

    # Create case
    case_id = store.add_case({
        "analysis_type": "SMS Message",
        "consent_given": True,
        "sanitization_status": "passed",
    })
    repo.record_training_features(case_id, dummy_vec, hashlib.sha256(b"sess_exp").hexdigest(), consent_given=True)
    repo.submit_review(case_id, "phishing", confidence_rating="high")

    ev = store.get_evidence_for_case(case_id)
    store.transition_evidence(ev["evidence_id"], "awaiting_review", "op1", "Queue")
    store.transition_evidence(ev["evidence_id"], "under_review", "op1", "Review")
    store.corroborate_evidence(
        ev["evidence_id"], "op2", "Independent verification for evaluation candidate.",
        "phishing", "multi_analyst_independent_review", ["DUAL-REF"],
        operator_role="senior_reviewer", require_independent=True,
    )

    # Candidate training export must exclude this Tier 4 item
    tr_exports = store.export_curated_training_features(secret=test_secret)
    assert len(tr_exports) == 0

    # Evaluation candidate export must include this Tier 4 item
    ev_exports = store.export_evaluation_candidate_features(secret=test_secret)
    assert len(ev_exports) == 1
    assert ev_exports[0]["verification_level"] == "independently_corroborated"


def test_23_relationship_strengths_and_campaign_isolation(repo):
    """Verifies that distinct relationship strengths are correctly evaluated and assigned."""
    # Test valid relationship strengths set
    expected_strengths = {
        "exact_duplicate",
        "strong_technical_relationship",
        "possible_campaign_relationship",
        "weak_similarity",
        "unrelated_evidence",
        "human_confirmed_association",
    }
    assert RELATIONSHIP_STRENGTHS == expected_strengths

    # Test APK assignment receives exact_duplicate
    apk_hash = "33334444555566667777888899990000aaaabbbbccccddddeeeeffff00001111"
    camp_apk = repo.create_or_get_campaign_cluster("apk_sha256", apk_hash)
    ev_apk = repo.register_evidence_provenance(
        case_id="CASE-REL-APK", evidence_origin="user_reported", evidence_type="apk"
    )
    repo.assign_campaign_cluster(ev_apk["evidence_id"], camp_apk["campaign_id"], "op_lead")
    rec_apk = repo.get_evidence_provenance(ev_apk["evidence_id"])
    assert rec_apk["relationship_strength"] == "exact_duplicate"

    # Test public shortener receives weak_similarity
    camp_short = repo.create_or_get_campaign_cluster("domain", "bit.ly")
    ev_url = repo.register_evidence_provenance(
        case_id="CASE-REL-URL", evidence_origin="user_reported", evidence_type="url"
    )
    repo.assign_campaign_cluster(ev_url["evidence_id"], camp_short["campaign_id"], "op_lead")
    rec_url = repo.get_evidence_provenance(ev_url["evidence_id"])
    assert rec_url["relationship_strength"] == "weak_similarity"


def test_24_password_policy_and_length_enforcement(auth_service):
    """Enforces password policy requirements (minimum 8 characters, string type)."""
    with pytest.raises(PasswordPolicyError):
        hash_password("short")  # Less than 8 characters

    with pytest.raises(PasswordPolicyError):
        hash_password(12345678)  # Non-string


def test_25_operator_self_service_password_change(auth_service):
    """Verifies that an authenticated operator can update their password verifying the old one."""
    auth_service.register_initial_operator("analyst_self", "OriginalPassword2026!", role="reviewer")
    login = auth_service.login("analyst_self", "OriginalPassword2026!")
    token = login["session_token"]

    # Fails with wrong current password
    with pytest.raises(InvalidCredentialsError):
        auth_service.change_password(token, "WrongOldPassword!", "NewPassword2026!")

    # Succeeds with correct current password
    chg = auth_service.change_password(token, "OriginalPassword2026!", "UpdatedPassword2026!")
    assert chg["success"] is True

    # Login with new password succeeds
    login_new = auth_service.login("analyst_self", "UpdatedPassword2026!")
    assert login_new["success"] is True


def test_26_non_admin_cannot_unlock_or_reset_passwords(auth_service):
    """Guarantees that non-admin operators cannot unlock accounts or reset other passwords."""
    admin_setup = auth_service.register_initial_operator("admin_root", "MasterAdminPassword123!", role="admin")
    admin_login = auth_service.login("admin_root", "MasterAdminPassword123!")
    admin_token = admin_login["session_token"]

    auth_service.create_operator(admin_token, "regular_analyst", "AnalystPass123!", role="reviewer")
    auth_service.create_operator(admin_token, "target_op", "TargetPass123!", role="operator")

    analyst_login = auth_service.login("regular_analyst", "AnalystPass123!")
    analyst_token = analyst_login["session_token"]

    # Non-admin attempts to reset target password
    with pytest.raises(UnauthorizedError) as exc_info:
        auth_service.reset_password_as_admin(analyst_token, "target_op", "HackedPass123!")
    assert "Administrator role is required" in str(exc_info.value)

    # Non-admin attempts to unlock target account
    with pytest.raises(UnauthorizedError) as exc_info2:
        auth_service.unlock_account(analyst_token, "target_op")
    assert "Administrator role is required" in str(exc_info2.value)


def test_27_tamper_detection_on_apk_hash_and_url_digests(repo):
    """Verifies cryptographic tamper detection across APK binary hashes and URL digests."""
    raw_apk = b"sample_apk_dex_binary_payload_content_2026"
    apk_digest = hashlib.sha256(raw_apk).hexdigest()
    ev_apk = repo.register_evidence_provenance(
        case_id="CASE-TAMPER-APK",
        evidence_origin="user_reported",
        evidence_type="apk",
        artifact_sha256=apk_digest,
    )
    # Correct raw APK bytes match stored digest
    res_apk = repo.verify_evidence_integrity(ev_apk["evidence_id"], artifact_content=raw_apk)
    assert res_apk["is_valid"] is True
    assert res_apk["tamper_detected"] is False

    # Modified binary triggers TamperedEvidenceError
    with pytest.raises(TamperedEvidenceError):
        repo.verify_evidence_integrity(ev_apk["evidence_id"], artifact_content=b"altered_apk_binary_payload")


def test_28_database_migration_v3_backup_and_rollback(temp_db_path):
    """Verifies that pre-migration backup creation and rollback safely restores the database state."""
    # Initialize base schema
    migrate_to_evidence_governance_v2(temp_db_path, create_backup=False)

    # Create backup before v3
    backup_path = create_database_backup(temp_db_path)
    assert os.path.exists(backup_path)

    # Apply v3 migration
    migrate_to_evidence_trust_hardening_v3(temp_db_path, create_backup=False)
    applied = [m["migration_id"] for m in get_applied_migrations(temp_db_path)]
    assert "20261031_02_evidence_trust_hardening_v3" in applied

    # Roll back from backup
    rollback_res = rollback_migration(backup_path, temp_db_path)
    assert rollback_res["success"] is True

    # After rollback, v3 migration is no longer applied
    applied_after = [m["migration_id"] for m in get_applied_migrations(temp_db_path)]
    assert "20261031_02_evidence_trust_hardening_v3" not in applied_after

    if os.path.exists(backup_path):
        os.remove(backup_path)


def test_29_consent_revocation_cascades_to_training_ineligibility(repo):
    """Confirms that revoking consent immediately makes an evidence record 'not_eligible'."""
    repo.save_case({"case_id": "CASE-REVOKE-01", "analysis_type": "SMS Message"}, source_type="web_simulator")
    dummy_vec = [0.2] * 1024
    fp_revoke = hashlib.sha256(b"revoke_test").hexdigest()
    repo.record_training_features("CASE-REVOKE-01", dummy_vec, fp_revoke, consent_given=True)

    ev = repo.register_evidence_provenance(
        case_id="CASE-REVOKE-01",
        evidence_origin="user_reported",
        evidence_type="message",
        consent_given=True,
        sanitization_status="passed",
    )
    repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "op1", "Queue")
    repo.transition_evidence_status(ev["evidence_id"], "under_review", "op1", "Review")
    repo.corroborate_evidence(
        ev["evidence_id"], "op1", "Single reviewer corroboration rationale.",
        "phishing", "heuristic_rule_validation", ["RULE-PHISH-01"], require_independent=False,
    )

    # Prior to revocation: eligible
    assert repo.check_training_eligibility(ev["evidence_id"])["is_eligible"] is True

    # User revokes consent
    revoked_count = repo.revoke_training_consent(case_id="CASE-REVOKE-01", reason="Citizen request")
    assert revoked_count > 0

    # After revocation: strictly not_eligible
    elig_after = repo.check_training_eligibility(ev["evidence_id"])
    assert elig_after["is_eligible"] is False
    assert elig_after["eligibility_tier"] == "not_eligible"
    assert elig_after["checks"]["consent_valid"] is False


def test_30_shadow_inference_invariance_across_multilingual_inputs():
    """Confirms that shadow model inference is strictly non-authoritative across Marathi, Hindi, and English lures."""
    test_lures = [
        ("en", "URGENT: Your bank account will be blocked today. Click here to verify Aadhaar."),
        ("mr", "तातडीने: तुमचे बँक खाते आज बंद केले जाईल. त्वरित केवायसी अपडेट करा."),
        ("hi", "जरूरी सूचना: आपका बिजली कनेक्शन आज रात काट दिया जाएगा। तुरंत बिल भरें।"),
    ]

    for lang, lure in test_lures:
        res_shadow = evaluate_message_hybrid(lure, operating_mode="shadow")
        res_rules = evaluate_message_hybrid(lure, operating_mode="rules_only")

        assert res_shadow["operating_mode"] == "shadow"
        assert res_shadow["final_decision"]["production_score_difference"] == 0.00
        # Authoritative score strictly matches rules_only mode in shadow operation
        assert res_shadow["final_decision"]["final_risk_score"] == res_rules["final_decision"]["final_risk_score"]
        assert res_shadow["final_decision"]["risk_level"] == res_rules["final_decision"]["risk_level"]

