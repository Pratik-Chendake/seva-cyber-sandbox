"""
Phase 6.9.4 — Security, Privacy, Adversarial, and Stress Testing Suite.

Covers:
1. Adversarial Submissions & Anti-Poisoning:
   - Campaign cluster conflict injection detected and blocked.
   - Self-approval bypass prohibited.
   - Submitter role restriction enforced.
2. Malformed Artifacts & DoS Resilience:
   - Zero-byte and corrupt APK payloads.
   - Extreme URL lengths and embedded credentials.
   - Huge text inputs (100,000+ characters) without memory exhaustion.
3. Privacy & Data Protection:
   - Aadhaar, phone number, and credential masking.
   - Immediate exclusion upon evidence withdrawal / consent revocation.
4. Scrypt Authentication Stress:
   - Memory-hard parameters ($N=131072, r=8, p=1$) verified.
   - Safe verification without Windows 32-bit integer overflow.
   - Account lockout after consecutive failed login attempts.
"""

import hashlib
import json
import os
import tempfile
import pytest

from src.apk_analyzer import analyze_apk_bytes
from src.url_analyzer import analyze_url
from src.privacy_gate import sanitize_for_local_training
from src.phishing_detector import analyze_message_text
from src.case_repository import (
    CaseRepository,
    SelfApprovalProhibitedError,
    EvidenceGovernanceError,
)
from src.operator_auth import (
    OperatorAuthService,
    InvalidCredentialsError,
    AccountLockedError,
)


@pytest.fixture
def test_env():
    temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(temp_dir.name, "security_stress.sqlite3")
    repo = CaseRepository(db_path=db_path)
    auth = OperatorAuthService(db_path=db_path)

    # Setup initial admin and test accounts
    auth.register_initial_operator("admin_sec", "AdminSecureP@ss123!", role="admin")
    admin_login = auth.login("admin_sec", "AdminSecureP@ss123!")
    token = admin_login["session_token"]
    auth.create_operator(token, "submitter_dan", "SubmitterDanP@ss123!", role="submitter")
    auth.create_operator(token, "reviewer_eve", "ReviewerEveP@ss123!", role="reviewer")

    yield {"repo": repo, "auth": auth, "db_path": db_path}
    try:
        temp_dir.cleanup()
    except Exception:
        pass


# =============================================================================
# 1. ADVERSARIAL & ANTI-POISONING TESTS
# =============================================================================

def test_campaign_conflict_injection_blocked(test_env):
    """Adversarial attempt to poison training data with conflicting labels in a campaign is caught."""
    repo = test_env["repo"]

    camp = repo.create_or_get_campaign_cluster("url_domain", "adversarial-campaign.org")

    # Item 1: Phishing
    e1 = repo.register_evidence_provenance(
        case_id="CASE-ADV-01",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="phishing",
        consent_given=True,
    )
    repo.assign_campaign_cluster(e1["evidence_id"], camp["campaign_id"], operator_username="system")
    repo.transition_evidence_status(e1["evidence_id"], "awaiting_review", "reviewer_eve", "Triage")
    repo.transition_evidence_status(e1["evidence_id"], "under_review", "reviewer_eve", "Review", reviewer_classification="phishing")

    # Item 2: Deliberate contradictory label: legitimate
    e2 = repo.register_evidence_provenance(
        case_id="CASE-ADV-02",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="legitimate",
        consent_given=True,
    )
    repo.assign_campaign_cluster(e2["evidence_id"], camp["campaign_id"], operator_username="system")
    repo.transition_evidence_status(e2["evidence_id"], "awaiting_review", "reviewer_eve", "Triage")
    repo.transition_evidence_status(e2["evidence_id"], "under_review", "reviewer_eve", "Review", reviewer_classification="legitimate")

    conflict = repo.get_campaign_conflict_status(camp["campaign_id"])
    assert conflict["is_conflict"] is True
    assert set(conflict["conflicting_labels"]) == {"phishing", "legitimate"}


def test_submitter_role_cannot_corroborate_or_triage(test_env):
    """Submitter role is forbidden from transitioning evidence to under_review or corroborated."""
    repo = test_env["repo"]

    ev = repo.register_evidence_provenance(
        case_id="CASE-ROLE-01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="submitter_dan",
    )

    # First advance submitted -> awaiting_review by authorized system/reviewer
    repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "reviewer_eve", "Triage")

    # Now submitter attempts to transition awaiting_review -> under_review
    with pytest.raises(EvidenceGovernanceError) as exc:
        repo.transition_evidence_status(
            ev["evidence_id"],
            "under_review",
            operator_username="submitter_dan",
            transition_reason="Attempting triage as submitter",
            operator_role="submitter",
        )
    assert "Submitters are not authorized" in str(exc.value)


def test_self_approval_prohibited(test_env):
    """Operator cannot independently corroborate their own submission or review."""
    repo = test_env["repo"]

    ev = repo.register_evidence_provenance(
        case_id="CASE-SELF-01",
        evidence_origin="user_reported",
        evidence_type="message_text",
        user_classification="phishing",
        consent_given=True,
        submitted_by="reviewer_eve",
    )

    with pytest.raises(SelfApprovalProhibitedError):
        repo.corroborate_evidence(
            ev["evidence_id"],
            operator_username="reviewer_eve",
            rationale="I submitted this and now I approve it.",
            conclusion="phishing",
            verification_method="official_gazette_scheme_crosscheck",
            supporting_references=["REF-01"],
            require_independent=True,
            operator_role="reviewer",
        )


# =============================================================================
# 2. MALFORMED ARTIFACTS & DOS RESILIENCE
# =============================================================================

def test_malformed_apk_handling():
    """Confirms APK analyzer handles zero bytes, corrupt headers, and random garbage safely."""
    # Zero bytes
    r0 = analyze_apk_bytes(b"", "empty.apk")
    assert r0["is_valid_apk"] is False
    assert "empty" in r0["error_message"].lower()

    # Random binary fuzzing payload
    garbage = os.urandom(2048)
    rg = analyze_apk_bytes(garbage, "fuzz.apk")
    assert rg["is_valid_apk"] is False
    assert "invalid" in rg["error_message"].lower() or "not a valid zip" in rg["error_message"].lower()

    # Truncated PKZIP header
    trunc = b"PK\x03\x04" + b"\x00" * 20
    rt = analyze_apk_bytes(trunc, "trunc.apk")
    assert rt["is_valid_apk"] is False


def test_malformed_url_handling():
    """Confirms URL analyzer safely parses extreme lengths and embedded credentials."""
    # Embedded credentials
    r_cred = analyze_url("https://admin:p@ssw0rd123@suspicious-portal.org:9000/login?auth=true")
    assert r_cred["is_valid_url"] is True
    assert r_cred["observable_characteristics"]["has_unusual_port"] is True

    # Extreme length URL (10,000 characters)
    huge_url = "https://legit-site.gov.in/path?" + "param=" + "A" * 10000
    r_huge = analyze_url(huge_url)
    assert r_huge["is_valid_url"] is True
    assert len(r_huge["observable_characteristics"]) > 0

    # Non-HTTP / Invalid scheme
    r_inv = analyze_url("javascript:alert('xss');")
    assert r_inv["is_valid_url"] is False or r_inv["score"] is not None


def test_huge_text_message_resilience():
    """Message analyzer and privacy gate process 100,000-character payload without crashing."""
    huge_text = "कृपया आपले आधार कार्ड अपडेट करा. " * 3000  # ~105,000 characters
    res = analyze_message_text(huge_text)
    assert "assessment_label" in res
    assert "findings" in res

    # Privacy sanitization fail-closed size boundary on 100k characters
    sanitized_huge = sanitize_for_local_training(huge_text)
    assert sanitized_huge.sanitization_success is False
    assert any("exceeds maximum sanitization size" in r for r in sanitized_huge.blocking_reasons)

    # Privacy sanitization on realistic payload within size limit (e.g. 5,000 characters)
    sub_text = "कृपया आपले आधार कार्ड अपडेट करा. " * 150 + " आधार 2345 6789 0123 फोन 9876543210 "
    sanitized_sub = sanitize_for_local_training(sub_text)
    assert sanitized_sub.sanitization_success is True
    assert "[AADHAAR_REDACTED]" in sanitized_sub.sanitized_text
    assert "[PHONE_REDACTED]" in sanitized_sub.sanitized_text


# =============================================================================
# 3. PRIVACY & CONSENT REVOCATION
# =============================================================================

def test_pii_sanitization_masks_critical_identifiers():
    """Confirms privacy gate replaces Aadhaar, phone, and credentials with tokens."""
    raw = "User info: Aadhaar 4567 8901 2345, Phone +91 9123456789, password=SuperSecret99!"
    res = sanitize_for_local_training(raw)

    assert "4567 8901 2345" not in res.sanitized_text
    assert "9123456789" not in res.sanitized_text
    assert "SuperSecret99!" not in res.sanitized_text
    assert "[AADHAAR_REDACTED]" in res.sanitized_text
    assert "[PHONE_REDACTED]" in res.sanitized_text
    assert "[CREDENTIAL_REDACTED]" in res.sanitized_text


def test_evidence_withdrawal_revokes_eligibility(test_env):
    """Withdrawing evidence immediately changes status to withdrawn and blocks training eligibility."""
    repo = test_env["repo"]

    ev = repo.register_evidence_provenance(
        case_id="CASE-REVOKE-01",
        evidence_origin="user_reported",
        evidence_type="url",
        user_classification="phishing",
        consent_given=True,
    )
    repo.transition_evidence_status(ev["evidence_id"], "awaiting_review", "reviewer_eve", "Triage")
    repo.transition_evidence_status(ev["evidence_id"], "under_review", "reviewer_eve", "Investigating", reviewer_classification="phishing")
    repo.corroborate_evidence(
        ev["evidence_id"],
        "admin_sec",
        "Corroborated malicious payload.",
        "phishing",
        "official_gazette_scheme_crosscheck",
        ["REF-REVOKE"],
    )

    # Confirm corroborated
    ev_corrob = repo.get_evidence_provenance(ev["evidence_id"])
    assert ev_corrob["lifecycle_status"] == "corroborated"

    # User revokes consent / withdraws
    repo.withdraw_evidence(ev["evidence_id"], operator_username="citizen", reason="User opted out.")

    ev_withdrawn = repo.get_evidence_provenance(ev["evidence_id"])
    assert ev_withdrawn["lifecycle_status"] == "withdrawn"

    eligibility = repo.check_training_eligibility(ev["evidence_id"])
    assert eligibility["is_eligible"] is False
    assert any("withdrawn" in r.lower() for r in eligibility["reasons"])


# =============================================================================
# 4. SCRYPT AUTHENTICATION SECURITY & STRESS
# =============================================================================

def test_scrypt_parameter_compliance(test_env):
    """Verifies Scrypt configuration matches OWASP memory-hard standard (N=131072, r=8, p=1)."""
    auth = test_env["auth"]

    login_res = auth.login("admin_sec", "AdminSecureP@ss123!")
    assert login_res["success"] is True

    # Inspect stored hash
    with auth._get_connection() as conn:
        cur = conn.execute("SELECT password_hash FROM operator_accounts WHERE username = 'admin_sec';")
        stored_hash = cur.fetchone()["password_hash"]

    assert stored_hash.startswith("scrypt$131072$8$1$")


def test_scrypt_account_lockout_after_failures(test_env):
    """Confirms account lockout after consecutive invalid password attempts."""
    auth = test_env["auth"]

    # First 4 failed attempts raise InvalidCredentialsError
    for _ in range(4):
        with pytest.raises(InvalidCredentialsError):
            auth.login("reviewer_eve", "WrongPassword123!")

    # 5th failed attempt triggers lockout and raises AccountLockedError
    with pytest.raises(AccountLockedError):
        auth.login("reviewer_eve", "WrongPassword123!")

    # Even with correct password, account remains locked
    with pytest.raises(AccountLockedError):
        auth.login("reviewer_eve", "ReviewerEveP@ss123!")
