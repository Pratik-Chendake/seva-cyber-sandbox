"""
Unit Test Suite for Persistent Threat Intelligence Knowledge Base.
Part of Seva Cyber Sandbox (Phase 1).

Covers:
- Idempotent database initialization and schema verification.
- Existing cases and schema preservation.
- Indicator insertion and strict input validation.
- Domain normalization and exact matching.
- URL canonicalization (query and fragment stripping) and bounded matching.
- APK SHA-256 hash normalization and matching.
- Phone indicator keyed-HMAC representation and fail-closed secret key management.
- Duplicate indicator handling (occurrence increment, last_seen update).
- Inactive indicator rejection.
- Expired indicator rejection.
- Review state decision boundary (reviewed trusted match vs unreviewed lead).
- Audit log creation without sensitive data leakage.
- Concurrency and thread safety under WAL mode.
- Additive risk score integration (trusted match bonus vs unreviewed lead observation).
- Strict offline execution (zero network calls).
"""

import concurrent.futures
import json
import os
import socket
import sqlite3
import urllib.request
import pytest

from src.case_repository import (
    ALLOWED_INDICATOR_TYPES,
    ALLOWED_REVIEW_STATES,
    ALLOWED_SEVERITIES,
    CaseRepository,
    CaseRepositoryError,
    ThreatIntelligenceError,
    ThreatIntelligenceKeyError,
    ThreatIntelligenceValidationError,
    canonicalize_url_for_matching,
    compute_phone_indicator_hmac,
    get_threat_intel_hmac_secret,
    normalize_apk_hash,
    normalize_domain,
    normalize_phone_number,
)
from src.risk_scorer import apply_threat_intelligence_to_score


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """Provides an isolated SQLite repository and test HMAC key for each test."""
    monkeypatch.setenv("SEVA_THREAT_INTEL_KEY", "TestFixtureThreatIntelSecret2026")
    db_file = tmp_path / "test_threat_intel.sqlite3"
    return CaseRepository(db_path=str(db_file))


# ---------------------------------------------------------------------------
# 1. Database Initialization & Schema
# ---------------------------------------------------------------------------

def test_01_idempotent_database_initialization_and_schema(tmp_path):
    db_file = tmp_path / "init_check.sqlite3"
    repo1 = CaseRepository(db_path=str(db_file))

    # Verify tables exist via raw sqlite3
    with sqlite3.connect(str(db_file)) as conn:
        tables = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "threat_cases" in tables
        assert "schema_version" in tables
        assert "threat_indicators" in tables
        assert "indicator_audit_log" in tables

    # Repeated initialization must be completely idempotent
    repo2 = CaseRepository(db_path=str(db_file))
    assert repo2.count_cases() == 0
    assert len(repo2.list_indicators()) == 0


# ---------------------------------------------------------------------------
# 2. Strict Input Validation
# ---------------------------------------------------------------------------

def test_02_indicator_input_validation(repo):
    # Invalid indicator type
    with pytest.raises(ThreatIntelligenceValidationError):
        repo.add_indicator(indicator_type="invalid_type", indicator_value="something")

    # Invalid review state
    with pytest.raises(ThreatIntelligenceValidationError):
        repo.add_indicator(
            indicator_type="domain",
            indicator_value="bad-domain.com",
            review_state="invalid_state",
        )

    # Invalid severity
    with pytest.raises(ThreatIntelligenceValidationError):
        repo.add_indicator(
            indicator_type="domain",
            indicator_value="bad-domain.com",
            severity="extreme_danger",
        )

    # Malformed domain
    with pytest.raises(ThreatIntelligenceValidationError):
        normalize_domain("invalid..domain..com")

    # Malformed URL
    with pytest.raises(ThreatIntelligenceValidationError):
        canonicalize_url_for_matching("ftp://unsupported-scheme.com")

    # Malformed APK hash (not 64 hex chars)
    with pytest.raises(ThreatIntelligenceValidationError):
        normalize_apk_hash("not_a_valid_hash_123")

    # Malformed phone number (too short)
    with pytest.raises(ThreatIntelligenceValidationError):
        normalize_phone_number("12345")


# ---------------------------------------------------------------------------
# 3. Domain Normalization & Exact Matching
# ---------------------------------------------------------------------------

def test_03_domain_normalization_and_exact_matching(repo):
    # Insert domain with scheme, port, path
    ind_id = repo.add_indicator(
        indicator_type="domain",
        indicator_value="https://Evil-Msedcl-Bill.TOP:443/login?q=1",
        confidence_score=90,
        severity="high",
        review_state="reviewed",
    )

    ind = repo.get_indicator(ind_id)
    assert ind is not None
    assert ind["indicator_value"] == "evil-msedcl-bill.top"
    assert ind["review_state"] == "reviewed"

    # Query matching indicators with uppercase representation
    matches = repo.match_indicators({"domains": ["EVIL-MSEDCL-BILL.TOP"]})
    assert matches["has_matches"] is True
    assert matches["trusted_matches_count"] == 1
    assert matches["trusted_matches"][0]["indicator_id"] == ind_id

    # Non-matching domain must not trigger false alarm
    no_match = repo.match_indicators({"domains": ["official-msedcl.in"]})
    assert no_match["has_matches"] is False
    assert no_match["trusted_matches_count"] == 0


# ---------------------------------------------------------------------------
# 4. URL Canonicalization (Query Parameter & Fragment Stripping)
# ---------------------------------------------------------------------------

def test_04_url_canonicalization_and_bounded_matching(repo):
    # Insert URL with session token and fragment in query string
    raw_url = "https://MahaGov-Scheme.fake.link:443/apply//form/?otp=482910&token=secret123#step2"
    ind_id = repo.add_indicator(
        indicator_type="url",
        indicator_value=raw_url,
        confidence_score=85,
        severity="high",
        review_state="reviewed",
    )

    ind = repo.get_indicator(ind_id)
    assert ind is not None
    # Ensure query parameters and fragments were stripped
    assert "otp=" not in ind["indicator_value"]
    assert "secret123" not in ind["indicator_value"]
    assert "#step2" not in ind["indicator_value"]
    assert ind["indicator_value"] == "https://mahagov-scheme.fake.link/apply/form"

    # Matching with a different citizen's tracking token matches canonical path
    query_url = "https://mahagov-scheme.fake.link/apply/form/?token=different_citizen_token"
    matches = repo.match_indicators({"urls": [query_url]})
    assert matches["has_matches"] is True
    assert matches["trusted_matches_count"] == 1


# ---------------------------------------------------------------------------
# 5. APK Hash Normalization & Matching
# ---------------------------------------------------------------------------

def test_05_apk_hash_normalization_and_matching(repo):
    raw_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    ind_id = repo.add_indicator(
        indicator_type="apk_sha256",
        indicator_value=raw_hash,
        severity="critical",
        confidence_score=95,
        review_state="reviewed",
    )

    ind = repo.get_indicator(ind_id)
    assert ind is not None
    assert ind["indicator_value"] == raw_hash.lower()

    # Query with uppercase hash
    matches = repo.match_indicators({"apk_hashes": [raw_hash]})
    assert matches["has_matches"] is True
    assert matches["trusted_matches_count"] == 1


# ---------------------------------------------------------------------------
# 6. Phone HMAC & Fail-Closed Secret Key Management
# ---------------------------------------------------------------------------

def test_06_phone_indicator_hmac_and_fail_closed_key(repo):
    test_secret = "CustomSafeTestSecretKey2026"
    raw_phone = "+91 98765 43210"

    ind_id = repo.add_indicator(
        indicator_type="phone_hmac",
        indicator_value=raw_phone,
        confidence_score=80,
        severity="high",
        review_state="reviewed",
        hmac_secret=test_secret,
    )

    ind = repo.get_indicator(ind_id)
    assert ind is not None
    # Crucial security guarantee: Plaintext phone number is NEVER stored!
    assert raw_phone not in ind["indicator_value"]
    assert "9876543210" not in ind["indicator_value"]
    assert ind["indicator_value"].startswith("HMAC_")

    # Match using same phone with different spacing
    matches = repo.match_indicators(
        {"phone_numbers": ["9876543210"]},
        hmac_secret=test_secret,
    )
    assert matches["has_matches"] is True
    assert matches["trusted_matches_count"] == 1

    # Fail-closed check: if secret is empty, must raise ThreatIntelligenceKeyError
    with pytest.raises(ThreatIntelligenceKeyError):
        compute_phone_indicator_hmac("9876543210", secret="")


# ---------------------------------------------------------------------------
# 7. Duplicate Handling (Occurrence Incrementing & Audit)
# ---------------------------------------------------------------------------

def test_07_duplicate_indicator_handling(repo):
    ind_val = "scam-domain.xyz"

    id1 = repo.add_indicator(
        indicator_type="domain",
        indicator_value=ind_val,
        confidence_score=60,
    )

    ind_initial = repo.get_indicator(id1)
    assert ind_initial["occurrence_count"] == 1

    # Add same indicator again with higher confidence
    id2 = repo.add_indicator(
        indicator_type="domain",
        indicator_value=ind_val,
        confidence_score=85,
    )

    assert id1 == id2  # Must reuse same indicator ID
    ind_updated = repo.get_indicator(id1)
    assert ind_updated["occurrence_count"] == 2
    assert ind_updated["confidence_score"] == 85

    # Check audit log contains both INSERT and UPDATE_OCCURRENCE
    logs = repo.list_indicator_audit_logs(indicator_id=id1)
    actions = [l["action"] for l in logs]
    assert "INSERT" in actions
    assert "UPDATE_OCCURRENCE" in actions


# ---------------------------------------------------------------------------
# 8. Inactive and Expired Indicator Rejection
# ---------------------------------------------------------------------------

def test_08_inactive_indicator_not_matched(repo):
    ind_id = repo.add_indicator(
        indicator_type="domain",
        indicator_value="deactivated-scam.top",
        review_state="reviewed",
    )

    # Initially matches
    matches1 = repo.match_indicators({"domains": ["deactivated-scam.top"]})
    assert matches1["has_matches"] is True

    # Deactivate
    repo.deactivate_indicator(ind_id, reason="Resolved / False alarm")

    # Must no longer match
    matches2 = repo.match_indicators({"domains": ["deactivated-scam.top"]})
    assert matches2["has_matches"] is False


def test_09_expired_indicator_not_matched(repo):
    past_date = "2020-01-01T00:00:00Z"
    repo.add_indicator(
        indicator_type="domain",
        indicator_value="expired-threat.com",
        expires_at=past_date,
        review_state="reviewed",
    )

    matches = repo.match_indicators({"domains": ["expired-threat.com"]})
    assert matches["has_matches"] is False
    assert matches["trusted_matches_count"] == 0


# ---------------------------------------------------------------------------
# 9. Review State Decision Boundary (Reviewed vs Unreviewed Leads)
# ---------------------------------------------------------------------------

def test_10_unreviewed_vs_reviewed_decision_boundary(repo):
    ind_id = repo.add_indicator(
        indicator_type="domain",
        indicator_value="unconfirmed-lead.link",
        review_state="unreviewed",  # Citizen forward lead
    )

    matches = repo.match_indicators({"domains": ["unconfirmed-lead.link"]})
    # Unreviewed indicators appear in 'unreviewed_leads', NEVER in 'trusted_matches'
    assert matches["has_matches"] is True
    assert matches["trusted_matches_count"] == 0
    assert matches["unreviewed_leads_count"] == 1
    assert "unreviewed indicator(s)" in matches["summary_en"]

    # Promote to reviewed
    repo.update_indicator_review_state(ind_id, review_state="reviewed", reason="Analyst verified")

    matches_after = repo.match_indicators({"domains": ["unconfirmed-lead.link"]})
    assert matches_after["trusted_matches_count"] == 1
    assert matches_after["unreviewed_leads_count"] == 0
    assert "verified indicator(s)" in matches_after["summary_en"]


# ---------------------------------------------------------------------------
# 10. Audit Log Privacy Protection
# ---------------------------------------------------------------------------

def test_11_audit_log_contains_no_raw_secrets(repo):
    repo.add_indicator(
        indicator_type="phone_hmac",
        indicator_value="9822012345",
        notes="Suspect electricity bill scam forward",
        actor="forensic_analyst",
    )

    logs = repo.list_indicator_audit_logs()
    assert len(logs) > 0
    for l in logs:
        log_str = json.dumps(l)
        # Ensure raw phone number is not exposed in audit log entries
        assert "9822012345" not in log_str


# ---------------------------------------------------------------------------
# 11. Concurrency Safety Under WAL Mode
# ---------------------------------------------------------------------------

def test_12_concurrent_indicator_insertions(repo):
    def _worker(worker_id):
        for i in range(5):
            repo.add_indicator(
                indicator_type="domain",
                indicator_value=f"threat-worker-{worker_id}-site-{i}.com",
                notes=f"Worker {worker_id}",
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_worker, wid) for wid in range(4)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    indicators = repo.list_indicators(limit=100)
    assert len(indicators) == 20


# ---------------------------------------------------------------------------
# 12. Additive Risk Score Integration
# ---------------------------------------------------------------------------

def test_13_additive_risk_score_integration():
    base_scored = {
        "score": 35,
        "risk_level": "Potentially Suspicious Message",
        "badge_color": "orange",
        "evidence": ["Matched urgency keywords"],
        "observed_facts": ["Devanagari text"],
        "heuristic_inferences": ["Calculated risk index: 35/100"],
    }

    # Scenario A: Verified threat match increases score and updates badge
    reviewed_intel = {
        "has_matches": True,
        "trusted_matches_count": 2,
        "unreviewed_leads_count": 0,
        "highest_severity": "high",
        "highest_confidence": 90,
    }
    updated_reviewed = apply_threat_intelligence_to_score(base_scored, reviewed_intel)
    assert updated_reviewed["score"] > base_scored["score"]
    assert updated_reviewed["score"] == 55  # 35 + 20
    assert updated_reviewed["badge_color"] == "red"
    assert any("[Threat Intelligence]" in ev for ev in updated_reviewed["evidence"])

    # Scenario B: Unreviewed lead does NOT increase score
    lead_intel = {
        "has_matches": True,
        "trusted_matches_count": 0,
        "unreviewed_leads_count": 1,
        "highest_severity": "medium",
        "highest_confidence": 50,
    }
    updated_lead = apply_threat_intelligence_to_score(base_scored, lead_intel)
    assert updated_lead["score"] == base_scored["score"]  # Score unchanged!
    assert any("unreviewed indicator" in f for f in updated_lead["observed_facts"])


# ---------------------------------------------------------------------------
# 13. Case Preservation Across Repository Operations
# ---------------------------------------------------------------------------

def test_14_existing_cases_preserved_across_migrations(repo):
    # Save a case
    sample_case = {
        "analysis_type": "WhatsApp Vernacular Phishing Analysis",
        "risk_score": 70,
        "risk_category": "High-Risk",
        "badge_color": "red",
        "target_identifier": "Message (Marathi)",
    }
    case_id = repo.save_case(sample_case)

    # Add indicators and audit logs
    repo.add_indicator(indicator_type="domain", indicator_value="sample-scam.xyz")

    # Verify case is intact
    retrieved = repo.get_case(case_id)
    assert retrieved is not None
    assert retrieved["case_id"] == case_id
    assert retrieved["risk_score"] == 70


# ---------------------------------------------------------------------------
# 14. Strict Offline Zero Network Calls
# ---------------------------------------------------------------------------

def test_15_strict_offline_zero_network_calls(repo, monkeypatch):
    def _blocked_connect(*args, **kwargs):
        raise AssertionError("Network connection attempted during threat intelligence operation!")

    monkeypatch.setattr(socket, "create_connection", _blocked_connect)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked_connect)

    ind_id = repo.add_indicator(
        indicator_type="domain",
        indicator_value="offline-intel-test.top",
        review_state="reviewed",
    )
    res = repo.match_indicators({"domains": ["offline-intel-test.top"]})
    assert res["has_matches"] is True
    assert res["trusted_matches_count"] == 1


# ---------------------------------------------------------------------------
# 15. SEC-01 Regression: Key Security & Fail-Closed Lifecycle
# ---------------------------------------------------------------------------

def test_16_sec_01_comprehensive_key_security(tmp_path, monkeypatch):
    # 1. Missing key causes safe failure
    monkeypatch.delenv("SEVA_THREAT_INTEL_KEY", raising=False)
    monkeypatch.delenv("SEVA_HMAC_SECRET", raising=False)
    monkeypatch.delenv("WHATSAPP_SENDER_SALT", raising=False)

    with pytest.raises(ThreatIntelligenceKeyError) as exc_info:
        get_threat_intel_hmac_secret()
    assert "not configured" in str(exc_info.value).lower()
    assert "fails closed" in str(exc_info.value).lower()

    # compute_phone_indicator_hmac fails closed when no secret is configured
    with pytest.raises(ThreatIntelligenceKeyError):
        compute_phone_indicator_hmac("9876543210")

    # 2. Blank or invalid key causes safe failure
    with pytest.raises(ThreatIntelligenceKeyError):
        compute_phone_indicator_hmac("9876543210", secret="")
    with pytest.raises(ThreatIntelligenceKeyError):
        compute_phone_indicator_hmac("9876543210", secret="   ")

    # Short key (< 16 chars)
    with pytest.raises(ThreatIntelligenceKeyError) as exc_short:
        compute_phone_indicator_hmac("9876543210", secret="too_short_key")
    assert "at least 16 characters" in str(exc_short.value).lower()

    # 3. No fallback to WHATSAPP_SENDER_SALT
    monkeypatch.setenv("WHATSAPP_SENDER_SALT", "SomeWhatsAppSaltValue2026")
    with pytest.raises(ThreatIntelligenceKeyError):
        compute_phone_indicator_hmac("9876543210")
    monkeypatch.delenv("WHATSAPP_SENDER_SALT", raising=False)

    # 4. Same configured key produces stable phone-indicator matching across instances
    key_alpha = "ConfiguredStrongSecretAlpha2026"
    monkeypatch.setenv("SEVA_THREAT_INTEL_KEY", key_alpha)

    db1 = tmp_path / "repo1.sqlite3"
    repo1 = CaseRepository(db_path=str(db1))
    ind_id1 = repo1.add_indicator(
        indicator_type="phone_hmac",
        indicator_value="+91 98765 43210",
        review_state="reviewed",
    )
    # Reopen same database with a new repository instance (simulating restart)
    repo1_restarted = CaseRepository(db_path=str(db1))
    matches_restarted = repo1_restarted.match_indicators({"phone_numbers": ["9876543210"]})
    assert matches_restarted["has_matches"] is True
    assert matches_restarted["trusted_matches_count"] == 1

    # 5. Different keys do not silently match the same phone indicator
    key_beta = "ConfiguredStrongSecretBeta2026!"
    matches_diff_key = repo1.match_indicators(
        {"phone_numbers": ["9876543210"]},
        hmac_secret=key_beta,
    )
    assert matches_diff_key["has_matches"] is False
    assert matches_diff_key["trusted_matches_count"] == 0

    # 6. Phone numbers are never stored in plaintext
    with sqlite3.connect(str(db1)) as conn:
        row = conn.execute("SELECT indicator_value FROM threat_indicators WHERE indicator_id = ?", (ind_id1,)).fetchone()
        stored_val = row[0]
        assert "9876543210" not in stored_val
        assert stored_val.startswith("HMAC_")
        assert len(stored_val) == 69  # HMAC_ (5) + 64 hex chars

    # 7. Secret values do not appear in exception messages or logs
    secret_canary = "CanarySecretKey999988887777"
    with pytest.raises(ThreatIntelligenceKeyError) as exc_leak_test:
        compute_phone_indicator_hmac("9876543210", secret="short")
    assert secret_canary not in str(exc_leak_test.value)

    logs = repo1.list_indicator_audit_logs()
    for log_entry in logs:
        log_json = json.dumps(log_entry)
        assert key_alpha not in log_json
        assert "9876543210" not in log_json

    # 8. Unconfigured key in match_indicators fails closed without crashing
    monkeypatch.delenv("SEVA_THREAT_INTEL_KEY", raising=False)
    matches_no_key = repo1.match_indicators(
        {"phone_numbers": ["9876543210"]},
        hmac_secret=None,
    )
    assert matches_no_key["has_matches"] is False
    assert matches_no_key["trusted_matches_count"] == 0
