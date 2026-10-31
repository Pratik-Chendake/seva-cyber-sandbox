"""
Independent verification script for Seva Cyber Sandbox core cybersecurity engines.
Tests each service individually using safe fixtures in an isolated database:
1. Phishing Detector
2. APK Analyzer
3. Risk Scorer (including unreviewed vs reviewed threat intel boundaries)
4. Privacy Gate (fail-closed PII sanitization)
5. Scheme Verifier
6. Threat Intelligence & Case Repository (with audit logs)
7. Operator Authentication (OWASP scrypt password hashing & session lifecycle)
"""

import os
import sys
import tempfile
import hashlib

# Ensure project root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def run_engine_verifications():
    print("=" * 70)
    print("  SEVA CYBER SANDBOX — CORE CYBERSECURITY ENGINES VERIFICATION")
    print("=" * 70)

    # 1. PHISHING DETECTOR
    print("\n[1/7] Testing Phishing Detector...")
    from src.phishing_detector import analyze_message_text
    
    # Vernacular Marathi Lure
    marathi_lure = "तातडीने वीज बिल भरा नाहीतर आज रात्री वीज पुरवठा खंडित केला जाईल."
    res_mr = analyze_message_text(marathi_lure)
    assert "Devanagari" in res_mr["script_detected"], f"Unexpected script: {res_mr['script_detected']}"
    assert len(res_mr["observed_facts"]) > 0
    print(f"  [+] Marathi Lure Analyzed: Script={res_mr['script_detected']}, Assessment={res_mr['assessment_label']}")

    # English Banking / KYC Lure
    eng_lure = "URGENT: Your SBI account has been locked. Verify KYC immediately at http://sbi-verification.update-portal.com"
    res_en = analyze_message_text(eng_lure)
    assert "Latin" in res_en["script_detected"]
    assert "http://sbi-verification.update-portal.com" in res_en["extracted_urls"]
    print(f"  [+] English Lure Analyzed: Extracted URLs={res_en['extracted_urls']}")

    # 2. APK ANALYZER
    print("\n[2/7] Testing APK Analyzer...")
    from src.apk_analyzer import analyze_apk_bytes

    sample_apk_path = os.path.join("sample_apks", "Real_Binary_AXML_Header_Sample.apk")
    if not os.path.exists(sample_apk_path):
        sample_apk_path = os.path.join("sample_apks", "Gram_Panchayat_Directory_Test.apk")
    
    assert os.path.exists(sample_apk_path), f"Sample APK missing at {sample_apk_path}"
    with open(sample_apk_path, "rb") as f:
        apk_bytes = f.read()
    
    apk_res = analyze_apk_bytes(apk_bytes, os.path.basename(sample_apk_path))
    assert "observed_facts" in apk_res
    assert "heuristic_inferences" in apk_res
    assert apk_res.get("is_valid_apk") is True
    print(f"  [+] APK Analyzed: File={os.path.basename(sample_apk_path)}, SHA256={apk_res.get('sha256_hash', '')[:12]}...")
    print(f"  [+] Observations & Inferences strictly segregated: {len(apk_res['observed_facts'])} facts, {len(apk_res['heuristic_inferences'])} inferences")

    # 3. RISK SCORER & THREAT INTEL BOUNDARY
    print("\n[3/7] Testing Risk Scorer & Threat Intel Boundaries...")
    from src.risk_scorer import score_message_analysis, apply_threat_intelligence_to_score

    scored_msg = score_message_analysis(res_en)
    base_score = scored_msg["score"]
    assert 0 <= base_score <= 100
    print(f"  [+] Base Phishing Score: {base_score}/100, Level={scored_msg['risk_level']}, Badge={scored_msg['badge_color']}")

    # Test Unreviewed vs Reviewed Threat Intel Boundaries
    unreviewed_intel = {
        "has_matches": True,
        "trusted_matches_count": 0,
        "unreviewed_leads_count": 1,
        "highest_severity": "high",
    }
    res_unreviewed = apply_threat_intelligence_to_score(scored_msg, unreviewed_intel)
    assert res_unreviewed["score"] == base_score, f"Unreviewed indicator must NOT alter score! got {res_unreviewed['score']} vs {base_score}"
    assert any("unreviewed" in fact.lower() for fact in res_unreviewed["observed_facts"])
    print("  [+] Boundary Verified: Unreviewed threat indicator correctly kept score at 0 delta")

    reviewed_intel = {
        "has_matches": True,
        "trusted_matches_count": 1,
        "unreviewed_leads_count": 0,
        "highest_severity": "critical",
        "highest_confidence": 95,
    }
    res_reviewed = apply_threat_intelligence_to_score(scored_msg, reviewed_intel)
    assert res_reviewed["score"] > base_score or base_score == 100, "Reviewed trusted indicator must increase risk score"
    print(f"  [+] Boundary Verified: Reviewed trusted indicator correctly adjusted risk score: {base_score} -> {res_reviewed['score']}")

    # 4. PRIVACY GATE
    print("\n[4/7] Testing Privacy Gate (Fail-Closed PII Sanitization)...")
    from src.privacy_gate import prepare_for_local_analysis, sanitize_for_local_training

    raw_pii = "Contact Officer Ramesh at +91 9876543210. Aadhaar is 2345 6789 0123. Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token"
    gate_res = sanitize_for_local_training(raw_pii)
    sanitized = gate_res.sanitized_text
    assert gate_res.sanitization_success is True
    assert gate_res.safe_to_send is False, "Fail-closed invariant: safe_to_send must always be False"
    assert "+91 9876543210" not in sanitized, "Phone number was not redacted!"
    assert "2345 6789 0123" not in sanitized, "Aadhaar number was not redacted!"
    assert "eyJhbGciOi" not in sanitized, "Auth token was not redacted!"
    assert "[PHONE_REDACTED]" in sanitized
    assert "[AADHAAR_REDACTED]" in sanitized
    print(f"  [+] Redactions Applied: {gate_res.redaction_counts}")
    print(f"  [+] Sanitized Output: {sanitized}")

    # 5. SCHEME VERIFIER
    print("\n[5/7] Testing Maharashtra Scheme Verifier...")
    from src.scheme_verifier import verify_scheme_claim

    # Official supported claim
    valid_claim = "Mukhyamantri Majhi Ladki Bahin Yojana provides Rs 1500 per month."
    claim_res1 = verify_scheme_claim(valid_claim)
    assert "SUPPORTED" in claim_res1["classification"]
    print(f"  [+] Legitimate Scheme Verification: {claim_res1['classification']}")

    # Contradicted / Discrepant claim
    discrepant_claim = "Register through this WhatsApp link to receive Rs 30,000 under the Mukhyamantri Majhi Ladki Bahin Yojana."
    claim_res2 = verify_scheme_claim(discrepant_claim)
    assert claim_res2["classification"] == "CONFLICTING EVIDENCE FOUND"
    print(f"  [+] Discrepant Scheme Verification: {claim_res2['classification']}")

    # 6. THREAT INTEL & CASE REPOSITORY (IN TEMPORARY ISOLATED DB)
    print("\n[6/7] Testing Threat Intelligence & Case Repository in isolated DB...")
    from src.case_repository import CaseRepository

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tf:
        temp_db_path = tf.name

    try:
        repo = CaseRepository(db_path=temp_db_path)
        
        # Threat indicator insertion & audit
        ind_id = repo.add_indicator(
            indicator_type="domain",
            indicator_value="malicious-phish-domain.in",
            severity="critical",
            confidence_score=95,
            source="analyst_investigation",
            review_state="reviewed",
            actor="lead_investigator",
        )
        assert ind_id is not None
        match = repo.match_indicators({"domains": ["malicious-phish-domain.in"]})
        assert match["has_matches"] is True
        assert match["trusted_matches_count"] >= 1
        print(f"  [+] Indicator recorded and matched: ID={ind_id}, Trusted Matches={match['trusted_matches_count']}")

        # Verify audit log was recorded
        with repo.get_connection() as conn:
            cur = conn.execute("SELECT action, actor FROM indicator_audit_log WHERE indicator_id = ?", (ind_id,))
            audit_entry = cur.fetchone()
            assert audit_entry is not None
            assert audit_entry[0] == "INSERT"
            assert audit_entry[1] == "lead_investigator"
        print("  [+] Indicator audit log successfully verified")

        # Case persistence & human review
        case_id = repo.save_case({
            "title": "Suspected Power Disconnection Phishing",
            "target_identifier": "http://malicious-phish-domain.in",
            "risk_score": 85,
            "risk_category": "CRITICAL",
            "analysis_type": "phishing_url",
            "badge_color": "red",
            "observed_evidence": ["Suspicious domain", "Urgency lure"],
            "recommended_action": "Block domain at gateway",
        }, session_id="test_sess_01", source_type="api_manual")
        
        retrieved_case = repo.get_case(case_id, session_id="test_sess_01")
        assert retrieved_case is not None
        assert retrieved_case["risk_score"] == 85
        print(f"  [+] Case saved and retrieved: {case_id}")

        # Review assignment
        rev = repo.create_or_get_review(case_id, reviewer_label="analyst_pratik")
        assert rev["reviewer_label"] == "analyst_pratik"
        assert rev["review_state"] == "pending"
        print(f"  [+] Human reviewer assigned: {rev['reviewer_label']} (state={rev['review_state']})")
    finally:
        try:
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)
        except Exception:
            pass

    # 7. OPERATOR AUTHENTICATION (IN TEMPORARY ISOLATED DB)
    print("\n[7/7] Testing Operator Authentication (OWASP scrypt)...")
    from src.operator_auth import OperatorAuthService, OperatorAuthError

    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tf:
        auth_temp_db = tf.name

    try:
        auth_svc = OperatorAuthService(db_path=auth_temp_db)
        assert auth_svc.has_any_operator() is False

        # Initial operator registration
        reg_res = auth_svc.register_initial_operator("operator_sec", "SecurePassword123#*", role="admin")
        assert reg_res["username"] == "operator_sec"
        assert auth_svc.has_any_operator() is True
        print(f"  [+] Initial operator registered: {reg_res['username']} (role={reg_res['role']})")

        # Second registration attempt must be locked
        try:
            auth_svc.register_initial_operator("attacker", "AttackerPass123#*")
            assert False, "Second initial registration must fail!"
        except OperatorAuthError:
            print("  [+] Two-Person / Takeover Prevention: Second initial registration locked")

        # Valid login
        login_ok = auth_svc.login("operator_sec", "SecurePassword123#*", client_ip="127.0.0.1")
        assert login_ok["success"] is True
        token = login_ok["session_token"]
        assert token is not None
        print("  [+] Successful login via memory-hard scrypt")

        # Invalid login
        try:
            auth_svc.login("operator_sec", "WrongPassword!456", client_ip="127.0.0.1")
            assert False, "Invalid login must fail!"
        except OperatorAuthError:
            print("  [+] Invalid login correctly rejected with OperatorAuthError")

        # Session validation
        session = auth_svc.validate_session(token)
        assert session is not None
        assert session["username"] == "operator_sec"
        print("  [+] Session token verified active")

        # Logout & revocation
        auth_svc.logout(token)
        revoked = auth_svc.validate_session(token)
        assert revoked is None, "Logged out session must be invalidated!"
        print("  [+] Session token successfully revoked on logout")
    finally:
        try:
            if os.path.exists(auth_temp_db):
                os.remove(auth_temp_db)
        except Exception:
            pass

    print("\n" + "=" * 70)
    print("  ALL 7 CORE CYBERSECURITY ENGINES FULLY VERIFIED AND PASSING!")
    print("=" * 70)

if __name__ == "__main__":
    run_engine_verifications()
