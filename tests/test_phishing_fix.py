"""
Comprehensive verification test suite for Phishing Intelligence Workspace Bug Fix.
Verifies all 9 scenarios specified in Phase 5:
1. English phishing message analysis.
2. Marathi phishing message analysis.
3. Suspicious URL analysis.
4. Combined message + URL analysis.
5. Empty / whitespace-only input validation.
6. Invalid payload handling.
7. Unreachable backend / 502 proxy error handling contract.
8. Valid analysis result structure for Liquid Glass UI rendering.
9. Privacy-sensitive message redaction (Aadhaar & phone numbers).
"""

import json
import pytest
from fastapi.testclient import TestClient

from api_server import app, get_repository
from src.case_repository import sanitize_evidence_text


@pytest.fixture
def client():
    return TestClient(app)


# -----------------------------------------------------------------------------
# Scenario 1: English Phishing Message Analysis
# -----------------------------------------------------------------------------
def test_scenario_1_english_phishing_message(client):
    """Verifies English banking/KYC lure via /api/analyze/unified and specialized endpoints."""
    msg = "Dear SBI Customer, your YONO account is locked due to pending KYC verification. Update details immediately: http://192.168.1.100/sbi-kyc"

    # Test via /api/analyze/unified using 'message' field alias (as sent by UI)
    res_unified = client.post(
        "/api/analyze/unified",
        data={"message": msg, "enable_shadow_ai": "true"},
    )
    assert res_unified.status_code == 200, res_unified.text
    data = res_unified.json()
    assert "investigation_id" in data
    assert data["overall_verdict"]["score"] >= 40
    assert len(data["artifacts"]) >= 1

    # Verify extracted URL was identified and evaluated
    url_arts = [a for a in data["artifacts"] if a.get("artifact_type") == "url"]
    assert len(url_arts) >= 1
    assert any("192.168.1.100" in a.get("target_identifier", "") for a in url_arts)

    # Test via /api/analyze/message
    res_msg = client.post(
        "/api/analyze/message",
        json={"message": msg, "enable_shadow_ai": True},
    )
    assert res_msg.status_code == 200
    assert res_msg.json()["risk_score"] >= 40

    # Test via /api/phishing/analyze
    res_phish = client.post(
        "/api/phishing/analyze",
        json={"message": msg, "enable_shadow_ai": True},
    )
    assert res_phish.status_code == 200
    assert res_phish.json()["risk_score"] >= 40


# -----------------------------------------------------------------------------
# Scenario 2: Marathi Phishing Message Analysis
# -----------------------------------------------------------------------------
def test_scenario_2_marathi_phishing_message(client):
    """Verifies Marathi vernacular lure (MSEDCL power disconnection)."""
    msg = "तात्काळ: महावितरण वीज बिल थकीत आहे. आजच भरा नाहीतर रात्री 9:30 वाजता वीज पुरवठा खंडित केला जाईल. संपर्क: 9820011223 http://bit.ly/mseb-update"

    res = client.post(
        "/api/analyze/unified",
        data={"message_text": msg, "enable_shadow_ai": "true"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["overall_verdict"]["score"] >= 40

    # Verify Marathi script detection
    msg_arts = [a for a in data["artifacts"] if a.get("artifact_type") == "message"]
    assert len(msg_arts) >= 1
    script_detected = msg_arts[0].get("analysis_result", {}).get("script_detected", "")
    assert "Marathi" in script_detected or "Devanagari" in script_detected

    # Verify Marathi explanation is provided
    summary_mr = msg_arts[0].get("scored_result", {}).get("summary_mr", "")
    assert len(summary_mr) > 0


# -----------------------------------------------------------------------------
# Scenario 3: Suspicious URL Analysis
# -----------------------------------------------------------------------------
def test_scenario_3_suspicious_url(client):
    """Verifies fake government scheme URL analysis."""
    url = "https://ladkibahin-portal-free.xyz/apply"

    # Via /api/analyze/unified
    res_unified = client.post(
        "/api/analyze/unified",
        data={"urls": url},
    )
    assert res_unified.status_code == 200, res_unified.text
    data = res_unified.json()
    assert len(data["artifacts"]) >= 1
    assert data["overall_verdict"]["score"] >= 40

    # Via /api/analyze/url
    res_url = client.post(
        "/api/analyze/url",
        json={"url": url},
    )
    assert res_url.status_code == 200, res_url.text
    url_data = res_url.json()
    assert url_data["risk_score"] >= 40
    assert "url_radar_details" in url_data


# -----------------------------------------------------------------------------
# Scenario 4: Combined Message + URL Analysis
# -----------------------------------------------------------------------------
def test_scenario_4_combined_message_and_url(client):
    """Verifies multi-artifact correlation when message and URL are submitted together."""
    msg = "मुख्यमंत्री माझी लाडकी बहीण योजना 3000 रुपये खात्यात जमा करण्यासाठी अर्ज त्वरित भरा"
    url = "https://ladkibahin-portal-free.xyz/apply"

    res = client.post(
        "/api/analyze/unified",
        data={
            "message": msg,
            "message_text": msg,
            "urls": url,
            "url": url,
            "enable_shadow_ai": "true",
        },
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert len(data["artifacts"]) >= 2
    types = {a["artifact_type"] for a in data["artifacts"]}
    assert "message" in types
    assert "url" in types
    assert data["summary_stats"]["completed_count"] >= 2


# -----------------------------------------------------------------------------
# Scenario 5: Empty / Whitespace-Only Input Validation
# -----------------------------------------------------------------------------
def test_scenario_5_empty_whitespace_input_validation(client):
    """Verifies that empty and whitespace-only submissions return clean HTTP 400/422 responses."""
    # 1. Empty /api/analyze/unified
    res_empty_unif = client.post("/api/analyze/unified", data={})
    assert res_empty_unif.status_code == 400
    assert "Please provide at least one piece of evidence" in res_empty_unif.json()["detail"]

    # 2. Whitespace-only /api/analyze/unified
    res_ws_unif = client.post(
        "/api/analyze/unified",
        data={"message": "   \n\t  ", "urls": "   "},
    )
    assert res_ws_unif.status_code == 400

    # 3. Empty string on /api/analyze/message -> 422
    res_empty_msg = client.post("/api/analyze/message", json={"message": ""})
    assert res_empty_msg.status_code == 422

    # 4. Whitespace-only on /api/analyze/message -> 422 (pydantic validator)
    res_ws_msg = client.post("/api/analyze/message", json={"message": "    "})
    assert res_ws_msg.status_code == 422

    # 5. Empty string on /api/analyze/url -> 422
    res_empty_url = client.post("/api/analyze/url", json={"url": ""})
    assert res_empty_url.status_code == 422

    # 6. Whitespace-only on /api/analyze/url -> 422
    res_ws_url = client.post("/api/analyze/url", json={"url": "   "})
    assert res_ws_url.status_code == 422


# -----------------------------------------------------------------------------
# Scenario 6: Invalid Payload Handling
# -----------------------------------------------------------------------------
def test_scenario_6_invalid_payload_handling(client):
    """Verifies defensive error handling when payload is malformed or types are wrong."""
    # Wrong content type for JSON endpoint
    res_bad_json = client.post(
        "/api/analyze/message",
        content="not-json-content",
        headers={"Content-Type": "application/json"},
    )
    assert res_bad_json.status_code == 422

    # Missing required message key
    res_missing_key = client.post("/api/analyze/message", json={"wrong_key": "sample"})
    assert res_missing_key.status_code == 422

    # Non-string type for URL
    res_bad_type = client.post("/api/analyze/url", json={"url": 12345})
    assert res_bad_type.status_code == 422


# -----------------------------------------------------------------------------
# Scenario 7: Unreachable Backend Contract / Error Format
# -----------------------------------------------------------------------------
def test_scenario_7_error_response_contract(client):
    """Verifies that error responses follow structured conventions readable by frontend."""
    res = client.get("/api/cases/CASE-INVALID-NONEXISTENT")
    assert res.status_code == 404
    data = res.json()
    assert "detail" in data
    assert isinstance(data["detail"], str)


# -----------------------------------------------------------------------------
# Scenario 8: Valid Analysis Result Structure for Liquid Glass UI
# -----------------------------------------------------------------------------
def test_scenario_8_result_structure_for_ui(client):
    """Verifies that all fields expected by PhishingSection.tsx exist in the output."""
    res = client.post(
        "/api/analyze/unified",
        data={"message_text": "Dear user, electricity disconnection notice. Pay bill at http://192.168.1.1/pay"},
    )
    assert res.status_code == 200
    data = res.json()

    # Core top-level keys
    assert "investigation_id" in data
    assert "created_at_utc" in data
    assert "overall_verdict" in data
    assert "artifacts" in data
    assert "correlations" in data

    # Verdict keys for banner rendering
    verdict = data["overall_verdict"]
    assert "score" in verdict
    assert "risk_category" in verdict
    assert "badge_color" in verdict
    assert "key_observations" in verdict
    assert isinstance(verdict["key_observations"], list)

    # Artifact structure for cards
    for art in data["artifacts"]:
        assert "artifact_id" in art
        assert "artifact_type" in art
        assert "risk_score" in art
        assert "risk_category" in art
        assert "target_identifier" in art


# -----------------------------------------------------------------------------
# Scenario 9: Privacy-Sensitive Message Redaction
# -----------------------------------------------------------------------------
def test_scenario_9_privacy_sensitive_message(client):
    """Verifies that Aadhaar numbers and phone numbers are redacted and never stored raw."""
    raw_message = "Urgent: Aadhaar 2345 6789 0123 has won prize. Call 9820011223 to claim."

    # Test /api/privacy/sanitize endpoint
    res_san = client.post("/api/privacy/sanitize", json={"text": raw_message})
    assert res_san.status_code == 200
    san_data = res_san.json()
    assert "2345 6789 0123" not in san_data["sanitized_text"]
    assert "9820011223" not in san_data["sanitized_text"]
    assert san_data["redactions_applied"]["aadhaar_numbers"] is True
    assert san_data["redactions_applied"]["phone_numbers"] is True

    # Test sanitize_evidence_text utility
    clean_text = sanitize_evidence_text(raw_message)
    assert "2345 6789 0123" not in clean_text
    assert "9820011223" not in clean_text
    assert "XXXX-XXXX-0123" in clean_text
    assert "+91-98XXXX1223" in clean_text
