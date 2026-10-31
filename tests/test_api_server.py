"""
Tests for Seva Cyber Sandbox FastAPI Server (api_server.py)
Validates all REST endpoints, auth, local airgap guarantees, and Liquid Glass SPA serving.
"""

import io
import json
import os
import pytest
from starlette.testclient import TestClient

from api_server import app


@pytest.fixture
def client(tmp_path):
    test_db = str(tmp_path / "test_seva_cases.sqlite3")
    old_db = os.environ.get("SEVA_DB_PATH")
    os.environ["SEVA_DB_PATH"] = test_db

    # Initialize schema in isolated temporary database
    from src.case_repository import CaseRepository
    CaseRepository(db_path=test_db)

    test_client = TestClient(app)
    yield test_client

    if old_db is not None:
        os.environ["SEVA_DB_PATH"] = old_db
    else:
        os.environ.pop("SEVA_DB_PATH", None)


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("operational", "degraded")
    assert "database" in data
    assert "active_model" in data
    assert data["active_model"]["operating_mode"] == "shadow"
    assert "Liquid Glass" in data["platform"]["visual_identity"]


def test_system_health_alias(client):
    response = client.get("/api/system/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("operational", "degraded")


def test_dashboard_summary(client):
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_cases" in data
    assert "malicious_cases_count" in data
    assert "airgap_enforced" in data
    assert data["airgap_enforced"] is True


def test_analyze_message_endpoint(client):
    payload = {
        "message": "तात्काळ: महावितरण बिल भरा अन्यथा वीज आज रात्री ९ वाजता बंद होईल http://msedcl-bill-update.online",
        "enable_shadow_ai": True,
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "investigation_id" in data
    assert "overall_verdict" in data
    assert data["overall_verdict"]["risk_category"] in ("MALICIOUS", "SUSPICIOUS", "High Risk", "Moderate Risk")
    assert len(data["artifacts"]) >= 1


def test_phishing_analyze_alias(client):
    payload = {
        "message": "PM Kisan KYC Update Required: Click http://pm-kisan-fraud.top to receive 2000 rupees.",
        "enable_shadow_ai": False,
    }
    response = client.post("/api/phishing/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "investigation_id" in data


def test_analyze_url_endpoint(client):
    payload = {"url": "http://ladki-bahin-yojna-free-portal.xyz"}
    response = client.post("/api/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "url_radar_details" in data
    assert "investigation_result" in data
    assert "risk_score" in data
    assert "risk_category" in data


def test_analyze_scheme_endpoint(client):
    payload = {"claim_text": "लाडकी बहीण योजनेचे १५०० रुपये मिळवण्यासाठी येथे नोंदणी करा"}
    response = client.post("/api/analyze/scheme", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "classification" in data


def test_analyze_apk_endpoint(client):
    fake_apk_bytes = b"PK\x05\x06" + b"\x00" * 18
    files = {"apk_file": ("test_sample.apk", io.BytesIO(fake_apk_bytes), "application/vnd.android.package-archive")}
    response = client.post("/api/analyze/apk", files=files, data={"enable_shadow_ai": "true"})
    assert response.status_code == 200
    data = response.json()
    assert "investigation_id" in data
    assert len(data["artifacts"]) == 1
    assert data["artifacts"][0]["artifact_type"] == "apk"


def test_cases_list_endpoint(client):
    response = client.get("/api/cases")
    assert response.status_code == 200
    data = response.json()
    assert "total_cases" in data
    assert "cases" in data
    assert isinstance(data["cases"], list)


def test_create_and_patch_case(client):
    new_case = {
        "analysis_type": "Message Threat Analysis",
        "target_identifier": "MSEDCL SMS Phishing Alert",
        "risk_score": 85,
        "risk_category": "MALICIOUS",
        "badge_color": "red",
        "recommended_action": "Do not open external link or submit banking OTP",
        "observed_evidence": ["Urgent disconnection threat", "Unregistered link domain"],
    }
    create_resp = client.post("/api/cases", json=new_case)
    assert create_resp.status_code == 200
    created_data = create_resp.json()
    case_id = created_data["case_id"]

    # Patch case
    patch_resp = client.patch(f"/api/cases/{case_id}", json={"reviewer": "senior_analyst", "notes": "Verified threat"})
    assert patch_resp.status_code == 200


def test_threat_graph_endpoint(client):
    response = client.get("/api/threat-intel/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "links" in data
    assert "meta" in data


def test_threat_indicators_list(client):
    response = client.get("/api/threat-intelligence/indicators?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "indicators" in data
    assert "total_count" in data


def test_ai_models_and_evaluations(client):
    resp1 = client.get("/api/ai/models")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["active_model"]["version"] == "custom-mlp-v4.0.0-seed42"

    resp2 = client.get("/api/ai/evaluations")
    assert resp2.status_code == 200


def test_privacy_status_and_sanitize(client):
    status_resp = client.get("/api/privacy/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["fail_closed_policy"] == "ACTIVE"

    sanitize_payload = {"text": "माझा आधार क्रमांक 2345 6789 0123 आहे आणि संपर्क 9876543210 आहे."}
    sanitize_resp = client.post("/api/privacy/sanitize", json=sanitize_payload)
    assert sanitize_resp.status_code == 200
    clean_data = sanitize_resp.json()
    assert "2345 6789 0123" not in clean_data["sanitized_text"]
    assert "9876543210" not in clean_data["sanitized_text"]


def test_evidence_storage_upload_and_retrieve(client):
    blob_content = b"%PDF-1.4 Fake Evidence Document for Testing"
    files = {"file": ("test_report.pdf", io.BytesIO(blob_content), "application/pdf")}
    upload_resp = client.post("/api/storage/upload", files=files, data={"artifact_type": "pdf"})
    assert upload_resp.status_code == 200
    upload_data = upload_resp.json()
    assert "storage_key" in upload_data
    storage_key = upload_data["storage_key"]

    # Retrieve stored blob
    get_resp = client.get(f"/api/storage/evidence/{storage_key}")
    assert get_resp.status_code == 200
    assert get_resp.content == blob_content


def test_operator_auth_lifecycle(client):
    # Test unauthenticated /me
    me_resp = client.get("/api/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["authenticated"] is False

    # Login
    login_resp = client.post("/api/auth/login", json={"username": "operator_lead", "password": "ComplexPassword123#!"})
    assert login_resp.status_code == 200
    token = login_resp.json()["session_token"]
    assert token is not None

    # Authenticated /me
    auth_me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert auth_me_resp.status_code == 200
    assert auth_me_resp.json()["authenticated"] is True
    assert auth_me_resp.json()["username"] == "operator_lead"

    # Logout
    logout_resp = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_resp.status_code == 200

    # Post-logout /me
    post_me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert post_me_resp.json()["authenticated"] is False


def test_static_spa_serving(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Seva Cyber Sandbox" in response.text
    assert "<div id=\"root\"></div>" in response.text
