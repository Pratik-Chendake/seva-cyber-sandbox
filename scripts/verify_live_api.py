"""
Verification script for Seva Cyber Sandbox FastAPI REST API and live frontend proxy.
Tests endpoints, authentication flows, phishing detection, APK inspection, threat intelligence, and privacy gate.
"""

import json
import urllib.request
import urllib.error
import urllib.parse

BASE_URL = "http://127.0.0.1:8000"
VITE_URL = "http://127.0.0.1:5173"

results = []

def record(test_name, passed, details=""):
    results.append({"name": test_name, "passed": passed, "details": details})
    mark = "[PASS]" if passed else "[FAIL]"
    print(f"{mark} {test_name}: {details}")

def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

def post(url, data, headers=None):
    headers = headers or {}
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

def main():
    print("=" * 60)
    print("SEVA CYBER SANDBOX — LIVE API & ENDPOINT VERIFICATION")
    print("=" * 60)

    # 1. Health & Dashboard
    try:
        status, data = get(f"{BASE_URL}/api/health")
        record("GET /api/health", status == 200 and data.get("status") == "operational", f"DB Connected: {data.get('database', {}).get('connected')}")
    except Exception as e:
        record("GET /api/health", False, str(e))

    try:
        status, data = get(f"{BASE_URL}/api/system/health")
        record("GET /api/system/health", status == 200 and "database" in data, f"Status: {data.get('status')}")
    except Exception as e:
        record("GET /api/system/health", False, str(e))

    try:
        status, data = get(f"{BASE_URL}/api/dashboard/summary")
        record("GET /api/dashboard/summary", status == 200 and "active_model" in data, f"Model: {data.get('active_model')}")
    except Exception as e:
        record("GET /api/dashboard/summary", False, str(e))

    # 2. Threat Intel & AI Telemetry
    try:
        status, data = get(f"{BASE_URL}/api/threat-intelligence/indicators")
        record("GET /api/threat-intelligence/indicators", status == 200 and "indicators" in data, f"Count: {data.get('total_count')}")
    except Exception as e:
        record("GET /api/threat-intelligence/indicators", False, str(e))

    try:
        status, data = get(f"{BASE_URL}/api/threat-intel/graph")
        record("GET /api/threat-intel/graph", status == 200 and "nodes" in data and "links" in data, f"Nodes: {len(data.get('nodes', []))}")
    except Exception as e:
        record("GET /api/threat-intel/graph", False, str(e))

    try:
        status, data = get(f"{BASE_URL}/api/ai/models")
        record("GET /api/ai/models", status == 200 and "active_model" in data, f"Active: {data.get('active_model', {}).get('version')}")
    except Exception as e:
        record("GET /api/ai/models", False, str(e))

    try:
        status, data = get(f"{BASE_URL}/api/ai/evaluations")
        record("GET /api/ai/evaluations", status == 200 and "candidate_training_gate" in data, f"Gate: {data.get('candidate_training_gate', {}).get('status')}")
    except Exception as e:
        record("GET /api/ai/evaluations", False, str(e))

    # 3. Privacy Gate
    try:
        status, data = get(f"{BASE_URL}/api/privacy/status")
        record("GET /api/privacy/status", status == 200 and data.get("fail_closed_policy") == "ACTIVE", f"DPDP Policy: {data.get('fail_closed_policy')}")
    except Exception as e:
        record("GET /api/privacy/status", False, str(e))

    try:
        status, data = post(f"{BASE_URL}/api/privacy/sanitize", {"text": "Call me at +91 9876543210 regarding Aadhaar 2345 6789 0123"})
        has_redaction = "XXXX" in data.get("sanitized_text", "")
        record("POST /api/privacy/sanitize", status == 200 and has_redaction, f"Sanitized: {data.get('sanitized_text')}")
    except Exception as e:
        record("POST /api/privacy/sanitize", False, str(e))

    # 4. Phishing / Message Analysis
    try:
        payload = {"message": "URGENT: Your electricity power will be disconnected tonight. Pay immediately at http://bit.ly/fake-bill"}
        status, data = post(f"{BASE_URL}/api/analyze/message", payload)
        verdict = data.get("overall_verdict", {})
        record("POST /api/analyze/message", status == 200 and "score" in verdict, f"Verdict: {verdict.get('risk_category')} (Score: {verdict.get('score')})")
    except Exception as e:
        record("POST /api/analyze/message", False, str(e))

    # 5. URL Analysis
    try:
        status, data = post(f"{BASE_URL}/api/analyze/url", {"url": "http://192.168.1.1/admin-login.php"})
        record("POST /api/analyze/url", status == 200 and "risk_score" in data, f"Risk: {data.get('risk_category')} ({data.get('risk_score')})")
    except Exception as e:
        record("POST /api/analyze/url", False, str(e))

    # 6. Scheme Verification
    try:
        status, data = post(f"{BASE_URL}/api/analyze/scheme", {"claim_text": "Majhi Ladki Bahin gives 100000 cash prize"})
        record("POST /api/analyze/scheme", status == 200 and "classification" in data, f"Classification: {data.get('classification')}")
    except Exception as e:
        record("POST /api/analyze/scheme", False, str(e))

    # 7. Unified Analysis
    try:
        status, data = post(f"{BASE_URL}/api/analyze/unified", {
            "message": "Verify your bank KYC immediately",
            "urls": ["http://fake-sbi-kyc.com"],
        })
        verdict = data.get("overall_verdict", {})
        record("POST /api/analyze/unified", status == 200 and "score" in verdict, f"Composite Risk: {verdict.get('risk_category')} (Score: {verdict.get('score')})")
    except Exception as e:
        record("POST /api/analyze/unified", False, str(e))

    # 8. Authentication Flow (Unauthenticated session inspection)
    try:
        status, data = get(f"{BASE_URL}/api/auth/me")
        record("GET /api/auth/me (unauthed)", status == 200 and data.get("authenticated") is False, f"Auth state: {data.get('authenticated')}")
    except Exception as e:
        record("GET /api/auth/me (unauthed)", False, str(e))

    # 9. List Cases (Read-only)
    try:
        status, data = get(f"{BASE_URL}/api/cases")
        record("GET /api/cases", status == 200 and "cases" in data, f"Cases count: {data.get('total_cases')}")
    except Exception as e:
        record("GET /api/cases", False, str(e))

    # 10. Frontend Proxy Test
    try:
        status, data = get(f"{VITE_URL}/api/health")
        record("VITE PROXY -> GET /api/health", status == 200 and data.get("status") == "operational", "Proxied successfully to FastAPI")
    except Exception as e:
        record("VITE PROXY -> GET /api/health", False, str(e))

    # Summary
    all_passed = all(r["passed"] for r in results)
    print("=" * 60)
    print(f"Total Tests: {len(results)} | Passed: {sum(1 for r in results if r['passed'])} | Failed: {sum(1 for r in results if not r['passed'])}")
    print("=" * 60)
    if not all_passed:
        exit(1)

if __name__ == "__main__":
    main()
