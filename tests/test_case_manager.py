"""
Comprehensive Automated Test Suite for Threat Case Manager & Evidence Export.
Tests cover:
1. Creating cases across all 4 analysis types (APK, Message, URL, Scheme).
2. Case ID uniqueness and format.
3. Timestamp ISO UTC formatting.
4. Exporting valid JSON and CSV formats.
5. Missing optional fields handling.
6. Empty case history handling.
7. Privacy guarantee: original file bytes and raw chat text are discarded by default.
8. Session isolation: one session's history is strictly separate from another.
9. Evidence report generation with required legal disclaimer and 1930 reporting links.
10. Error resilience and graceful degradation on malformed case entries.
"""

import csv
import json
import os
import sys

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.case_manager import (
    SessionCaseStore,
    create_apk_case,
    create_message_case,
    create_scheme_case,
    create_url_case,
    generate_case_id,
    generate_evidence_report,
    get_utc_timestamp_iso,
)


def test_01_create_case_and_id_uniqueness():
    """Generates 50 case IDs and verifies they are completely unique."""
    ids = [generate_case_id("CASE-TEST") for _ in range(50)]
    assert len(ids) == len(set(ids)), "Case IDs must be strictly unique"
    for cid in ids:
        assert cid.startswith("CASE-TEST-")
        assert len(cid) >= 18


def test_02_timestamp_utc_iso_format():
    """Verifies that timestamp generated adheres to ISO 8601 UTC format."""
    ts = get_utc_timestamp_iso()
    assert ts.endswith("Z")
    assert "T" in ts
    assert len(ts) == 20


def test_03_apk_case_creation_and_privacy_default():
    """
    Verifies that create_apk_case extracts SHA-256 and observations
    while strictly discarding original raw bytes.
    """
    sample_apk_res = {
        "filename": "fake_trojan.apk",
        "is_valid_apk": True,
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "package_name": "com.fraud.msedcl",
        "file_size_bytes": 1024,
        "manifest_format": "Synthetic Plain-Text XML",
        "dex_format": "Synthetic Stub",
        "permissions_found": [
            {
                "permission": "android.permission.RECEIVE_SMS",
                "severity": "High",
                "family": "SMS_ACCESS",
            }
        ],
        "confirmed_observations": ["Manifest Format: Synthetic Plain-Text XML"],
        "heuristic_warnings": ["Filename references utility"],
        "passive_urls": ["http://phish-msedcl.xyz"],
    }
    scored_res = {
        "score": 75,
        "risk_level": "High-Risk Permission Indicators Detected",
        "badge_color": "red",
        "safe_next_steps_en": ["Delete APK immediately", "Call 1930"],
        "limitations": "Static inspection only.",
    }

    case = create_apk_case(sample_apk_res, scored_res)
    assert case["case_id"].startswith("CASE-APK-")
    assert case["sha256_hash"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert case["risk_score"] == 75
    assert case["raw_data_stored"] is False
    assert "file_bytes" not in case


def test_04_message_case_creation_and_privacy_default():
    """
    Verifies that create_message_case stores indicator metadata
    without retaining original raw message text by default.
    """
    msg_res = {
        "is_empty": False,
        "normalized_text": "Private personal text with phone 9800000000",
        "script_detected": "Marathi (Devanagari Script)",
        "findings": [
            {
                "id": "CREDENTIAL_HARVEST",
                "category": "OTP Request",
                "matched_text": "OTP सांगा",
                "why_it_matters_en": "Banks never ask for OTP.",
            }
        ],
        "extracted_urls": ["http://fake-sbi.xyz"],
        "context_only_suppressed": False,
        "protective_advisory_detected": False,
    }
    scored_res = {
        "score": 60,
        "risk_level": "High-Risk Phishing Indicators Detected",
        "badge_color": "red",
        "safe_next_steps_en": ["Do not share OTP"],
    }

    case = create_message_case(msg_res, scored_res, store_raw_text=False)
    assert case["case_id"].startswith("CASE-MSG-")
    assert case["raw_data_stored"] is False
    assert "raw_text_sample" not in case
    assert len(case["observed_evidence"]) > 0
    assert len(case["heuristic_inferences"]) > 0


def test_05_url_and_scheme_case_creations():
    """Verifies URL and Government Scheme case creation and citations."""
    url_eval = {
        "url": "http://msedcl-bill-fake.xyz",
        "hostname": "msedcl-bill-fake.xyz",
        "scheme": "http",
        "is_valid_url": True,
        "score": 65,
        "risk_level": "High-Risk Suspicious Link Detected",
        "badge_color": "red",
        "observable_characteristics": {
            "is_ip_address": False,
            "is_shortener": False,
            "is_official_allowlisted": False,
        },
        "matched_indicators": [
            {
                "category": "Lookalike Brand",
                "severity": "High",
                "evidence_en": "Mimics MSEDCL on .xyz domain.",
            }
        ],
        "safe_next_steps_en": ["Do not click link"],
    }
    url_case = create_url_case(url_eval)
    assert url_case["case_id"].startswith("CASE-URL-")
    assert url_case["risk_score"] == 65
    assert url_case["target_identifier"] == "msedcl-bill-fake.xyz"

    scheme_res = {
        "classification": "CONFLICTING EVIDENCE FOUND",
        "matched_scheme_title": "Majhi Ladki Bahin Yojana",
        "supporting_evidence": ["Official Scheme Identified"],
        "conflicting_evidence": ["Amount discrepancy: Rs 3000 vs Rs 1500"],
        "official_sources": [
            {
                "title": "Mukhyamantri Majhi Ladki Bahin Yojana",
                "gr_number": "GR-2024-147",
                "publication_date": "2024-06-28",
                "portal_url": "https://ladakibahin.maharashtra.gov.in/",
            }
        ],
        "safe_next_steps_en": ["Verify at official portal"],
        "url_assessment": {"url": "http://ladki-scam.xyz"},
    }
    scheme_case = create_scheme_case(scheme_res)
    assert scheme_case["case_id"].startswith("CASE-GOV-")
    assert scheme_case["risk_category"] == "CONFLICTING EVIDENCE FOUND"
    assert len(scheme_case["official_sources"]) == 1
    assert scheme_case["official_sources"][0]["gr_number"] == "GR-2024-147"


def test_06_session_isolation():
    """
    CRITICAL PRIVACY TEST:
    Verifies that CaseStore A has zero access to CaseStore B's cases.
    """
    store_a = SessionCaseStore(session_id="session-user-alice")
    store_b = SessionCaseStore(session_id="session-user-bob")

    case_a = {"case_id": "CASE-ALICE-01", "analysis_type": "URL", "risk_score": 10}
    store_a.add_case(case_a)

    assert store_a.count() == 1
    assert store_b.count() == 0
    assert store_b.get_case("CASE-ALICE-01") is None
    assert len(store_b.list_cases()) == 0


def test_07_export_valid_json_and_csv():
    """Verifies that export_json produces valid JSON and export_csv produces valid CSV."""
    store = SessionCaseStore(session_id="test-export-session")
    store.add_case({
        "case_id": "CASE-01",
        "timestamp_utc": "2026-10-28T12:00:00Z",
        "analysis_type": "URL",
        "risk_score": 50,
        "risk_category": "Suspicious",
        "indicator_count": 2,
        "sha256_hash": "N/A",
        "extracted_urls": ["http://test.xyz"],
        "analysis_status": "Completed",
        "recommended_action": "Do not open",
    })

    # Test JSON export
    raw_json = store.export_json()
    parsed_json = json.loads(raw_json)
    assert parsed_json["total_cases"] == 1
    assert parsed_json["cases"][0]["case_id"] == "CASE-01"

    # Test CSV export
    raw_csv = store.export_csv()
    reader = csv.DictReader(raw_csv.splitlines())
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["Case ID"] == "CASE-01"
    assert rows[0]["Risk Index"] == "50"


def test_08_empty_case_history_export():
    """Verifies that an empty case store exports valid empty structures without crashing."""
    store = SessionCaseStore()
    assert store.count() == 0

    json_str = store.export_json()
    parsed = json.loads(json_str)
    assert parsed["total_cases"] == 0
    assert parsed["cases"] == []

    csv_str = store.export_csv()
    assert "Case ID,Timestamp UTC" in csv_str


def test_09_evidence_report_disclaimers_and_reporting_links():
    """
    Verifies that generate_evidence_report includes the mandatory disclaimer label
    and official verified reporting links (1930, cybercrime.gov.in).
    """
    case = {
        "case_id": "CASE-VERIFY-99",
        "analysis_type": "Android .APK Static Security Inspection",
        "risk_score": 85,
        "risk_category": "High-Risk Permission Indicators Detected",
        "sha256_hash": "a1b2c3d4e5f67890",
        "hash_algorithm": "SHA-256",
        "target_identifier": "suspicious_msedcl.apk",
        "observed_evidence": ["Permission READ_SMS found", "Permission BIND_ACCESSIBILITY_SERVICE found"],
        "heuristic_inferences": ["Combines SMS access with screen control"],
        "extracted_urls": ["http://c2-server.xyz"],
        "recommended_action": "Enable Airplane Mode, uninstall app, and call 1930",
    }
    report = generate_evidence_report(case)

    # Mandatory Header Check
    assert "CYBERSECURITY ANALYSIS SUMMARY — NOT AN OFFICIAL FORENSIC CERTIFICATION" in report
    # Mandatory Disclaimers
    assert "Not an Official Forensic Certification" in report
    assert "Section 65B of the Indian Evidence Act" in report
    # Official Helpline Links
    assert "1930" in report
    assert "https://cybercrime.gov.in" in report
    assert "https://maharashtra.gov.in" in report
    assert "CASE-VERIFY-99" in report
    assert "a1b2c3d4e5f67890" in report


def test_10_missing_optional_fields_graceful_handling():
    """Ensures records with sparse or missing fields generate reports without throwing KeyError."""
    sparse_case = {
        "case_id": "CASE-SPARSE",
        # Missing timestamp, sha256, evidence, etc.
    }
    report = generate_evidence_report(sparse_case)
    assert "CASE-SPARSE" in report
    assert "Payload Fingerprint:   Not Applicable" in report
    assert "CYBERSECURITY ANALYSIS SUMMARY" in report
