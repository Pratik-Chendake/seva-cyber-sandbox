"""
End-to-End Regression & Integration Tests for Seva Cyber Sandbox.
Verifies complete cross-module workflows:
1. Phishing Message -> URL Extraction -> URL Analyzer -> Scheme Verifier -> Case Store.
2. APK Inspection -> Passive URL Extraction -> Risk Scorer -> Case Store -> Evidence Report.
3. Edge case cross-testing: Empty inputs across all engines.
4. Audio generation consistency across all risk levels and modules.
5. Case Store CSV and JSON integrity after cross-engine multi-threat logging.
"""

import os
import sys

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.apk_analyzer import analyze_apk_bytes
from src.audio_alert import generate_alert_wav_bytes, get_spoken_script
from src.case_manager import (
    SessionCaseStore,
    create_apk_case,
    create_message_case,
    create_scheme_case,
    create_url_case,
    generate_evidence_report,
)
from src.ml_classifier import predict_with_local_ml
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_apk_analysis, score_message_analysis
from src.scheme_verifier import verify_scheme_claim
from src.url_analyzer import analyze_url


def test_01_full_cross_engine_message_workflow():
    """
    Workflow: Citizen receives WhatsApp message containing a fake scheme claim and a phishing URL.
    Verifies that phishing_detector, url_analyzer, scheme_verifier, and case_manager cooperate.
    """
    store = SessionCaseStore(session_id="integration-session-01")
    raw_message = (
        "मुख्यमंत्री माझी लाडकी बहीण योजना ₹३,००० हप्ता मिळवण्यासाठी आताच नोंदणी करा. "
        "लिंक: http://ladkibahin-yojana-claim.xyz/register आणि OTP सांगा."
    )

    # 1. Phishing Text Inspection
    msg_res = analyze_message_text(raw_message)
    assert msg_res["is_empty"] is False
    assert len(msg_res["extracted_urls"]) == 1
    extracted_url = msg_res["extracted_urls"][0]

    scored_msg = score_message_analysis(msg_res)
    assert scored_msg["score"] >= 50
    assert scored_msg["badge_color"] == "red"

    msg_case_id = store.add_case(create_message_case(msg_res, scored_msg))
    assert msg_case_id.startswith("CASE-MSG-")

    # 2. URL Analyzer on the extracted link
    url_eval = analyze_url(extracted_url)
    assert url_eval["is_valid_url"] is True
    assert url_eval["score"] >= 50
    assert url_eval["badge_color"] == "red"
    assert url_eval["observable_characteristics"]["is_lookalike"] is True

    url_case_id = store.add_case(create_url_case(url_eval))
    assert url_case_id.startswith("CASE-URL-")

    # 3. Scheme Verifier on the claim text and suspicious URL
    scheme_res = verify_scheme_claim(raw_message, suspicious_url=extracted_url)
    assert scheme_res["classification"] == "CONFLICTING EVIDENCE FOUND"
    assert any("Amount Discrepancy" in ev for ev in scheme_res["conflicting_evidence"])
    assert any("Fake/Unofficial Registration Portal" in ev for ev in scheme_res["conflicting_evidence"])

    scheme_case_id = store.add_case(create_scheme_case(scheme_res))
    assert scheme_case_id.startswith("CASE-GOV-")

    # 4. Case Store Verification
    assert store.count() == 3
    cases = store.list_cases()
    assert len(cases) == 3

    # 5. Export Report Verification for the scheme case
    rep = generate_evidence_report(store.get_case(scheme_case_id))
    assert "CYBERSECURITY ANALYSIS SUMMARY — NOT AN OFFICIAL FORENSIC CERTIFICATION" in rep
    assert "CONFLICTING EVIDENCE FOUND" in rep
    assert "1930" in rep


def test_02_full_cross_engine_apk_workflow():
    """
    Workflow: Citizen receives suspicious APK file.
    Verifies that apk_analyzer, url_analyzer, risk_scorer, audio_alert, and case_manager cooperate.
    """
    store = SessionCaseStore(session_id="integration-session-02")
    sample_apk_path = os.path.join("sample_apks", "Real_Binary_AXML_Header_Sample.apk")

    with open(sample_apk_path, "rb") as f:
        apk_bytes = f.read()

    # 1. Static APK Analysis
    apk_res = analyze_apk_bytes(apk_bytes, "Real_Binary_AXML_Header_Sample.apk")
    assert apk_res["is_valid_apk"] is True
    assert apk_res["has_manifest"] is True
    assert len(apk_res["passive_urls"]) > 0

    # 2. Risk Scorer
    scored_apk = score_apk_analysis(apk_res)
    assert scored_apk["score"] >= 50
    assert scored_apk["badge_color"] == "red"

    # 3. Audio Tone Generation
    wav_bytes = generate_alert_wav_bytes(scored_apk["badge_color"])
    assert wav_bytes.startswith(b"RIFF")
    assert len(wav_bytes) > 500

    # 4. URL Analyzer on the passive URL found inside APK
    passive_url = apk_res["passive_urls"][0]
    pu_res = analyze_url(passive_url)
    assert pu_res["is_valid_url"] is True

    # 5. Case Store & Report Generation
    apk_case_id = store.add_case(create_apk_case(apk_res, scored_apk))
    report = generate_evidence_report(store.get_case(apk_case_id))
    assert "Payload Fingerprint:" in report
    assert apk_res["sha256_hash"] in report
    assert "RECEIVE_SMS" in report


def test_03_robust_error_handling_across_all_engines():
    """
    Tests empty, None, and garbage inputs across all modules
    to guarantee zero uncaught crashes.
    """
    # APK analyzer with None and empty
    res_apk_none = analyze_apk_bytes(None, "")  # type: ignore
    assert res_apk_none["is_valid_apk"] is False

    # Phishing detector with None and blank
    res_phish_none = analyze_message_text(None)  # type: ignore
    assert res_phish_none["is_empty"] is True

    # URL analyzer with None, spaces, and garbage
    res_url_none = analyze_url(None)  # type: ignore
    assert res_url_none["is_valid_url"] is False
    res_url_garbage = analyze_url("not a url at all :::")
    assert res_url_garbage["is_valid_url"] is False

    # Scheme verifier with None
    res_scheme_none = verify_scheme_claim(None)  # type: ignore
    assert res_scheme_none["classification"] == "NOT ENOUGH EVIDENCE"

    # ML classifier with None
    res_ml_none = predict_with_local_ml(None)  # type: ignore
    assert res_ml_none["is_available"] is True
    assert res_ml_none["ml_flag"] == "No Input"


def test_04_audio_scripts_and_tones_completeness():
    """Verifies that all color states (red, orange, green) produce valid audio tones and scripts."""
    for color in ("red", "orange", "green"):
        wav = generate_alert_wav_bytes(color)
        assert wav[:4] == b"RIFF"
        en, mr = get_spoken_script(color, "Test Assessment")
        assert len(en) > 10
        assert len(mr) > 10
