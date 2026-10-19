"""
Comprehensive Automated Test Suite for Seva Cyber Sandbox (16 Tests).
Covers empty files, invalid uploads, oversized files, corrupt ZIPs, missing manifests,
synthetic fixtures, binary AXML parsing, permission deduplication, Marathi/Romanized/Mixed/English
phishing detection, false-positive prevention, ML dataset validation, and audio fallback.

Run command: python -m pytest -v
"""

import io
import os
import sys
import zipfile

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import create_sample_apks
from src.apk_analyzer import MAX_APK_UPLOAD_BYTES, analyze_apk_bytes
from src.audio_alert import generate_alert_wav_bytes, get_spoken_script
from src.ml_classifier import predict_with_local_ml, train_and_evaluate_local_model
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_apk_analysis, score_message_analysis


def setup_module(module):
    """Generate the 5 safe test files in sample_apks/ before running tests."""
    create_sample_apks.main()


def test_01_empty_apk_upload():
    res = analyze_apk_bytes(b"", "empty.apk")
    assert res["is_valid_apk"] is False
    assert "empty" in (res["error_message"] or "").lower()


def test_02_invalid_file_renamed_to_apk():
    path = os.path.join("sample_apks", "Corrupted_Not_A_Real_APK.apk")
    with open(path, "rb") as f:
        res = analyze_apk_bytes(f.read(), "Corrupted_Not_A_Real_APK.apk")
    assert res["is_valid_apk"] is False
    assert "not a valid zip/apk archive" in (res["error_message"] or "").lower()
    scored = score_apk_analysis(res)
    assert "Invalid or Unreadable File" in scored["risk_level"]


def test_03_oversized_apk_upload():
    huge_bytes = b"A" * (MAX_APK_UPLOAD_BYTES + 100)
    res = analyze_apk_bytes(huge_bytes, "oversized.apk")
    assert res["is_valid_apk"] is False
    assert "exceeds the 15 mb safety limit" in (res["error_message"] or "").lower()


def test_04_zip_without_android_manifest():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "Just a normal zip file without a manifest.")
    res = analyze_apk_bytes(buf.getvalue(), "no_manifest.apk")
    assert res["is_valid_apk"] is False
    assert "androidmanifest.xml" in (res["error_message"] or "").lower()


def test_05_synthetic_high_risk_fixture_labeled_honestly():
    path = os.path.join("sample_apks", "MSEDCL_Light_Bill_Update_Test.apk")
    with open(path, "rb") as f:
        res = analyze_apk_bytes(f.read(), "MSEDCL_Light_Bill_Update_Test.apk")
    assert res["is_valid_apk"] is True
    assert res["is_synthetic_fixture"] is True
    assert "Synthetic Plain-Text XML" in res["manifest_format"]
    perms = {p["short_name"] for p in res["permissions_found"]}
    assert "READ_SMS" in perms
    assert "BIND_ACCESSIBILITY_SERVICE" in perms
    scored = score_apk_analysis(res)
    assert scored["score"] >= 55
    assert "High-Risk Permission Indicators Detected" in scored["risk_level"]


def test_06_binary_axml_manifest_parsing():
    path = os.path.join("sample_apks", "Real_Binary_AXML_Header_Sample.apk")
    with open(path, "rb") as f:
        res = analyze_apk_bytes(f.read(), "Real_Binary_AXML_Header_Sample.apk")
    assert res["is_valid_apk"] is True
    assert res["is_synthetic_fixture"] is False
    assert "Compiled Android Binary XML" in res["manifest_format"]
    perms = {p["short_name"] for p in res["permissions_found"]}
    assert "RECEIVE_SMS" in perms
    assert "READ_SMS" in perms
    assert "SYSTEM_ALERT_WINDOW" in perms


def test_07_low_risk_apk_never_claimed_guaranteed_safe():
    path = os.path.join("sample_apks", "Simple_Marathi_Calendar_Test.apk")
    with open(path, "rb") as f:
        res = analyze_apk_bytes(f.read(), "Simple_Marathi_Calendar_Test.apk")
    scored = score_apk_analysis(res)
    assert scored["score"] < 20
    assert scored["risk_level"] == "No Strong Permission-Risk Indicators Detected"
    assert "cannot guarantee" in scored["summary_en"].lower()


def test_08_permission_family_deduplication_cap():
    path = os.path.join("sample_apks", "Real_Binary_AXML_Header_Sample.apk")
    with open(path, "rb") as f:
        res = analyze_apk_bytes(f.read(), "generic_name.apk")
    scored = score_apk_analysis(res)
    assert scored["score"] == 64


def test_09_marathi_devanagari_phishing_message():
    msg = (
        "प्रिय ग्राहक, तुमचे महावितरण वीज बिल अपडेट केलेले नाही. आज रात्री ९:३० वाजता वीज कनेक्शन बंद केले जाईल. "
        "तात्काळ MSEDCL_Bill.apk डाउनलोड करा आणि OTP सांगा."
    )
    res = analyze_message_text(msg)
    scored = score_message_analysis(res)
    assert scored["score"] >= 50
    assert "High-Risk Phishing Indicators Detected" in scored["risk_level"]


def test_10_romanized_marathi_phishing_message():
    msg = (
        "Tumche SBI bank khate aaj block honar aahe karan PAN KYC pending aahe. "
        "Lagech http://sbi-kyc-update.xyz var click karun tumcha OTP aani ATM PIN taka."
    )
    res = analyze_message_text(msg)
    scored = score_message_analysis(res)
    assert scored["score"] >= 50


def test_11_mixed_marathi_english_phishing_message():
    msg = (
        "मुख्यमंत्री लाडकी बहीण योजना ₹3000 हप्ता मिळवण्यासाठी e-KYC करणे आवश्यक आहे. "
        "आताच Yojna_KYC.apk install करा आणि UPI PIN टाका."
    )
    res = analyze_message_text(msg)
    scored = score_message_analysis(res)
    assert scored["score"] >= 50


def test_12_english_phishing_message():
    msg = (
        "URGENT ALERT: Vehicle MH-12 e-Challan is pending. Pay immediately within 2 hours "
        "to avoid court warrant. Download RTO_Challan.apk or visit http://echallan-pay.top"
    )
    res = analyze_message_text(msg)
    scored = score_message_analysis(res)
    assert scored["score"] >= 50


def test_13_legitimate_messages_zero_false_positives():
    legit_bill = (
        "महावितरण सूचना: ग्राहक क्र. 170012345678 चे ऑक्टोबर २०२६ चे वीज बिल ₹८४० आहे. "
        "कृपया महावितरणच्या अधिकृत वेबसाइटवरूनच भरणा करावा."
    )
    res1 = analyze_message_text(legit_bill)
    assert res1["context_only_suppressed"] is True
    assert score_message_analysis(res1)["score"] == 0

    legit_advisory = (
        "Dear Customer, your bank never asks for your OTP or PIN. "
        "Do not download unknown .apk files shared on WhatsApp."
    )
    res2 = analyze_message_text(legit_advisory)
    assert res2["protective_advisory_detected"] is True
    assert score_message_analysis(res2)["score"] == 0


def test_14_empty_and_non_string_message_inputs():
    res_empty = analyze_message_text("   ")
    assert res_empty["is_empty"] is True
    res_none = analyze_message_text(None)  # type: ignore
    assert res_none["is_empty"] is True


def test_15_optional_ml_baseline_and_bad_path_handling():
    good = train_and_evaluate_local_model()
    assert good["is_available"] is True
    assert good["total_samples"] == 20
    pred = predict_with_local_ml("Download MSEDCL_Update.apk and share OTP immediately")
    assert pred["is_available"] is True

    bad = train_and_evaluate_local_model(dataset_path="non_existent_file.json", force_retrain=True)
    assert bad["is_available"] is False


def test_16_offline_wav_audio_generation():
    for color in ("red", "orange", "green"):
        wav_bytes = generate_alert_wav_bytes(color)
        assert wav_bytes[:4] == b"RIFF"
        assert len(wav_bytes) > 1000
    en_script, mr_script = get_spoken_script("red", "APK Assessment")
    assert "Caution" in en_script
    assert "सावधान" in mr_script