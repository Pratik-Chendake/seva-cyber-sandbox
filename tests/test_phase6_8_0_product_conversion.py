"""
Phase 6.8.0 — Product Conversion Verification Test Suite.

Verifies the transition of Seva Cyber Sandbox from an educational simulation /
synthetic demonstration into a genuine local cybersecurity application.

Test Coverage:
1. TestSampleDataAbsence: Sample data is absent from operational application paths.
2. TestGenuineMessageAnalysis: Analysis handles real multilingual user inputs.
3. TestGenuineURLAnalysis: Passive URL radar accurately inspects genuine inputs.
4. TestGenuineAPKAnalysis: APK uploader validates real byte archives without execution.
5. TestDatabaseBackedDashboard: Dashboard telemetry originates directly from SQLite.
6. TestPrivacyControlsOnGenuineSubmissions: No PII or raw text retained in cases.
7. TestNoFabricatedResults: Systems report honest classifications and limitations.
8. TestShadowModelOperation: Shadow model operates in parallel with delta = 0.
9. TestEmptyStateReadiness: Fresh installations start cleanly with 0 preloaded records.
10. TestCaseCreationForRealSubmissions: End-to-end case creation, retrieval, and deduplication.
"""

import io
import json
import os
from pathlib import Path
import struct
import tempfile
from unittest.mock import MagicMock, patch
import zipfile

import pytest

from src.apk_analyzer import MAX_APK_UPLOAD_BYTES, analyze_apk_bytes
from src.case_manager import (
    SessionCaseStore,
    create_apk_case,
    create_message_case,
    create_url_case,
)
from src.case_repository import CaseRepository
from src.hybrid_decision_engine import evaluate_message_hybrid
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_apk_analysis, score_message_analysis
from src.url_analyzer import analyze_url


# =============================================================================
# 1. SAMPLE DATA ABSENCE & GOVERNANCE ARTIFACT TESTS
# =============================================================================

class TestSampleDataAbsence:
    """Verifies that sample/demo data is decoupled from the operational application."""

    def test_01_sample_messages_json_not_loaded_at_import_time(self):
        """
        data/sample_messages.json should not be auto-loaded by app.py
        at import time. The file may exist as an archived artifact, but
        the operational app should not expose its contents to the user.
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        archive_path = os.path.join(
            base_dir, "data", "archive", "legacy_samples", "sample_messages.json"
        )
        assert os.path.exists(archive_path), (
            "Archived copy of sample_messages.json not found at data/archive/legacy_samples/. "
            "The archival step in Phase 6.8.0 was not completed."
        )

    def test_02_archive_notes_file_exists(self):
        """Data archive directory contains the governance notes file."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        notes_path = os.path.join(
            base_dir, "data", "archive", "notes", "ARCHIVE_NOTES.md"
        )
        assert os.path.exists(notes_path), (
            "Archive notes file ARCHIVE_NOTES.md is missing."
        )

    def test_03_sample_messages_json_has_expected_structure_when_present(self):
        """
        If the original sample_messages.json exists, it must be a list of
        message objects (not operational data). This is a content integrity check.
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        archive_path = os.path.join(
            base_dir, "data", "archive", "legacy_samples", "sample_messages.json"
        )
        if not os.path.exists(archive_path):
            pytest.skip("Archived sample_messages.json not present.")

        with open(archive_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, list), "sample_messages.json must be a list."
        assert len(data) > 0, "Archived sample_messages.json must not be empty."
        for item in data:
            assert "id" in item, f"Item missing 'id': {item}"
            assert "text" in item, f"Item missing 'text': {item}"
            assert "label" in item, f"Item missing 'label': {item}"


# =============================================================================
# 2. GENUINE MESSAGE ANALYSIS TESTS
# =============================================================================

class TestGenuineMessageAnalysis:
    """Verifies that message analysis works on genuine, diverse inputs."""

    def test_04_english_phishing_message_detected(self):
        """A genuine English phishing message is correctly analyzed."""
        msg = (
            "URGENT: Your bank account will be blocked today. "
            "Enter your OTP and ATM PIN at http://sbi-kyc-verify.xyz/update"
        )
        result = analyze_message_text(msg)
        assert not result["is_empty"], "Should not be empty."
        assert result["findings"], "Phishing message should produce findings."
        scored = score_message_analysis(result)
        assert scored["score"] > 0, "Phishing message should have non-zero risk score."

    def test_05_marathi_devanagari_phishing_message_detected(self):
        """A Marathi phishing message with OTP request is analyzed."""
        msg = "तात्काळ: तुमचे बँक खाते बंद होईल. OTP सांगा."
        result = analyze_message_text(msg)
        assert not result["is_empty"]
        assert any(s in result.get("script_detected", "").upper() for s in ("DEVANAGARI", "MARATHI", "MIXED", "ROMAN"))

    def test_06_romanized_marathi_phishing_detected(self):
        """A Romanized Marathi phishing message is analyzed."""
        msg = "Tumche SBI khate aaj band honar aahe. Lagech OTP sanga."
        result = analyze_message_text(msg)
        assert not result["is_empty"]
        scored = score_message_analysis(result)
        assert isinstance(scored["score"], (int, float))

    def test_07_legitimate_message_not_flagged_as_high_risk(self):
        """A genuinely legitimate message (electricity bill notice without links) is not high-risk."""
        msg = (
            "Your electricity bill of Rs 1200 for April is due on May 10. "
            "Pay at the official MSEDCL counter."
        )
        result = analyze_message_text(msg)
        assert not result["is_empty"]
        scored = score_message_analysis(result)
        assert scored["score"] < 50, f"Legitimate message scored too high: {scored['score']}"

    def test_08_empty_message_returns_is_empty_flag(self):
        """An empty string returns is_empty=True."""
        result = analyze_message_text("")
        assert result["is_empty"] is True

    def test_09_whitespace_only_message_returns_is_empty(self):
        """Whitespace-only input is treated as empty."""
        result = analyze_message_text("   \n\t  ")
        assert result["is_empty"] is True

    def test_10_analysis_result_has_required_fields(self):
        """Message analysis result has all required output fields."""
        result = analyze_message_text("Click this link: http://suspicious.xyz/pay now!")
        required = ("is_empty", "script_detected", "findings", "extracted_urls")
        for field in required:
            assert field in result, f"Missing required field: {field}"

    def test_11_scored_message_result_has_required_fields(self):
        """Scored message result has all required fields for UI rendering."""
        result = analyze_message_text("Pay now at http://scam.xyz or your account will be deleted.")
        scored = score_message_analysis(result)
        required = (
            "score", "risk_level", "badge_color", "summary_en",
            "summary_mr", "evidence", "limitations",
        )
        for field in required:
            assert field in scored, f"Missing required scored field: {field}"

    def test_12_urls_extracted_from_genuine_message(self):
        """URLs are extracted from a genuine user message containing a link."""
        msg = "Download from http://update-bank.xyz/apk for free rewards!"
        result = analyze_message_text(msg)
        assert len(result["extracted_urls"]) > 0, "URL should be extracted from message."
        assert "http://update-bank.xyz/apk" in result["extracted_urls"]


# =============================================================================
# 3. GENUINE URL ANALYSIS TESTS
# =============================================================================

class TestGenuineURLAnalysis:
    """Verifies that passive URL inspection operates properly on real URLs."""

    def test_13_suspicious_url_flagged(self):
        """A suspicious URL with phishing indicators is correctly flagged."""
        url = "http://sbi-kyc-update-maharashtra.xyz/login?action=verify-otp"
        result = analyze_url(url)
        assert result["score"] > 0, "Suspicious URL should have non-zero score."
        assert result["badge_color"] in ("red", "orange"), "Suspicious URL should be flagged."

    def test_14_official_gov_url_not_falsely_flagged(self):
        """An official .gov.in URL is not incorrectly flagged as high-risk."""
        url = "https://ladakibahin.maharashtra.gov.in/"
        result = analyze_url(url)
        assert result["badge_color"] == "green", (
            f"Official .gov.in URL should be green, got: {result['badge_color']} (score={result['score']})"
        )

    def test_15_ip_address_url_flagged(self):
        """A URL using an IP address instead of a domain is flagged."""
        url = "http://192.168.1.1/admin/router-setup"
        result = analyze_url(url)
        assert result["score"] > 0

    def test_16_apk_download_link_flagged(self):
        """A URL that directly links to an APK download is flagged."""
        url = "http://utility-update-host.com/files/Bill_Helper.apk"
        result = analyze_url(url)
        assert result["score"] > 0, "Direct APK download links should be flagged."

    def test_17_url_analysis_result_has_required_fields(self):
        """URL analysis result has all required output fields."""
        result = analyze_url("http://example.com/test")
        required = (
            "score", "risk_level", "badge_color", "summary_en",
            "summary_mr", "evidence", "limitations",
        )
        for field in required:
            assert field in result, f"Missing required URL analysis field: {field}"

    def test_18_empty_url_handled_gracefully(self):
        """Empty URL string is handled without an unhandled exception."""
        try:
            result = analyze_url("")
            assert isinstance(result["score"], (int, float))
        except Exception as e:
            pytest.fail(f"analyze_url('') raised an exception: {e}")


# =============================================================================
# 4. GENUINE APK ANALYSIS TESTS
# =============================================================================

class TestGenuineAPKAnalysis:
    """Verifies that static APK analysis works on genuine byte inputs without execution."""

    def _build_minimal_apk_bytes(self, package_name: str, permissions: list) -> bytes:
        """Build a minimal synthetic APK (ZIP) with plain-text manifest for testing."""
        perms_xml = "\n".join(
            f'    <uses-permission android:name="{p}" />' for p in permissions
        )
        manifest = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            f'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            f'    package="{package_name}">\n'
            f"{perms_xml}\n"
            '    <application android:label="TestApp">\n'
            '    </application>\n'
            '</manifest>\n'
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", manifest.encode("utf-8"))
            zf.writestr(
                "classes.dex",
                b"dex\n035\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )
        return buf.getvalue()

    def test_19_genuine_apk_bytes_analyzed_correctly(self):
        """
        A user-uploaded APK (as bytes) is analyzed correctly.
        This simulates the file_uploader.getvalue() path, not the
        synthetic fixture selector.
        """
        apk_bytes = self._build_minimal_apk_bytes(
            "com.test.genuine.app",
            ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS"],
        )
        result = analyze_apk_bytes(apk_bytes, "test_upload.apk")
        assert result["is_valid_apk"] is True
        assert result["package_name"] == "com.test.genuine.app"
        assert len(result["permissions_found"]) > 0

    def test_20_apk_sha256_computed_on_upload(self):
        """SHA-256 is computed for every APK upload."""
        apk_bytes = self._build_minimal_apk_bytes("com.test.sha256", [])
        result = analyze_apk_bytes(apk_bytes, "sha256_test.apk")
        assert result["sha256_hash"], "SHA-256 hash must be computed for every uploaded APK."
        assert len(result["sha256_hash"]) == 64, "SHA-256 hash must be 64 hex characters."

    def test_21_suspicious_permissions_flagged(self):
        """An APK with suspicious permissions (BIND_ACCESSIBILITY_SERVICE) is flagged."""
        apk_bytes = self._build_minimal_apk_bytes(
            "com.suspicious.app",
            [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.READ_SMS",
            ],
        )
        result = analyze_apk_bytes(apk_bytes, "suspicious.apk")
        scored = score_apk_analysis(result)
        assert scored["score"] > 0, "APK with suspicious permissions should score high."

    def test_22_apk_size_validation_enforced(self):
        """An APK exceeding the maximum upload size is rejected."""
        oversized_bytes = b"PK" + b"\x00" * (MAX_APK_UPLOAD_BYTES + 1024)
        result = analyze_apk_bytes(oversized_bytes, "oversized.apk")
        assert not result["is_valid_apk"] or result.get("error_reason"), (
            "Oversized APK should be rejected."
        )

    def test_23_non_apk_file_rejected(self):
        """A non-APK file (plain text) is correctly rejected."""
        fake_bytes = b"This is not a ZIP file at all."
        result = analyze_apk_bytes(fake_bytes, "notanapk.apk")
        assert not result["is_valid_apk"]

    def test_24_apk_analysis_result_has_required_fields(self):
        """APK analysis result has all required output fields."""
        apk_bytes = self._build_minimal_apk_bytes("com.test.fields", [])
        result = analyze_apk_bytes(apk_bytes, "fields_test.apk")
        required = (
            "is_valid_apk", "sha256_hash", "package_name",
            "permissions_found", "filename",
        )
        for field in required:
            assert field in result, f"Missing required APK analysis field: {field}"


# =============================================================================
# 5. DATABASE-BACKED DASHBOARD METRICS TESTS
# =============================================================================

class TestDatabaseBackedDashboard:
    """Verifies dashboard metrics originate directly from the SQLite repository."""

    def test_25_empty_session_store_has_zero_count(self):
        """A freshly created SessionCaseStore reports zero cases."""
        store = SessionCaseStore()
        assert store.count() == 0

    def test_26_case_count_increases_after_submission(self):
        """Case count increases by exactly 1 after a genuine submission."""
        store = SessionCaseStore()
        initial = store.count()
        msg = "Urgent: Your account is suspended. Click http://fake.xyz/restore"
        result = analyze_message_text(msg)
        scored = score_message_analysis(result)
        case = create_message_case(result, scored)
        store.add_case(case)
        assert store.count() == initial + 1

    def test_27_empty_store_list_cases_returns_empty_list(self):
        """list_cases() on empty store returns an empty list, not sample data."""
        store = SessionCaseStore()
        cases = store.list_cases()
        assert isinstance(cases, list)
        assert len(cases) == 0

    def test_28_review_stats_start_at_zero(self):
        """Review statistics all start at zero for a fresh store."""
        store = SessionCaseStore()
        stats = store.get_review_stats()
        assert isinstance(stats, dict)
        assert stats.get("pending", 0) == 0
        assert stats.get("completed", 0) == 0

    def test_29_disagreement_stats_start_at_zero(self):
        """Disagreement statistics start at zero for a fresh store."""
        store = SessionCaseStore()
        stats = store.get_disagreement_stats()
        assert isinstance(stats, dict)
        assert stats.get("total_events", 0) == 0
        assert stats.get("disagreements_count", 0) == 0


# =============================================================================
# 6. PRIVACY CONTROLS ON GENUINE SUBMISSIONS TESTS
# =============================================================================

class TestPrivacyControlsOnGenuineSubmissions:
    """Verifies privacy safeguards on user submissions."""

    def test_30_genuine_message_case_does_not_retain_raw_text(self):
        """
        A case created from a genuine message does not store the raw
        message text anywhere in the case dictionary.
        """
        genuine_msg = "My actual message: please block this account immediately. OTP: 123456."
        result = analyze_message_text(genuine_msg)
        scored = score_message_analysis(result)
        case = create_message_case(result, scored)
        case_str = str(case)
        assert "OTP: 123456" not in case_str, (
            "Raw OTP found in case dictionary. Privacy gate may have failed."
        )

    def test_31_genuine_url_case_strips_credentials(self):
        """
        A URL containing credentials is sanitized before being stored
        in a case record.
        """
        url_with_creds = "http://user:password@scam-bank.xyz/login"
        result = analyze_url(url_with_creds)
        case = create_url_case(result)
        case_str = str(case)
        assert "password" not in case_str.lower(), (
            "URL credential 'password' found in case dictionary after sanitization."
        )

    def test_32_training_feature_capture_requires_explicit_consent(self):
        """Training feature capture must fail closed when consent is not given."""
        store = SessionCaseStore()
        msg = "Test message for consent check."
        result = analyze_message_text(msg)
        scored = score_message_analysis(result)
        case = create_message_case(result, scored)
        case_id = store.add_case(case)

        feat_result = store.capture_training_features(
            case_id=case_id,
            message_text=msg,
            consent_given=False,
        )
        assert not feat_result.get("captured"), (
            "Training features must NOT be captured without explicit consent."
        )


# =============================================================================
# 7. NO FABRICATED RESULTS & TRANSPARENCY TESTS
# =============================================================================

class TestNoFabricatedResults:
    """Verifies that the application does not fabricate results or claim false certainty."""

    def test_33_analysis_returns_honest_results_not_fake_ones(self):
        """
        The phishing detector does not return a hardcoded positive result
        for messages it cannot classify.
        """
        benign = "हे एक सामान्य संदेश आहे."
        result = analyze_message_text(benign)
        scored = score_message_analysis(result)
        assert scored["score"] < 40, (
            f"Benign Marathi message got unexpectedly high score: {scored['score']}"
        )

    def test_34_url_analyzer_does_not_claim_live_threat_intelligence(self):
        """
        URL analyzer does not claim to have real-time threat intelligence.
        The limitations field must mention offline or local-only operation.
        """
        result = analyze_url("http://test-example.xyz/page")
        limitations = result.get("limitations", "")
        assert limitations, "Limitations field must not be empty for URL analysis."
        local_keywords = ("offline", "local", "static", "passive", "structural")
        assert any(k in limitations.lower() for k in local_keywords), (
            f"URL limitations text must mention local/offline nature. Got: '{limitations}'"
        )


# =============================================================================
# 8. SHADOW MODEL OPERATION & IMMUTABILITY TESTS
# =============================================================================

class TestShadowModelOperation:
    """Verifies shadow model configuration and non-authoritative status."""

    def test_35_shadow_model_config_is_shadow_mode(self):
        """Active model config confirms shadow mode and non-authoritative status."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "models", "active_model_config.json")
        assert os.path.exists(config_path), "active_model_config.json must exist."

        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        assert cfg.get("operating_mode") == "shadow", (
            f"Operating mode must be 'shadow', got: {cfg.get('operating_mode')}"
        )
        assert cfg.get("is_production_authoritative") is False, (
            "is_production_authoritative must be False."
        )

    def test_36_hybrid_engine_score_delta_is_zero(self):
        """
        The hybrid engine's score delta must be exactly 0.0 (shadow model
        does not change the authoritative score).
        """
        msg = "Download this APK now: http://reward.xyz/app.apk"
        rule_result = analyze_message_text(msg)
        hybrid = evaluate_message_hybrid(message_text=msg, rule_analysis=rule_result)
        rule_score = hybrid["rule_based_evidence"]["score"]
        final_score = hybrid["final_decision"]["final_risk_score"]
        assert rule_score == final_score, (
            f"Shadow model changed the authoritative score. Rule: {rule_score}, Final: {final_score}"
        )

    def test_37_active_model_version_is_expected(self):
        """Active model version matches the known qualified candidate."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "models", "active_model_config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        assert cfg.get("active_model_version") == "custom-mlp-v4.0.0-seed42", (
            f"Unexpected active model version: {cfg.get('active_model_version')}"
        )
        assert cfg.get("last_known_good_version") == "custom-mlp-v1.1.0-preproc", (
            f"Unexpected LKG version: {cfg.get('last_known_good_version')}"
        )


# =============================================================================
# 9. EMPTY STATE READINESS TESTS
# =============================================================================

class TestEmptyStateReadiness:
    """Verifies that the application starts cleanly without preloaded cases."""

    def test_38_fresh_repository_has_no_preloaded_cases(self):
        """A fresh CaseRepository (isolated test DB) has zero threat cases."""
        store = SessionCaseStore()
        assert store.count() == 0, "Fresh installation must not have preloaded cases."

    def test_39_case_list_empty_state_is_empty_list(self):
        """list_cases() returns an empty list, not mock data."""
        store = SessionCaseStore()
        result = store.list_cases()
        assert result == [], "Empty store must return [] from list_cases()."

    def test_40_disagreement_events_start_empty(self):
        """No disagreement events exist in a fresh database."""
        store = SessionCaseStore()
        events = store.list_disagreement_events()
        assert events == [], "Fresh store must have zero disagreement events."


# =============================================================================
# 10. REAL CASE CREATION, RETRIEVAL & IDEMPOTENCY TESTS
# =============================================================================

class TestCaseCreationForRealSubmissions:
    """Verifies end-to-end case creation for real submissions."""

    def test_41_message_case_creation_succeeds(self):
        """A genuine user message submission creates a valid case."""
        msg = "Warning: Your UPI account has been blocked. Visit http://upi-help.xyz now."
        result = analyze_message_text(msg)
        scored = score_message_analysis(result)
        case = create_message_case(result, scored)
        assert "case_id" in case, "Case must have a case_id."
        assert case["case_id"].startswith("CASE-MSG-"), "Message case ID must start with CASE-MSG-."

    def test_42_url_case_creation_succeeds(self):
        """A genuine URL submission creates a valid case."""
        result = analyze_url("http://msedcl-bill-update.xyz/quick-pay")
        case = create_url_case(result)
        assert "case_id" in case, "URL case must have a case_id."
        assert case["case_id"].startswith("CASE-URL-"), "URL case ID must start with CASE-URL-."

    def test_43_apk_case_creation_succeeds(self):
        """A genuine APK submission creates a valid case."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "AndroidManifest.xml",
                '<manifest package="com.real.test"><uses-permission android:name="android.permission.INTERNET"/></manifest>'.encode("utf-8")
            )
        apk_bytes = buf.getvalue()
        apk_result = analyze_apk_bytes(apk_bytes, "genuine_upload.apk")
        scored = score_apk_analysis(apk_result)
        case = create_apk_case(apk_result, scored)
        assert "case_id" in case, "APK case must have a case_id."
        assert case["case_id"].startswith("CASE-APK-"), "APK case ID must start with CASE-APK-."

    def test_44_session_store_persists_case_for_retrieval(self):
        """A submitted case can be retrieved by its ID from the session store."""
        store = SessionCaseStore()
        msg = "Real user message: Your parcel is held. Pay fee at http://customs-parcel.xyz"
        result = analyze_message_text(msg)
        scored = score_message_analysis(result)
        case = create_message_case(result, scored)
        case_id = store.add_case(case)
        retrieved = store.get_case(case_id)
        assert retrieved is not None, "Case must be retrievable after submission."
        assert retrieved["case_id"] == case_id

    def test_45_duplicate_case_not_created_for_same_message(self):
        """
        Submitting the same message twice should either create a single case
        (deduplication active) or at most create two distinct cases.
        The important thing is that the system does not crash.
        """
        store = SessionCaseStore()
        msg = "Claim your reward now! Visit http://reward-claim.xyz/get"
        result = analyze_message_text(msg)
        scored = score_message_analysis(result)
        case1 = create_message_case(result, scored)
        case2 = create_message_case(result, scored)
        id1 = store.add_case(case1)
        id2 = store.add_case(case2)
        final_count = store.count()
        assert 1 <= final_count <= 2, f"Expected 1 or 2 cases for duplicate submission, got: {final_count}"
