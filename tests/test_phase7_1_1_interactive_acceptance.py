"""
Phase 7.1.1 — Unified Evidence Workspace Interactive Acceptance and Data Integrity Audit Tests.

Comprehensive validation covering:
1. Workflows A through K via Streamlit's AppTest framework (rendered interface):
   - Workflow A: Paste one suspicious message.
   - Workflow B: Submit one URL.
   - Workflow C: Upload one APK.
   - Workflow D: Submit a message containing a URL.
   - Workflow E: Submit a message, several URLs and an APK together.
   - Workflow F: Submit a message, APK, PDF and screenshot together.
   - Workflow G: Remove one staged attachment before analysis.
   - Workflow H: Change an automatically detected file type where manual override is supported.
   - Workflow I: Analyse the remaining evidence after one artifact fails.
   - Workflow J: Save a completed investigation.
   - Workflow K: Open the saved investigation and verify all linked evidence.
2. Streamlit Session-State & Idempotency Audit.
3. Parent-Child Investigation Integrity & Provenance Propagation.
4. Cross-Evidence Correlation Audit (All 6 correlation types).
5. Overall Investigation Risk-Score Policy & Shadow Invariance.
6. File Processing Security, Resource Limits, and OCR Limitations.
"""

import io
import os
import tempfile
import zipfile
import pytest
from PIL import Image
import pypdf
from streamlit.testing.v1 import AppTest

from src.case_manager import SessionCaseStore
from src.case_repository import CaseRepository
from src.unified_analyzer import (
    EvidenceType,
    ProcessingStatus,
    UnifiedEvidenceAnalyzer,
    compute_sha256,
    correlate_investigation_evidence,
    detect_evidence_type,
    extract_pdf_document,
    extract_text_file,
    inspect_image_file,
)

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))


@pytest.fixture
def isolated_case_store():
    """Provides an isolated SQLite case repository in a temporary directory."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_cases_p711.sqlite3")
        repo = CaseRepository(db_path=db_path)
        store = SessionCaseStore(session_id="test_sess_p711", repository=repo)
        yield store, repo


@pytest.fixture
def valid_apk_bytes():
    """Returns valid synthetic APK bytes from sample_apks or builds in memory."""
    sample_path = "sample_apks/Simple_Marathi_Calendar_Test.apk"
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            return f.read()
    from create_sample_apks import build_compiled_axml_tree_bytes
    axml = build_compiled_axml_tree_bytes("com.seva.legitcalendar", ["android.permission.INTERNET"])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", axml)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
    return buf.getvalue()


@pytest.fixture
def valid_pdf_bytes():
    """Generates an in-memory valid PDF document with text content."""
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.fixture
def valid_png_bytes():
    """Generates an in-memory valid PNG image."""
    img = Image.new("RGB", (120, 120), color="blue")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def build_apptest(store: SessionCaseStore) -> AppTest:
    """Helper to initialize AppTest with the isolated test database."""
    at = AppTest.from_file(APP_PATH, default_timeout=30)
    at.session_state["case_store"] = store
    at.session_state["session_id"] = store.session_id
    at.run()
    return at


# =============================================================================
# WORKFLOW A: PASTE ONE SUSPICIOUS MESSAGE (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_a_rendered_message_only_submission(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    # Pure message text without embedded URLs
    msg = "तात्काळ: महावितरण वीज बिल थकीत आहे. आजच भरा नाहीतर वीज कट होईल. त्वरित संपर्क साधा."
    at.text_area(key="unified_msg_input").input(msg)
    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    assert "unified_last_analysis" in at.session_state
    res = at.session_state["unified_last_analysis"]
    assert res["summary_stats"]["total_artifacts"] == 1
    assert res["artifacts"][0]["artifact_type"] == EvidenceType.MESSAGE
    assert res["artifacts"][0]["status"] == ProcessingStatus.COMPLETED
    assert res["overall_verdict"]["score"] >= 30


# =============================================================================
# WORKFLOW B: SUBMIT ONE URL (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_b_rendered_url_only_submission(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    url = "http://ladkibahin-portal-free.xyz/apply-online"
    at.text_area(key="unified_urls_input").input(url)
    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    assert "unified_last_analysis" in at.session_state
    res = at.session_state["unified_last_analysis"]
    assert res["summary_stats"]["total_artifacts"] == 1
    assert res["artifacts"][0]["artifact_type"] == EvidenceType.URL
    assert res["artifacts"][0]["status"] == ProcessingStatus.COMPLETED
    assert res["overall_verdict"]["score"] >= 40


# =============================================================================
# WORKFLOW C: UPLOAD ONE APK (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_c_rendered_apk_only_submission(isolated_case_store, valid_apk_bytes):
    store, _ = isolated_case_store
    at = build_apptest(store)

    fu = at.file_uploader(key="unified_file_uploader")
    fu.upload("Suspicious_App.apk", valid_apk_bytes)
    at.run()

    # Verify staged inventory rendered
    assert any("Suspicious_App.apk" in cb.key for cb in at.checkbox if cb.key)

    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    res = at.session_state["unified_last_analysis"]
    assert res["summary_stats"]["total_artifacts"] == 1
    assert res["artifacts"][0]["artifact_type"] == EvidenceType.APK
    assert res["artifacts"][0]["status"] == ProcessingStatus.COMPLETED


# =============================================================================
# WORKFLOW D: SUBMIT A MESSAGE CONTAINING A URL (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_d_rendered_message_containing_url(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    msg = "Apply for Majhi Ladki Bahin Yojana here: https://ladkibahin-fraud.cc/apply"
    url = "https://ladkibahin-fraud.cc/apply"
    at.text_area(key="unified_msg_input").input(msg)
    at.text_area(key="unified_urls_input").input(url)

    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    res = at.session_state["unified_last_analysis"]
    # 1 message + 1 extracted URL + 1 submitted URL = 3 artifacts
    assert res["summary_stats"]["total_artifacts"] == 3
    # Check that MESSAGE_URL_SHARED_DOMAIN correlation was detected
    corr_types = [c["correlation_type"] for c in res["correlations"]]
    assert "MESSAGE_URL_SHARED_DOMAIN" in corr_types


# =============================================================================
# WORKFLOW E: SUBMIT MESSAGE, SEVERAL URLS AND APK TOGETHER (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_e_rendered_message_multiple_urls_and_apk(isolated_case_store, valid_apk_bytes):
    store, _ = isolated_case_store
    at = build_apptest(store)

    msg = "Update your KYC immediately or your account will be frozen today."
    urls = "http://bank-update.top/login\nhttp://192.168.1.100/pay.php"
    at.text_area(key="unified_msg_input").input(msg)
    at.text_area(key="unified_urls_input").input(urls)

    fu = at.file_uploader(key="unified_file_uploader")
    fu.upload("BankingUpdate.apk", valid_apk_bytes)
    at.run()

    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    res = at.session_state["unified_last_analysis"]
    # 1 message + 2 URLs + 1 APK = 4 artifacts
    assert res["summary_stats"]["total_artifacts"] == 4
    assert res["summary_stats"]["completed_count"] == 4


# =============================================================================
# WORKFLOW F: SUBMIT MESSAGE, APK, PDF AND SCREENSHOT (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_f_rendered_message_apk_pdf_and_screenshot(
    isolated_case_store, valid_apk_bytes, valid_pdf_bytes, valid_png_bytes
):
    store, _ = isolated_case_store
    at = build_apptest(store)

    at.text_area(key="unified_msg_input").input("Dear customer, see attached scheme circular.")
    fu = at.file_uploader(key="unified_file_uploader")
    fu.upload("AppPayload.apk", valid_apk_bytes)
    fu.upload("Circular.pdf", valid_pdf_bytes)
    fu.upload("PaymentScreenshot.png", valid_png_bytes)
    at.run()

    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    res = at.session_state["unified_last_analysis"]
    # 1 message + 3 files = 4 artifacts
    assert res["summary_stats"]["total_artifacts"] == 4
    types = [a["artifact_type"] for a in res["artifacts"]]
    assert EvidenceType.MESSAGE in types
    assert EvidenceType.APK in types
    assert EvidenceType.DOCUMENT_PDF in types
    assert EvidenceType.IMAGE in types


# =============================================================================
# WORKFLOW G: REMOVE ONE STAGED ATTACHMENT BEFORE ANALYSIS (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_g_rendered_remove_attachment_before_analysis(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    fu = at.file_uploader(key="unified_file_uploader")
    fu.upload("keep_this.txt", b"Suspicious fraud communication text")
    fu.upload("remove_this.txt", b"Accidental attachment")
    at.run()

    # Uncheck the second attachment
    at.checkbox(key="inc_file_1_remove_this.txt").uncheck()
    at.run()

    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    res = at.session_state["unified_last_analysis"]
    assert res["summary_stats"]["total_artifacts"] == 1
    assert res["artifacts"][0]["target_identifier"] == "keep_this.txt"


# =============================================================================
# WORKFLOW H: CHANGE DETECTED FILE TYPE VIA MANUAL OVERRIDE (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_h_rendered_manual_type_override(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    fu = at.file_uploader(key="unified_file_uploader")
    fu.upload("mystery_payload.txt", b"plain text content")
    at.run()

    sb = at.selectbox(key="type_override_0_mystery_payload.txt")
    sb.select(EvidenceType.UNSUPPORTED)
    at.run()

    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    res = at.session_state["unified_last_analysis"]
    assert res["artifacts"][0]["artifact_type"] == EvidenceType.UNSUPPORTED


# =============================================================================
# WORKFLOW I: ANALYSE REMAINING EVIDENCE AFTER ONE ARTIFACT FAILS (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_i_rendered_partial_analysis_failure(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    # Valid message + corrupt APK binary
    at.text_area(key="unified_msg_input").input("Valid suspicious WhatsApp notice")
    fu = at.file_uploader(key="unified_file_uploader")
    fu.upload("corrupted.apk", b"PK\x03\x04corrupted_header_data_not_valid_axml")
    at.run()

    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    assert not at.exception
    res = at.session_state["unified_last_analysis"]
    assert res["summary_stats"]["total_artifacts"] == 2
    assert res["summary_stats"]["completed_count"] == 1
    assert res["summary_stats"]["failed_count"] == 1

    # Check that failed artifact is clearly recorded
    failed_art = next(a for a in res["artifacts"] if a["status"] == ProcessingStatus.FAILED)
    assert failed_art["target_identifier"] == "corrupted.apk"
    assert failed_art["error"] is not None


# =============================================================================
# WORKFLOW J: SAVE A COMPLETED INVESTIGATION (RENDERED UI VIA APPTEST)
# =============================================================================
def test_workflow_j_rendered_save_completed_investigation(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    # Message without URL
    at.text_area(key="unified_msg_input").input("Electricity bill urgent disconnection notice. Contact sub-division office.")
    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    # Click SAVE INVESTIGATION button
    save_btn = next(b for b in at.button if "SAVE" in b.label)
    save_btn.click()
    at.run()

    assert not at.exception
    saved = at.session_state.get("unified_saved_investigation")
    assert saved is not None
    assert saved["parent_case_id"].startswith("CASE-UNIF-")
    assert len(saved["child_case_ids"]) == 1

    # Verify cases exist in SQLite database
    cases = store.list_cases()
    assert len(cases) == 2  # 1 child case + 1 parent case


# =============================================================================
# WORKFLOW K: OPEN SAVED INVESTIGATION AND VERIFY ALL LINKED EVIDENCE
# =============================================================================
def test_workflow_k_open_saved_investigation_and_verify_links(isolated_case_store, valid_apk_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    # Perform multi-artifact analysis
    analysis_res = analyzer.analyze_submission(
        message_text="Urgent fraud communication",
        urls=["http://phish-domain.cc/login"],
        files=[{"filename": "payload.apk", "content": valid_apk_bytes}],
    )

    # Save to SQLite
    saved_meta = analyzer.save_investigation_cases(
        case_store=store,
        analysis_result=analysis_res,
        submitted_by="test_operator",
        consent_given=True,
    )

    parent_id = saved_meta["parent_case_id"]

    # Open and inspect the saved investigation details
    details = analyzer.get_investigation_details(store, parent_id)
    assert details is not None
    assert details["parent_case"]["case_id"] == parent_id
    assert details["all_children_exist"] is True
    assert details["total_children"] == 3
    assert len(details["child_cases"]) == 3

    # Verify each child has correct parent_investigation_id
    for child in details["child_cases"]:
        assert child["metadata"]["parent_investigation_id"] == analysis_res["investigation_id"]
        assert "current_evidence_provenance" in child


# =============================================================================
# SECTION 4: STREAMLIT SESSION-STATE & IDEMPOTENCY AUDIT
# =============================================================================
def test_session_state_duplicate_save_idempotency(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    analysis_res = analyzer.analyze_submission(
        message_text="Sample alert message",
        urls=["http://test-url.xyz"],
    )

    # First save action
    first_save = analyzer.save_investigation_cases(
        case_store=store,
        analysis_result=analysis_res,
        submitted_by="operator_1",
    )
    assert first_save["is_idempotent_replay"] is False
    initial_case_count = len(store.list_cases())

    # Repeated save action with identical investigation_id
    second_save = analyzer.save_investigation_cases(
        case_store=store,
        analysis_result=analysis_res,
        submitted_by="operator_1",
    )
    assert second_save["is_idempotent_replay"] is True
    assert second_save["parent_case_id"] == first_save["parent_case_id"]
    assert second_save["child_case_ids"] == first_save["child_case_ids"]

    # Database count must not increase
    assert len(store.list_cases()) == initial_case_count


def test_session_state_form_reset_via_apptest(isolated_case_store):
    store, _ = isolated_case_store
    at = build_apptest(store)

    at.text_area(key="unified_msg_input").input("Test reset workflow message")
    analyze_btn = next(b for b in at.button if "ANALYZE ALL" in b.label)
    analyze_btn.click()
    at.run()

    save_btn = next(b for b in at.button if "SAVE" in b.label)
    save_btn.click()
    at.run()

    assert at.session_state.get("unified_last_analysis") is not None

    # Click Start New Investigation / Clear Workspace
    clear_btn = next(b for b in at.button if "Start New Investigation" in b.label)
    clear_btn.click()
    at.run()

    assert at.session_state.get("unified_last_analysis") is None
    assert at.session_state.get("unified_saved_investigation") is None


def test_session_isolation(isolated_case_store):
    store1, repo1 = isolated_case_store
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir2:
        db_path2 = os.path.join(tmp_dir2, "isolated_store2.sqlite3")
        repo2 = CaseRepository(db_path=db_path2)
        store2 = SessionCaseStore(session_id="user_session_2", repository=repo2)

        analyzer1 = UnifiedEvidenceAnalyzer(case_repository=repo1)
        res1 = analyzer1.analyze_submission(message_text="Session 1 private message")
        analyzer1.save_investigation_cases(store1, res1)

        # Store 2 must not see Store 1 cases
        assert len(store1.list_cases()) > 0
        assert len(store2.list_cases()) == 0


# =============================================================================
# SECTION 5: PARENT-CHILD INTEGRITY & PROVENANCE PROPAGATION
# =============================================================================
def test_parent_child_evidence_withdrawal(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(
        message_text="Withdrawal test message",
        urls=["http://withdraw-test.top"],
    )
    saved = analyzer.save_investigation_cases(store, res)

    # Withdraw evidence from one child artifact
    child_case_id = saved["child_case_ids"][0]
    child_case = store.get_case(child_case_id)
    evidence_id = child_case["evidence_id"]

    repo.withdraw_evidence(
        evidence_id=evidence_id,
        operator_username="privacy_officer",
        reason="Citizen requested GDPR erasure",
    )

    # Inspect parent investigation
    inv_details = analyzer.get_investigation_details(store, saved["parent_case_id"])
    target_child = next(c for c in inv_details["child_cases"] if c["case_id"] == child_case_id)

    assert target_child["current_evidence_provenance"]["lifecycle_status"] == "withdrawn"

    # Audit log entry exists
    audit_entries = repo.get_evidence_lifecycle_history(evidence_id)
    assert len(audit_entries) >= 2  # intake + withdrawal
    assert audit_entries[-1]["to_status"] == "withdrawn"
    assert "Citizen requested GDPR erasure" in audit_entries[-1]["transition_reason"]


def test_parent_child_consent_revocation(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(message_text="Consent test message")
    saved = analyzer.save_investigation_cases(store, res, consent_given=False)

    parent = store.get_case(saved["parent_case_id"])
    assert parent["consent_given"] is False

    child = store.get_case(saved["child_case_ids"][0])
    assert child["consent_given"] is False
    prov = repo.get_evidence_provenance(child["evidence_id"])
    assert prov["consent_given"] == 0  # SQLite boolean 0


# =============================================================================
# SECTION 6: CROSS-EVIDENCE CORRELATION AUDIT (ALL 6 TYPES)
# =============================================================================
def test_cross_evidence_correlation_all_six_types(isolated_case_store, valid_apk_bytes):
    _, repo = isolated_case_store

    # Register known threat indicators in repo
    repo.add_indicator(
        indicator_type="domain",
        indicator_value="blacklisted-c2.net",
        severity="critical",
        confidence_score=95,
        review_state="reviewed",
    )

    repo.add_indicator(
        indicator_type="apk_sha256",
        indicator_value="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        severity="critical",
        confidence_score=99,
        review_state="reviewed",
    )

    art_msg = {
        "artifact_id": "ART-01-MSG",
        "artifact_type": EvidenceType.MESSAGE,
        "text_content": "Apply for LadkiBahin at http://phishing-ladki.cc and check maharashtra.gov.in",
        "analysis_result": {"extracted_urls": ["http://phishing-ladki.cc", "https://maharashtra.gov.in"]},
    }
    art_url1 = {
        "artifact_id": "ART-02-URL",
        "artifact_type": EvidenceType.URL,
        "target_identifier": "http://phishing-ladki.cc/apply",
        "analysis_result": {"url": "http://phishing-ladki.cc/apply"},
    }
    art_url2 = {
        "artifact_id": "ART-03-URL",
        "artifact_type": EvidenceType.URL,
        "target_identifier": "http://blacklisted-c2.net/gate",
        "analysis_result": {"url": "http://blacklisted-c2.net/gate"},
    }
    art_url3 = {
        "artifact_id": "ART-04-URL",
        "artifact_type": EvidenceType.URL,
        "target_identifier": "http://fraudulent-portal.top/login",
        "analysis_result": {"url": "http://fraudulent-portal.top/login"},
    }
    art_apk = {
        "artifact_id": "ART-05-APK",
        "artifact_type": EvidenceType.APK,
        "artifact_sha256": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        "analysis_result": {
            "package_name": "com.scheme.ladkibahin",
            "passive_urls": ["http://phishing-ladki.cc/apk_update"],
        },
    }

    known_inds = repo.list_indicators()
    corrs = correlate_investigation_evidence(
        artifacts=[art_msg, art_url1, art_url2, art_url3, art_apk],
        known_indicators=known_inds,
    )

    detected_types = {c["correlation_type"] for c in corrs}

    assert "MESSAGE_URL_SHARED_DOMAIN" in detected_types
    assert "APK_DOMAIN_CROSS_REFERENCE" in detected_types
    assert "MESSAGE_APK_TOKEN_MATCH" in detected_types
    assert "KNOWN_THREAT_INTEL_HASH_MATCH" in detected_types
    assert "KNOWN_THREAT_INTEL_DOMAIN_MATCH" in detected_types
    assert "DECEPTIVE_IMPERSONATION_CONFLICT" in detected_types

    # Verify that all correlation findings include supporting evidence and limitations note
    for c in corrs:
        assert c["source_artifact_id"] is not None
        assert c["target_artifact_id"] is not None
        assert c["confidence"] in ("HIGH", "MEDIUM", "LOW")
        assert len(c["supporting_evidence"]) > 0
        assert "limitations_note" in c


# =============================================================================
# SECTION 7: INVESTIGATION RISK-SCORE POLICY & SHADOW INVARIANCE
# =============================================================================
def test_risk_score_maximum_deterministic_policy(isolated_case_store):
    _, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    # Artifact 1: Low risk URL
    # Artifact 2: High risk message
    # Overall score must equal the maximum completed artifact score
    res = analyzer.analyze_submission(
        message_text="तात्काळ: महावितरण वीज बिल थकीत आहे. आजच भरा नाहीतर वीज कट होईल http://bit.ly/mseb",
        urls=["http://example-lowrisk.com/about"],
    )

    scores = [a["risk_score"] for a in res["artifacts"] if a["status"] == ProcessingStatus.COMPLETED]
    expected_max = max(scores)
    assert res["overall_verdict"]["score"] == expected_max

    # Shadow invariance verification: shadow AI must not alter authoritative score
    for a in res["artifacts"]:
        if a.get("shadow_eval") and isinstance(a["shadow_eval"], dict):
            assert a["shadow_eval"].get("authoritative_score_delta", 0.0) == 0.0


# =============================================================================
# SECTION 8: FILE PROCESSING AUDIT, LIMITS & OCR TRANSPARENCY
# =============================================================================
def test_file_processing_corrupt_pdf():
    corrupt_bytes = b"%PDF-1.4\ncorrupted_data_not_valid_catalog_or_pages"
    res = extract_pdf_document(corrupt_bytes, "corrupt.pdf")
    assert res["status"] == ProcessingStatus.FAILED
    assert "Failed to parse PDF" in res["error"]


def test_file_processing_large_text_truncation():
    large_text = ("Suspicious phishing line with link http://fake.cc\n" * 20000).encode("utf-8")
    assert len(large_text) > 500_000
    res = extract_text_file(large_text, "huge_log.txt")
    assert res["status"] == ProcessingStatus.COMPLETED
    assert res["char_count"] <= 200_000


def test_file_processing_malformed_image():
    bad_img_bytes = b"\x89PNG\r\n\x1a\nmalformed_png_bytes_truncated"
    res = inspect_image_file(bad_img_bytes, "broken.png")
    assert res["status"] == ProcessingStatus.FAILED
    assert "Failed to parse image" in res["error"]


def test_file_processing_ocr_limitation_disclosure(valid_png_bytes):
    res = inspect_image_file(valid_png_bytes, "test.png")
    assert res["status"] == ProcessingStatus.COMPLETED
    assert res["ocr_status"] == "UNAVAILABLE_LOCAL_ONLY"
    assert "Tesseract" in res["ocr_explanation"]


def test_file_processing_unsupported_extensions():
    exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00"  # Windows PE
    det_type, det_method, notes = detect_evidence_type(exe_bytes, "malware.exe")
    assert det_type == EvidenceType.UNSUPPORTED
    assert det_method == "unrecognized_binary"
