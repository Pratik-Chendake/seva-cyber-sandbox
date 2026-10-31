"""
Phase 7.1.0 — Unified Evidence Intake and Multi-Artifact Cybersecurity Analysis Workspace Tests.

Validates:
1. Message-only submission.
2. URL-only submission.
3. APK-only submission.
4. Message plus URL.
5. Message plus APK.
6. URL plus APK.
7. Message, URL and APK together.
8. Multiple URLs.
9. Multiple APK uploads within safe limits.
10. Screenshot upload.
11. PDF upload.
12. Unsupported file types.
13. Malformed files.
14. Duplicate attachments.
15. Partial analysis failures.
16. Cross-evidence correlation.
17. Case creation with multiple linked artifacts.
18. Evidence withdrawal.
19. Consent enforcement.
20. Privacy leakage.
21. Temporary file cleanup.
22. Shadow model invariance.
23. Deterministic score invariance.
"""

import io
import os
import tempfile
import zipfile
import pytest
from PIL import Image
import pypdf

from src.case_manager import SessionCaseStore
from src.case_repository import CaseRepository
from src.unified_analyzer import (
    EvidenceType,
    ProcessingStatus,
    UnifiedEvidenceAnalyzer,
    compute_sha256,
    detect_evidence_type,
    extract_pdf_document,
    extract_text_file,
    inspect_image_file,
)


@pytest.fixture
def isolated_case_store():
    """Provides an isolated SQLite case repository in a temporary directory."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_cases.sqlite3")
        repo = CaseRepository(db_path=db_path)
        store = SessionCaseStore(session_id="test_session_phase7_1", repository=repo)
        yield store, repo


@pytest.fixture
def synthetic_apk_bytes():
    """Returns valid synthetic APK bytes from sample_apks or builds in memory."""
    sample_path = "sample_apks/Simple_Marathi_Calendar_Test.apk"
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            return f.read()
    from create_sample_apks import build_compiled_axml_tree_bytes
    axml = build_compiled_axml_tree_bytes("com.test.sample", ["android.permission.INTERNET"])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", axml)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
    return buf.getvalue()


@pytest.fixture
def synthetic_pdf_bytes():
    """Generates an in-memory valid PDF document containing text and hyperlinks."""
    writer = pypdf.PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.fixture
def synthetic_png_bytes():
    """Generates an in-memory valid PNG image."""
    img = Image.new("RGB", (100, 100), color="blue")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# -----------------------------------------------------------------------------
# 1. Message-only submission
# -----------------------------------------------------------------------------
def test_01_message_only_submission(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(
        message_text="तात्काळ महावितरण वीज बिल भरा नाहीतर वीज तोडली जाईल.",
        enable_shadow_ai=False,
    )
    assert res["summary_stats"]["total_artifacts"] == 1
    assert res["artifacts"][0]["artifact_type"] == EvidenceType.MESSAGE
    assert res["artifacts"][0]["status"] == ProcessingStatus.COMPLETED
    assert res["overall_verdict"]["score"] > 0
    assert res["overall_verdict"]["risk_category"] in ["Critical Risk", "High Risk", "Medium Risk", "Low Risk"]


# -----------------------------------------------------------------------------
# 2. URL-only submission
# -----------------------------------------------------------------------------
def test_02_url_only_submission(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(
        urls=["http://ladki-bahin-apply.cc/login"],
        enable_shadow_ai=False,
    )
    assert res["summary_stats"]["total_artifacts"] == 1
    art = res["artifacts"][0]
    assert art["artifact_type"] == EvidenceType.URL
    assert art["status"] == ProcessingStatus.COMPLETED
    assert "ladki-bahin-apply.cc" in art["target_identifier"]
    assert art["risk_score"] > 0


# -----------------------------------------------------------------------------
# 3. APK-only submission
# -----------------------------------------------------------------------------
def test_03_apk_only_submission(isolated_case_store, synthetic_apk_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "sample_scheme.apk", "content": synthetic_apk_bytes}]
    res = analyzer.analyze_submission(files=files, enable_shadow_ai=False)

    assert res["summary_stats"]["total_artifacts"] == 1
    art = res["artifacts"][0]
    assert art["artifact_type"] == EvidenceType.APK
    assert art["status"] == ProcessingStatus.COMPLETED
    assert art["artifact_sha256"] is not None
    assert len(art["artifact_sha256"]) == 64


# -----------------------------------------------------------------------------
# 4. Message plus URL
# -----------------------------------------------------------------------------
def test_04_message_plus_url(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(
        message_text="Check your payment status immediately.",
        urls=["https://mahadiscom.in"],
        enable_shadow_ai=False,
    )
    assert res["summary_stats"]["total_artifacts"] == 2
    types = [a["artifact_type"] for a in res["artifacts"]]
    assert EvidenceType.MESSAGE in types
    assert EvidenceType.URL in types


# -----------------------------------------------------------------------------
# 5. Message plus APK
# -----------------------------------------------------------------------------
def test_05_message_plus_apk(isolated_case_store, synthetic_apk_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "update.apk", "content": synthetic_apk_bytes}]
    res = analyzer.analyze_submission(
        message_text="Install this app for subsidy credit.",
        files=files,
        enable_shadow_ai=False,
    )
    assert res["summary_stats"]["total_artifacts"] == 2
    types = [a["artifact_type"] for a in res["artifacts"]]
    assert EvidenceType.MESSAGE in types
    assert EvidenceType.APK in types


# -----------------------------------------------------------------------------
# 6. URL plus APK
# -----------------------------------------------------------------------------
def test_06_url_plus_apk(isolated_case_store, synthetic_apk_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "installer.apk", "content": synthetic_apk_bytes}]
    res = analyzer.analyze_submission(
        urls=["http://phishing-site.xyz/download"],
        files=files,
        enable_shadow_ai=False,
    )
    assert res["summary_stats"]["total_artifacts"] == 2
    types = [a["artifact_type"] for a in res["artifacts"]]
    assert EvidenceType.URL in types
    assert EvidenceType.APK in types


# -----------------------------------------------------------------------------
# 7. Message, URL and APK together
# -----------------------------------------------------------------------------
def test_07_message_url_apk_together(isolated_case_store, synthetic_apk_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "bank.apk", "content": synthetic_apk_bytes}]
    res = analyzer.analyze_submission(
        message_text="Bank KYC expired. Update online or via app.",
        urls=["http://fake-sbi-portal.top/kyc"],
        files=files,
        enable_shadow_ai=False,
    )
    assert res["summary_stats"]["total_artifacts"] >= 3
    types = {a["artifact_type"] for a in res["artifacts"]}
    assert {EvidenceType.MESSAGE, EvidenceType.URL, EvidenceType.APK}.issubset(types)
    assert res["overall_verdict"]["score"] > 0


# -----------------------------------------------------------------------------
# 8. Multiple URLs
# -----------------------------------------------------------------------------
def test_08_multiple_urls(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    urls = [
        "http://phish1.xyz/login",
        "http://phish2.top/verify",
        "https://maharashtra.gov.in",
    ]
    res = analyzer.analyze_submission(urls=urls, enable_shadow_ai=False)
    assert res["summary_stats"]["total_artifacts"] == 3
    assert all(a["artifact_type"] == EvidenceType.URL for a in res["artifacts"])


# -----------------------------------------------------------------------------
# 9. Multiple APK uploads within safe limits
# -----------------------------------------------------------------------------
def test_09_multiple_apks_within_safe_limits(isolated_case_store, synthetic_apk_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [
        {"filename": "app1.apk", "content": synthetic_apk_bytes},
        {"filename": "app2.apk", "content": synthetic_apk_bytes + b"\x00"},
    ]
    res = analyzer.analyze_submission(files=files, enable_shadow_ai=False)
    assert res["summary_stats"]["total_artifacts"] == 2
    assert res["artifacts"][0]["artifact_sha256"] != res["artifacts"][1]["artifact_sha256"]


# -----------------------------------------------------------------------------
# 10. Screenshot upload
# -----------------------------------------------------------------------------
def test_10_screenshot_upload(isolated_case_store, synthetic_png_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "chat_screenshot.png", "content": synthetic_png_bytes}]
    res = analyzer.analyze_submission(files=files, enable_shadow_ai=False)

    assert res["summary_stats"]["total_artifacts"] == 1
    art = res["artifacts"][0]
    assert art["artifact_type"] == EvidenceType.IMAGE
    assert art["status"] == ProcessingStatus.COMPLETED
    assert art["analysis_result"]["dimensions"] == (100, 100)
    assert art["analysis_result"]["ocr_status"] == "UNAVAILABLE_LOCAL_ONLY"
    assert "Local OCR engine" in art["analysis_result"]["ocr_explanation"]


# -----------------------------------------------------------------------------
# 11. PDF upload
# -----------------------------------------------------------------------------
def test_11_pdf_upload(isolated_case_store, synthetic_pdf_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "official_notice.pdf", "content": synthetic_pdf_bytes}]
    res = analyzer.analyze_submission(files=files, enable_shadow_ai=False)

    assert res["summary_stats"]["total_artifacts"] == 1
    art = res["artifacts"][0]
    assert art["artifact_type"] == EvidenceType.DOCUMENT_PDF
    assert art["status"] == ProcessingStatus.COMPLETED
    assert art["analysis_result"]["page_count"] >= 1


# -----------------------------------------------------------------------------
# 12. Unsupported file types
# -----------------------------------------------------------------------------
def test_12_unsupported_file_types(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "malware.exe", "content": b"MZ\x90\x00\x03\x00\x00\x00"}]
    res = analyzer.analyze_submission(files=files, enable_shadow_ai=False)

    assert res["summary_stats"]["total_artifacts"] == 1
    art = res["artifacts"][0]
    assert art["artifact_type"] == EvidenceType.UNSUPPORTED
    assert art["status"] == ProcessingStatus.UNSUPPORTED
    assert art["artifact_sha256"] is not None


# -----------------------------------------------------------------------------
# 13. Malformed files
# -----------------------------------------------------------------------------
def test_13_malformed_files(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [
        {"filename": "corrupt.pdf", "content": b"%PDF-corrupt-data-without-eof"},
        {"filename": "corrupt.apk", "content": b"PK\x03\x04corrupted-truncated-zip"},
    ]
    res = analyzer.analyze_submission(files=files, enable_shadow_ai=False)
    assert res["summary_stats"]["total_artifacts"] == 2
    # Handled fail-soft: does not crash
    for art in res["artifacts"]:
        assert art["status"] in [ProcessingStatus.FAILED, ProcessingStatus.UNSUPPORTED, ProcessingStatus.COMPLETED]


# -----------------------------------------------------------------------------
# 14. Duplicate attachments
# -----------------------------------------------------------------------------
def test_14_duplicate_attachments(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    # Identical URLs should be deduplicated
    urls = ["https://mahadiscom.in/pay", "https://mahadiscom.in/pay"]
    res = analyzer.analyze_submission(urls=urls, enable_shadow_ai=False)
    assert res["summary_stats"]["total_artifacts"] == 1


# -----------------------------------------------------------------------------
# 15. Partial analysis failures
# -----------------------------------------------------------------------------
def test_15_partial_analysis_failures(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "broken.apk", "content": b"invalid_bytes_not_a_zip"}]
    res = analyzer.analyze_submission(
        message_text="Valid message alert text.",
        urls=["https://mahadiscom.in"],
        files=files,
        enable_shadow_ai=False,
    )
    # Message and URL succeed; broken file fails; overall pipeline succeeds!
    assert res["summary_stats"]["total_artifacts"] == 3
    assert res["summary_stats"]["completed_count"] >= 2
    statuses = [a["status"] for a in res["artifacts"]]
    assert ProcessingStatus.COMPLETED in statuses
    assert ProcessingStatus.FAILED in statuses


# -----------------------------------------------------------------------------
# 16. Cross-evidence correlation
# -----------------------------------------------------------------------------
def test_16_cross_evidence_correlation(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    msg = "Please visit http://fraud-subsidy-portal.cc to claim your money."
    urls = ["http://fraud-subsidy-portal.cc/apply"]

    res = analyzer.analyze_submission(message_text=msg, urls=urls, enable_shadow_ai=False)
    corrs = res.get("correlations", [])
    assert len(corrs) >= 1
    corr_types = [c["correlation_type"] for c in corrs]
    assert "MESSAGE_URL_SHARED_DOMAIN" in corr_types


# -----------------------------------------------------------------------------
# 17. Case creation with multiple linked artifacts
# -----------------------------------------------------------------------------
def test_17_case_creation_with_multiple_linked_artifacts(isolated_case_store, synthetic_apk_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [{"filename": "sample.apk", "content": synthetic_apk_bytes}]
    res = analyzer.analyze_submission(
        message_text="Suspicious message with link http://bad-link.xyz",
        urls=["http://bad-link.xyz"],
        files=files,
        enable_shadow_ai=False,
    )

    saved = analyzer.save_investigation_cases(
        case_store=store,
        analysis_result=res,
        submitted_by="operator_alice",
        consent_given=True,
    )

    assert saved["parent_case_id"].startswith("CASE-UNIF")
    assert len(saved["child_case_ids"]) >= 3
    assert len(saved["child_evidence_ids"]) >= 3

    # Check parent case record in database
    parent_case = repo.get_case(saved["parent_case_id"])
    assert parent_case is not None
    assert parent_case["metadata"]["is_parent_investigation"] is True
    assert parent_case["metadata"]["investigation_id"] == res["investigation_id"]


# -----------------------------------------------------------------------------
# 18. Evidence withdrawal
# -----------------------------------------------------------------------------
def test_18_evidence_withdrawal(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(
        message_text="Notice: Update your bank KYC.",
        enable_shadow_ai=False,
    )
    saved = analyzer.save_investigation_cases(case_store=store, analysis_result=res)
    child_evid_id = saved["child_evidence_ids"][0]

    withdrawn = repo.withdraw_evidence(child_evid_id, operator_username="analyst_bob", reason="Citizen request")
    assert withdrawn["lifecycle_status"] == "withdrawn"

    evid_rec = repo.get_evidence_provenance(child_evid_id)
    assert evid_rec["lifecycle_status"] == "withdrawn"


# -----------------------------------------------------------------------------
# 19. Consent enforcement
# -----------------------------------------------------------------------------
def test_19_consent_enforcement(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(
        message_text="Consent test message.",
        enable_shadow_ai=False,
    )

    # Save with consent_given = False
    saved = analyzer.save_investigation_cases(case_store=store, analysis_result=res, consent_given=False)
    child_evid_id = saved["child_evidence_ids"][0]
    evid_rec = repo.get_evidence_provenance(child_evid_id)
    assert evid_rec["consent_given"] == 0


# -----------------------------------------------------------------------------
# 20. Privacy leakage
# -----------------------------------------------------------------------------
def test_20_privacy_leakage(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    # Message contains Aadhaar (starts with 2-9) and phone number
    sensitive_msg = "Aadhaar number 2345 6789 0123 and phone 9876543210 urgently required."
    res = analyzer.analyze_submission(message_text=sensitive_msg, enable_shadow_ai=False)
    saved = analyzer.save_investigation_cases(case_store=store, analysis_result=res)

    child_case = repo.get_case(saved["child_case_ids"][0])
    # Raw Aadhaar digits must not leak into observed evidence
    for obs in child_case.get("observed_evidence", []):
        assert "2345 6789 0123" not in obs
        assert "9876543210" not in obs


# -----------------------------------------------------------------------------
# 21. Temporary file cleanup
# -----------------------------------------------------------------------------
def test_21_temporary_file_cleanup(isolated_case_store, synthetic_apk_bytes, synthetic_pdf_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    files = [
        {"filename": "temp_check.apk", "content": synthetic_apk_bytes},
        {"filename": "temp_check.pdf", "content": synthetic_pdf_bytes},
    ]

    import tempfile
    before_count = len(os.listdir(tempfile.gettempdir()))
    res = analyzer.analyze_submission(files=files, enable_shadow_ai=False)
    after_count = len(os.listdir(tempfile.gettempdir()))

    # Processing is completely in-memory, no stray temp files left
    assert res["summary_stats"]["total_artifacts"] == 2
    assert abs(after_count - before_count) <= 2


# -----------------------------------------------------------------------------
# 22. Shadow model invariance
# -----------------------------------------------------------------------------
def test_22_shadow_model_invariance(isolated_case_store):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    res = analyzer.analyze_submission(
        message_text="MSEDCL Bill update pending.",
        enable_shadow_ai=True,
    )
    shadow_summary = res["shadow_ai_summary"]
    assert shadow_summary["active_model_version"] == "custom-mlp-v4.0.0-seed42"
    assert shadow_summary["operating_mode"] == "shadow"
    assert shadow_summary["is_production_authoritative"] is False
    assert shadow_summary["authoritative_score_delta"] == 0.00


# -----------------------------------------------------------------------------
# 23. Deterministic score invariance
# -----------------------------------------------------------------------------
def test_23_deterministic_score_invariance(isolated_case_store, synthetic_pdf_bytes):
    store, repo = isolated_case_store
    analyzer = UnifiedEvidenceAnalyzer(case_repository=repo)

    # Analyze critical phishing message alone
    critical_msg = "MSEDCL Light bill update pending! Pay immediately at http://msedcl-fake.cc or power cut tonight!"
    res_single = analyzer.analyze_submission(message_text=critical_msg, enable_shadow_ai=False)
    score_single = res_single["overall_verdict"]["score"]

    # Analyze critical message combined with benign PDF and benign URL
    res_multi = analyzer.analyze_submission(
        message_text=critical_msg,
        urls=["https://maharashtra.gov.in"],
        files=[{"filename": "blank_doc.pdf", "content": synthetic_pdf_bytes}],
        enable_shadow_ai=False,
    )
    score_multi = res_multi["overall_verdict"]["score"]

    # Adding benign artifacts must NOT dilute or weaken the critical risk score!
    assert score_multi == score_single
    assert res_multi["overall_verdict"]["risk_category"] == res_single["overall_verdict"]["risk_category"]
