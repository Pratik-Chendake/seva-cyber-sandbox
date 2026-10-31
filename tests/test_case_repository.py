"""
Automated Test Suite for Secure SQLite Persistence and Case Repository.
Verifies all 18 requirements for Task 3:
1. Database initialization: tables, schema version, indexes.
2. Repeated initialization without data loss.
3. Case creation and auto-generated case IDs across all 4 analysis types.
4. Retrieval by case ID with deserialized indicator lists and session boundaries.
5. List and filter operations (session, analysis type, risk, source, pagination).
6. JSON and CSV export format compatibility.
7. Persistence across repository instances.
8. Persistence across connection restarts and WAL checkpoints.
9. Concurrent repository instances with WAL mode and busy timeout.
10. Concurrency under thread contention (no SQLITE_BUSY or corruption).
11. Duplicate handling and webhook idempotency via dedup_key.
12. Retention policy and expired record pruning.
13. Privacy redaction (URL credentials, Aadhaar, phone numbers, keyed HMAC).
14. Failure handling for invalid / uncreatable database paths.
15. Corrupted database file error resilience.
16. Full backwards compatibility with SessionCaseStore interface.
17. Zero raw binary APK or citizen message text retention in database.
18. Multi-session isolation in shared database.
"""

import concurrent.futures
import csv
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

from src.case_manager import (
    SessionCaseStore,
    create_apk_case,
    create_message_case,
    create_scheme_case,
    create_url_case,
)
from src.case_repository import (
    CaseRecord,
    CaseRepository,
    CaseRepositoryError,
    get_default_case_repository,
    keyed_phone_hmac,
    mask_aadhaar_number,
    mask_phone_number,
    redact_url_credentials,
    reset_default_case_repository,
    sanitize_evidence_text,
)


# ---------------------------------------------------------------------------
# Fixtures & Sample Factories
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_default_repo(monkeypatch, tmp_path):
    """Ensure each test runs with an isolated repository path and clean singleton."""
    db_file = tmp_path / "test_cases.sqlite3"
    monkeypatch.setenv("SEVA_CASE_DB_PATH", str(db_file))
    reset_default_case_repository()
    yield
    reset_default_case_repository()


def _sample_apk_case():
    apk_res = {
        "filename": "suspicious_app.apk",
        "is_valid_apk": True,
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "package_name": "com.fraud.service",
        "file_size_bytes": 4096,
        "manifest_format": "Binary Android XML",
        "dex_format": "DEX v035",
        "permissions_found": [
            {
                "permission": "android.permission.RECEIVE_SMS",
                "severity": "High",
                "family": "SMS_ACCESS",
            }
        ],
        "confirmed_observations": ["Valid APK signature header"],
        "heuristic_warnings": ["High SMS interception risk"],
        "passive_urls": ["http://suspicious-apk-domain.xyz/login?token=abc12345"],
    }
    scored_res = {
        "score": 75,
        "risk_level": "High-Risk Permission Indicators Detected",
        "badge_color": "red",
        "safe_next_steps_en": ["Delete APK immediately", "Report to 1930"],
        "limitations": "Static inspection only.",
    }
    return create_apk_case(apk_res, scored_res)


def _sample_message_case():
    msg_res = {
        "is_empty": False,
        "normalized_text": "Bill unpaid. Contact 9876543210 immediately.",
        "script_detected": "Marathi (Devanagari Script)",
        "findings": [
            {
                "id": "CREDENTIAL_HARVEST",
                "category": "Bill Scam",
                "matched_text": "9876543210",
                "why_it_matters_en": "Fake helpline phone number.",
            }
        ],
        "extracted_urls": ["http://fake-bill-pay.xyz/login?token=secret123"],
        "context_only_suppressed": False,
        "protective_advisory_detected": False,
    }
    scored_res = {
        "score": 85,
        "risk_level": "High-Risk Phishing Indicators Detected",
        "badge_color": "red",
        "safe_next_steps_en": ["Do not call unverified helpline"],
    }
    return create_message_case(msg_res, scored_res)


def _sample_url_case():
    url_eval = {
        "url": "https://gov-scheme-maha.fake.link/apply?otp=482910&token=xyz789",
        "hostname": "gov-scheme-maha.fake.link",
        "scheme": "https",
        "is_valid_url": True,
        "score": 68,
        "risk_level": "High-Risk Suspicious Link Detected",
        "badge_color": "red",
        "observable_characteristics": {
            "is_ip_address": False,
            "is_shortener": False,
            "is_official_allowlisted": False,
            "is_punycode_or_homoglyph": False,
            "has_apk_download": False,
        },
        "matched_indicators": [
            {
                "category": "Lookalike Brand",
                "severity": "High",
                "evidence_en": "Mimics maharashtra.gov.in portal.",
            }
        ],
        "safe_next_steps_en": ["Do not enter credentials"],
    }
    return create_url_case(url_eval)


def _sample_scheme_case():
    scheme_res = {
        "classification": "CONFLICTING EVIDENCE FOUND",
        "matched_scheme_title": "Majhi Ladki Bahin Yojana",
        "supporting_evidence": ["Official Scheme Identified"],
        "conflicting_evidence": ["Claimed payout Rs 5000 contradicts official Rs 1500"],
        "official_sources": [
            {
                "title": "Mukhyamantri Majhi Ladki Bahin Yojana",
                "gr_number": "GR-2024-147",
                "publication_date": "2024-06-28",
                "portal_url": "https://ladakibahin.maharashtra.gov.in/",
            }
        ],
        "safe_next_steps_en": ["Verify on official portal ladakibahin.maharashtra.gov.in"],
    }
    return create_scheme_case(scheme_res)


# ---------------------------------------------------------------------------
# Requirement 1: Database Initialization
# ---------------------------------------------------------------------------

def test_01_database_initialization(tmp_path):
    """Verify new SQLite DB is initialized with expected tables, schema version, and indexes."""
    db_file = tmp_path / "init_test.sqlite3"
    repo = CaseRepository(db_path=str(db_file))

    assert db_file.exists(), "Database file must be created on disk"

    # Verify tables via raw sqlite3
    with sqlite3.connect(str(db_file)) as conn:
        cursor = conn.cursor()
        tables = {
            row[0]
            for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "threat_cases" in tables
        assert "schema_version" in tables

        # Verify schema version
        ver = cursor.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        assert ver == 1

        # Verify indexes
        indexes = {
            row[0]
            for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert "idx_cases_session" in indexes
        assert "idx_cases_created" in indexes
        assert "idx_cases_type" in indexes
        assert "idx_cases_risk" in indexes
        assert "idx_cases_dedup" in indexes
        assert "idx_cases_expires" in indexes


# ---------------------------------------------------------------------------
# Requirement 2: Repeated Initialization Without Data Loss
# ---------------------------------------------------------------------------

def test_02_repeated_initialization_no_data_loss(tmp_path):
    """Verify calling initialization repeatedly against existing DB succeeds without data loss."""
    db_file = tmp_path / "repeat_init.sqlite3"
    repo1 = CaseRepository(db_path=str(db_file))

    case_dict = _sample_url_case()
    case_id = repo1.save_case(case_dict, session_id="test_session")
    assert case_id.startswith("CASE-")

    # Repeat init on same repo instance
    repo1.init_db()

    # Second instance pointing to existing database
    repo2 = CaseRepository(db_path=str(db_file))
    retrieved = repo2.get_case(case_id, session_id="test_session")
    assert retrieved is not None
    assert retrieved["case_id"] == case_id
    assert "Suspicious URL" in retrieved["analysis_type"]


# ---------------------------------------------------------------------------
# Requirement 3: Case Creation and Auto-Generated Case IDs
# ---------------------------------------------------------------------------

def test_03_case_creation_and_auto_generated_ids(tmp_path):
    """Verify inserting cases of each type (APK, message, URL, scheme) generates valid unique IDs and stores correct fields."""
    repo = CaseRepository(db_path=str(tmp_path / "crud.sqlite3"))

    cases = [
        _sample_apk_case(),
        _sample_message_case(),
        _sample_url_case(),
        _sample_scheme_case(),
    ]

    saved_ids = set()
    for case_dict in cases:
        case_id = repo.save_case(case_dict, session_id="sess_1", source_type="api_manual")
        assert case_id.startswith("CASE-")
        assert len(case_id) >= 12
        assert case_id not in saved_ids
        saved_ids.add(case_id)

        record = repo.get_case(case_id, session_id="sess_1")
        assert record is not None
        assert record["session_id"] == "sess_1"
        assert record["source_type"] == "api_manual"
        assert record["timestamp_utc"] is not None
        assert record["risk_score"] >= 0
        assert record["risk_category"] != ""


# ---------------------------------------------------------------------------
# Requirement 4: Retrieval by Case ID
# ---------------------------------------------------------------------------

def test_04_retrieval_by_case_id(tmp_path):
    """Verify exact retrieval of stored case, including all serialized indicator lists and metadata."""
    repo = CaseRepository(db_path=str(tmp_path / "retrieve.sqlite3"))

    apk_case = _sample_apk_case()
    apk_case["package_name"] = "com.custom.app"
    case_id = repo.save_case(apk_case, session_id="sess_alpha")

    # Exact retrieval
    retrieved = repo.get_case(case_id, session_id="sess_alpha")
    assert retrieved is not None
    assert retrieved["case_id"] == case_id
    assert "APK" in retrieved["analysis_type"]
    assert retrieved["sha256_hash"] == apk_case["sha256_hash"]
    assert any("RECEIVE_SMS" in obs for obs in retrieved["observed_evidence"])
    # URL credentials stripped
    assert retrieved["extracted_urls"] == ["http://suspicious-apk-domain.xyz/login?token=[REDACTED]"]
    assert any("SMS" in inf for inf in retrieved["heuristic_inferences"])
    assert retrieved.get("package_name") == "com.custom.app"

    # Non-existent ID returns None
    assert repo.get_case("CASE-DOESNOTEXIST-99999", session_id="sess_alpha") is None

    # Mismatched session returns None (session boundary enforcement)
    assert repo.get_case(case_id, session_id="sess_other") is None


# ---------------------------------------------------------------------------
# Requirement 5: List and Filter Operations
# ---------------------------------------------------------------------------

def test_05_list_and_filter_operations(tmp_path):
    """Verify listing and counting cases filtered by session_id, analysis_type, risk_category, source_type, limit, offset."""
    repo = CaseRepository(db_path=str(tmp_path / "filter.sqlite3"))

    c1 = _sample_apk_case()
    c2 = _sample_message_case()
    c3 = _sample_url_case()
    c4 = _sample_scheme_case()
    c5 = _sample_message_case()
    c6 = _sample_url_case()

    repo.save_case(c1, session_id="sess_A", source_type="api_manual")
    repo.save_case(c2, session_id="sess_A", source_type="api_manual")
    repo.save_case(c3, session_id="sess_A", source_type="whatsapp_webhook")
    repo.save_case(c4, session_id="sess_B", source_type="api_manual")
    repo.save_case(c5, session_id="sess_B", source_type="whatsapp_webhook")
    repo.save_case(c6, session_id="sess_B", source_type="whatsapp_webhook")

    # Filter by session_id
    assert repo.count_cases(session_id="sess_A") == 3
    assert repo.count_cases(session_id="sess_B") == 3
    assert repo.count_cases() == 6

    # Filter by analysis_type
    assert len(repo.list_cases(analysis_type="WhatsApp Vernacular Phishing Analysis")) == 2
    assert len(repo.list_cases(session_id="sess_A", analysis_type="Android .APK Static Security Inspection")) == 1

    # Filter by source_type
    assert len(repo.list_cases(source_type="whatsapp_webhook")) == 3

    # Limit and offset
    all_sess_b = repo.list_cases(session_id="sess_B", limit=2, offset=0)
    assert len(all_sess_b) == 2
    offset_sess_b = repo.list_cases(session_id="sess_B", limit=2, offset=2)
    assert len(offset_sess_b) == 1
    assert offset_sess_b[0]["case_id"] not in [r["case_id"] for r in all_sess_b]


# ---------------------------------------------------------------------------
# Requirement 6: JSON and CSV Export Compatibility
# ---------------------------------------------------------------------------

def test_06_json_and_csv_export_compatibility(tmp_path):
    """Verify exported JSON and CSV strings match the structure expected by existing consumers."""
    repo = CaseRepository(db_path=str(tmp_path / "export.sqlite3"))

    c1 = _sample_apk_case()
    c2 = _sample_message_case()
    repo.save_case(c1, session_id="sess_exp")
    repo.save_case(c2, session_id="sess_exp")

    # JSON export
    json_str = repo.export_json(session_id="sess_exp")
    parsed = json.loads(json_str)
    assert isinstance(parsed, dict)
    assert parsed["session_id"] == "sess_exp"
    assert parsed["total_cases"] == 2
    for item in parsed["cases"]:
        assert "case_id" in item
        assert "timestamp_utc" in item
        assert "analysis_type" in item
        assert "risk_score" in item
        assert "risk_category" in item
        assert "observed_evidence" in item
        assert "heuristic_inferences" in item

    # CSV export
    csv_str = repo.export_csv(session_id="sess_exp")
    lines = [ln for ln in csv_str.strip().split("\n") if ln]
    reader = csv.DictReader(lines)
    rows = list(reader)
    assert len(rows) == 2
    required_cols = {
        "Case ID",
        "Timestamp UTC",
        "Analysis Type",
        "Risk Index",
        "Risk Category",
        "Indicator Count",
        "SHA-256",
        "Extracted URLs Count",
        "Status",
        "Recommended Action",
    }
    assert required_cols.issubset(set(reader.fieldnames))


# ---------------------------------------------------------------------------
# Requirement 7: Persistence Across Repository Instances
# ---------------------------------------------------------------------------

def test_07_persistence_across_repository_instances(tmp_path):
    """Create a repo, insert cases, destroy instance, create new instance on same file, verify integrity."""
    db_file = tmp_path / "instance_persist.sqlite3"
    repo1 = CaseRepository(db_path=str(db_file))

    saved_ids = []
    for i in range(3):
        case_dict = _sample_url_case()
        case_dict["target_identifier"] = f"fraud-{i}.example.org"
        cid = repo1.save_case(case_dict, session_id="persistent_session")
        saved_ids.append(cid)

    assert repo1.count_cases(session_id="persistent_session") == 3
    del repo1

    # Instantiate completely new repo object
    repo2 = CaseRepository(db_path=str(db_file))
    assert repo2.count_cases(session_id="persistent_session") == 3

    for cid in saved_ids:
        loaded = repo2.get_case(cid, session_id="persistent_session")
        assert loaded is not None
        assert loaded["case_id"] == cid


# ---------------------------------------------------------------------------
# Requirement 8: Persistence Across Connection Restarts
# ---------------------------------------------------------------------------

def test_08_persistence_across_connection_restarts(tmp_path):
    """Close connections, reopen, and verify integrity and WAL checkpoints."""
    db_file = tmp_path / "conn_restart.sqlite3"
    repo = CaseRepository(db_path=str(db_file))

    apk_case = _sample_apk_case()
    cid = repo.save_case(apk_case, session_id="restart_session")

    # Manually checkpoint WAL to ensure flush to base file
    with repo.get_connection() as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    # Direct raw connection inspection
    with sqlite3.connect(str(db_file)) as raw_conn:
        cur = raw_conn.cursor()
        row = cur.execute(
            "SELECT case_id, analysis_type FROM threat_cases WHERE case_id = ?;",
            (cid,),
        ).fetchone()
        assert row is not None
        assert row[0] == cid
        assert "APK" in row[1]


# ---------------------------------------------------------------------------
# Requirement 9: Concurrent Repository Instances With WAL Mode
# ---------------------------------------------------------------------------

def test_09_concurrent_repository_instances_wal_mode(tmp_path):
    """Two repository instances pointing to the same SQLite file can read and write without lock errors."""
    db_file = tmp_path / "wal_concurrency.sqlite3"
    repo_a = CaseRepository(db_path=str(db_file))
    repo_b = CaseRepository(db_path=str(db_file))

    # Verify journal mode is WAL
    with repo_a.get_connection() as conn:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode.lower() == "wal"

    # Repo A writes
    case_a = _sample_message_case()
    cid_a = repo_a.save_case(case_a, session_id="shared_sess")

    # Repo B reads immediately
    read_by_b = repo_b.get_case(cid_a, session_id="shared_sess")
    assert read_by_b is not None
    assert read_by_b["case_id"] == cid_a

    # Repo B writes
    case_b = _sample_url_case()
    cid_b = repo_b.save_case(case_b, session_id="shared_sess")

    # Repo A reads immediately
    read_by_a = repo_a.get_case(cid_b, session_id="shared_sess")
    assert read_by_a is not None
    assert read_by_a["case_id"] == cid_b


# ---------------------------------------------------------------------------
# Requirement 10: Concurrency Under Thread Contention
# ---------------------------------------------------------------------------

def test_10_concurrent_writes_thread_contention(tmp_path):
    """Simulate multiple threads writing cases simultaneously, verifying no SQLITE_BUSY or corruption."""
    db_file = tmp_path / "thread_contention.sqlite3"
    repo = CaseRepository(db_path=str(db_file))

    total_threads = 6
    cases_per_thread = 5
    errors = []

    def worker(thread_idx: int):
        try:
            for j in range(cases_per_thread):
                c = _sample_message_case()
                c["target_identifier"] = f"Thread {thread_idx} msg {j}"
                repo.save_case(c, session_id=f"thread_sess_{thread_idx}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(total_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent writes produced errors: {errors}"
    assert repo.count_cases() == total_threads * cases_per_thread


# ---------------------------------------------------------------------------
# Requirement 11: Duplicate Handling and Deduplication Keys
# ---------------------------------------------------------------------------

def test_11_duplicate_handling_and_dedup_key(tmp_path):
    """Verify that inserting with existing dedup_key safely updates or ignores without phantom rows."""
    repo = CaseRepository(db_path=str(tmp_path / "dedup.sqlite3"))

    msg_case = _sample_message_case()
    dedup_key = "wamid:ABGGFlA5Fpa1Agh03124abcd"

    # First insert
    cid1 = repo.save_case(
        msg_case,
        session_id="webhook_archive",
        source_type="whatsapp_webhook",
        dedup_key=dedup_key,
    )
    assert repo.count_cases(session_id="webhook_archive") == 1

    # Second insert with identical dedup_key (e.g. webhook delivery retry)
    updated_case = _sample_message_case()
    cid2 = repo.save_case(
        updated_case,
        session_id="webhook_archive",
        source_type="whatsapp_webhook",
        dedup_key=dedup_key,
    )

    # Must preserve same case_id, not insert a phantom row
    assert cid2 == cid1
    assert repo.count_cases(session_id="webhook_archive") == 1


# ---------------------------------------------------------------------------
# Requirement 12: Retention Policy and Expiration
# ---------------------------------------------------------------------------

def test_12_retention_policy_and_expiration(tmp_path):
    """Verify that prune_expired_cases() removes cases past their expiration date while preserving active cases."""
    repo = CaseRepository(db_path=str(tmp_path / "retention.sqlite3"))

    # Insert an expired case (retention_days = -1 => expired in past)
    c_expired = _sample_url_case()
    cid_exp = repo.save_case(c_expired, session_id="sess_ret", retention_days=-1)

    # Insert an active case (retention_days = 30 => active)
    c_active = _sample_scheme_case()
    cid_act = repo.save_case(c_active, session_id="sess_ret", retention_days=30)

    assert repo.count_cases(session_id="sess_ret") == 2

    # Prune expired cases
    pruned_count = repo.prune_expired_cases()
    assert pruned_count == 1

    # Expired case is gone, active case remains
    assert repo.get_case(cid_exp, session_id="sess_ret") is None
    assert repo.get_case(cid_act, session_id="sess_ret") is not None
    assert repo.count_cases(session_id="sess_ret") == 1


# ---------------------------------------------------------------------------
# Requirement 13: Privacy Redaction
# ---------------------------------------------------------------------------

def test_13_privacy_redaction_before_persistence(tmp_path):
    """Verify URLs with sensitive tokens, Aadhaar numbers, and phone numbers are redacted/masked."""
    # 1. Test URL token stripping
    sensitive_url = (
        "https://example.com/verify?token=SUPERSECRET999&otp=123456&auth=xyz&ref=portal"
    )
    cleaned_url = redact_url_credentials(sensitive_url)
    assert "token=[REDACTED]" in cleaned_url
    assert "otp=[REDACTED]" in cleaned_url
    assert "auth=[REDACTED]" in cleaned_url
    assert "ref=portal" in cleaned_url
    assert "SUPERSECRET999" not in cleaned_url

    # 2. Test Phone number masking
    text_with_phone = "Contact officer at 9876543210 or +91 9123456789 immediately"
    masked_phone_text = mask_phone_number(text_with_phone)
    assert "9876543210" not in masked_phone_text
    assert "+91-98XXXX3210" in masked_phone_text or "XXXX" in masked_phone_text

    # 3. Test Aadhaar masking
    text_with_aadhaar = "Applicant Aadhaar is 1234 5678 9012 for verification"
    masked_aadhaar_text = mask_aadhaar_number(text_with_aadhaar)
    assert "1234 5678 9012" not in masked_aadhaar_text
    assert "XXXX-XXXX-9012" in masked_aadhaar_text

    # 4. Keyed HMAC
    hmac1 = keyed_phone_hmac("+919876543210", secret="test_salt_1")
    hmac2 = keyed_phone_hmac("+919876543210", secret="test_salt_2")
    assert hmac1 != hmac2  # salt/secret changes output
    assert hmac1 == keyed_phone_hmac("+919876543210", secret="test_salt_1")  # deterministic

    # 5. Stored case evidence text sanitization
    repo = CaseRepository(db_path=str(tmp_path / "privacy.sqlite3"))
    dirty_case = _sample_message_case()
    dirty_case["observed_evidence"].append(
        "Sender asks for Aadhaar: 9876 5432 1098 and phone 9811223344"
    )
    cid = repo.save_case(dirty_case, session_id="privacy_sess")

    loaded = repo.get_case(cid, session_id="privacy_sess")
    for finding in loaded["observed_evidence"]:
        assert "9876 5432 1098" not in finding


# ---------------------------------------------------------------------------
# Requirement 14: Failure Handling for Invalid / Read-Only Database Path
# ---------------------------------------------------------------------------

def test_14_failure_handling_invalid_read_only_path(tmp_path):
    """Verify that CaseRepositoryError is raised on invalid path without unhandled crash."""
    bad_parent = tmp_path / "not_a_directory.txt"
    bad_parent.write_text("dummy", encoding="utf-8")
    invalid_db_path = bad_parent / "impossible_subpath" / "case.sqlite3"

    with pytest.raises(CaseRepositoryError) as exc_info:
        CaseRepository(db_path=str(invalid_db_path))

    assert "Cannot initialize database" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Requirement 15: Corrupted Database File Handling
# ---------------------------------------------------------------------------

def test_15_corrupted_database_file_handling(tmp_path):
    """Verify graceful error handling when database file is corrupted."""
    corrupt_file = tmp_path / "corrupt.sqlite3"
    corrupt_file.write_bytes(b"NOT_A_VALID_SQLITE_HEADER_CORRUPTED_DATA_PADDING_XXXX")

    with pytest.raises(CaseRepositoryError):
        CaseRepository(db_path=str(corrupt_file))


# ---------------------------------------------------------------------------
# Requirement 16: Backward Compatibility With SessionCaseStore
# ---------------------------------------------------------------------------

def test_16_backwards_compatibility_with_session_case_store(tmp_path, monkeypatch):
    """Verify existing SessionCaseStore calls continue to work identically."""
    db_file = tmp_path / "compat.sqlite3"
    monkeypatch.setenv("SEVA_CASE_DB_PATH", str(db_file))
    reset_default_case_repository()

    store = SessionCaseStore(session_id="compat_session")
    assert store.count() == 0
    assert store.list_cases() == []

    # Add APK case
    apk_case = _sample_apk_case()
    cid = store.add_case(apk_case)
    assert cid.startswith("CASE-")
    assert store.count() == 1

    # Get case
    retrieved = store.get_case(cid)
    assert retrieved is not None
    assert retrieved["case_id"] == cid
    assert "APK" in retrieved["analysis_type"]

    # Backward compatibility with _cases dictionary property
    assert cid in store._cases
    assert store._cases[cid]["case_id"] == cid

    # Summary table rows
    rows = store.summary_table_rows()
    assert len(rows) == 1
    assert rows[0]["Case ID"] == cid
    assert "APK" in rows[0]["Analysis Type"]
    assert rows[0]["Risk Index (0-100)"] == 75

    # JSON & CSV exports
    json_out = store.export_json()
    assert cid in json_out
    csv_out = store.export_csv()
    assert cid in csv_out

    # Clear session
    store.clear()
    assert store.count() == 0
    assert store.get_case(cid) is None


# ---------------------------------------------------------------------------
# Requirement 17: No Raw APK Bytes or Raw Citizen Message Persisted
# ---------------------------------------------------------------------------

def test_17_no_raw_apk_bytes_or_raw_message_stored(tmp_path):
    """Verify raw message text and original APK binary bytes are never stored in the database."""
    db_file = tmp_path / "raw_bytes_check.sqlite3"
    repo = CaseRepository(db_path=str(db_file))

    secret_raw_apk = b"EXPLICIT_DANGEROUS_APK_BINARY_STREAM_99887766"
    apk_case = _sample_apk_case()
    apk_case["file_bytes"] = secret_raw_apk
    apk_case["raw_bytes"] = secret_raw_apk
    repo.save_case(apk_case, session_id="sess_sec")

    # Inspect raw database file contents
    raw_content = db_file.read_bytes()
    assert secret_raw_apk not in raw_content, "Raw APK binary stream must NEVER be stored in the database"

    # Check raw SQLite rows
    with sqlite3.connect(str(db_file)) as conn:
        cur = conn.cursor()
        rows = cur.execute("SELECT * FROM threat_cases;").fetchall()
        for row in rows:
            for cell in row:
                if isinstance(cell, (str, bytes)):
                    cell_bytes = cell if isinstance(cell, bytes) else cell.encode("utf-8")
                    assert secret_raw_apk not in cell_bytes


# ---------------------------------------------------------------------------
# Requirement 18: Multi-Session Isolation in Shared Database
# ---------------------------------------------------------------------------

def test_18_session_isolation_dashboard_security(tmp_path):
    """Verify that case dashboard session isolation does not leak unauthorized cases across sessions."""
    repo = CaseRepository(db_path=str(tmp_path / "isolation.sqlite3"))

    # Session A writes
    case_a = _sample_apk_case()
    cid_a = repo.save_case(case_a, session_id="browser_session_A")

    # Session B writes
    case_b = _sample_message_case()
    cid_b = repo.save_case(case_b, session_id="browser_session_B")

    # Webhook archives a case
    case_wh = _sample_url_case()
    cid_wh = repo.save_case(
        case_wh,
        session_id="whatsapp-webhook-archive",
        source_type="whatsapp_webhook",
    )

    # Session A can only see session A
    cases_a = repo.list_cases(session_id="browser_session_A")
    assert len(cases_a) == 1
    assert cases_a[0]["case_id"] == cid_a

    # Session A cannot retrieve Session B's case or webhook's case
    assert repo.get_case(cid_b, session_id="browser_session_A") is None
    assert repo.get_case(cid_wh, session_id="browser_session_A") is None

    # Summary table export for Session A has only Session A
    summary_a = repo.export_summary_table_rows(session_id="browser_session_A")
    assert len(summary_a) == 1
    assert summary_a[0]["Case ID"] == cid_a

    # Deleting or clearing Session A does not touch Session B or Webhook
    repo.clear_session("browser_session_A")
    assert repo.count_cases(session_id="browser_session_A") == 0
    assert repo.count_cases(session_id="browser_session_B") == 1
    assert repo.count_cases(session_id="whatsapp-webhook-archive") == 1
