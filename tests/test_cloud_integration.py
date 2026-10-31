"""
Seva Cyber Sandbox — Cloud Integration & Runtime Readiness Verification Tests
Tests PostgreSQL dialect translation, concurrency protection, shared rate limiting,
and Cloudflare R2 S3 storage adapter behavior.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import os
import threading
import time
import pytest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from api_server import app
from src.database_adapter import (
    is_postgres_url,
    translate_query_for_postgres,
    get_db_connection,
    PostgresCursorWrapper,
    PostgresConnectionWrapper,
)
from src.rate_limiter import check_rate_limit, RATE_LIMIT_RULES
from src.storage_manager import (
    EvidenceStorageManager,
    MAX_FILE_SIZE_BYTES,
    validate_file_signature,
)


def test_postgres_dialect_translation():
    # 1. Parameter marker translation
    sql = "SELECT * FROM threat_cases WHERE case_id = ? AND risk_score >= ?;"
    translated = translate_query_for_postgres(sql)
    assert "%s" in translated
    assert "?" not in translated

    # 2. PRAGMA table_info translation
    pragma_sql = "PRAGMA table_info(threat_cases);"
    translated_pragma = translate_query_for_postgres(pragma_sql)
    assert "information_schema.columns" in translated_pragma
    assert "LOWER(table_name) = 'threat_cases'" in translated_pragma

    # 3. PRAGMA no-op translation
    noop_sql = "PRAGMA foreign_keys = ON;"
    translated_noop = translate_query_for_postgres(noop_sql)
    assert "pragma_noop" in translated_noop

    # 4. sqlite_master translation
    master_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?;"
    translated_master = translate_query_for_postgres(master_sql)
    assert "information_schema.tables" in translated_master
    assert "sqlite_master" not in translated_master

    # 5. INSERT OR REPLACE translation
    replace_sql = "INSERT OR REPLACE INTO threat_cases (case_id, session_id) VALUES (?, ?);"
    translated_replace = translate_query_for_postgres(replace_sql)
    assert "ON CONFLICT (case_id) DO UPDATE" in translated_replace
    assert "INSERT OR REPLACE" not in translated_replace


def test_postgres_cursor_wrapper_mock():
    mock_raw_cur = MagicMock()
    mock_raw_cur.fetchone.return_value = {"case_id": "CASE-001", "risk_score": 90}
    mock_raw_cur.rowcount = 1

    wrapper = PostgresCursorWrapper(mock_raw_cur)
    res = wrapper.execute("SELECT * FROM threat_cases WHERE case_id = ?;", ("CASE-001",))
    assert res is wrapper
    assert mock_raw_cur.execute.called

    row = wrapper.fetchone()
    assert row["case_id"] == "CASE-001"
    assert row["risk_score"] == 90
    assert wrapper.rowcount == 1


def test_concurrent_admin_setup_prevention(tmp_path):
    test_db = str(tmp_path / "test_concurrent_auth.sqlite3")
    old_db = os.environ.get("SEVA_DB_PATH")
    old_case_db = os.environ.get("SEVA_CASE_DB_PATH")
    os.environ["SEVA_DB_PATH"] = test_db
    os.environ["SEVA_CASE_DB_PATH"] = test_db

    from src.rate_limiter import _IN_MEMORY_TIMESTAMPS
    _IN_MEMORY_TIMESTAMPS.clear()

    try:
        from src.case_repository import CaseRepository
        CaseRepository(db_path=test_db)

        client = TestClient(app)
        results = []
        barrier = threading.Barrier(5)

        def attempt_setup(idx):
            barrier.wait()
            resp = client.post(
                "/api/auth/setup-admin",
                json={"username": f"admin_{idx}", "password": f"Password123!#{idx}"},
            )
            return resp.status_code, resp.json()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(attempt_setup, i) for i in range(5)]
            for f in futures:
                results.append(f.result())

        # Exactly ONE thread must succeed with 200, all other 4 must be rejected with 403
        status_codes = [r[0] for r in results]
        assert status_codes.count(200) == 1
        assert status_codes.count(403) == 4
    finally:
        if old_db:
            os.environ["SEVA_DB_PATH"] = old_db
        else:
            os.environ.pop("SEVA_DB_PATH", None)
        if old_case_db:
            os.environ["SEVA_CASE_DB_PATH"] = old_case_db
        else:
            os.environ.pop("SEVA_CASE_DB_PATH", None)


def test_shared_rate_limiting():
    ip = "192.168.1.100"
    path = "/api/auth/login"

    # Reset in-memory window for test
    from src.rate_limiter import _IN_MEMORY_TIMESTAMPS
    _IN_MEMORY_TIMESTAMPS.clear()

    # Login limit is 15 requests per minute
    for _ in range(15):
        assert check_rate_limit(ip, path) is False

    # 16th request must trigger rate limit (return True)
    assert check_rate_limit(ip, path) is True


def test_r2_storage_adapter_lifecycle(tmp_path):
    storage_dir = tmp_path / "storage"

    # Mock S3 Client simulating Cloudflare R2
    mock_s3 = MagicMock()
    mock_s3.put_object.return_value = {"ETag": '"abcdef123456"'}
    mock_s3.get_object.return_value = {"Body": io.BytesIO(b"%PDF-1.4 Simulated Cloud Document")}
    mock_s3.generate_presigned_url.return_value = "https://r2.cloudflarestorage.com/signed?token=xyz"

    mock_boto3 = MagicMock()
    mock_boto3.client.return_value = mock_s3
    mock_botocore = MagicMock()

    with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.config": mock_botocore}):
        manager = EvidenceStorageManager(
            account_id="fake_cf_account",
            access_key_id="fake_r2_access_key",
            secret_access_key="fake_r2_secret_key",
            bucket_name="seva-evidence-test-bucket",
            local_fallback_dir=str(storage_dir),
        )
        assert manager.is_cloud_storage is True

        content = b"%PDF-1.4 Simulated Cloud Document"
        expected_hash = hashlib.sha256(content).hexdigest()

        # 1. Store
        meta = manager.store_evidence(
            content=content,
            filename="cloud_report.pdf",
            artifact_type="pdf",
            case_id="CASE-R2-001",
        )
        assert meta["storage_backend"] == "cloudflare_r2"
        assert meta["sha256_hash"] == expected_hash
        assert expected_hash in meta["storage_key"]
        assert mock_s3.put_object.called

        # 2. Retrieve
        retrieved = manager.get_evidence_bytes(meta["storage_key"])
        assert retrieved == content

        # 3. Signed URL
        signed = manager.generate_signed_url(meta["storage_key"], expires_in_seconds=600)
        assert signed["backend"] == "cloudflare_r2"
        assert "signed?token=xyz" in signed["signed_url"]

        # 4. Error Fallback to Local Storage
        mock_s3.put_object.side_effect = Exception("Cloudflare R2 Network Timeout")
        fallback_meta = manager.store_evidence(
            content=content,
            filename="fallback_report.pdf",
            artifact_type="pdf",
        )
        assert fallback_meta["storage_backend"] == "local_filesystem_fallback"
