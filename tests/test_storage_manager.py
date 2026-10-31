"""
Tests for EvidenceStorageManager and file validation.
Ensures Phase 10 Cloudflare R2 / S3-compatible private object storage behavior and security invariants.
"""

import hashlib
import os
import pytest
from unittest.mock import MagicMock, patch

from src.storage_manager import (
    EvidenceStorageManager,
    MAX_FILE_SIZE_BYTES,
    validate_file_signature,
)


def test_validate_file_signature():
    # Empty content
    assert validate_file_signature(b"", "apk") is False

    # Valid signatures
    assert validate_file_signature(b"PK\x03\x04rest_of_zip", "apk") is True
    assert validate_file_signature(b"PK\x03\x04rest_of_zip", "zip") is True
    assert validate_file_signature(b"%PDF-1.4...", "pdf") is True
    assert validate_file_signature(b"\x89PNG\r\n\x1a\n...", "png") is True
    assert validate_file_signature(b"\xff\xd8\xff...", "jpg") is True

    # Invalid signatures
    assert validate_file_signature(b"NOT_A_ZIP", "apk") is False
    assert validate_file_signature(b"NOT_A_PDF", "pdf") is False

    # Plain text / unsupported type allows pass
    assert validate_file_signature(b"plain text content", "txt") is True


def test_storage_manager_local_storage(tmp_path):
    storage_dir = tmp_path / "storage"
    manager = EvidenceStorageManager(local_fallback_dir=str(storage_dir))
    assert manager.is_cloud_storage is False

    test_content = b"PK\x03\x04test_apk_content_bytes"
    expected_hash = hashlib.sha256(test_content).hexdigest()

    metadata = manager.store_evidence(
        content=test_content,
        filename="malicious.apk",
        artifact_type="apk",
        case_id="CASE-2026-001",
    )

    assert metadata["sha256_hash"] == expected_hash
    assert metadata["size_bytes"] == len(test_content)
    assert metadata["signature_valid"] is True
    assert metadata["storage_backend"] == "local_filesystem"
    assert metadata["is_private"] is True
    assert expected_hash in metadata["storage_key"]

    # Retrieval
    retrieved = manager.get_evidence_bytes(metadata["storage_key"])
    assert retrieved == test_content

    # Missing retrieval
    assert manager.get_evidence_bytes("nonexistent/key.apk") is None

    # Presigned / local URL
    signed = manager.generate_signed_url(metadata["storage_key"])
    assert signed["backend"] == "local_proxy"
    assert metadata["storage_key"] in signed["signed_url"]


def test_storage_manager_file_size_limit(tmp_path):
    storage_dir = tmp_path / "storage"
    manager = EvidenceStorageManager(local_fallback_dir=str(storage_dir))

    oversized_content = b"X" * (MAX_FILE_SIZE_BYTES + 10)
    with pytest.raises(ValueError, match="exceeds maximum permissible size"):
        manager.store_evidence(
            content=oversized_content,
            filename="large.bin",
            artifact_type="bin",
        )


def test_storage_manager_cloud_mock(tmp_path):
    mock_s3 = MagicMock()
    mock_s3.generate_presigned_url.return_value = "https://r2.cloudflarestorage.com/signed?token=abc"

    storage_dir = tmp_path / "storage"
    mock_boto3 = MagicMock()
    mock_boto3.client.return_value = mock_s3
    mock_botocore = MagicMock()

    with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.config": mock_botocore}):
        manager = EvidenceStorageManager(
            account_id="fake_account",
            access_key_id="fake_key",
            secret_access_key="fake_secret",
            bucket_name="test-bucket",
            local_fallback_dir=str(storage_dir),
        )
        assert manager.is_cloud_storage is True

        content = b"%PDF-1.4 dummy document"
        metadata = manager.store_evidence(
            content=content,
            filename="report.pdf",
            artifact_type="pdf",
        )
        assert metadata["storage_backend"] == "cloudflare_r2"
        assert mock_s3.put_object.called

        signed = manager.generate_signed_url(metadata["storage_key"])
        assert signed["backend"] == "cloudflare_r2"
        assert signed["signed_url"] == "https://r2.cloudflarestorage.com/signed?token=abc"
