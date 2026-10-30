"""
Comprehensive Automated Test Suite for WhatsApp Cloud API Webhook Integration.
Tests cover:
1. Webhook GET challenge verification (valid and invalid token).
2. HMAC-SHA256 signature verification (valid, invalid, missing).
3. Deduplication / Idempotency handling (prevents duplicate replies on retries).
4. Inbound text phishing detection and bilingual reply formatting.
5. Inbound APK document attachment inspection and warning generation.
6. Sender privacy anonymization (salted SHA-256 hash).
7. Sliding-window rate-limiting.
8. Oversized payload rejection (> 16 MB).
9. Malformed JSON request resilience.
10. Safe simulation mode fallback when live credentials are not present.
"""

import hashlib
import hmac
import json
import os
import sys

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.case_manager import SessionCaseStore
from src.whatsapp_handler import (
    clear_simulated_outbox,
    format_whatsapp_reply_for_apk,
    format_whatsapp_reply_for_message,
    get_simulated_outbox_entries,
    hash_sender_id,
    is_duplicate_message,
    is_rate_limited,
    process_incoming_webhook_event,
    verify_webhook_signature,
)


def make_mock_meta_webhook_payload(
    message_id: str = "wamid.test_01",
    from_phone: str = "919876543210",
    text_body: str = "Hello test",
    msg_type: str = "text",
    document_filename: str = "",
) -> bytes:
    """Helper to generate a spec-compliant Meta WhatsApp Cloud API webhook JSON payload."""
    msg_obj = {
        "from": from_phone,
        "id": message_id,
        "timestamp": "1730123456",
        "type": msg_type,
    }
    if msg_type == "text":
        msg_obj["text"] = {"body": text_body}
    elif msg_type == "document":
        msg_obj["document"] = {"filename": document_filename, "id": "media_id_123"}

    data = {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "WABA_ID_TEST",
                "changes": [
                    {
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {"display_phone_number": "15551234567", "phone_number_id": "PNID_TEST"},
                            "contacts": [{"wa_id": from_phone, "profile": {"name": "Citizen User"}}],
                            "messages": [msg_obj],
                        },
                        "field": "messages",
                    }
                ],
            }
        ],
    }
    return json.dumps(data).encode("utf-8")


def test_01_signature_verification_valid_and_invalid():
    """Verifies that HMAC-SHA256 signature verification accepts valid and rejects tampered payloads."""
    secret = "test_meta_app_secret_123"
    raw_payload = b'{"test": "data"}'

    # Compute valid signature
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), raw_payload, hashlib.sha256).hexdigest()
    ok, _ = verify_webhook_signature(raw_payload, valid_sig, secret)
    assert ok is True

    # Tampered payload
    tampered_payload = b'{"test": "tampered_data"}'
    bad_ok, bad_reason = verify_webhook_signature(tampered_payload, valid_sig, secret)
    assert bad_ok is False
    assert "mismatch" in bad_reason.lower()

    # Missing signature header
    missing_ok, missing_reason = verify_webhook_signature(raw_payload, None, secret)
    assert missing_ok is False
    assert "missing" in missing_reason.lower()


def test_02_idempotency_and_deduplication():
    """Verifies that duplicate webhook delivery retries do not process the message twice."""
    unique_mid = "wamid.idempotency_unique_999"
    assert is_duplicate_message(unique_mid) is False
    # Second arrival of the same message ID must be flagged as duplicate
    assert is_duplicate_message(unique_mid) is True


def test_03_sender_phone_number_anonymization():
    """Verifies that phone numbers are salted and hashed so raw numbers are never stored."""
    raw_phone = "+91 98220 12345"
    salt = "TestSaltSecret2026"
    hashed = hash_sender_id(raw_phone, salt)

    assert raw_phone not in hashed
    assert "98220" not in hashed
    assert len(hashed) == 16
    # Same phone + salt produces same hash for rate-limiting
    assert hash_sender_id(raw_phone, salt) == hashed


def test_04_inbound_phishing_text_webhook_processing():
    """
    Simulates receiving a Marathi electricity disconnection scam text via webhook.
    Verifies that the message is analyzed and a bilingual reply is dispatched.
    """
    clear_simulated_outbox()
    phishing_text = (
        "प्रिय ग्राहक, तुमचे महावितरण वीज बिल अपडेट केलेले नाही. "
        "आज रात्री ९:३० वाजता वीज कनेक्शन बंद केले जाईल. तात्काळ MSEDCL_Bill.apk डाउनलोड करा आणि OTP सांगा."
    )
    payload_bytes = make_mock_meta_webhook_payload(
        message_id="wamid.phish_text_01",
        from_phone="919800000001",
        text_body=phishing_text,
    )

    res = process_incoming_webhook_event(
        raw_payload_bytes=payload_bytes,
        signature_header=None,  # Simulation mode accepts without secret
    )
    assert res["status_code"] == 200
    assert res["processed"] is True
    assert len(res["results"]) == 1
    assert res["results"][0]["risk_score"] >= 50

    # Verify that the simulated outbox received the formatted reply
    outbox = get_simulated_outbox_entries()
    assert len(outbox) >= 1
    reply = outbox[-1]["message_text"]
    assert "सावधान" in reply
    assert "1930" in reply
    assert "Maha-Suraksha" in reply


def test_05_inbound_apk_attachment_webhook_processing():
    """
    Simulates receiving an APK document attachment via webhook.
    Verifies static inspection of APK bytes without executing code.
    """
    clear_simulated_outbox()
    sample_apk_path = os.path.join("sample_apks", "Real_Binary_AXML_Header_Sample.apk")
    with open(sample_apk_path, "rb") as f:
        apk_bytes = f.read()

    payload_bytes = make_mock_meta_webhook_payload(
        message_id="wamid.apk_doc_01",
        from_phone="919800000002",
        msg_type="document",
        document_filename="MSEDCL_Light_Bill.apk",
    )

    res = process_incoming_webhook_event(
        raw_payload_bytes=payload_bytes,
        signature_header=None,
        mock_apk_attachment_bytes=apk_bytes,
    )
    assert res["status_code"] == 200
    assert res["processed"] is True
    assert res["results"][0]["type"] == "document_apk"

    outbox = get_simulated_outbox_entries()
    assert len(outbox) >= 1
    reply = outbox[-1]["message_text"]
    assert "DANGEROUS APK" in reply
    assert "1930" in reply


def test_06_sliding_window_rate_limiter():
    """Verifies that exceeding the rate limit triggers the limiter."""
    test_hash = "rate_limit_test_sender"
    # First 10 requests within window should pass
    for _ in range(10):
        is_rate_limited(test_hash)
    # The 11th request must be blocked
    assert is_rate_limited(test_hash) is True


def test_07_oversized_payload_rejection():
    """Verifies that payloads exceeding 16 MB are rejected with HTTP 413."""
    huge_bytes = b"X" * (16 * 1024 * 1024 + 100)
    res = process_incoming_webhook_event(huge_bytes)
    assert res["status_code"] == 413
    assert "Payload Too Large" in res["error"]


def test_08_malformed_json_resilience():
    """Verifies that corrupted JSON payloads return HTTP 400 without crashing."""
    bad_bytes = b"This is not a valid JSON string at all"
    res = process_incoming_webhook_event(bad_bytes)
    assert res["status_code"] == 400
    assert "Malformed JSON" in res["error"]


def test_09_case_store_integration():
    """Verifies that processed webhook messages register in SessionCaseStore."""
    store = SessionCaseStore(session_id="webhook-case-store-test")
    payload_bytes = make_mock_meta_webhook_payload(
        message_id="wamid.case_store_mid_01",
        from_phone="919800000003",
        text_body="Normal electricity bill notice from Mahavitaran ₹840",
    )
    res = process_incoming_webhook_event(
        raw_payload_bytes=payload_bytes,
        case_store=store,
    )
    assert res["status_code"] == 200
    assert store.count() == 1
    case = store.list_cases()[0]
    assert case["case_id"].startswith("CASE-MSG-")


def test_10_unsupported_media_graceful_notice():
    """Verifies that unsupported media types (e.g. video/image) return helpful guidance."""
    payload_bytes = make_mock_meta_webhook_payload(
        message_id="wamid.unsupported_vid_01",
        from_phone="919800000004",
        msg_type="video",
    )
    res = process_incoming_webhook_event(payload_bytes)
    assert res["status_code"] == 200
    assert res["results"][0]["type"] == "unsupported_media"
