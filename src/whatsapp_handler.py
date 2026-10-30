"""
WhatsApp Business Platform (Cloud API) Message Processing & Webhook Handler.
Part of Seva Cyber Sandbox (Maha-Suraksha).

SECURITY, PRIVACY & FORENSIC BOUNDARIES:
1. Validates incoming webhook HMAC-SHA256 signatures (X-Hub-Signature-256).
2. Deduplication & Idempotency: Caches processed message IDs to prevent sending duplicate replies on retries.
3. Privacy Preservation: Anonymizes sender phone numbers via cryptographic salted SHA-256 hashing.
   Raw phone numbers and raw message texts are never logged or stored permanently.
4. Safe Attachment Inspection: Evaluates .apk documents statically in memory without installing or executing code.
5. Mode Transparency: Runs in "Simulation / Sandbox Mode" until real Meta Cloud API credentials are provided.
"""

from collections import deque
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
import ssl
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
import urllib.parse
import urllib.request

from src.apk_analyzer import MAX_APK_UPLOAD_BYTES, analyze_apk_bytes
from src.case_manager import SessionCaseStore, create_apk_case, create_message_case
from src.phishing_detector import analyze_message_text
from src.risk_scorer import score_apk_analysis, score_message_analysis
from src.scheme_verifier import verify_scheme_claim
from src.url_analyzer import analyze_url

# Default Configuration & Safety Limits
MAX_WEBHOOK_PAYLOAD_BYTES = 16 * 1024 * 1024  # 16 MB max HTTP body
MAX_TEXT_MESSAGE_CHARS = 4096                  # WhatsApp max text length
RATE_LIMIT_WINDOW_SEC = 60.0                   # 1 minute sliding window
RATE_LIMIT_MAX_REQUESTS = 10                   # 10 queries per sender per minute
IDEMPOTENCY_CACHE_SIZE = 5000                  # Number of recent message IDs remembered
OUTBOX_LOG_MAX = 50                            # Keep recent replies in memory for dashboard inspect

# Shared In-Memory State for Webhook Handler
_PROCESSED_MESSAGE_IDS: Deque[str] = deque(maxlen=IDEMPOTENCY_CACHE_SIZE)
_PROCESSED_MESSAGE_SET: Set[str] = set()
_RATE_LIMITER_RECORDS: Dict[str, Deque[float]] = {}
_SIMULATED_OUTBOX: Deque[Dict[str, Any]] = deque(maxlen=OUTBOX_LOG_MAX)


def load_whatsapp_config() -> Dict[str, Any]:
    """
    Loads WhatsApp Cloud API configuration from environment variables.
    Defaults to safe 'simulation' mode when live credentials are not present.
    """
    verify_token = os.environ.get("WHATSAPP_VERIFY_TOKEN", "SEVA_SANDBOX_VERIFY_TOKEN_2026")
    app_secret = os.environ.get("WHATSAPP_APP_SECRET", "")
    access_token = os.environ.get("WHATSAPP_ACCESS_TOKEN", "")
    phone_number_id = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "")
    api_version = os.environ.get("WHATSAPP_API_VERSION", "v21.0")
    sender_salt = os.environ.get("WHATSAPP_SENDER_SALT", "MahaSurakshaPrivacySalt2026")

    has_live_credentials = bool(access_token and phone_number_id and app_secret)
    mode = "live" if (has_live_credentials and os.environ.get("WHATSAPP_MODE") == "live") else "simulation"

    return {
        "verify_token": verify_token,
        "app_secret": app_secret,
        "access_token": access_token,
        "phone_number_id": phone_number_id,
        "api_version": api_version,
        "sender_salt": sender_salt,
        "mode": mode,
        "has_live_credentials": has_live_credentials,
    }


def hash_sender_id(raw_phone_number: str, salt: str) -> str:
    """
    Cryptographically hashes a sender phone number with a private salt.
    Prevents storage of cleartext phone numbers while supporting rate limiting.
    """
    clean_num = re.sub(r"[^0-9]", "", str(raw_phone_number or ""))
    salted = f"{salt}:{clean_num}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()[:16]


def is_rate_limited(sender_hash: str) -> bool:
    """
    Sliding window rate-limiter: allows up to RATE_LIMIT_MAX_REQUESTS within RATE_LIMIT_WINDOW_SEC.
    """
    now = time.time()
    if sender_hash not in _RATE_LIMITER_RECORDS:
        _RATE_LIMITER_RECORDS[sender_hash] = deque()

    timestamps = _RATE_LIMITER_RECORDS[sender_hash]
    # Drop timestamps older than window
    while timestamps and (now - timestamps[0]) > RATE_LIMIT_WINDOW_SEC:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        return True

    timestamps.append(now)
    return False


def verify_webhook_signature(
    raw_payload_bytes: bytes,
    signature_header: Optional[str],
    app_secret: str,
) -> Tuple[bool, str]:
    """
    Validates the X-Hub-Signature-256 header against the computed HMAC-SHA256 signature.
    In simulation mode (when app_secret is unset), allows requests with a note.
    """
    if not app_secret:
        return True, "Simulation Mode: No WHATSAPP_APP_SECRET configured; signature check skipped."

    if not signature_header:
        return False, "Missing X-Hub-Signature-256 header."

    if not signature_header.startswith("sha256="):
        return False, "Invalid signature format; expected 'sha256=<hex>'."

    expected_sig = signature_header[len("sha256=") :]
    computed_sig = hmac.new(
        app_secret.encode("utf-8"),
        raw_payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    if hmac.compare_digest(expected_sig, computed_sig):
        return True, "HMAC-SHA256 signature verified successfully."

    return False, "Signature mismatch: incoming payload does not match Meta App Secret."


def is_duplicate_message(message_id: str) -> bool:
    """
    Checks if a message ID has already been processed to prevent duplicate responses.
    """
    if not message_id:
        return False

    if message_id in _PROCESSED_MESSAGE_SET:
        return True

    if len(_PROCESSED_MESSAGE_IDS) >= IDEMPOTENCY_CACHE_SIZE:
        evicted = _PROCESSED_MESSAGE_IDS.popleft()
        _PROCESSED_MESSAGE_SET.discard(evicted)

    _PROCESSED_MESSAGE_IDS.append(message_id)
    _PROCESSED_MESSAGE_SET.add(message_id)
    return False


def format_whatsapp_reply_for_message(
    msg_res: Dict[str, Any],
    scored_msg: Dict[str, Any],
    scheme_res: Optional[Dict[str, Any]] = None,
    url_eval: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Formats a concise, bilingual WhatsApp alert message (readable on mobile).
    Respects the 4096-character limit and highlights immediate actions.
    """
    score = scored_msg.get("score", 0)
    category = scored_msg.get("risk_level", "Security Review")
    badge = "🚨 *सावधान / CAUTION*" if score >= 50 else ("⚠️ *सूचना / NOTICE*" if score >= 20 else "ℹ️ *तपासणी पूर्ण / CHECKED*")

    lines = [
        f"{badge}",
        f"*Seva Cyber Sandbox (Maha-Suraksha)*",
        f"• *धोका निर्देशांक / Risk Score:* {score} / 100",
        f"• *निष्कर्ष / Verdict:* {category}",
        "",
        "*🔍 आढळलेले संकेत / Detected Indicators:*",
    ]

    for f in msg_res.get("findings", [])[:3]:
        lines.append(f"• [{f['category']}] Matched: '{f['matched_text']}'")

    if scheme_res and scheme_res.get("classification") == "CONFLICTING EVIDENCE FOUND":
        lines.append("")
        lines.append("*🏛️ शासकीय योजना पडताळणी / Scheme Check:*")
        lines.append(f"• {scheme_res.get('summary_mr', 'माहिती अधिकृत नियमांशी विसंगत आहे.')}")
        for conf in scheme_res.get("conflicting_evidence", [])[:2]:
            lines.append(f"  - {conf}")

    if url_eval and url_eval.get("score", 0) >= 20:
        lines.append("")
        lines.append("*🌐 संशयास्पद लिंक / Link Check:*")
        lines.append(f"• Host: {url_eval.get('hostname')}")
        lines.append(f"• {url_eval.get('summary_mr')}")

    lines.extend([
        "",
        "*🛡️ सुरक्षित पावले / Safe Next Steps:*",
        "1. कोणत्याही लिंकवर क्लिक करू नका किंवा .apk फाईल इन्स्टॉल करू नका.",
        "2. कोणालाही बँक OTP, ATM पिन किंवा UPI PIN सांगू नका.",
        "3. फसवणूक झाल्यास तात्काळ *1930* सायबर हेल्पलाईनवर संपर्क साधा किंवा *https://cybercrime.gov.in* वर तक्रार नोंदवा.",
        "",
        "_टीप: ही स्वयंचलित तपासणी आहे. अधिकृत माहितीसाठी https://maharashtra.gov.in ला भेट द्या._"
    ])

    return "\n".join(lines)


def format_whatsapp_reply_for_apk(
    apk_res: Dict[str, Any],
    scored_apk: Dict[str, Any],
) -> str:
    """
    Formats a concise bilingual WhatsApp alert for an uploaded APK file.
    """
    score = scored_apk.get("score", 0)
    badge = "🚨 *धोकादायक APK / DANGEROUS APK*" if score >= 50 else "⚠️ *संशयास्पद APK / SUSPICIOUS APK*"

    lines = [
        f"{badge}",
        f"*Seva Cyber Sandbox — Static APK Inspection*",
        f"• *फाईल / File:* {apk_res.get('filename')}",
        f"• *धोका निर्देशांक / Risk Score:* {score} / 100",
        f"• *SHA-256:* `{(apk_res.get('sha256_hash') or '')[:12]}...`",
        "",
        "*🔐 संवेदनशील परवानग्या / Sensitive Permissions Found:*",
    ]

    perms = apk_res.get("permissions_found", [])
    if perms:
        for p in perms[:4]:
            lines.append(f"• *{p['short_name']}* ({p['severity']}): {p['reason_mr']}")
    else:
        lines.append("• कोणतीही अतिसंवेदनशील परवानगी आढळली नाही.")

    lines.extend([
        "",
        "*🛑 तात्काळ कृती / Immediate Action:*",
        "1. ही फाईल इन्स्टॉल करू नका आणि फोनमधून तात्काळ डिलीट करा.",
        "2. अधिकृत ॲप्स फक्त *Google Play Store* वरूनच डाउनलोड करा.",
        "3. व्हॉट्सॲपवर पाठवलेले कोणतेही ॲप अधिकृत नसते.",
        "4. बँक फसवणुकीची तक्रार *1930* वर तात्काळ नोंदवा."
    ])

    return "\n".join(lines)


def dispatch_whatsapp_message(
    recipient_phone: str,
    message_text: str,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Dispatches a reply message to the recipient.
    In 'live' mode: calls the official Meta Graph API.
    In 'simulation' mode: records outbound message in memory outbox.
    """
    cfg = config or load_whatsapp_config()
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # SIMULATION / TEST DISPATCH
    if cfg["mode"] != "live" or not cfg["has_live_credentials"]:
        outbox_entry = {
            "recipient_masked": recipient_phone[:4] + "****" + recipient_phone[-2:] if len(recipient_phone) > 6 else "Anonymous",
            "timestamp_utc": timestamp_utc,
            "mode": "Simulation / Standby",
            "message_text": message_text,
            "status": "Simulated Success (Captured in Sandbox Outbox)",
        }
        _SIMULATED_OUTBOX.append(outbox_entry)
        return {
            "success": True,
            "mode": "simulation",
            "status": "Message queued in simulation outbox.",
            "recipient": outbox_entry["recipient_masked"],
        }

    # LIVE META CLOUD API DISPATCH
    phone_number_id = cfg["phone_number_id"]
    access_token = cfg["access_token"]
    api_version = cfg["api_version"]
    url = f"https://graph.facebook.com/{api_version}/{phone_number_id}/messages"

    payload_data = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": recipient_phone,
        "type": "text",
        "text": {"preview_url": False, "body": message_text},
    }
    payload_bytes = json.dumps(payload_data).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload_bytes,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": "Seva-Cyber-Sandbox/1.0",
        },
        method="POST",
    )

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=5.0, context=ctx) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            return {
                "success": True,
                "mode": "live",
                "status": "Delivered to Meta Cloud API",
                "meta_response": resp_data,
            }
    except Exception as exc:
        return {
            "success": False,
            "mode": "live",
            "status": f"Delivery failure: {exc}",
            "error": str(exc),
        }


def process_incoming_webhook_event(
    raw_payload_bytes: bytes,
    signature_header: Optional[str] = None,
    mock_apk_attachment_bytes: Optional[bytes] = None,
    case_store: Optional[SessionCaseStore] = None,
) -> Dict[str, Any]:
    """
    Main webhook ingress pipeline:
    1. Enforces size limit.
    2. Validates HMAC-SHA256 signature.
    3. Deduplicates incoming message IDs.
    4. Anonymizes sender identifier and applies sliding-window rate limit.
    5. Dispatches to static analyzers and generates compact WhatsApp warning.
    """
    config = load_whatsapp_config()

    # 1. Size limit check
    if len(raw_payload_bytes) > MAX_WEBHOOK_PAYLOAD_BYTES:
        return {
            "status_code": 413,
            "error": "Payload Too Large: Exceeds 16 MB webhook ceiling.",
            "processed": False,
        }

    # 2. HMAC-SHA256 Signature verification
    sig_ok, sig_reason = verify_webhook_signature(
        raw_payload_bytes, signature_header, config["app_secret"]
    )
    if not sig_ok:
        return {
            "status_code": 403,
            "error": f"Forbidden: {sig_reason}",
            "processed": False,
        }

    # 3. Parse JSON
    try:
        body = json.loads(raw_payload_bytes.decode("utf-8"))
    except Exception as exc:
        return {
            "status_code": 400,
            "error": f"Bad Request: Malformed JSON ({exc}).",
            "processed": False,
        }

    # Verify Meta event structure
    if body.get("object") != "whatsapp_business_account":
        return {
            "status_code": 200,
            "message": "Ignored: Non-WhatsApp event object.",
            "processed": False,
        }

    entries = body.get("entry", [])
    if not entries:
        return {"status_code": 200, "message": "No entries in webhook event.", "processed": False}

    results: List[Dict[str, Any]] = []

    for entry in entries:
        for change in entry.get("changes", []):
            val = change.get("value", {})
            messages = val.get("messages", [])

            for msg in messages:
                msg_id = msg.get("id", "")
                from_num = msg.get("from", "")
                msg_type = msg.get("type", "unknown")

                # Idempotency / Duplicate Check
                if is_duplicate_message(msg_id):
                    results.append({
                        "message_id": msg_id,
                        "status": "Ignored duplicate webhook event.",
                        "is_duplicate": True,
                    })
                    continue

                # Anonymize phone number for rate-limiting
                sender_hash = hash_sender_id(from_num, config["sender_salt"])

                # Rate Limiter
                if is_rate_limited(sender_hash):
                    rate_reply = (
                        "⚠️ *Rate Limit Notice / गती मर्यादा*\n"
                        "You have reached the maximum number of queries allowed per minute (10/min).\n"
                        "कृपया १ मिनिटानंतर पुन्हा प्रयत्न करा."
                    )
                    dispatch_whatsapp_message(from_num, rate_reply, config)
                    results.append({
                        "message_id": msg_id,
                        "status": "Rate limited",
                        "sender_hash": sender_hash,
                    })
                    continue

                # Process Text Messages
                if msg_type == "text":
                    raw_text = msg.get("text", {}).get("body", "")[:MAX_TEXT_MESSAGE_CHARS]
                    msg_res = analyze_message_text(raw_text)
                    scored_msg = score_message_analysis(msg_res)

                    # Extract URLs for secondary evaluation
                    url_eval = None
                    if msg_res.get("extracted_urls"):
                        url_eval = analyze_url(msg_res["extracted_urls"][0])

                    # Check for government scheme keywords
                    scheme_res = None
                    if any(k in raw_text.lower() for k in ("ladki", "yojana", "shetkari", "scholarship", "mahavitaran")):
                        scheme_res = verify_scheme_claim(raw_text)

                    # Format WhatsApp Reply
                    reply_text = format_whatsapp_reply_for_message(
                        msg_res=msg_res,
                        scored_msg=scored_msg,
                        scheme_res=scheme_res,
                        url_eval=url_eval,
                    )
                    dispatch_res = dispatch_whatsapp_message(from_num, reply_text, config)

                    # Optional Case Store registration
                    if case_store is not None:
                        case_rec = create_message_case(msg_res, scored_msg, store_raw_text=False)
                        case_store.add_case(case_rec)

                    results.append({
                        "message_id": msg_id,
                        "type": "text",
                        "sender_hash": sender_hash,
                        "risk_score": scored_msg.get("score"),
                        "dispatch": dispatch_res,
                    })

                # Process Document / APK Attachments
                elif msg_type == "document":
                    doc_info = msg.get("document", {})
                    doc_filename = doc_info.get("filename", "attachment.bin")

                    # Handle APK attachment
                    if doc_filename.lower().endswith(".apk"):
                        apk_bytes = mock_apk_attachment_bytes or b""
                        if not apk_bytes:
                            # In live mode without binary payload, report instructions
                            reply_text = (
                                "📦 *APK File Received / फाईल प्राप्त झाली*\n"
                                f"File: {doc_filename}\n"
                                "Analyzing static permissions in memory...\n\n"
                                "🚨 *Warning:* Never install APK files received over WhatsApp. "
                                "Always use the official Google Play Store."
                            )
                        else:
                            apk_res = analyze_apk_bytes(apk_bytes, doc_filename)
                            scored_apk = score_apk_analysis(apk_res)
                            reply_text = format_whatsapp_reply_for_apk(apk_res, scored_apk)

                            if case_store is not None:
                                apk_case = create_apk_case(apk_res, scored_apk)
                                case_store.add_case(apk_case)

                        dispatch_res = dispatch_whatsapp_message(from_num, reply_text, config)
                        results.append({
                            "message_id": msg_id,
                            "type": "document_apk",
                            "filename": doc_filename,
                            "sender_hash": sender_hash,
                            "dispatch": dispatch_res,
                        })

                else:
                    unsupported_reply = (
                        "ℹ️ *Supported Media Types / समर्थित प्रकार:*\n"
                        "Seva Cyber Sandbox currently inspects:\n"
                        "1. Suspicious text messages (Marathi, Romanized Marathi, English)\n"
                        "2. Web links (.xyz, shortened links)\n"
                        "3. Android .apk files\n\n"
                        "Audio/Video analysis is not supported."
                    )
                    dispatch_whatsapp_message(from_num, unsupported_reply, config)
                    results.append({
                        "message_id": msg_id,
                        "type": "unsupported_media",
                        "sender_hash": sender_hash,
                    })

    return {
        "status_code": 200,
        "processed": True,
        "results": results,
    }


def get_simulated_outbox_entries() -> List[Dict[str, Any]]:
    """Returns recent outgoing WhatsApp messages captured during simulation."""
    return list(_SIMULATED_OUTBOX)


def clear_simulated_outbox() -> None:
    """Clears the in-memory outbox."""
    _SIMULATED_OUTBOX.clear()
