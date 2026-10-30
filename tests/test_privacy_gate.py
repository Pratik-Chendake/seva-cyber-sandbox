"""
Unit Test Suite for Local-First Privacy Gate & External Sharing Sanitizer.
Part of Seva Cyber Sandbox (Phase 1).

Covers:
- Indian mobile number variations (standard, prefixed, spaced, Devanagari numerals).
- Aadhaar-like 12-digit identifiers (spaced, hyphenated, contextual).
- Labelled bank accounts, IFSC codes, payment cards.
- Credentials, passwords, OTPs, PINs, auth tokens.
- Labelled personal names and honorific prefixes.
- Email addresses.
- Multi-PII complex messages.
- Benign text usability without unnecessary corruption.
- External-sharing default-denied policy (fail-closed).
- Ambiguous sensitive content fail-closed handling.
- Input validation and exception resilience.
- Assurance that sensitive values are never reflected in logs or error reasons.
- Local analysis preparation (leaves text available for in-memory rules).
- Strict offline execution (zero network calls).
"""

import socket
import urllib.request
import pytest

from src.privacy_gate import (
    AADHAAR_REDACTION_TOKEN,
    AMBIGUOUS_PII_TOKEN,
    BANK_ACCOUNT_REDACTION_TOKEN,
    CARD_REDACTION_TOKEN,
    CREDENTIAL_REDACTION_TOKEN,
    EMAIL_REDACTION_TOKEN,
    NAME_REDACTION_TOKEN,
    PHONE_REDACTION_TOKEN,
    TOKEN_REDACTION_TOKEN,
    PrivacyGateResult,
    normalize_devanagari_numerals,
    prepare_for_local_analysis,
    sanitize_for_external,
)


# ---------------------------------------------------------------------------
# 1. Indian Phone Numbers
# ---------------------------------------------------------------------------

def test_01_phone_number_formats_redacted():
    test_cases = [
        ("Contact us at +91 98765 43210 today.", "98765 43210"),
        ("Call +91-9876543210 immediately.", "9876543210"),
        ("Send SMS to 919876543210 now.", "919876543210"),
        ("Dial 09876543210 to verify.", "09876543210"),
        ("Helpline number is 9876543210.", "9876543210"),
        ("Call on 98765-43210 quickly.", "98765-43210"),
    ]
    for text, raw_val in test_cases:
        res = sanitize_for_external(text, allow_external=True)
        assert res.sanitization_success is True
        assert PHONE_REDACTION_TOKEN in res.sanitized_text
        assert raw_val not in res.sanitized_text
        assert "phone_number" in res.detected_categories


def test_02_devanagari_numerals_phone_redacted():
    # Marathi text with Devanagari numerals for phone: ९८७६५४३२१०
    text = "कृपया या ९८७६५४३२१० नंबरवर संपर्क साधा."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert PHONE_REDACTION_TOKEN in res.sanitized_text
    assert "९८७६५४३२१०" not in res.sanitized_text
    assert "phone_number" in res.detected_categories


# ---------------------------------------------------------------------------
# 2. Aadhaar Numbers
# ---------------------------------------------------------------------------

def test_03_aadhaar_identifier_variations_redacted():
    test_cases = [
        ("Aadhaar link: 2345 6789 0123 update required.", "2345 6789 0123"),
        ("Aadhaar card 2345-6789-0123 eKYC pending.", "2345-6789-0123"),
        ("UIDAI verification for Aadhaar: 234567890123.", "234567890123"),
        ("तुमचा आधार क्रमांक 2345 6789 0123 ब्लॉक झाला आहे.", "2345 6789 0123"),
    ]
    for text, raw_val in test_cases:
        res = sanitize_for_external(text, allow_external=True)
        assert res.sanitization_success is True
        assert AADHAAR_REDACTION_TOKEN in res.sanitized_text
        assert raw_val not in res.sanitized_text
        assert "aadhaar_number" in res.detected_categories


# ---------------------------------------------------------------------------
# 3. Bank Accounts, IFSC, Cards
# ---------------------------------------------------------------------------

def test_04_labelled_bank_account_and_ifsc_redacted():
    text = "Transfer to A/C No: 123456789012, IFSC: SBIN0001234."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert BANK_ACCOUNT_REDACTION_TOKEN in res.sanitized_text
    assert "123456789012" not in res.sanitized_text
    assert "SBIN0001234" not in res.sanitized_text
    assert "bank_account_number" in res.detected_categories
    assert "ifsc_code" in res.detected_categories


def test_05_marathi_labelled_bank_account_redacted():
    text = "तुमचे खाते क्र: 987654321098 तपासण्यात आले आहे."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert BANK_ACCOUNT_REDACTION_TOKEN in res.sanitized_text
    assert "987654321098" not in res.sanitized_text


def test_06_credit_debit_card_redacted():
    text = "Payment card: 4111 2222 3333 4444 submitted."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert CARD_REDACTION_TOKEN in res.sanitized_text
    assert "4111 2222 3333 4444" not in res.sanitized_text
    assert "payment_card_number" in res.detected_categories


# ---------------------------------------------------------------------------
# 4. Credentials, Passwords, OTPs, Tokens
# ---------------------------------------------------------------------------

def test_07_otps_passwords_and_tokens_redacted():
    text = (
        "Your OTP is 482910. PIN: 1234. Password is MySecretPassword99! "
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123"
    )
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert "482910" not in res.sanitized_text
    assert "MySecretPassword99!" not in res.sanitized_text
    assert "token123" not in res.sanitized_text
    assert CREDENTIAL_REDACTION_TOKEN in res.sanitized_text
    assert TOKEN_REDACTION_TOKEN in res.sanitized_text


# ---------------------------------------------------------------------------
# 5. Labelled Personal Names & Honorifics
# ---------------------------------------------------------------------------

def test_08_labelled_personal_names_and_honorifics_redacted():
    text = "Customer Name: Ramesh Kumar Sharma. Beneficiary: Sunita Deshmukh. Shri Rajesh Pawar approved."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert "Ramesh Kumar Sharma" not in res.sanitized_text
    assert "Sunita Deshmukh" not in res.sanitized_text
    assert "Rajesh Pawar" not in res.sanitized_text
    assert NAME_REDACTION_TOKEN in res.sanitized_text
    assert "personal_name" in res.detected_categories


def test_09_marathi_labelled_name_redacted():
    text = "धारक: तुकाराम पांडुरंग शिंदे यांचे वीज बिल बाकी आहे."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert "तुकाराम पांडुरंग शिंदे" not in res.sanitized_text
    assert NAME_REDACTION_TOKEN in res.sanitized_text


# ---------------------------------------------------------------------------
# 6. Email Addresses
# ---------------------------------------------------------------------------

def test_10_email_addresses_redacted():
    text = "Send confirmation to citizen.help@mahadiscom.in or user123@gmail.com."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert "citizen.help@mahadiscom.in" not in res.sanitized_text
    assert "user123@gmail.com" not in res.sanitized_text
    assert EMAIL_REDACTION_TOKEN in res.sanitized_text
    assert "email_address" in res.detected_categories


# ---------------------------------------------------------------------------
# 7. Multi-PII Complex Message
# ---------------------------------------------------------------------------

def test_11_multiple_sensitive_values_in_single_message():
    raw_msg = (
        "Dear Customer Name: Aniket Kulkarni, your SBI A/c 123456789012 has received a refund. "
        "Aadhaar 3456 7890 1234 link pending. Your OTP is 987654. "
        "Call officer at +91 98220 12345 or email aniket@kulkarni.org. "
        "Avoid blocking by entering PIN: 4321."
    )
    res = sanitize_for_external(raw_msg, allow_external=True)
    assert res.sanitization_success is True
    # Zero sensitive values leaked
    assert "Aniket Kulkarni" not in res.sanitized_text
    assert "123456789012" not in res.sanitized_text
    assert "3456 7890 1234" not in res.sanitized_text
    assert "987654" not in res.sanitized_text
    assert "98220 12345" not in res.sanitized_text
    assert "aniket@kulkarni.org" not in res.sanitized_text
    assert "4321" not in res.sanitized_text

    expected_cats = {
        "personal_name", "bank_account_number", "aadhaar_number",
        "otp", "phone_number", "email_address", "pin",
    }
    for cat in expected_cats:
        assert cat in res.detected_categories


# ---------------------------------------------------------------------------
# 8. Benign Message Usability
# ---------------------------------------------------------------------------

def test_12_benign_messages_remain_usable():
    benign_text = (
        "सर्व नागरिकांना सूचित करण्यात येते की उद्या ग्रामपंचायतीची बैठक "
        "सकाळी ११ वाजता आयोजित करण्यात आली आहे. सर्वांनी उपस्थित राहावे."
    )
    res = sanitize_for_external(benign_text, allow_external=True)
    assert res.sanitization_success is True
    assert res.safe_to_send is True
    assert "ग्रामपंचायतीची बैठक" in res.sanitized_text
    assert len(res.detected_categories) == 0


# ---------------------------------------------------------------------------
# 9. External Sharing Default-Denied (Fail-Closed)
# ---------------------------------------------------------------------------

def test_13_external_sharing_disabled_by_default():
    text = "Hello world, simple message."
    # Calling without allow_external=True must ALWAYS result in safe_to_send = False
    res = sanitize_for_external(text)
    assert res.safe_to_send is False
    assert any("disabled by default" in reason.lower() for reason in res.blocking_reasons)


def test_14_fail_closed_on_ambiguous_long_numeric():
    # 13 unlabelled digits that could be a card or account
    text = "Your reference code is 98765432109876 for inspection."
    res = sanitize_for_external(text, allow_external=True)
    # Ambiguous long numeric triggers fail-closed
    assert res.safe_to_send is False
    assert "ambiguous_unclassified_numeric" in res.detected_categories
    assert any("unclassified" in r.lower() for r in res.blocking_reasons)
    assert AMBIGUOUS_PII_TOKEN in res.sanitized_text


# ---------------------------------------------------------------------------
# 10. Robustness, Type Handling & Zero PII Leakage in Errors
# ---------------------------------------------------------------------------

def test_15_fail_closed_on_none_and_invalid_types():
    res_none = sanitize_for_external(None, allow_external=True)
    assert res_none.sanitization_success is False
    assert res_none.safe_to_send is False
    assert res_none.sanitized_text is None

    res_int = sanitize_for_external(12345, allow_external=True)
    assert res_int.sanitization_success is False
    assert res_int.safe_to_send is False


def test_16_no_sensitive_values_in_errors_or_categories():
    raw_secret = "UltraSecretPassword998877"
    raw_phone = "+91 99887 76655"
    text = f"Password is {raw_secret} and call {raw_phone}"
    res = sanitize_for_external(text, allow_external=False)

    report_str = str(res.to_dict())
    assert raw_secret not in report_str
    assert raw_phone not in report_str
    assert raw_phone.replace(" ", "") not in report_str


# ---------------------------------------------------------------------------
# 11. Local Analysis Support (Does NOT Block Local Detection)
# ---------------------------------------------------------------------------

def test_17_prepare_for_local_analysis_does_not_block():
    text = "तातडीने वीज बिल भरा. संपर्क: 9876543210. OTP कोणाला सांगू नका."
    local_prep = prepare_for_local_analysis(text)

    assert local_prep["is_valid"] is True
    # Crucial requirement: raw text remains accessible in RAM for local rule matching
    assert "9876543210" in local_prep["text"]
    assert "phone_number" in local_prep["detected_categories"]
    assert local_prep["character_count"] == len(text)
    assert local_prep["error"] is None


def test_18_strict_offline_zero_network_calls(monkeypatch):
    def _blocked_connect(*args, **kwargs):
        raise AssertionError("Network connection attempted during privacy sanitization!")

    monkeypatch.setattr(socket, "create_connection", _blocked_connect)
    monkeypatch.setattr(urllib.request, "urlopen", _blocked_connect)

    text = "Citizen message with http://phish-site.top?token=secret123 and phone 9876543210."
    res = sanitize_for_external(text, allow_external=True)
    assert res.sanitization_success is True
    assert "9876543210" not in res.sanitized_text


# ---------------------------------------------------------------------------
# 12. SEC-02 Regression: Exact Devanagari Aadhaar and OTP Redaction
# ---------------------------------------------------------------------------

def test_19_sec_02_devanagari_aadhaar_and_otp_exact_redaction():
    # 1. Formatted Aadhaar with ASCII digits
    ascii_aadh = "Applicant Aadhaar 2345 6789 0123 submitted for verification."
    res_a1 = sanitize_for_external(ascii_aadh, allow_external=True)
    assert res_a1.sanitization_success is True
    assert res_a1.safe_to_send is True
    assert AADHAAR_REDACTION_TOKEN in res_a1.sanitized_text
    assert "2345 6789 0123" not in res_a1.sanitized_text
    assert res_a1.sanitized_text == "Applicant Aadhaar [AADHAAR_REDACTED] submitted for verification."

    # 2. Formatted Aadhaar with Devanagari digits (spaced)
    dev_aadh = "तुमचा आधार क्रमांक २३४५ ६७८९ ०१२३ ब्लॉक झाला आहे."
    res_a2 = sanitize_for_external(dev_aadh, allow_external=True)
    assert res_a2.sanitization_success is True
    assert res_a2.safe_to_send is True
    assert AADHAAR_REDACTION_TOKEN in res_a2.sanitized_text
    assert "२३४५ ६७८९ ०१२३" not in res_a2.sanitized_text
    assert "२३४५" not in res_a2.sanitized_text
    assert "६७८९" not in res_a2.sanitized_text
    assert "०१२३" not in res_a2.sanitized_text
    assert "तुमचा आधार क्रमांक [AADHAAR_REDACTED] ब्लॉक झाला आहे." == res_a2.sanitized_text

    # 3. Formatted Aadhaar with Devanagari digits (hyphenated)
    dev_aadh_hyphen = "आधार कार्ड २३४५-६७८९-०१२३ त्वरित लिंक करा."
    res_a3 = sanitize_for_external(dev_aadh_hyphen, allow_external=True)
    assert res_a3.sanitization_success is True
    assert res_a3.safe_to_send is True
    assert AADHAAR_REDACTION_TOKEN in res_a3.sanitized_text
    assert "२३४५-६७८९-०१२३" not in res_a3.sanitized_text
    assert "आधार कार्ड [AADHAAR_REDACTED] त्वरित लिंक करा." == res_a3.sanitized_text

    # 4. OTP following a Marathi label with Devanagari digits
    dev_otp_mr = "तुमचा ओटीपी आहे ४८२९ त्वरित प्रविष्ट करा."
    res_o1 = sanitize_for_external(dev_otp_mr, allow_external=True)
    assert res_o1.sanitization_success is True
    assert res_o1.safe_to_send is True
    assert CREDENTIAL_REDACTION_TOKEN in res_o1.sanitized_text
    assert "४८२९" not in res_o1.sanitized_text
    assert "तुमचा ओटीपी: [CREDENTIAL_REDACTED] त्वरित प्रविष्ट करा." == res_o1.sanitized_text

    dev_otp_colon = "ओटीपी: १२३४५६ कोणाशीही शेअर करू नका."
    res_o2 = sanitize_for_external(dev_otp_colon, allow_external=True)
    assert res_o2.sanitization_success is True
    assert res_o2.safe_to_send is True
    assert CREDENTIAL_REDACTION_TOKEN in res_o2.sanitized_text
    assert "१२३४५६" not in res_o2.sanitized_text
    assert "ओटीपी: [CREDENTIAL_REDACTED] कोणाशीही शेअर करू नका." == res_o2.sanitized_text

    # 5. OTP following an English label with Devanagari digits
    dev_otp_en = "Your OTP is १२३४५६ for transaction."
    res_o3 = sanitize_for_external(dev_otp_en, allow_external=True)
    assert res_o3.sanitization_success is True
    assert res_o3.safe_to_send is True
    assert CREDENTIAL_REDACTION_TOKEN in res_o3.sanitized_text
    assert "१२३४५६" not in res_o3.sanitized_text
    assert "Your OTP: [CREDENTIAL_REDACTED] for transaction." == res_o3.sanitized_text

    # 6. Mixed Marathi-English text containing both Aadhaar-like and OTP values
    mixed_msg = "Applicant Aadhaar २३४५ ६७८९ ०१२३, OTP: ४८२९१० received."
    res_m = sanitize_for_external(mixed_msg, allow_external=True)
    assert res_m.sanitization_success is True
    assert res_m.safe_to_send is True
    assert AADHAAR_REDACTION_TOKEN in res_m.sanitized_text
    assert CREDENTIAL_REDACTION_TOKEN in res_m.sanitized_text
    assert "२३४५ ६७८९ ०१२३" not in res_m.sanitized_text
    assert "४८२९१०" not in res_m.sanitized_text
    assert "Applicant Aadhaar [AADHAAR_REDACTED], OTP: [CREDENTIAL_REDACTED] received." == res_m.sanitized_text


def test_20_sec_02_benign_marathi_and_ambiguous_numerics():
    # 7. Benign Marathi text that should remain readable
    benign_texts = [
        "महावितरणच्या अधिकृत केंद्रात जाऊन वीज बिल भरावे.",
        "पंतप्रधान किसान सन्मान निधी योजनेचा लाभ घेण्यासाठी अधिकृत संकेतस्थळाला भेट द्या.",
        "दिवाळीच्या हार्दिक शुभेच्छा! आज संध्याकाळी ५ वाजता कार्यक्रम आहे.",
    ]
    for b_text in benign_texts:
        res_b = sanitize_for_external(b_text, allow_external=True)
        assert res_b.sanitization_success is True
        assert res_b.safe_to_send is True
        assert res_b.sanitized_text == b_text, "Benign Marathi text was corrupted!"
        assert len(res_b.detected_categories) == 0

    # 8. Ambiguous numeric data in Devanagari (>= 9 digits) that must fail closed
    ambig_dev = "रेफरन्स ट्रॅकिंग क्रमांक १२३४५६७८९०१ नोंदवला आहे."
    res_amb = sanitize_for_external(ambig_dev, allow_external=True)
    assert res_amb.sanitization_success is True
    # Crucial security guarantee: fail-closed on unclassified long numeric strings
    assert res_amb.safe_to_send is False
    assert "ambiguous_unclassified_numeric" in res_amb.detected_categories
    assert AMBIGUOUS_PII_TOKEN in res_amb.sanitized_text
    assert "१२३४५६७८९०१" not in res_amb.sanitized_text
    assert any("unclassified long numeric" in r for r in res_amb.blocking_reasons)
