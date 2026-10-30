"""
Privacy Gate & Conservative Data Sanitization Module.
Part of Seva Cyber Sandbox (Phase 1).

SECURITY & PRIVACY ARCHITECTURE:
1. Two Distinct Use Cases:
   A. Local Analysis (local-first):
      Existing APK, URL, and vernacular phishing detection operates locally in-memory.
      Local analysis is NOT blocked simply because a message contains a phone number,
      citizen name, or other personal detail.
   B. External-Sharing Preparation:
      Separate, explicitly invoked sanitization interface (`sanitize_for_external`).
      External sharing is DISABLED by default (safe_to_send = False).
      Zero network transmission occurs in this phase.
2. Fail-Closed Design:
   Any uncertainty, detected ambiguity, or sanitization failure produces
   `safe_to_send = False`.
3. Conservative Redaction:
   Detects and masks Indian mobile numbers, Aadhaar-like 12-digit identifiers,
   labelled bank account numbers, credentials/passwords/OTPs/tokens, labelled
   personal names, credit/debit card numbers, and email addresses.
4. Logging & Error Safety:
   Original sensitive values are NEVER included in warning messages, errors, or logs.
   Deterministic markers (e.g. `[PHONE_REDACTED]`, `[CREDENTIAL_REDACTED]`) are used.

DOCUMENTED LIMITATIONS:
- Regular expressions cannot reliably identify every arbitrary person's name in
  free-form unstructured vernacular text without grammatical context or explicit labels.
- Bank account numbers appearing without keywords or structured labels (e.g., bare 11-digit
  numbers) cannot be distinguished with certainty from tracking IDs, transaction amounts,
  or timestamps. If such ambiguity is detected, external sharing fails closed.
"""

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Deterministic Redaction Tokens
PHONE_REDACTION_TOKEN = "[PHONE_REDACTED]"
AADHAAR_REDACTION_TOKEN = "[AADHAAR_REDACTED]"
BANK_ACCOUNT_REDACTION_TOKEN = "[BANK_ACCOUNT_REDACTED]"
CREDENTIAL_REDACTION_TOKEN = "[CREDENTIAL_REDACTED]"
TOKEN_REDACTION_TOKEN = "[TOKEN_REDACTED]"
NAME_REDACTION_TOKEN = "[NAME_REDACTED]"
EMAIL_REDACTION_TOKEN = "[EMAIL_REDACTED]"
CARD_REDACTION_TOKEN = "[CARD_REDACTED]"
AMBIGUOUS_PII_TOKEN = "[PII_REDACTED]"

# Devanagari to ASCII digit mapping
DEVANAGARI_DIGITS = "०१२३४५६७८९"
ASCII_DIGITS = "0123456789"
DEV_TO_ASCII_MAP = str.maketrans(DEVANAGARI_DIGITS, ASCII_DIGITS)


@dataclass
class PrivacyGateResult:
    """
    Structured outcome of the privacy sanitization gate.
    """
    sanitized_text: Optional[str]
    sanitization_success: bool
    safe_to_send: bool
    detected_categories: List[str] = field(default_factory=list)
    blocking_reasons: List[str] = field(default_factory=list)
    redaction_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Returns dictionary representation."""
        return asdict(self)


def normalize_devanagari_numerals(text: str) -> str:
    """Translates Devanagari numerals (०-९) to ASCII numerals (0-9)."""
    if not text:
        return ""
    return text.translate(DEV_TO_ASCII_MAP)


# =============================================================================
# REGEX PATTERNS FOR CONSERVATIVE SENSITIVE DATA REDACTION
# =============================================================================

# Word boundaries for multilingual text (supporting ASCII and Devanagari character sets)
WORD_START = r"(?<![A-Za-z0-9\u0900-\u097F])"
WORD_END = r"(?![A-Za-z0-9\u0900-\u097F])"
DIGIT_CHAR = r"[0-9०-९]"
AADHAAR_FIRST_DIGIT = r"[2-9२-९]"

# 1. Email Addresses
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

# 2. Indian Mobile Numbers (ASCII and Devanagari numerals)
# Matches +91, 91, or 0 prefixes with 10 digits starting with [6-9] / [६-९],
# with optional spaces or hyphens between digit groups.
RE_PHONE_PREFIXED = re.compile(
    r"(?:\+91[\s\-\.]?|91[\s\-\.]?|0[\s\-\.]?|\+?९१[\s\-\.]?|०[\s\-\.]?)[6-9६-९][0-9०-९]{4}[\s\-\.]?[0-9०-९]{5}\b"
)
RE_PHONE_STANDALONE = re.compile(
    r"\b[6-9६-९][0-9०-९]{4}[\s\-\.]?[0-9०-९]{5}\b"
)
RE_PHONE_TIGHT = re.compile(
    r"\b[6-9६-९][0-9०-९]{9}\b"
)

# 3. Aadhaar-like 12-digit Identifiers (SEC-02 FIX)
# Standard 4-4-4 spacing or hyphenation with ASCII or Devanagari numerals
RE_AADHAAR_FORMATTED = re.compile(
    rf"(?<!{DIGIT_CHAR}){AADHAAR_FIRST_DIGIT}{DIGIT_CHAR}{{3}}[\s\-]{DIGIT_CHAR}{{4}}[\s\-]{DIGIT_CHAR}{{4}}(?!{DIGIT_CHAR})"
)
# Contextual unformatted 12-digit Aadhaar (preceded by Aadhaar / आधार keywords)
RE_AADHAAR_CONTEXTUAL = re.compile(
    rf"(?i){WORD_START}(aadhaar|uidai|आधार|aadhar){WORD_END}\s*(?:card|कार्ड|no\.?|number|क्रमांक|क्र\.?)?\s*[:=-]?\s*({AADHAAR_FIRST_DIGIT}{DIGIT_CHAR}{{11}})(?!{DIGIT_CHAR})"
)
# Standalone unformatted 12-digit number (starts with 2-9)
RE_AADHAAR_UNFORMATTED = re.compile(
    rf"(?<!{DIGIT_CHAR}){AADHAAR_FIRST_DIGIT}{DIGIT_CHAR}{{11}}(?!{DIGIT_CHAR})"
)

# 4. Bank Account Numbers & Financial Identifiers
# Labelled bank account numbers (9-18 digits) supporting Devanagari numerals
RE_BANK_ACCOUNT_LABELLED = re.compile(
    rf"(?i){WORD_START}(a\/c|acct|account|खाते){WORD_END}\s*(?:no\.?|number|num|क्रमांक|क्र\.?)?\s*[:=-]?\s*({DIGIT_CHAR}{{9,18}})(?!{DIGIT_CHAR})"
)
# Indian Financial System Code (IFSC)
RE_IFSC_CODE = re.compile(
    r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
)
# Credit / Debit Cards (16 digits with common 4-4-4-4 grouping or continuous)
RE_CARD_FORMATTED = re.compile(
    r"\b(?:4\d{3}|5[1-5]\d{2}|6011|65\d{2})[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"
)
RE_CARD_CONTINUOUS = re.compile(
    r"\b(?:4\d{15}|5[1-5]\d{14}|6011\d{12}|65\d{14})\b"
)

# 5. Credentials, Passwords, OTPs, Tokens (SEC-02 FIX)
# Supports Marathi and English labels, connectors (आहे, :, -, code, क्रमांक), and Devanagari/ASCII digits
RE_OTP = re.compile(
    rf"(?i){WORD_START}(otp|one\s*time\s*password|ओटीपी|verification\s*code|सत्यापन\s*कोड|सुरक्षा\s*कोड){WORD_END}\s*(?:is|code|no\.?|क्रमांक|कोड|आहे|:|-|=|\s)*\s*({DIGIT_CHAR}{{4,8}})(?!{DIGIT_CHAR})"
)
RE_PIN = re.compile(
    rf"(?i){WORD_START}(pin|mpin|upi\s*pin|atm\s*pin|पिन){WORD_END}\s*(?:is|क्रमांक|कोड|आहे|:|-|=|\s)*\s*({DIGIT_CHAR}{{4,6}})(?!{DIGIT_CHAR})"
)
RE_PASSWORD_LABELLED = re.compile(
    rf"(?i){WORD_START}(password|passwd|pwd|पासवर्ड){WORD_END}\s*(?:is|आहे|:|-|=|\s)*\s*([^\s,;]+)"
)
RE_CVV = re.compile(
    rf"(?i){WORD_START}(cvv|cvv2|cvc){WORD_END}\s*(?:is|:|-|=|\s)*\s*({DIGIT_CHAR}{{3,4}})(?!{DIGIT_CHAR})"
)
RE_AUTH_BEARER = re.compile(
    r"\bBearer\s+[A-Za-z0-9_\-\.]{16,}\b"
)
RE_AUTH_KEY_LABELLED = re.compile(
    r"(?i)\b(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|private[_\-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{12,})['\"]?"
)

# 6. Personal Names with Explicit Labels or Honorifics
RE_NAME_LABELLED = re.compile(
    r"(?i)\b(name|full\s*name|customer(?:\s*name)?|beneficiary(?:\s*name)?|नाव|युझर|धारक)\s*[:=-]\s*([A-Za-z\u0900-\u097F]+(?:\s+[A-Za-z\u0900-\u097F]+){0,3})"
)
RE_NAME_HONORIFIC = re.compile(
    r"\b(Mr\.|Mrs\.|Ms\.|Shri|Smt\.|श्री|श्रीमती)\s+([A-Za-z\u0900-\u097F]{2,25}(?:\s+[A-Za-z\u0900-\u097F]{2,25}){1,2})\b"
)


# =============================================================================
# LOCAL ANALYSIS INTERFACE (LOCAL-FIRST DESIGN)
# =============================================================================

def prepare_for_local_analysis(text: Any) -> Dict[str, Any]:
    """
    Validates and prepares input for in-memory local analysis.

    CRITICAL PRIVACY GUARANTEE:
    - Does NOT block local processing when personal data is present.
    - Message text remains exclusively in RAM for local rule matching.
    - Zero network requests are made.
    - Raw text is NEVER persisted to the SQLite database.
    """
    if text is None:
        return {
            "is_valid": False,
            "text": "",
            "detected_categories": [],
            "character_count": 0,
            "error": "Input text cannot be None.",
        }

    raw_str = str(text)
    char_len = len(raw_str)

    if char_len == 0:
        return {
            "is_valid": True,
            "text": "",
            "detected_categories": [],
            "character_count": 0,
            "error": None,
        }

    if char_len > 50000:
        return {
            "is_valid": False,
            "text": "",
            "detected_categories": [],
            "character_count": char_len,
            "error": "Input exceeds maximum safe local length (50,000 characters).",
        }

    # Passively detect categories present for facilitator awareness
    categories_found: Set[str] = set()
    norm_text = normalize_devanagari_numerals(raw_str)

    if RE_EMAIL.search(raw_str):
        categories_found.add("email_address")
    if (
        RE_PHONE_PREFIXED.search(raw_str)
        or RE_PHONE_STANDALONE.search(raw_str)
        or RE_PHONE_TIGHT.search(raw_str)
        or RE_PHONE_PREFIXED.search(norm_text)
        or RE_PHONE_STANDALONE.search(norm_text)
        or RE_PHONE_TIGHT.search(norm_text)
    ):
        categories_found.add("phone_number")
    if (
        RE_AADHAAR_FORMATTED.search(raw_str)
        or RE_AADHAAR_CONTEXTUAL.search(raw_str)
        or RE_AADHAAR_FORMATTED.search(norm_text)
        or RE_AADHAAR_CONTEXTUAL.search(norm_text)
    ):
        categories_found.add("aadhaar_identifier")
    if (
        RE_BANK_ACCOUNT_LABELLED.search(raw_str)
        or RE_BANK_ACCOUNT_LABELLED.search(norm_text)
        or RE_IFSC_CODE.search(raw_str)
    ):
        categories_found.add("bank_account_details")
    if (
        RE_OTP.search(raw_str)
        or RE_OTP.search(norm_text)
        or RE_PIN.search(raw_str)
        or RE_PIN.search(norm_text)
        or RE_PASSWORD_LABELLED.search(raw_str)
        or RE_AUTH_BEARER.search(raw_str)
        or RE_AUTH_KEY_LABELLED.search(raw_str)
        or RE_CVV.search(raw_str)
        or RE_CVV.search(norm_text)
    ):
        categories_found.add("credentials_or_secrets")
    if RE_NAME_LABELLED.search(raw_str) or RE_NAME_HONORIFIC.search(raw_str):
        categories_found.add("personal_name_labelled")
    if (
        RE_CARD_FORMATTED.search(norm_text)
        or RE_CARD_CONTINUOUS.search(norm_text)
        or RE_CARD_FORMATTED.search(raw_str)
    ):
        categories_found.add("payment_card_number")

    return {
        "is_valid": True,
        "text": raw_str,
        "detected_categories": sorted(list(categories_found)),
        "character_count": char_len,
        "error": None,
    }


# =============================================================================
# EXTERNAL SHARING SANITIZATION (FAIL-CLOSED DESIGN)
# =============================================================================

def sanitize_for_external(
    text: Any,
    allow_external: bool = False,
    max_unclassified_digits: int = 8,
) -> PrivacyGateResult:
    """
    Sanitizes text specifically for potential future external sharing.

    SAFETY & FAIL-CLOSED BOUNDARIES:
    - External sharing is DISABLED BY DEFAULT (allow_external=False).
    - If allow_external is False, safe_to_send is GUARANTEED to be False.
    - If sanitization fails, encounters an exception, or detects unresolved
      ambiguous sensitive identifiers, safe_to_send is ALWAYS False.
    - Deterministic redaction tokens replace detected sensitive content.
    - Original sensitive values are NEVER included in returned messages.

    Args:
        text: Raw text to sanitize.
        allow_external: Explicit administrative toggle (default: False).
        max_unclassified_digits: Maximum length of unclassified digit sequence
                                 permitted before triggering an ambiguity block.

    Returns:
        PrivacyGateResult with sanitized_text, sanitization_success,
        safe_to_send, detected_categories, blocking_reasons, and redaction_counts.
    """
    blocking_reasons: List[str] = []
    detected_categories: Set[str] = set()
    redaction_counts: Dict[str, int] = {}

    # Policy Check: External sharing disabled by default in Phase 1
    if not allow_external:
        blocking_reasons.append(
            "External sharing is disabled by default (Phase 1 local-first policy)."
        )

    if text is None:
        blocking_reasons.append("Input text is None.")
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    if not isinstance(text, str):
        blocking_reasons.append(f"Input must be string, got {type(text).__name__}.")
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    if len(text.strip()) == 0:
        return PrivacyGateResult(
            sanitized_text="",
            sanitization_success=True,
            safe_to_send=allow_external,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    if len(text) > 50000:
        blocking_reasons.append(
            "Input exceeds maximum sanitization size (50,000 characters)."
        )
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    try:
        working_text = text

        # Step 1: Redact Bearer Tokens & API Keys
        def _sub_token(m):
            return TOKEN_REDACTION_TOKEN

        def _sub_bearer(m):
            return f"Bearer {TOKEN_REDACTION_TOKEN}"

        b_matches = len(RE_AUTH_BEARER.findall(working_text))
        if b_matches > 0:
            working_text = RE_AUTH_BEARER.sub(_sub_bearer, working_text)
            detected_categories.add("authentication_token")
            redaction_counts["authentication_token"] = redaction_counts.get("authentication_token", 0) + b_matches

        k_matches = len(RE_AUTH_KEY_LABELLED.findall(working_text))
        if k_matches > 0:
            working_text = RE_AUTH_KEY_LABELLED.sub(r"\1: " + TOKEN_REDACTION_TOKEN, working_text)
            detected_categories.add("api_key")
            redaction_counts["api_key"] = redaction_counts.get("api_key", 0) + k_matches

        # Step 2: Redact Passwords
        p_matches = len(RE_PASSWORD_LABELLED.findall(working_text))
        if p_matches > 0:
            working_text = RE_PASSWORD_LABELLED.sub(r"password: " + CREDENTIAL_REDACTION_TOKEN, working_text)
            detected_categories.add("password")
            redaction_counts["password"] = redaction_counts.get("password", 0) + p_matches

        # Step 3: Redact Email Addresses
        e_matches = len(RE_EMAIL.findall(working_text))
        if e_matches > 0:
            working_text = RE_EMAIL.sub(EMAIL_REDACTION_TOKEN, working_text)
            detected_categories.add("email_address")
            redaction_counts["email_address"] = redaction_counts.get("email_address", 0) + e_matches

        # Step 4: Redact Labelled Bank Accounts & Cards
        c_matches = len(RE_CARD_FORMATTED.findall(working_text)) + len(RE_CARD_CONTINUOUS.findall(working_text))
        if c_matches > 0:
            working_text = RE_CARD_FORMATTED.sub(CARD_REDACTION_TOKEN, working_text)
            working_text = RE_CARD_CONTINUOUS.sub(CARD_REDACTION_TOKEN, working_text)
            detected_categories.add("payment_card_number")
            redaction_counts["payment_card_number"] = redaction_counts.get("payment_card_number", 0) + c_matches

        ba_matches = len(RE_BANK_ACCOUNT_LABELLED.findall(working_text))
        if ba_matches > 0:
            working_text = RE_BANK_ACCOUNT_LABELLED.sub(lambda m: f"{m.group(1)}: {BANK_ACCOUNT_REDACTION_TOKEN}", working_text)
            detected_categories.add("bank_account_number")
            redaction_counts["bank_account_number"] = redaction_counts.get("bank_account_number", 0) + ba_matches

        ifsc_matches = len(RE_IFSC_CODE.findall(working_text))
        if ifsc_matches > 0:
            working_text = RE_IFSC_CODE.sub(BANK_ACCOUNT_REDACTION_TOKEN, working_text)
            detected_categories.add("ifsc_code")
            redaction_counts["ifsc_code"] = redaction_counts.get("ifsc_code", 0) + ifsc_matches

        # Step 5: Redact OTPs, PINs, CVV (Operates directly on working_text, supporting Devanagari)
        otp_matches = len(RE_OTP.findall(working_text))
        if otp_matches > 0:
            working_text = RE_OTP.sub(lambda m: f"{m.group(1)}: {CREDENTIAL_REDACTION_TOKEN}", working_text)
            detected_categories.add("otp")
            redaction_counts["otp"] = redaction_counts.get("otp", 0) + otp_matches

        pin_matches = len(RE_PIN.findall(working_text))
        if pin_matches > 0:
            working_text = RE_PIN.sub(lambda m: f"{m.group(1)}: {CREDENTIAL_REDACTION_TOKEN}", working_text)
            detected_categories.add("pin")
            redaction_counts["pin"] = redaction_counts.get("pin", 0) + pin_matches

        cvv_matches = len(RE_CVV.findall(working_text))
        if cvv_matches > 0:
            working_text = RE_CVV.sub(lambda m: f"{m.group(1)}: {CREDENTIAL_REDACTION_TOKEN}", working_text)
            detected_categories.add("cvv")
            redaction_counts["cvv"] = redaction_counts.get("cvv", 0) + cvv_matches

        # Step 6: Redact Aadhaar Numbers (Operates directly on working_text, supporting Devanagari)
        aadh_f_matches = len(RE_AADHAAR_FORMATTED.findall(working_text))
        if aadh_f_matches > 0:
            working_text = RE_AADHAAR_FORMATTED.sub(AADHAAR_REDACTION_TOKEN, working_text)
            detected_categories.add("aadhaar_number")
            redaction_counts["aadhaar_number"] = redaction_counts.get("aadhaar_number", 0) + aadh_f_matches

        aadh_c_matches = len(RE_AADHAAR_CONTEXTUAL.findall(working_text))
        if aadh_c_matches > 0:
            working_text = RE_AADHAAR_CONTEXTUAL.sub(lambda m: f"{m.group(1)}: {AADHAAR_REDACTION_TOKEN}", working_text)
            detected_categories.add("aadhaar_number")
            redaction_counts["aadhaar_number"] = redaction_counts.get("aadhaar_number", 0) + aadh_c_matches

        # Step 7: Redact Indian Mobile Numbers (Operates directly on working_text, supporting Devanagari)
        p_pre_matches = len(RE_PHONE_PREFIXED.findall(working_text))
        if p_pre_matches > 0:
            working_text = RE_PHONE_PREFIXED.sub(PHONE_REDACTION_TOKEN, working_text)
            detected_categories.add("phone_number")
            redaction_counts["phone_number"] = redaction_counts.get("phone_number", 0) + p_pre_matches

        p_std_matches = len(RE_PHONE_STANDALONE.findall(working_text))
        if p_std_matches > 0:
            working_text = RE_PHONE_STANDALONE.sub(PHONE_REDACTION_TOKEN, working_text)
            detected_categories.add("phone_number")
            redaction_counts["phone_number"] = redaction_counts.get("phone_number", 0) + p_std_matches

        p_tgt_matches = len(RE_PHONE_TIGHT.findall(working_text))
        if p_tgt_matches > 0:
            working_text = RE_PHONE_TIGHT.sub(PHONE_REDACTION_TOKEN, working_text)
            detected_categories.add("phone_number")
            redaction_counts["phone_number"] = redaction_counts.get("phone_number", 0) + p_tgt_matches

        # Step 8: Redact Labelled Personal Names
        n_lbl_matches = len(RE_NAME_LABELLED.findall(working_text))
        if n_lbl_matches > 0:
            working_text = RE_NAME_LABELLED.sub(r"\1: " + NAME_REDACTION_TOKEN, working_text)
            detected_categories.add("personal_name")
            redaction_counts["personal_name"] = redaction_counts.get("personal_name", 0) + n_lbl_matches

        n_hon_matches = len(RE_NAME_HONORIFIC.findall(working_text))
        if n_hon_matches > 0:
            working_text = RE_NAME_HONORIFIC.sub(r"\1 " + NAME_REDACTION_TOKEN, working_text)
            detected_categories.add("personal_name")
            redaction_counts["personal_name"] = redaction_counts.get("personal_name", 0) + n_hon_matches

        # Step 9: Post-Redaction Ambiguity & Residual Risk Check
        # Check for residual unclassified long digit sequences (>= 9 digits) in ASCII or Devanagari numerals
        residual_digits = re.findall(rf"(?<!{DIGIT_CHAR}){DIGIT_CHAR}{{9,}}(?!{DIGIT_CHAR})", working_text)
        if residual_digits:
            detected_categories.add("ambiguous_unclassified_numeric")
            blocking_reasons.append(
                f"Detected {len(residual_digits)} unclassified long numeric sequence(s) (>= 9 digits); "
                "failing closed for external sharing."
            )
            # Redact residual ambiguous numbers
            working_text = re.sub(rf"(?<!{DIGIT_CHAR}){DIGIT_CHAR}{{9,}}(?!{DIGIT_CHAR})", AMBIGUOUS_PII_TOKEN, working_text)

        # Check for unredacted basic-auth credentials in URLs (e.g., https://user:pass@host)
        if re.search(r"://[^:@\s]+:[^@\s]+@", working_text):
            detected_categories.add("url_credentials")
            working_text = re.sub(r"://[^:@\s]+:[^@\s]+@", r"://[CREDENTIAL_REDACTED]@", working_text)
            redaction_counts["url_credentials"] = redaction_counts.get("url_credentials", 0) + 1

        # Check for raw sensitive keys in key-value constructs (e.g. "auth_token=...")
        if re.search(r"(?i)\b(?:token|auth|secret|password|passwd|otp)=[^\s&]+", working_text):
            detected_categories.add("sensitive_url_param")
            working_text = re.sub(
                r"(?i)\b(token|auth|secret|password|passwd|otp)=[^\s&]+",
                r"\1=[CREDENTIAL_REDACTED]",
                working_text,
            )

        sanitization_success = True
        safe_to_send = allow_external and (len(blocking_reasons) == 0)

        return PrivacyGateResult(
            sanitized_text=working_text,
            sanitization_success=sanitization_success,
            safe_to_send=safe_to_send,
            detected_categories=sorted(list(detected_categories)),
            blocking_reasons=blocking_reasons,
            redaction_counts=redaction_counts,
        )

    except Exception as exc:
        # FAIL-CLOSED ON ANY EXCEPTION
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=sorted(list(detected_categories)),
            blocking_reasons=[f"Sanitization pipeline failure: {type(exc).__name__}"],
            redaction_counts=redaction_counts,
        )


# =============================================================================
# LOCAL TRAINING FEATURE SANITIZATION (PHASE 6.1.1 BOUNDARY HARDENING)
# =============================================================================

def sanitize_for_local_training(
    text: Any,
    max_unclassified_digits: int = 8,
) -> PrivacyGateResult:
    """
    Sanitizes sensitive text specifically for local training feature extraction (Phase 6.1.1).

    SAFETY & ARCHITECTURAL GUARANTEES (SEC-06-LOCAL-BOUNDARY):
    1. Local-Only Boundary: External sharing is PERMANENTLY PROHIBITED (safe_to_send is ALWAYS False).
    2. Zero External Authorization: Never authorizes external data transmission under any flag or condition.
    3. Fail-Closed Design: If sanitization encounters ambiguity, unexpected types, or any exception,
       sanitization_success is False and sanitized_text is None.
    4. Deterministic Redaction: Applies conservative redaction for Indian mobile numbers, Aadhaar,
       labelled bank accounts, cards, credentials, OTPs, PINs, CVVs, API tokens, and sensitive query params.
    5. Multilingual Compatibility: Preserves Devanagari numerals and script context while redacting identifiers.
    6. Transient In-Memory Processing: The returned sanitized_text is intended solely for immediate
       in-memory feature hashing. Python cannot guarantee secure hardware memory erasure, but sanitized
       text is never persisted to disk, logs, or databases.
    7. No Network Activity: Strictly executes local regex substitutions with zero sockets or APIs.

    Returns:
        PrivacyGateResult with:
        - sanitized_text: Sanitized string if successful, else None
        - sanitization_success: True if redaction completed cleanly without unclassified blockers
        - safe_to_send: ALWAYS False (external transmission prohibited)
        - detected_categories: List of detected sensitive data categories
        - blocking_reasons: List of reasons if blocked (always includes local-only policy)
        - redaction_counts: Counts of redacted tokens
    """
    blocking_reasons: List[str] = [
        "External transmission prohibited (local training boundary policy)."
    ]
    detected_categories: Set[str] = set()
    redaction_counts: Dict[str, int] = {}

    if text is None:
        blocking_reasons.append("Input text is None.")
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    if not isinstance(text, str):
        blocking_reasons.append(f"Input must be string, got {type(text).__name__}.")
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    if len(text.strip()) == 0:
        return PrivacyGateResult(
            sanitized_text="",
            sanitization_success=True,
            safe_to_send=False,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    if len(text) > 50000:
        blocking_reasons.append(
            "Input exceeds maximum sanitization size (50,000 characters)."
        )
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=[],
            blocking_reasons=blocking_reasons,
            redaction_counts={},
        )

    try:
        working_text = text

        # Step 1: Redact Bearer Tokens & API Keys
        def _sub_token(m):
            return TOKEN_REDACTION_TOKEN

        def _sub_bearer(m):
            return f"Bearer {TOKEN_REDACTION_TOKEN}"

        b_matches = len(RE_AUTH_BEARER.findall(working_text))
        if b_matches > 0:
            working_text = RE_AUTH_BEARER.sub(_sub_bearer, working_text)
            detected_categories.add("authentication_token")
            redaction_counts["authentication_token"] = redaction_counts.get("authentication_token", 0) + b_matches

        k_matches = len(RE_AUTH_KEY_LABELLED.findall(working_text))
        if k_matches > 0:
            working_text = RE_AUTH_KEY_LABELLED.sub(r"\1: " + TOKEN_REDACTION_TOKEN, working_text)
            detected_categories.add("api_key")
            redaction_counts["api_key"] = redaction_counts.get("api_key", 0) + k_matches

        # Step 2: Redact Passwords
        p_matches = len(RE_PASSWORD_LABELLED.findall(working_text))
        if p_matches > 0:
            working_text = RE_PASSWORD_LABELLED.sub(r"password: " + CREDENTIAL_REDACTION_TOKEN, working_text)
            detected_categories.add("password")
            redaction_counts["password"] = redaction_counts.get("password", 0) + p_matches

        # Step 3: Redact Email Addresses
        e_matches = len(RE_EMAIL.findall(working_text))
        if e_matches > 0:
            working_text = RE_EMAIL.sub(EMAIL_REDACTION_TOKEN, working_text)
            detected_categories.add("email_address")
            redaction_counts["email_address"] = redaction_counts.get("email_address", 0) + e_matches

        # Step 4: Redact Labelled Bank Accounts & Cards
        c_matches = len(RE_CARD_FORMATTED.findall(working_text)) + len(RE_CARD_CONTINUOUS.findall(working_text))
        if c_matches > 0:
            working_text = RE_CARD_FORMATTED.sub(CARD_REDACTION_TOKEN, working_text)
            working_text = RE_CARD_CONTINUOUS.sub(CARD_REDACTION_TOKEN, working_text)
            detected_categories.add("payment_card_number")
            redaction_counts["payment_card_number"] = redaction_counts.get("payment_card_number", 0) + c_matches

        ba_matches = len(RE_BANK_ACCOUNT_LABELLED.findall(working_text))
        if ba_matches > 0:
            working_text = RE_BANK_ACCOUNT_LABELLED.sub(lambda m: f"{m.group(1)}: {BANK_ACCOUNT_REDACTION_TOKEN}", working_text)
            detected_categories.add("bank_account_number")
            redaction_counts["bank_account_number"] = redaction_counts.get("bank_account_number", 0) + ba_matches

        ifsc_matches = len(RE_IFSC_CODE.findall(working_text))
        if ifsc_matches > 0:
            working_text = RE_IFSC_CODE.sub(BANK_ACCOUNT_REDACTION_TOKEN, working_text)
            detected_categories.add("ifsc_code")
            redaction_counts["ifsc_code"] = redaction_counts.get("ifsc_code", 0) + ifsc_matches

        # Step 5: Redact OTPs, PINs, CVV
        otp_matches = len(RE_OTP.findall(working_text))
        if otp_matches > 0:
            working_text = RE_OTP.sub(lambda m: f"{m.group(1)}: {CREDENTIAL_REDACTION_TOKEN}", working_text)
            detected_categories.add("otp")
            redaction_counts["otp"] = redaction_counts.get("otp", 0) + otp_matches

        pin_matches = len(RE_PIN.findall(working_text))
        if pin_matches > 0:
            working_text = RE_PIN.sub(lambda m: f"{m.group(1)}: {CREDENTIAL_REDACTION_TOKEN}", working_text)
            detected_categories.add("pin")
            redaction_counts["pin"] = redaction_counts.get("pin", 0) + pin_matches

        cvv_matches = len(RE_CVV.findall(working_text))
        if cvv_matches > 0:
            working_text = RE_CVV.sub(lambda m: f"{m.group(1)}: {CREDENTIAL_REDACTION_TOKEN}", working_text)
            detected_categories.add("cvv")
            redaction_counts["cvv"] = redaction_counts.get("cvv", 0) + cvv_matches

        # Step 6: Redact Aadhaar Numbers
        aadh_f_matches = len(RE_AADHAAR_FORMATTED.findall(working_text))
        if aadh_f_matches > 0:
            working_text = RE_AADHAAR_FORMATTED.sub(AADHAAR_REDACTION_TOKEN, working_text)
            detected_categories.add("aadhaar_number")
            redaction_counts["aadhaar_number"] = redaction_counts.get("aadhaar_number", 0) + aadh_f_matches

        aadh_c_matches = len(RE_AADHAAR_CONTEXTUAL.findall(working_text))
        if aadh_c_matches > 0:
            working_text = RE_AADHAAR_CONTEXTUAL.sub(lambda m: f"{m.group(1)}: {AADHAAR_REDACTION_TOKEN}", working_text)
            detected_categories.add("aadhaar_number")
            redaction_counts["aadhaar_number"] = redaction_counts.get("aadhaar_number", 0) + aadh_c_matches

        # Step 7: Redact Indian Mobile Numbers
        p_pre_matches = len(RE_PHONE_PREFIXED.findall(working_text))
        if p_pre_matches > 0:
            working_text = RE_PHONE_PREFIXED.sub(PHONE_REDACTION_TOKEN, working_text)
            detected_categories.add("phone_number")
            redaction_counts["phone_number"] = redaction_counts.get("phone_number", 0) + p_pre_matches

        p_tight_matches = len(RE_PHONE_TIGHT.findall(working_text))
        if p_tight_matches > 0:
            working_text = RE_PHONE_TIGHT.sub(PHONE_REDACTION_TOKEN, working_text)
            detected_categories.add("phone_number")
            redaction_counts["phone_number"] = redaction_counts.get("phone_number", 0) + p_tight_matches

        p_std_matches = len(RE_PHONE_STANDALONE.findall(working_text))
        if p_std_matches > 0:
            working_text = RE_PHONE_STANDALONE.sub(PHONE_REDACTION_TOKEN, working_text)
            detected_categories.add("phone_number")
            redaction_counts["phone_number"] = redaction_counts.get("phone_number", 0) + p_std_matches

        # Step 8: Redact Labelled Personal Names
        name_matches = len(RE_NAME_LABELLED.findall(working_text))
        if name_matches > 0:
            working_text = RE_NAME_LABELLED.sub(lambda m: f"{m.group(1)}: {NAME_REDACTION_TOKEN}", working_text)
            detected_categories.add("personal_name_labelled")
            redaction_counts["personal_name_labelled"] = redaction_counts.get("personal_name_labelled", 0) + name_matches

        # Step 9: Ambiguous Unclassified Digit Sequences
        norm_digits = normalize_devanagari_numerals(working_text)
        ambiguous_matches = list(re.finditer(rf"\b\d{{{max_unclassified_digits + 1},}}\b", norm_digits))
        if ambiguous_matches:
            detected_categories.add("ambiguous_unclassified_identifier")
            blocking_reasons.append(
                f"Detected {len(ambiguous_matches)} ambiguous digit sequence(s) exceeding {max_unclassified_digits} digits."
            )
            return PrivacyGateResult(
                sanitized_text=None,
                sanitization_success=False,
                safe_to_send=False,
                detected_categories=sorted(list(detected_categories)),
                blocking_reasons=blocking_reasons,
                redaction_counts=redaction_counts,
            )

        # Step 10: Redact basic auth in URLs and sensitive query parameters
        if re.search(r"://[^:@\s]+:[^@\s]+@", working_text):
            detected_categories.add("url_credentials")
            working_text = re.sub(r"://[^:@\s]+:[^@\s]+@", r"://[CREDENTIAL_REDACTED]@", working_text)
            redaction_counts["url_credentials"] = redaction_counts.get("url_credentials", 0) + 1

        if re.search(r"(?i)\b(?:token|auth|secret|password|passwd|otp)=[^\s&]+", working_text):
            detected_categories.add("sensitive_url_param")
            working_text = re.sub(
                r"(?i)\b(token|auth|secret|password|passwd|otp)=[^\s&]+",
                r"\1=[CREDENTIAL_REDACTED]",
                working_text,
            )

        return PrivacyGateResult(
            sanitized_text=working_text,
            sanitization_success=True,
            safe_to_send=False,  # ALWAYS False for local training
            detected_categories=sorted(list(detected_categories)),
            blocking_reasons=blocking_reasons,
            redaction_counts=redaction_counts,
        )

    except Exception as exc:
        return PrivacyGateResult(
            sanitized_text=None,
            sanitization_success=False,
            safe_to_send=False,
            detected_categories=sorted(list(detected_categories)),
            blocking_reasons=[f"Sanitization pipeline failure: {type(exc).__name__}"],
            redaction_counts=redaction_counts,
        )
