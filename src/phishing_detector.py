"""
Vernacular & Multilingual WhatsApp Phishing Indicator Detector.
Analyzes Marathi (Devanagari), Romanized Marathi, Mixed Marathi-English, and English text.

DESIGN PRINCIPLES:
- Normalizes Devanagari numerals (०-९ -> 0-9) and extra whitespace before pattern matching.
- Evaluates 7 threat categories: credential requests, APK sideload lures, urgency/coercion,
  fake KYC/account blocks, suspicious links, lottery/paid tasks, and utility impersonation.
- Uses protective-negation rules so legitimate security advisories are not falsely flagged.
- Suppresses false alarms when utility/bank names appear in standard informational contexts.
"""

import re
from typing import Any, Dict, List

# Map Devanagari digits ०-९ to standard ASCII digits 0-9 for consistent regex matching
DEVANAGARI_DIGIT_MAP = str.maketrans("०१२३४५६७८९", "0123456789")

INDICATOR_RULES: List[Dict[str, Any]] = [
    {
        "id": "CREDENTIAL_HARVEST",
        "category": "OTP, PIN, or Password Request",
        "weight": 35,
        "severity": "High",
        "patterns": [
            r"\botp\s*(share|sanga|pathva|takun|taka|enter|verify)\b",
            r"\b(upi\s*pin|atm\s*pin|netbanking\s*password|cvv)\s*(taka|takun|enter|share|sanga)\b",
            r"(ओटीपी|otp)\s*(शेअर|सांगा|टाका|पाठवा|व्हेरिफाय|कस्टमर\s*केअरला\s*सांगा)",
            r"(यूपीआय\s*पिन|upi\s*pin|पासवर्ड)\s*(टाका|सांगा|शेअर)",
            r"enter\s+your\s+(netbanking\s+password|otp|upi\s*pin|password|cvv)",
        ],
        "protective_negations": [
            r"never\s+(?:asks?|share)\s+(?:for\s+)?(?:your\s+)?(?:otp|pin|password|cvv)",
            r"do\s+not\s+share\s+(?:your\s+)?(?:otp|pin|password|cvv)",
            r"(?:ओटीपी|otp|पिन|पासवर्ड)\s*कोणालाही\s*(?:सांगू|शेअर\s*करू|देवू)\s*नका",
            r"(?:devu|sangu|share\s*karu)\s*naka",
        ],
        "why_it_matters_en": (
            "Legitimate banks, utilities, and government offices never ask you to share an OTP, "
            "UPI PIN, or password over WhatsApp or to receive a refund/subsidy."
        ),
        "why_it_matters_mr": (
            "कोणतीही अधिकृत बँक, महावितरण किंवा सरकारी कार्यालय व्हॉट्सॲपवर OTP किंवा UPI PIN मागत नाही."
        ),
    },
    {
        "id": "APK_SIDELOAD_LURE",
        "category": "Direct .APK File Installation Lure",
        "weight": 35,
        "severity": "High",
        "patterns": [
            r"[a-zA-Z0-9_\-]+\.apk\b",
            r"(apk\s*फाईल|apk\s*file|ॲप\s*डाउनलोड|install\s*करा)",
        ],
        "protective_negations": [
            r"do\s+not\s+download\s+unknown\s+\.apk",
            r"अनोळखी\s*apk\s*डाउनलोड\s*करू\s*नका",
        ],
        "why_it_matters_en": (
            "Official utility, banking, and government apps are distributed through the Google Play Store. "
            "Forwarding raw .apk installation files in chat is a primary method for installing SMS spyware."
        ),
        "why_it_matters_mr": (
            "अधिकृत सरकारी किंवा बँकिंग ॲप्स फक्त Google Play Store वर मिळतात. व्हॉट्सॲपवर आलेली .apk फाईल इन्स्टॉल करणे धोकादायक आहे."
        ),
    },
    {
        "id": "URGENCY_OR_THREAT",
        "category": "Artificial Urgency or Disconnection/Arrest Threat",
        "weight": 22,
        "severity": "Moderate",
        "patterns": [
            r"(आज\s*रात्री.*(?:कट|बंद|मीटर|खंडित|कारवाई)|तात्काळ|ताबडतोब|24\s*तासात)",
            r"(कनेक्शन\s*कट|कनेक्शन\s*बंद|खाते\s*ब्लॉक|अटक\s*टाळण्यासाठी)",
            r"\b(aaj\s*ratri.*(?:cut|block|line|meter|band)|tatkal|block\s*honar|line\s*cut\s*hoil)\b",
            r"\b(urgent\s*alert|immediately\s*(?:pay|call|download|click|verify)|within\s*\d+\s*hours|avoid\s*court\s*warrant)\b",
        ],
        "protective_negations": [
            r"(?:1930|cybercrime\.gov\.in).*(?:लगेच|तात्काळ|immediately|tatkal|contact|संपर्क|dial|तक्रार)",
            r"(?:लगेच|तात्काळ|immediately|tatkal).*(?:1930|cybercrime\.gov\.in|तक्रार|हेल्पलाइन|helpline|dial)",
        ],
        "why_it_matters_en": (
            "Scammers manufacture panic ('electricity cut tonight at 9:30 PM', 'arrest warrant', 'blocked in 24 hours') "
            "so victims act before verifying with an official office."
        ),
        "why_it_matters_mr": (
            "भीती घालून ('आज रात्री वीज बंद होईल', 'खाते ब्लॉक होईल') घाईत चुकीची कृती करायला लावणे ही फसवणुकीची पद्धत आहे."
        ),
    },
    {
        "id": "FAKE_KYC_OR_BLOCK",
        "category": "Unverified KYC Expiry or Account/SIM Block Claim",
        "weight": 20,
        "severity": "Moderate",
        "patterns": [
            r"\b(pan\s*kyc|aadhaar\s*ekyc|kyc\s*pending|kyc\s*update|sim\s*card.*बंद)\b",
            r"(केवायसी|kyc|ekyc)\s*(अपूर्ण|अपडेट|पेन्डिंग|करणे\s*आवश्यक)",
            r"\b(khate.*block|account.*blocked|sim.*deactivated)\b",
        ],
        "protective_negations": [],
        "why_it_matters_en": (
            "Deceptive KYC expiration or SIM deactivation warnings are commonly used to lure users "
            "into installing remote-access apps or submitting banking credentials."
        ),
        "why_it_matters_mr": (
            "केवायसी (KYC) किंवा सिम कार्ड बंद होण्याच्या नावाखाली फसव्या लिंकवर क्लिक करायला लावले जाते."
        ),
    },
    {
        "id": "SUSPICIOUS_URL",
        "category": "Unverified or Lookalike Web Link",
        "weight": 28,
        "severity": "High",
        "patterns": [
            r"https?://[^\s]+(?:\.xyz|\.top|\.click|\.buzz|\.tk|\.ml|\.cf)\b",
            r"http://[^\s]+",
            r"https?://(?:bit\.ly|tinyurl\.com|rb\.gy|t\.co)/[^\s]+",
        ],
        "protective_negations": [],
        "why_it_matters_en": (
            "Uses an unencrypted (http://), shortened, or non-governmental domain (.xyz, .top, .click) "
            "instead of a verified official domain (.gov.in or .mahadiscom.in)."
        ),
        "why_it_matters_mr": (
            "अधिकृत सरकारी वेबसाइट (.gov.in किंवा .mahadiscom.in) ऐवजी संशयास्पद वेब लिंक (.xyz, .top, http://) दिलेली आहे."
        ),
    },
    {
        "id": "SUSPICIOUS_PAYMENT_OR_TASK",
        "category": "Unrealistic Cashback, Refund, or Paid Task Lure",
        "weight": 24,
        "severity": "Moderate",
        "patterns": [
            r"(कॅशबॅक\s*बक्षीस|लॉटरी|बक्षीस\s*मिळाले)",
            r"\b(ghara\s*baslya\s*darroj|youtube\s*video\s*like\s*kara|registration\s*sathi.*fee)\b",
            r"\b(overpaid.*refund|instant\s*credit|daily\s*income\s*task)\b",
        ],
        "protective_negations": [
            r"(?:लॉटरी|lottery|बक्षीस|कॅशबॅक|cashback|link|लिंक).*(?:क्लिक\s*करू\s*नका|click\s*karu\s*naka|do\s+not\s+click)",
            r"(?:do\s+not\s+click|क्लिक\s*करू\s*नका).*(?:लॉटरी|lottery|बक्षीस|कॅशबॅक|cashback|link|लिंक)",
        ],
        "why_it_matters_en": (
            "Promises easy daily income for liking videos or unexpected refunds that require registration fees or PIN entry."
        ),
        "why_it_matters_mr": (
            "घरबसल्या हजारो रुपये कमवा किंवा बक्षीस मिळवा असे सांगून आधी फी किंवा पिन मागणे हे फसवणुकीचे लक्षण आहे."
        ),
    },
    {
        "id": "UTILITY_GOVT_IMPERSONATION",
        "category": "Utility, Bank, RTO, or Welfare Scheme Reference",
        "weight": 12,
        "severity": "Low-Contextual",
        "patterns": [
            r"(महावितरण|msedcl|mahavitaran|वीज\s*बिल|light\s*bill)",
            r"(लाडकी\s*बहीण|pm-kisan|पीएम\s*किसान|e-challan|rto\s*challan|कस्टम\s*विभाग)",
            r"\b(sbi|bank\s*khate|electricity\s*bill)\b",
        ],
        "protective_negations": [],
        "why_it_matters_en": (
            "References a public utility, bank, or government scheme. Only treated as a warning sign "
            "when combined with another threat indicator (such as an APK lure, suspicious link, or OTP request)."
        ),
        "why_it_matters_mr": (
            "महावितरण, बँक किंवा सरकारी योजनेचा उल्लेख आहे. (सोबत अनोळखी लिंक किंवा OTP मागणी असल्यास धोकादायक)."
        ),
    },
]


MAX_MESSAGE_CHARACTERS = 10000

# Zero-width characters often inserted for regex evasion:
# U+200B (Zero-width space), U+200C (ZWNJ), U+200D (ZWJ), U+200E (LTR mark), U+200F (RTL mark), U+FEFF (BOM)
ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]")


def normalize_text(text: str) -> str:
    """Normalizes Devanagari numerals to ASCII digits, strips zero-width evasion characters, and collapses repeated whitespace."""
    if not text or not isinstance(text, str):
        return ""
    bounded = text[:MAX_MESSAGE_CHARACTERS]
    cleaned_zw = ZERO_WIDTH_PATTERN.sub("", bounded)
    translated = cleaned_zw.translate(DEVANAGARI_DIGIT_MAP)
    return re.sub(r"\s+", " ", translated).strip()


def detect_script_mix(text: str) -> str:
    """Identifies whether the input text uses Devanagari, Latin, or a combination of both."""
    has_devanagari = bool(re.search(r"[\u0900-\u097F]", text))
    has_latin = bool(re.search(r"[a-zA-Z]", text))
    if has_devanagari and has_latin:
        return "Mixed (Marathi Devanagari + English/Latin)"
    if has_devanagari:
        return "Marathi (Devanagari Script)"
    if has_latin:
        return "Romanized Marathi / English (Latin Script)"
    return "Other / Symbols Only"


def analyze_message_text(text: str) -> Dict[str, Any]:
    """
    Analyzes a WhatsApp-style text message and returns a consistent structured dictionary.
    """
    raw_input = text if isinstance(text, str) else ""
    normalized = normalize_text(raw_input)

    if not normalized:
        return {
            "is_empty": True,
            "normalized_text": "",
            "script_detected": "None",
            "assessment_label": "No Input Provided",
            "findings": [],
            "extracted_urls": [],
            "context_only_suppressed": False,
            "protective_advisory_detected": False,
            "advice_en": "Paste or select a message to inspect its warning indicators.",
            "advice_mr": "कृपया तपासणीसाठी मेसेज टाका किंवा नमुना निवडा.",
            "observed_facts": ["No input text received (empty, whitespace, or non-string)."],
            "heuristic_inferences": ["Assessment skipped due to empty input."],
            "uncertainty_note": (
                "Automated text analysis checks for known phishing patterns and cannot verify the sender's identity."
            ),
        }

    script_type = detect_script_mix(normalized)
    extracted_urls = re.findall(r"https?://[^\s]+", normalized)
    findings: List[Dict[str, Any]] = []
    protective_hit = False

    for rule in INDICATOR_RULES:
        is_negated = any(
            re.search(neg, normalized, flags=re.IGNORECASE)
            for neg in rule.get("protective_negations", [])
        )
        if is_negated:
            protective_hit = True
            continue

        matched_phrases: List[str] = []
        for pattern in rule["patterns"]:
            match = re.search(pattern, normalized, flags=re.IGNORECASE)
            if match:
                matched_phrases.append(match.group(0))

        if matched_phrases:
            findings.append(
                {
                    "id": rule["id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "weight": rule["weight"],
                    "matched_text": matched_phrases[0],
                    "why_it_matters_en": rule["why_it_matters_en"],
                    "why_it_matters_mr": rule["why_it_matters_mr"],
                }
            )

    # Suppress false alarm if ONLY a bank/utility name is mentioned without any actual threat indicator
    context_only_suppressed = False
    if len(findings) == 1 and findings[0]["id"] == "UTILITY_GOVT_IMPERSONATION":
        context_only_suppressed = True
        findings = []

    # Suppress residual urgency/utility findings if this is an explicit protective advisory
    if protective_hit and not any(f["severity"] == "High" for f in findings):
        findings = []

    if len(findings) >= 2 or any(f["severity"] == "High" for f in findings):
        assessment_label = "Suspicious (Multiple or High-Risk Indicators Detected)"
        advice_en = (
            "Do not click links, install .apk files, or share OTP/PIN numbers. "
            "Verify independently through an official website or local office."
        )
        advice_mr = (
            "कोणत्याही लिंकवर क्लिक करू नका, .apk फाईल इन्स्टॉल करू नका किंवा OTP/PIN सांगू नका."
        )
    elif len(findings) == 1:
        assessment_label = "Potentially Suspicious (Verify Independently)"
        advice_en = (
            "This message contains a warning sign commonly used in social engineering. "
            "Confirm the claim through official channels before acting."
        )
        advice_mr = (
            "या मेसेजमध्ये संशयास्पद संकेत आढळला आहे. अधिकृत कार्यालयातून खात्री केल्याशिवाय कृती करू नका."
        )
    else:
        assessment_label = "No Strong Indicators Detected"
        advice_en = (
            "No known phishing patterns were triggered. However, always stay cautious with unexpected requests."
        )
        advice_mr = (
            "यात फसवणुकीचे ठळक संकेत आढळले नाहीत, तरीही अनोळखी मेसेजबाबत नेहमी सावधगिरी बाळगा."
        )

    observed_facts = [
        f"Input length: {len(raw_input)} characters",
        f"Normalized length: {len(normalized)} characters",
        f"Script classification: {script_type}",
        f"Extracted web URLs count: {len(extracted_urls)}",
        f"Triggered indicator rules count: {len(findings)}",
        f"Protective advisory matched: {'Yes' if protective_hit else 'No'}",
        f"Single-utility context suppressed: {'Yes' if context_only_suppressed else 'No'}",
    ]

    heuristic_inferences = [
        f"Assessment verdict: {assessment_label}",
    ]
    for f in findings:
        heuristic_inferences.append(
            f"Rule [{f['id']}] weight {f['weight']}: {f['category']} (matched: '{f['matched_text']}')"
        )

    return {
        "is_empty": False,
        "normalized_text": normalized,
        "script_detected": script_type,
        "assessment_label": assessment_label,
        "findings": findings,
        "extracted_urls": extracted_urls,
        "context_only_suppressed": context_only_suppressed,
        "protective_advisory_detected": protective_hit,
        "advice_en": advice_en,
        "advice_mr": advice_mr,
        "observed_facts": observed_facts,
        "heuristic_inferences": heuristic_inferences,
        "uncertainty_note": (
            "Rule-based language detection evaluates known Marathi, Romanized Marathi, and English scam patterns. "
            "It cannot understand every regional dialect or novel scam phrasing, and 'No Strong Indicators Detected' "
            "does not guarantee that a message is safe."
        ),
    }