"""
Maharashtra Government Scheme & Announcement Verification Engine.
Part of Seva Cyber Sandbox (Maha-Suraksha).

SAFETY & INTEGRITY GUARANTEES:
1. Passively inspects user-provided claims and suspicious URLs without ever fetching user URLs.
2. Only connects to explicitly allowlisted official government domains (.gov.in, .maharashtra.gov.in, .mahadiscom.in).
3. Enforces strict timeouts (3.0s) and response-size limits (32 KB) on live health checks.
4. Distinguishes between verified official records and unindexed claims without making false assumptions.
5. Evaluates scheme promises and registration links independently: a genuine scheme name never validates a fraudulent link.
"""

from datetime import datetime, timezone
import json
import os
import re
import ssl
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import urllib.request

# Default registry location
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REGISTRY_PATH = os.path.join(BASE_DIR, "data", "official_sources.json")

# Safety limits for allowlisted official portal probing
MAX_PROBE_RESPONSE_BYTES = 32 * 1024  # 32 KB maximum read
DEFAULT_PROBE_TIMEOUT = 3.0           # 3 seconds max timeout

# Devanagari digits mapping for normalization
DEVANAGARI_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

# In-memory registry cache to avoid repeated disk reads
_REGISTRY_CACHE: Dict[str, Any] = {}


def normalize_text_for_matching(text: str) -> str:
    """Normalizes Devanagari numerals, strips zero-width chars, and collapses whitespace."""
    if not text:
        return ""
    # Map Devanagari numerals to ASCII digits
    t = text.translate(DEVANAGARI_DIGITS)
    # Remove invisible zero-width characters (\u200B, \u200C, \u200D, \uFEFF)
    t = re.sub(r"[\u200B-\u200D\uFEFF]", "", t)
    # Collapse multiple whitespaces
    return re.sub(r"\s+", " ", t).strip()


def load_official_sources(registry_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Loads and validates the official sources registry from data/official_sources.json.
    Returns structured data dictionary with error indicators if file is missing or malformed.
    """
    path = registry_path or DEFAULT_REGISTRY_PATH
    if path in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[path]

    if not os.path.exists(path):
        return {
            "is_valid": False,
            "error": f"Official sources registry file not found at: {path}",
            "schemes": [],
            "allowlisted_domains": [],
            "source_evaluations": [],
            "last_curated": "Unknown",
        }

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return {
            "is_valid": False,
            "error": f"Failed to parse official sources JSON: {exc}",
            "schemes": [],
            "allowlisted_domains": [],
            "source_evaluations": [],
            "last_curated": "Unknown",
        }

    if not isinstance(data, dict) or "schemes" not in data or not isinstance(data["schemes"], list):
        return {
            "is_valid": False,
            "error": "Malformed registry structure: missing 'schemes' list.",
            "schemes": [],
            "allowlisted_domains": [],
            "source_evaluations": [],
            "last_curated": "Unknown",
        }

    result = {
        "is_valid": True,
        "error": None,
        "schema_version": data.get("schema_version", "1.0.0"),
        "last_curated": data.get("last_curated", "2026-10-28"),
        "curator": data.get("curator", "Seva Cyber Sandbox Verification Desk"),
        "disclaimer": data.get("disclaimer", ""),
        "allowlisted_domains": data.get("allowlisted_domains", ["maharashtra.gov.in", "gov.in", "mahadiscom.in"]),
        "source_evaluations": data.get("source_evaluations", []),
        "schemes": data["schemes"],
    }
    _REGISTRY_CACHE[path] = result
    return result


def is_domain_allowlisted(url_or_domain: str, allowlisted_domains: List[str]) -> Tuple[bool, str]:
    """
    Checks if a URL or host string belongs to an allowlisted official government domain.
    Returns (is_allowlisted, parsed_hostname).
    """
    if not url_or_domain:
        return False, ""

    candidate = url_or_domain.strip().lower()
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate

    try:
        parsed = urllib.parse.urlparse(candidate)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return False, ""

    if not hostname:
        return False, ""

    for allowed in allowlisted_domains:
        clean_allowed = allowed.strip().lower()
        if hostname == clean_allowed or hostname.endswith("." + clean_allowed):
            return True, hostname

    return False, hostname


def analyze_suspicious_url(url: str, allowlisted_domains: List[str]) -> Dict[str, Any]:
    """
    PASSIVELY analyzes a URL string without ever sending an HTTP request or resolving DNS.
    Evaluates protocol, domain legitimacy, suspicious TLDs, and URL shorteners.
    """
    raw_url = (url or "").strip()
    if not raw_url:
        return {
            "has_url": False,
            "url": "",
            "hostname": "",
            "is_official_domain": False,
            "warnings_en": [],
            "warnings_mr": [],
        }

    is_official, hostname = is_domain_allowlisted(raw_url, allowlisted_domains)
    warnings_en: List[str] = []
    warnings_mr: List[str] = []

    # Check protocol
    is_unencrypted = raw_url.lower().startswith("http://")
    if is_unencrypted:
        warnings_en.append("Insecure Protocol: URL uses unencrypted 'http://' instead of 'https://'.")
        warnings_mr.append("असुरक्षित प्रोटोकॉल: लिंकमध्ये 'https://' ऐवजी असुरक्षित 'http://' वापरले आहे.")

    # Check suspicious TLDs
    suspicious_tld_pattern = r"\.(xyz|top|click|buzz|club|site|tk|ml|cf|gq|rest|work|cam|fun)\b"
    if re.search(suspicious_tld_pattern, hostname, re.IGNORECASE):
        warnings_en.append(f"Suspicious Domain Extension: Hostname '{hostname}' uses an unverified commercial TLD.")
        warnings_mr.append(f"संशयास्पद डोमेन: '{hostname}' हा सरकारी डोमेन नसून अनधिकृत खाजगी विस्तार आहे.")

    # Check shortener
    shortener_domains = ("bit.ly", "tinyurl.com", "rb.gy", "t.co", "cutt.ly", "is.gd", "shorturl.at")
    if any(hostname == s or hostname.endswith("." + s) for s in shortener_domains):
        warnings_en.append(f"Masked/Shortened URL: Uses a URL shortening service ({hostname}) to disguise the destination.")
        warnings_mr.append(f"लपवलेली लिंक: मूळ वेबसाइट पत्ता लपवण्यासाठी शॉर्टनर ({hostname}) वापरले आहे.")

    # Check IP address as host
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        warnings_en.append(f"Raw IP Address: Link directs to a raw numerical IP ({hostname}) rather than a named portal.")
        warnings_mr.append(f"थेट आयपी पत्ता: लिंक थेट आयपी नंबरवर ({hostname}) जाते, जी अधिकृत पद्धत नाही.")

    # Check APK file extension in path
    if raw_url.lower().endswith(".apk") or ".apk?" in raw_url.lower():
        warnings_en.append("Direct APK Download: URL directs to an Android package (.apk) installation file.")
        warnings_mr.append("थेट .apk डाउनलोड: ही लिंक ॲप इन्स्टॉलेशन फाईल डाउनलोड करण्याचा प्रयत्न करते.")

    # Domain verdict
    if not is_official:
        warnings_en.append(
            f"Unofficial Domain: '{hostname}' does not belong to the Government of Maharashtra "
            "allowlisted domains (.gov.in, .maharashtra.gov.in, .mahadiscom.in)."
        )
        warnings_mr.append(
            f"अनधिकृत वेबसाइट: '{hostname}' हे महाराष्ट्र शासनाचे अधिकृत पोर्टल (.gov.in / .maharashtra.gov.in) नाही."
        )

    return {
        "has_url": True,
        "url": raw_url,
        "hostname": hostname,
        "is_official_domain": is_official,
        "is_unencrypted": is_unencrypted,
        "warnings_en": warnings_en,
        "warnings_mr": warnings_mr,
    }


def check_official_portal_health(
    target_url: str,
    allowlisted_domains: List[str],
    timeout_sec: float = DEFAULT_PROBE_TIMEOUT,
) -> Dict[str, Any]:
    """
    Safely probes an explicitly ALLOWLISTED official government portal to check uptime/freshness.
    STRICT SAFETY: Refuses to probe any URL that is not on the allowlist.
    """
    is_allowed, hostname = is_domain_allowlisted(target_url, allowlisted_domains)
    if not is_allowed:
        return {
            "target_url": target_url,
            "is_reachable": False,
            "status_code": None,
            "latency_ms": 0.0,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "error": f"Safety Violation: Domain '{hostname}' is not in the official allowlist. Probe aborted.",
        }

    start_time = datetime.now(timezone.utc)
    ctx = ssl.create_default_context()

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "Seva-Cyber-Sandbox-Verifier/1.0 (Defensive Citizen Protection Tool)"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec, context=ctx) as resp:
            # Bound read size to 32 KB
            _ = resp.read(MAX_PROBE_RESPONSE_BYTES)
            elapsed_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000.0
            return {
                "target_url": target_url,
                "is_reachable": True,
                "status_code": getattr(resp, "status", 200),
                "latency_ms": round(elapsed_ms, 1),
                "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "error": None,
            }
    except Exception as exc:
        elapsed_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000.0
        return {
            "target_url": target_url,
            "is_reachable": False,
            "status_code": getattr(exc, "code", None) if hasattr(exc, "code") else None,
            "latency_ms": round(elapsed_ms, 1),
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "error": f"Official portal connection error: {exc}",
        }


def extract_claimed_amounts(text: str) -> List[int]:
    """Extracts numeric monetary amounts mentioned in text (e.g. ₹3,000, 3000, 1500)."""
    clean_text = normalize_text_for_matching(text or "")
    amounts: List[int] = []
    # Match ₹ 1500, Rs 3000, 3000 rs, 3,000 रुपये
    matches = re.findall(r"(?:₹|rs\.?|रुपये)\s*([0-9,]+)", clean_text, re.IGNORECASE)
    matches += re.findall(r"([0-9,]+)\s*(?:₹|rs\.?|रुपये|rupees)", clean_text, re.IGNORECASE)

    for m in matches:
        cleaned = m.replace(",", "").strip()
        if cleaned.isdigit():
            val = int(cleaned)
            if 10 <= val <= 10000000:
                amounts.append(val)

    # Match written forms e.g. "3 हजार" -> 3000
    hajar_matches = re.findall(r"([0-9]+)\s*(?:हजार|hazar|thousand)", text, re.IGNORECASE)
    for hm in hajar_matches:
        if hm.isdigit():
            amounts.append(int(hm) * 1000)

    return sorted(list(set(amounts)))


def verify_scheme_claim(
    claim_text: str,
    suspicious_url: Optional[str] = None,
    registry_path: Optional[str] = None,
    check_live_portal: bool = False,
) -> Dict[str, Any]:
    """
    Main verification pipeline for a suspicious government-scheme claim.
    Returns one of four explicit classifications:
    1. SUPPORTED BY OFFICIAL SOURCE
    2. CONFLICTING EVIDENCE FOUND
    3. NOT ENOUGH EVIDENCE
    4. SOURCE UNAVAILABLE
    """
    # 1. Handle invalid/empty claim inputs
    raw_claim = (claim_text or "").strip()
    if not raw_claim:
        return {
            "classification": "NOT ENOUGH EVIDENCE",
            "confidence_note": "No claim text was entered for analysis.",
            "summary_en": "Please paste a specific scheme message, claim, or announcement text to verify.",
            "summary_mr": "कृपया पडताळणीसाठी शासकीय योजनेचा मेसेज किंवा माहिती टाका.",
            "supporting_evidence": [],
            "conflicting_evidence": [],
            "official_sources": [],
            "retrieval_metadata": {
                "retrieval_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "source_freshness": "Unavailable",
                "mode": "No Input",
                "live_health": None,
            },
            "safe_next_steps_en": [
                "Paste the complete WhatsApp message or claim text into the analysis field.",
                "Verify official scheme details at https://maharashtra.gov.in."
            ],
            "safe_next_steps_mr": [
                "तपासणीसाठी व्हॉट्सॲपवर आलेला संपूर्ण मेसेज बॉक्समध्ये टाका.",
                "अधिकृत योजनांची माहिती https://maharashtra.gov.in वर तपासा."
            ],
            "url_assessment": analyze_suspicious_url("", []),
            "limitations": "Claim analysis requires input text describing the scheme promise or registration procedure."
        }

    # 2. Load official registry
    registry = load_official_sources(registry_path)
    if not registry["is_valid"]:
        return {
            "classification": "SOURCE UNAVAILABLE",
            "confidence_note": "The official sources registry could not be accessed or parsed.",
            "summary_en": f"Official verification database unavailable: {registry.get('error')}",
            "summary_mr": "शासकीय माहितीचा अधिकृत डेटाबेस उपलब्ध होऊ शकला नाही. कृपया थोड्या वेळाने प्रयत्न करा.",
            "supporting_evidence": [],
            "conflicting_evidence": [],
            "official_sources": [],
            "retrieval_metadata": {
                "retrieval_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "source_freshness": "Unreachable",
                "mode": "Error",
                "live_health": None,
            },
            "safe_next_steps_en": [
                "Independent Verification: Visit https://maharashtra.gov.in or https://gr.maharashtra.gov.in directly.",
                "Do not submit personal data or banking PINs while verification sources are offline."
            ],
            "safe_next_steps_mr": [
                "थेट अधिकृत वेबसाइटवर (https://maharashtra.gov.in) जाऊन खात्री करा.",
                "माहिती उपलब्ध नसताना अनोळखी लिंकवर कोणतीही वैयक्तिक माहिती भरू नका."
            ],
            "url_assessment": analyze_suspicious_url(suspicious_url or "", []),
            "limitations": "Verification is temporarily incomplete because the ground-truth registry could not be read."
        }

    allowlisted = registry["allowlisted_domains"]
    schemes = registry["schemes"]
    normalized_claim = normalize_text_for_matching(raw_claim).lower()

    # 3. Analyze optional suspicious URL passively
    extracted_urls = re.findall(r"https?://[^\s]+", raw_claim)
    url_to_analyze = (suspicious_url or "").strip()
    if not url_to_analyze and extracted_urls:
        url_to_analyze = extracted_urls[0]

    url_analysis = analyze_suspicious_url(url_to_analyze, allowlisted)

    # 4. Search for matching scheme in official registry
    matched_scheme: Optional[Dict[str, Any]] = None
    for s in schemes:
        # Check explicit keywords
        for kw in s.get("keywords", []):
            norm_kw = normalize_text_for_matching(kw).lower()
            if norm_kw in normalized_claim:
                matched_scheme = s
                break
        if matched_scheme:
            break

    supporting_evidence: List[str] = []
    conflicting_evidence: List[str] = []
    official_sources: List[Dict[str, Any]] = []

    # 5. Case A: No matching official scheme found in registry
    if not matched_scheme:
        # A failure to find a scheme must NEVER automatically be interpreted as proof that the scheme is fake.
        classification = "NOT ENOUGH EVIDENCE"
        summary_en = (
            "No official Maharashtra Government Resolution (GR) or listed scheme in the verified registry "
            "matched the keywords in this claim. This does not automatically prove the scheme is fake, "
            "as local or very recent announcements may not yet be indexed."
        )
        summary_mr = (
            "पडताळणीकृत अधिकृत नोंदींमध्ये या नावाच्या योजनेची माहिती आढळली नाही. "
            "याचा अर्थ योजना खोटीच आहे असा होत नाही, मात्र अधिकृत कार्यालयातून खात्री केल्याशिवाय विश्वास ठेवू नका."
        )

        if url_analysis["has_url"] and not url_analysis["is_official_domain"]:
            conflicting_evidence.append(
                f"Suspicious Web Link: The claim points to '{url_analysis['hostname']}', which is not a verified "
                "Maharashtra Government portal (.gov.in or .maharashtra.gov.in)."
            )

        safe_next_steps_en = [
            "Do not enter personal information, bank account details, or Aadhaar numbers on unverified links.",
            "Verify the scheme in person at your nearest Gram Panchayat, Ward Office, or Maha e-Seva / Setu Kendra.",
            "Search the official Government Resolutions portal: https://gr.maharashtra.gov.in."
        ]
        safe_next_steps_mr = [
            "अनोळखी लिंकवर आधार क्रमांक, बँक तपशील किंवा OTP भरू नका.",
            "जवळच्या ग्रामपंचायत, वॉर्ड कार्यालय किंवा महा ई-सेवा / सेतू केंद्रात जाऊन थेट विचारणा करा.",
            "अधिकृत शासन निर्णय पोर्टलवर (https://gr.maharashtra.gov.in) तपासणी करा."
        ]

        return {
            "classification": classification,
            "confidence_note": "Explicit official records for this scheme were not located in the verified registry.",
            "summary_en": summary_en,
            "summary_mr": summary_mr,
            "matched_scheme_title": None,
            "supporting_evidence": supporting_evidence,
            "conflicting_evidence": conflicting_evidence,
            "official_sources": [],
            "retrieval_metadata": {
                "retrieval_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "source_freshness": f"Registry curated on {registry.get('last_curated')}",
                "mode": "Source-Backed Registry Match",
                "live_health": None,
            },
            "safe_next_steps_en": safe_next_steps_en,
            "safe_next_steps_mr": safe_next_steps_mr,
            "url_assessment": url_analysis,
            "limitations": "Registry covers major high-frequency schemes targeted by WhatsApp scams and is updated periodically."
        }

    # 6. Case B: Scheme is matched — evaluate claim vs. official facts
    title_en = matched_scheme["official_title_en"]
    title_mr = matched_scheme["official_title_mr"]
    gr_num = matched_scheme.get("official_gr_number", "N/A")
    pub_date = matched_scheme.get("publication_date", "N/A")
    portal_url = matched_scheme.get("official_portal_url", "https://maharashtra.gov.in/")
    official_amounts = matched_scheme.get("benefit_numeric_values", [])

    supporting_evidence.append(
        f"Official Scheme Identified: '{title_en}' ({title_mr}) is a verified program under {matched_scheme['department_en']}."
    )
    supporting_evidence.append(
        f"Official Government Resolution: Document Reference '{gr_num}', Published on {pub_date}."
    )
    supporting_evidence.append(
        f"Official Benefit Amount: {matched_scheme['benefit_amount_description_en']}."
    )

    official_sources.append(
        {
            "title": title_en,
            "title_mr": title_mr,
            "portal_url": portal_url,
            "gr_url": matched_scheme.get("official_gr_url", portal_url),
            "gr_number": gr_num,
            "publication_date": pub_date,
            "department": matched_scheme["department_en"],
        }
    )

    # 7. Discrepancy Evaluation (Amounts, Registration Channels, URLs)
    claimed_amounts = extract_claimed_amounts(raw_claim)

    # Check 7.1: Amount Discrepancy
    if claimed_amounts and official_amounts:
        # Check if any claimed amount conflicts with official amounts
        matching_amount = any(ca in official_amounts for ca in claimed_amounts)
        conflicting_amounts = [ca for ca in claimed_amounts if ca not in official_amounts]
        if conflicting_amounts and not matching_amount:
            conflicting_evidence.append(
                f"Benefit Amount Discrepancy: The claim promises ₹{conflicting_amounts[0]:,}, whereas the official "
                f"Government Resolution strictly prescribes {matched_scheme['benefit_amount_description_en']}."
            )
        elif matching_amount:
            supporting_evidence.append(
                f"Benefit Amount Confirmed: The claimed amount aligns with the official figure ({matched_scheme['benefit_amount_description_en']})."
            )

    # Check 7.2: Unofficial WhatsApp registration or APK lure in claim
    whatsapp_or_apk_patterns = [
        (r"\b(whatsapp\s*link|whatsapp\s*var|या\s*लिंकवर)\b", "Claims registration occurs through a WhatsApp forwarding link."),
        (r"\b([a-zA-Z0-9_\-]+\.apk|apk\s*डाउनलोड|install\s*kara)\b", "Instructs citizens to install an unauthorized .apk package."),
        (r"\b(forward\s*to|ग्रुपवर\s*पाठवा|शेअर\s*करा)\b", "Requires forwarding to multiple WhatsApp groups to claim benefits."),
    ]
    for pattern, desc in whatsapp_or_apk_patterns:
        if re.search(pattern, normalized_claim):
            conflicting_evidence.append(
                f"Unofficial Channel: {desc} Official applications are accepted strictly through: "
                f"{', '.join(matched_scheme['official_application_channels_en'])}."
            )
            break

    # Check 7.3: Fee Demands (Government schemes are free)
    fee_patterns = r"(fee|charges|शुल्क|रजिस्ट्रेशन\s*फी|advance\s*payment|पैसे\s*भरा)"
    if re.search(fee_patterns, normalized_claim):
        conflicting_evidence.append(
            "Fraudulent Fee Demand: The claim demands a fee or advance payment. "
            "Official Maharashtra Government schemes do not charge citizens an application fee."
        )

    # Check 7.4: Separate URL Evaluation
    # A genuine scheme name must NOT automatically validate a suspicious link!
    if url_analysis["has_url"]:
        if url_analysis["is_official_domain"]:
            supporting_evidence.append(
                f"Verified Portal Domain: The link '{url_analysis['url']}' belongs to an allowlisted official portal ({url_analysis['hostname']})."
            )
        else:
            conflicting_evidence.append(
                f"Fake/Unofficial Registration Portal: The link provided '{url_analysis['url']}' is on '{url_analysis['hostname']}'. "
                f"The official portal for this scheme is strictly: {portal_url}."
            )
            for w in url_analysis["warnings_en"]:
                if "Unofficial Domain" not in w:
                    conflicting_evidence.append(f"URL Risk Factor: {w}")

    # Optional Live Portal Health Probe (only for allowlisted official portal)
    live_health = None
    if check_live_portal and portal_url:
        live_health = check_official_portal_health(portal_url, allowlisted)

    # 8. Determine Final Result Classification
    if conflicting_evidence:
        classification = "CONFLICTING EVIDENCE FOUND"
        summary_en = (
            f"While '{title_en}' is an authentic government scheme, the claim contains serious factual "
            f"conflicts (such as an incorrect payout amount, fake WhatsApp registration link, or third-party URL)."
        )
        summary_mr = (
            f"'{title_mr}' ही खरी सरकारी योजना असली, तरी या मेसेजमधील माहिती खोटी किंवा संशयास्पद आहे "
            "(रक्कम चुकीची आहे किंवा अधिकृत पोर्टल ऐवजी अनोळखी लिंक / व्हॉट्सॲपवरून अर्ज करण्यास सांगितले आहे)."
        )
    else:
        classification = "SUPPORTED BY OFFICIAL SOURCE"
        summary_en = (
            f"The details of this claim align with official records for '{title_en}'. "
            "Applications and notifications match official Government of Maharashtra guidelines."
        )
        summary_mr = (
            f"या मेसेजमधील माहिती '{title_mr}' च्या अधिकृत शासन निर्णयानुसार आणि माहितीनुसार सुसंगत आढळली आहे."
        )

    safe_next_steps_en = [
        f"Always use the verified official portal: {portal_url}",
        "Never share your bank account OTP, UPI PIN, or netbanking credentials to receive government payouts.",
        "Apply in person at an official Setu Suvidha Kendra, Gram Panchayat, or Anganwadi center.",
        "If you encounter a fraudulent scheme link on WhatsApp, report it to 1930 or https://cybercrime.gov.in."
    ]
    safe_next_steps_mr = [
        f"नेहमी अधिकृत वेबसाइटचाच वापर करा: {portal_url}",
        "योजनेचे पैसे मिळवण्यासाठी कोणालाही बँक OTP, UPI PIN किंवा पासवर्ड सांगू नका.",
        "अधिकृत सेतू सुविधा केंद्र, ग्रामपंचायत किंवा अंगणवाडी केंद्रात जाऊन प्रत्यक्ष माहिती घ्या.",
        "व्हॉट्सॲपवरील फसव्या लिंकबाबत सायबर हेल्पलाईन १९३० (1930) वर किंवा cybercrime.gov.in वर तक्रार करा."
    ]

    return {
        "classification": classification,
        "confidence_note": "Evaluated against verified Government of Maharashtra Resolutions and official portal registries.",
        "summary_en": summary_en,
        "summary_mr": summary_mr,
        "matched_scheme_title": f"{title_en} ({title_mr})",
        "supporting_evidence": supporting_evidence,
        "conflicting_evidence": conflicting_evidence,
        "official_sources": official_sources,
        "retrieval_metadata": {
            "retrieval_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "source_freshness": f"Source-Backed Registry (Curated {registry.get('last_curated')})",
            "mode": "Official Source-Backed Registry" + (" with Live Portal Health Probe" if check_live_portal else ""),
            "live_health": live_health,
        },
        "safe_next_steps_en": safe_next_steps_en,
        "safe_next_steps_mr": safe_next_steps_mr,
        "url_assessment": url_analysis,
        "limitations": (
            "Verification is grounded in verified Maharashtra Government Resolutions and allowlisted portals. "
            "It evaluates stated parameters and cannot inspect private or encrypted chat conversations."
        ),
    }
