"""
Safe Suspicious URL & Domain Analyzer for Seva Cyber Sandbox.

SECURITY & DEFENSIVE GUARANTEES:
1. NEVER automatically opens, resolves, crawls, or fetches user-supplied URLs.
2. NEVER downloads files or executes JavaScript from any target link.
3. Detects internal network addresses (RFC 1918, loopback, link-local) to guard against SSRF.
4. Identifies domain typosquatting, punycode/IDN homoglyphs, URL shorteners, and suspicious TLDs.
5. Emits a transparent 0-100 heuristic severity score separate from any ML classifier.
"""

import ipaddress
import os
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

# Configurable registry of allowlisted official domains
DEFAULT_OFFICIAL_DOMAINS = [
    "maharashtra.gov.in",
    "gov.in",
    "mahadiscom.in",
    "nic.in",
    "sbi.co.in",
    "rbi.org.in",
    "cybercrime.gov.in",
    "npci.org.in",
]

# Known public URL-shortening services
KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "rb.gy",
    "t.co",
    "cutt.ly",
    "is.gd",
    "shorturl.at",
    "ow.ly",
    "rebrand.ly",
    "goo.gl",
    "clck.ru",
    "tiny.cc",
}

# TLDs frequently abused in rapid-turnaround mass phishing campaigns
FREQUENTLY_ABUSED_TLDS = {
    "xyz",
    "top",
    "click",
    "buzz",
    "club",
    "site",
    "tk",
    "ml",
    "cf",
    "gq",
    "rest",
    "work",
    "cam",
    "fun",
    "icu",
    "monster",
    "space",
    "online",
    "vip",
    "live",
}

# Target brands commonly impersonated in Maharashtra and Indian cyber scams
LOOKALIKE_BRANDS = [
    ("msedcl", "Mahavitaran / MSEDCL Electricity Utility"),
    ("mahavitaran", "Mahavitaran Electricity Utility"),
    ("mahadiscom", "MSEDCL Electricity Distribution"),
    ("lightbill", "Electricity Bill Utility"),
    ("sbi", "State Bank of India"),
    ("statebank", "State Bank of India"),
    ("hdfc", "HDFC Bank"),
    ("icici", "ICICI Bank"),
    ("bankofmaharashtra", "Bank of Maharashtra"),
    ("pmkisan", "PM-Kisan Scheme"),
    ("ladkibahin", "Majhi Ladki Bahin Scheme"),
    ("ladaki-bahin", "Majhi Ladki Bahin Scheme"),
    ("mahadbt", "MahaDBT Direct Benefit Transfer"),
    ("echallan", "Traffic Police e-Challan Portal"),
    ("parivahan", "Parivahan Transport Ministry"),
]

# Sensitive keywords in path or query parameters
CREDENTIAL_OR_LURE_KEYWORDS = [
    ("otp", "OTP Request"),
    ("pin", "PIN / UPI PIN Entry"),
    ("cvv", "Card CVV Entry"),
    ("password", "Password Prompt"),
    ("login", "Login Authentication Page"),
    ("signin", "Sign-in Page"),
    ("verify", "Identity Verification Prompt"),
    ("kyc", "KYC Expiry / Update"),
    ("ekyc", "e-KYC Submission"),
    ("aadhaar", "Aadhaar Number Collection"),
    ("pan", "PAN Card Collection"),
    ("refund", "Refund Claim Lure"),
    ("cashback", "Cashback Prize Lure"),
    ("update", "Account / Bill Update Prompt"),
    ("bill-pay", "Payment Collection"),
]


def normalize_url_string(raw_url: str) -> str:
    """Cleans extra whitespace and quotes from a raw URL string."""
    if not raw_url:
        return ""
    cleaned = raw_url.strip().strip("'\"<>[]()")
    return cleaned


def is_ip_address_host(hostname: str) -> Tuple[bool, str, Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    """
    Checks if a hostname string is an IPv4 or IPv6 address.
    Returns (is_ip, ip_category, ip_obj).
    Categories: 'Loopback/Localhost', 'Private RFC1918', 'Link-Local', 'Public IPv4', 'IPv6', 'None'.
    """
    if not hostname:
        return False, "None", None

    clean_host = hostname.strip("[]")  # Handle IPv6 bracket format [::1]

    # Check localhost string
    if clean_host.lower() == "localhost":
        return True, "Loopback/Localhost", None

    try:
        ip = ipaddress.ip_address(clean_host)
        if ip.is_loopback:
            return True, "Loopback/Localhost", ip
        if ip.is_private:
            return True, "Private RFC1918", ip
        if ip.is_link_local:
            return True, "Link-Local", ip
        if isinstance(ip, ipaddress.IPv4Address):
            return True, "Public IPv4", ip
        return True, "IPv6", ip
    except ValueError:
        return False, "None", None


def check_domain_allowlist(hostname: str, allowlisted_domains: List[str]) -> Tuple[bool, Optional[str]]:
    """Checks if hostname matches or is a subdomain of an allowlisted official domain."""
    if not hostname:
        return False, None

    lower_host = hostname.lower()
    for allowed in allowlisted_domains:
        clean_allowed = allowed.strip().lower()
        if lower_host == clean_allowed or lower_host.endswith("." + clean_allowed):
            return True, clean_allowed

    return False, None


def detect_lookalike_brand(hostname: str, is_official: bool) -> Optional[Tuple[str, str]]:
    """
    Checks if an UNOFFICIAL hostname contains brand keywords of legitimate banks/utilities.
    Returns (brand_keyword, brand_name) if suspicious lookalike is detected.
    """
    if is_official or not hostname:
        return None

    lower_host = hostname.lower()
    # Remove separators like '-', '.', '_' for inspection
    condensed = re.sub(r"[\-._]", "", lower_host)

    for kw, brand_desc in LOOKALIKE_BRANDS:
        if kw in lower_host or kw in condensed:
            return kw, brand_desc

    return None


def detect_punycode_or_homoglyphs(hostname: str) -> Tuple[bool, str]:
    """
    Detects Punycode (xn--) or non-ASCII / mixed-script characters in the hostname.
    Returns (has_punycode_or_idn, explanation).
    """
    if not hostname:
        return False, ""

    lower_host = hostname.lower()

    if "xn--" in lower_host:
        try:
            decoded = lower_host.encode("ascii").decode("idna")
            return True, f"Punycode encoded domain (ASCII: '{lower_host}' -> Unicode: '{decoded}')."
        except Exception:
            return True, f"Punycode formatted hostname: '{lower_host}'."

    # Check for non-ASCII characters directly in hostname
    has_non_ascii = any(ord(char) > 127 for char in hostname)
    if has_non_ascii:
        return True, f"Internationalized Domain Name (IDN) contains non-ASCII characters in '{hostname}'."

    return False, ""


def analyze_url(
    raw_url: str,
    allowlisted_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Passively and defensively inspects a URL string without making any network connection.
    Returns a structured dictionary with observable traits, matched indicators, and heuristic score.
    """
    cleaned = normalize_url_string(raw_url)
    registry = allowlisted_domains or DEFAULT_OFFICIAL_DOMAINS

    result: Dict[str, Any] = {
        "url": raw_url,
        "normalized_url": cleaned,
        "is_valid_url": False,
        "scheme": "",
        "hostname": "",
        "port": None,
        "path": "",
        "query": "",
        "observable_characteristics": {},
        "matched_indicators": [],
        "score": 0,
        "risk_level": "Invalid or Empty Input",
        "badge_color": "gray",
        "summary_en": "Please provide a valid URL string to analyze.",
        "summary_mr": "कृपया तपासणीसाठी वैध वेब लिंक टाका.",
        "evidence": [],
        "safe_next_steps_en": [
            "Never click on unknown or unverified links received via WhatsApp or SMS.",
            "Verify any claims directly by typing the official website address into your browser."
        ],
        "safe_next_steps_mr": [
            "व्हॉट्सॲप किंवा एसएमएसवर आलेल्या अनोळखी लिंकवर क्लिक करू नका.",
            "माहितीची खात्री करण्यासाठी अधिकृत वेबसाइटचा पत्ता स्वतः टाईप करून उघडा."
        ],
        "limitations": "Passive static URL inspection checks domain structure, indicators, and keywords. It does not resolve DNS or fetch remote pages.",
    }

    # 1. Reject empty inputs
    if not cleaned:
        result["evidence"] = ["No URL text was provided."]
        return result

    # 2. Check for dangerous non-HTTP schemes
    lower_input = cleaned.lower()
    dangerous_schemes = ("javascript:", "data:", "file:", "blob:", "vbscript:", "ftp:")
    for d_scheme in dangerous_schemes:
        if lower_input.startswith(d_scheme):
            result["scheme"] = d_scheme.rstrip(":")
            result["risk_level"] = "Blocked / Dangerous URI Scheme"
            result["badge_color"] = "red"
            result["score"] = 95
            result["summary_en"] = (
                f"Dangerous URI Scheme: '{result['scheme']}:' can execute local scripts or access files. "
                "This is not a safe web hyperlink."
            )
            result["summary_mr"] = (
                f"धोकादायक लिंक प्रकार: '{result['scheme']}:' ही सामान्य वेबसाइट नसून कोड रन करणारी किंवा फाईल उघडणारी असुरक्षित लिंक आहे."
            )
            result["evidence"] = [f"Direct execution scheme '{d_scheme}' detected."]
            result["matched_indicators"].append({
                "id": "BLOCKED_SCHEME",
                "category": "Dangerous Scheme",
                "severity": "Critical",
                "weight": 95,
                "evidence_en": f"URI uses execution scheme '{d_scheme}'.",
                "evidence_mr": f"असुरक्षित URI प्रकार '{d_scheme}' आढळला.",
            })
            return result

    # 3. Add default protocol if missing for URL parsing
    parseable_url = cleaned
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
        parseable_url = "http://" + cleaned

    try:
        parsed = urllib.parse.urlparse(parseable_url)
    except Exception as exc:
        result["summary_en"] = f"Malformed URL syntax: {exc}"
        result["summary_mr"] = "लिंकची रचना चुकीची (malformed) आहे."
        result["evidence"] = [f"Parsing error: {exc}"]
        return result

    try:
        hostname = (parsed.hostname or "").strip().lower()
        port = parsed.port
    except (ValueError, TypeError) as val_err:
        result["summary_en"] = f"Invalid host or port in URL syntax: {val_err}"
        result["summary_mr"] = "लिंकमधील वेबसाइट पत्ता किंवा पोर्ट अवैध आहे."
        result["evidence"] = [f"URL parsing validation error: {val_err}"]
        return result

    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""

    if not hostname:
        result["summary_en"] = "Invalid URL: Could not extract a valid host or domain name."
        result["summary_mr"] = "अवैध लिंक: या लिंकमधून वेबसाइट पत्ता (domain) समजू शकला नाही."
        result["evidence"] = ["No valid hostname identified in URL structure."]
        return result

    result["is_valid_url"] = True
    result["scheme"] = scheme
    result["hostname"] = hostname
    result["port"] = port
    result["path"] = path
    result["query"] = query

    # 4. Extract Observable Characteristics
    is_official, matched_official = check_domain_allowlist(hostname, registry)
    is_ip, ip_type, _ = is_ip_address_host(hostname)
    has_punycode, puny_desc = detect_punycode_or_homoglyphs(hostname)
    lookalike_info = detect_lookalike_brand(hostname, is_official)

    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 and not is_ip else ""
    is_suspicious_tld = tld in FREQUENTLY_ABUSED_TLDS

    is_shortener = hostname in KNOWN_SHORTENERS or any(hostname.endswith("." + s) for s in KNOWN_SHORTENERS)

    # Check unusual port
    has_unusual_port = port is not None and port not in (80, 443)

    # Check excessive percent-encoding in path/query
    has_excessive_encoding = cleaned.count("%") >= 3 or "%2e%2e" in lower_input or "%2f" in lower_input

    # Check APK download
    has_apk = path.lower().endswith(".apk") or ".apk?" in lower_input or "download" in path.lower() and ".apk" in lower_input

    # Check credential or lure keywords in path/query
    matched_lure_keywords: List[str] = []
    combined_path_query = (path + " " + query).lower()
    for kw, kw_desc in CREDENTIAL_OR_LURE_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", combined_path_query) or f"/{kw}" in combined_path_query or f"={kw}" in combined_path_query:
            matched_lure_keywords.append(kw_desc)

    result["observable_characteristics"] = {
        "is_https": scheme == "https",
        "is_ip_address": is_ip,
        "ip_type": ip_type,
        "is_punycode_or_homoglyph": has_punycode,
        "punycode_details": puny_desc,
        "is_official_allowlisted": is_official,
        "matched_official_domain": matched_official,
        "is_lookalike": lookalike_info is not None,
        "lookalike_brand": lookalike_info[1] if lookalike_info else None,
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "is_shortener": is_shortener,
        "has_unusual_port": has_unusual_port,
        "port": port,
        "has_excessive_encoding": has_excessive_encoding,
        "has_apk_download": has_apk,
        "matched_lure_keywords": matched_lure_keywords,
    }

    # 5. Evaluate Indicators & Apply Deduplicated Weights
    indicators: List[Dict[str, Any]] = []

    # Case A: Private / Internal / SSRF IP Address
    if is_ip and ip_type in ("Loopback/Localhost", "Private RFC1918", "Link-Local"):
        indicators.append({
            "id": "INTERNAL_NETWORK_TARGET",
            "category": "Private / Internal Network Address",
            "severity": "Critical",
            "weight": 85,
            "evidence_en": f"Targets internal/private address ({hostname} - {ip_type}) which should never be exposed in public links.",
            "evidence_mr": f"खाजगी किंवा अंतर्गत नेटवर्क पत्ता ({hostname}) लक्ष्य केला आहे, जो सार्वजनिक लिंकवर कधीही नसावा.",
        })

    # Case B: Public IP as host
    elif is_ip:
        indicators.append({
            "id": "PUBLIC_IP_HOST",
            "category": "Numerical IP Address Host",
            "severity": "High",
            "weight": 35,
            "evidence_en": f"Uses raw numerical IP address ({hostname}) instead of a registered domain name with verified TLS certificates.",
            "evidence_mr": f"नोंदणीकृत अधिकृत डोमेन ऐवजी थेट संख्यात्मक आयपी पत्ता ({hostname}) वापरला आहे.",
        })

    # Case C: Lookalike brand on unverified domain (Typosquatting)
    if lookalike_info:
        indicators.append({
            "id": "UNOFFICIAL_LOOKALIKE",
            "category": "Deceptive Brand Lookalike",
            "severity": "High",
            "weight": 40,
            "evidence_en": f"Hostname '{hostname}' mimics {lookalike_info[1]} ('{lookalike_info[0]}') but does not belong to an official domain.",
            "evidence_mr": f"वेबसाइटचे नाव '{hostname}' हे अधिकृत {lookalike_info[1]} सारखे भासवणारे आहे, मात्र अधिकृत पोर्टल नाही.",
        })

    # Case D: Punycode or IDN Homoglyph
    if has_punycode:
        indicators.append({
            "id": "PUNYCODE_HOMOGLYPH",
            "category": "Punycode / Homoglyph Encoding",
            "severity": "High",
            "weight": 30,
            "evidence_en": puny_desc,
            "evidence_mr": f"Punycode किंवा आंतरराष्ट्रीय लिपीतील अक्षरे वापरून फसवण्याचा संशय ({hostname}).",
        })

    # Case E: APK Sideload Target
    if has_apk:
        indicators.append({
            "id": "APK_DOWNLOAD_TARGET",
            "category": "Direct APK Download Path",
            "severity": "High",
            "weight": 30,
            "evidence_en": "URL directly targets an Android application package (.apk) file.",
            "evidence_mr": "ही लिंक थेट फोनमध्ये .apk फाईल डाउनलोड करण्याचा प्रयत्न करते.",
        })

    # Case F: Suspicious TLD
    if is_suspicious_tld:
        indicators.append({
            "id": "SUSPICIOUS_TLD",
            "category": "High-Abuse Domain Extension",
            "severity": "Moderate",
            "weight": 20,
            "evidence_en": f"Uses domain extension '.{tld}', which is frequently abused in automated cyber fraud.",
            "evidence_mr": f"'.{tld}' हा विस्तार सामान्यतः फसव्या वेबसाईट्ससाठी वापरला जातो.",
        })

    # Case G: URL Shortener
    if is_shortener:
        indicators.append({
            "id": "URL_SHORTENER",
            "category": "Shortened / Masked Web Link",
            "severity": "Moderate",
            "weight": 20,
            "evidence_en": f"Uses a URL shortener ({hostname}) to disguise the actual destination webpage.",
            "evidence_mr": f"मूळ वेबसाइट लपवण्यासाठी शॉर्टनर ({hostname}) वापरले आहे.",
        })

    # Case H: Credential or KYC keywords in path/query
    if matched_lure_keywords and not is_official:
        kw_str = ", ".join(matched_lure_keywords[:3])
        indicators.append({
            "id": "CREDENTIAL_OR_KYC_PATH",
            "category": "Credential / KYC Lure in URL",
            "severity": "Moderate",
            "weight": 18,
            "evidence_en": f"Path or query parameter contains sensitive terms: {kw_str}.",
            "evidence_mr": f"लिंकमध्ये संवेदनशील शब्द आढळले: {kw_str}.",
        })

    # Case I: Unusual Non-Standard Port
    if has_unusual_port:
        indicators.append({
            "id": "UNUSUAL_PORT",
            "category": "Non-Standard Web Port",
            "severity": "Moderate",
            "weight": 16,
            "evidence_en": f"Specifies non-standard port :{port} (standard web traffic uses 80 or 443).",
            "evidence_mr": f"असामान्य पोर्ट :{port} वापरले आहे.",
        })

    # Case J: Obfuscated Percent Encoding
    if has_excessive_encoding:
        indicators.append({
            "id": "OBFUSCATED_ENCODING",
            "category": "Obfuscated / Percent Encoding",
            "severity": "Moderate",
            "weight": 15,
            "evidence_en": "Contains excessive percent-encoding or path traversal characters.",
            "evidence_mr": "लिंकमध्ये अस्पष्ट किंवा लपवलेले कोडिंग आढळले.",
        })

    # Case K: Insecure HTTP
    if scheme == "http" and not is_ip:
        indicators.append({
            "id": "UNENCRYPTED_HTTP",
            "category": "Unencrypted HTTP Protocol",
            "severity": "Low",
            "weight": 10,
            "evidence_en": "Traffic is transmitted in plain text without SSL/TLS encryption (http://).",
            "evidence_mr": "माहिती एनक्रिप्ट केलेली नाही (असुरक्षित http://).",
        })

    # Case L: Official Allowlisted Portal
    if is_official and not has_apk:
        # Verified official domain without rogue APK payloads
        indicators.append({
            "id": "OFFICIAL_GOVERNMENT_PORTAL",
            "category": "Allowlisted Official Domain",
            "severity": "Informational",
            "weight": -50,
            "evidence_en": f"Hostname belongs to verified allowlisted domain '{matched_official}'.",
            "evidence_mr": f"महाराष्ट्र शासनाचे किंवा अधिकृत बँकेचे पडताळणीकृत पोर्टल '{matched_official}'.",
        })

    # 6. Calculate Heuristic Score (Deduplicated with Family Maximums)
    raw_score = sum(ind["weight"] for ind in indicators)
    final_score = max(0, min(100, raw_score))

    # Official allowlisted domains override score to 0 unless an APK download is explicitly attached
    if is_official and not has_apk:
        final_score = 0

    result["score"] = final_score
    result["matched_indicators"] = indicators

    # 7. Formulate Evidence Bullet Points
    evidence_list: List[str] = []
    for ind in indicators:
        if ind["weight"] > 0:
            evidence_list.append(f"[{ind['category']}] ({ind['severity']}): {ind['evidence_en']}")
        else:
            evidence_list.append(f"[{ind['category']}]: {ind['evidence_en']}")

    if not evidence_list:
        evidence_list.append("No suspicious indicators or high-risk domain patterns were matched.")

    result["evidence"] = evidence_list

    # 8. Determine Risk Level, Badge Color, and Bilingual Advice
    if final_score >= 50:
        result["risk_level"] = "High-Risk Suspicious Link Detected"
        result["badge_color"] = "red"
        result["summary_en"] = (
            f"This link ({hostname}) exhibits multiple high-risk indicators commonly seen in phishing, "
            "malware delivery, or brand impersonation scams. Do not enter credentials or download files."
        )
        result["summary_mr"] = (
            f"धोकादायक लिंक! ही लिंक ({hostname}) फसवणूक करण्यासाठी किंवा बनावट पेजवर नेण्यासाठी तयार केल्यासारखी दिसते. "
            "या लिंकवर कोणतीही माहिती भरू नका आणि फाईल डाउनलोड करू नका."
        )
        result["safe_next_steps_en"] = [
            "CRITICAL: NEVER enter OTPs, netbanking passwords, debit card CVV, or UPI PINs into this page.",
            "Do not download or install any .apk files prompted by this link.",
            "Delete the forwarded message from your chat.",
            "Report fraudulent links to 1930 or https://cybercrime.gov.in."
        ]
        result["safe_next_steps_mr"] = [
            "अत्यंत महत्त्वाचे: या पेजवर तुमचा बँक OTP, पासवर्ड, एटीएम पिन किंवा UPI PIN कधीही टाकू नका.",
            "या लिंकवरून आलेली कोणतीही .apk फाईल इन्स्टॉल करू नका.",
            "हा मेसेज तात्काळ डिलीट करा.",
            "सायबर हेल्पलाईन १९३० (1930) वर किंवा cybercrime.gov.in वर तक्रार नोंदवा."
        ]
    elif final_score >= 20:
        result["risk_level"] = "Potentially Suspicious Link (Review Context)"
        result["badge_color"] = "orange"
        result["summary_en"] = (
            f"This link uses a masked URL shortener, non-standard extension, or unencrypted connection. "
            "Verify the destination independently before trusting it."
        )
        result["summary_mr"] = (
            f"सावधान! या लिंकमध्ये शॉर्टनर किंवा असामान्य डोमेन आढळले आहे. "
            "अधिकृत वेबसाइटवरून खात्री केल्याशिवाय यावर विश्वास ठेवू नका."
        )
        result["safe_next_steps_en"] = [
            "Avoid sharing personal details or financial credentials on shortened links.",
            "If this claims to be from a utility or bank, open the official app or website directly instead."
        ]
        result["safe_next_steps_mr"] = [
            "शॉर्टनर लिंकवर वैयक्तिक किंवा बँक माहिती देणे टाळा.",
            "महावितरण किंवा बँकेचे काम असल्यास अधिकृत ॲप किंवा अधिकृत वेबसाइटचाच वापर करा."
        ]
    else:
        result["risk_level"] = "No Strong Risk Indicators Detected"
        result["badge_color"] = "green"
        result["summary_en"] = (
            f"No prominent phishing or lookalike patterns were detected for '{hostname}'. "
            "However, passive inspection cannot guarantee that an external web page is 100% safe."
        )
        result["summary_mr"] = (
            f"या लिंकमध्ये ({hostname}) फसवणुकीचे ठळक संकेत आढळले नाहीत. "
            "तरीही अनोळखी व्यक्तीने पाठवलेल्या लिंकबाबत नेहमी सावध राहा."
        )
        result["safe_next_steps_en"] = [
            "Always check that the address bar displays a secure padlock icon and verified domain.",
            "Remember that legitimate government offices never ask for UPI PINs or OTPs over the internet."
        ]
        result["safe_next_steps_mr"] = [
            "नेहमी ब्राउझरमधील वेबसाइट पत्ता तपासूनच पुढे जा.",
            "कोणतेही सरकारी कार्यालय किंवा बँक पैशांसाठी UPI PIN किंवा OTP मागत नाही हे लक्षात ठेवा."
        ]

    return result
