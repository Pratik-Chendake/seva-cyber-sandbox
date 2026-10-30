"""
Comprehensive Automated Test Suite for Safe Suspicious URL Analyzer.
Tests cover:
1. Benign and allowlisted official URLs.
2. Malformed, empty, and non-string inputs.
3. Dangerous / blocked schemes (javascript:, file:, data:).
4. Typosquatting and deceptive lookalike domains (e.g. msedcl, sbi).
5. Punycode and Internationalized Domain Names (IDN homoglyphs).
6. Known URL-shortening services.
7. Public IP addresses vs. private/internal network addresses (SSRF guard).
8. Non-standard ports and obfuscated percent-encoding.
9. Direct APK download lures and credential harvesting paths.
10. Strict offline verification: confirms zero remote network calls are made.
"""

import os
import sys
from unittest.mock import patch

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.url_analyzer import analyze_url, is_ip_address_host, normalize_url_string


def test_01_benign_official_url():
    """Allowlisted official Maharashtra portals must score 0 and produce green status."""
    res = analyze_url("https://ladakibahin.maharashtra.gov.in/index.html")
    assert res["is_valid_url"] is True
    assert res["score"] == 0
    assert res["badge_color"] == "green"
    assert "No Strong Risk Indicators" in res["risk_level"]
    assert res["observable_characteristics"]["is_official_allowlisted"] is True


def test_02_benign_general_url():
    """Standard benign websites should not be flagged as malicious."""
    res = analyze_url("https://www.google.com/search?q=weather")
    assert res["is_valid_url"] is True
    assert res["score"] < 20
    assert res["badge_color"] == "green"


def test_03_empty_and_malformed_inputs():
    """Handles empty strings, whitespaces, and unparseable inputs gracefully."""
    empty_res = analyze_url("")
    assert empty_res["is_valid_url"] is False
    assert empty_res["badge_color"] == "gray"

    spaces_res = analyze_url("   \t  ")
    assert spaces_res["is_valid_url"] is False

    none_res = analyze_url(None)  # type: ignore
    assert none_res["is_valid_url"] is False


def test_04_dangerous_blocked_schemes():
    """Rejects javascript:, file:, and data: schemes with high severity."""
    js_res = analyze_url("javascript:alert(document.cookie)")
    assert js_res["scheme"] == "javascript"
    assert js_res["score"] >= 90
    assert js_res["badge_color"] == "red"
    assert "Blocked / Dangerous" in js_res["risk_level"]

    file_res = analyze_url("file:///etc/passwd")
    assert file_res["scheme"] == "file"
    assert file_res["score"] >= 90

    data_res = analyze_url("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")
    assert data_res["scheme"] == "data"
    assert data_res["score"] >= 90


def test_05_lookalike_typosquatting_domain():
    """Detects brand impersonation (msedcl, sbi) on unverified domains."""
    url = "http://msedcl-bill-update-maharashtra.xyz/pay"
    res = analyze_url(url)
    assert res["is_valid_url"] is True
    assert res["score"] >= 50
    assert res["badge_color"] == "red"
    assert any(ind["id"] == "UNOFFICIAL_LOOKALIKE" for ind in res["matched_indicators"])
    assert any(ind["id"] == "SUSPICIOUS_TLD" for ind in res["matched_indicators"])
    assert any(ind["id"] == "UNENCRYPTED_HTTP" for ind in res["matched_indicators"])


def test_06_punycode_and_homoglyphs():
    """Identifies punycode (xn--) and non-ASCII character homoglyphs."""
    puny_url = "http://xn--sbi-8ka.com/login"
    res_puny = analyze_url(puny_url)
    assert res_puny["observable_characteristics"]["is_punycode_or_homoglyph"] is True
    assert any(ind["id"] == "PUNYCODE_HOMOGLYPH" for ind in res_puny["matched_indicators"])

    # Cyrillic 'а' (U+0430) instead of Latin 'a'
    homoglyph_url = "http://m\u0430h\u0430discom.com/bill"
    res_homo = analyze_url(homoglyph_url)
    assert res_homo["observable_characteristics"]["is_punycode_or_homoglyph"] is True


def test_07_url_shortening_service():
    """Flags URL shorteners proportionately without marking them as immediately malicious."""
    res = analyze_url("https://bit.ly/3xY8zPay")
    assert res["is_valid_url"] is True
    assert res["observable_characteristics"]["is_shortener"] is True
    # Shortener alone should be moderate (orange), not 100 max
    assert 15 <= res["score"] < 50
    assert res["badge_color"] == "orange"
    assert any(ind["id"] == "URL_SHORTENER" for ind in res["matched_indicators"])


def test_08_ip_address_host_and_internal_network_guard():
    """Differentiates public IP hosts from private/internal network targets (SSRF protection)."""
    # Private / internal IP target
    internal_res = analyze_url("http://192.168.1.1/admin/setup")
    assert internal_res["observable_characteristics"]["is_ip_address"] is True
    assert internal_res["observable_characteristics"]["ip_type"] == "Private RFC1918"
    assert internal_res["score"] >= 80
    assert any(ind["id"] == "INTERNAL_NETWORK_TARGET" for ind in internal_res["matched_indicators"])

    # Loopback / localhost target
    loopback_res = analyze_url("http://127.0.0.1:8080/secret")
    assert loopback_res["observable_characteristics"]["ip_type"] == "Loopback/Localhost"
    assert any(ind["id"] == "INTERNAL_NETWORK_TARGET" for ind in loopback_res["matched_indicators"])

    # Public IP target
    public_res = analyze_url("http://45.33.32.156/verify")
    assert public_res["observable_characteristics"]["ip_type"] == "Public IPv4"
    assert any(ind["id"] == "PUBLIC_IP_HOST" for ind in public_res["matched_indicators"])


def test_09_unusual_port_and_obfuscated_encoding():
    """Detects non-standard ports (e.g. 8888) and excessive percent-encoding."""
    res = analyze_url("http://example.com:8888/test%2e%2e%2fpath")
    assert res["observable_characteristics"]["has_unusual_port"] is True
    assert res["observable_characteristics"]["has_excessive_encoding"] is True
    assert any(ind["id"] == "UNUSUAL_PORT" for ind in res["matched_indicators"])
    assert any(ind["id"] == "OBFUSCATED_ENCODING" for ind in res["matched_indicators"])


def test_10_apk_download_target_and_credential_lures():
    """Detects direct APK download references and credential collection paths."""
    res = analyze_url("https://unverified-utility-host.com/updates/MSEDCL_Bill_Helper.apk?user=test")
    assert res["observable_characteristics"]["has_apk_download"] is True
    assert any(ind["id"] == "APK_DOWNLOAD_TARGET" for ind in res["matched_indicators"])

    cred_res = analyze_url("https://unverified-site.com/verify-kyc?action=enter-otp")
    assert any(ind["id"] == "CREDENTIAL_OR_KYC_PATH" for ind in cred_res["matched_indicators"])


def test_11_strict_offline_zero_network_calls():
    """
    CRITICAL SECURITY CHECK:
    Guarantees that analyze_url NEVER sends any HTTP, HTTPS, or socket connection.
    """
    with patch("urllib.request.urlopen") as mock_urlopen, patch("socket.socket") as mock_socket:
        _ = analyze_url("http://dangerous-malware-c2-server.xyz/payload.exe")
        mock_urlopen.assert_not_called()
        mock_socket.assert_not_called()
