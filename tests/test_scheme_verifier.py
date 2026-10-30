"""
Automated Test Suite for Maharashtra Government Scheme & Announcement Verifier.
Tests cover:
1. Claim supported by official-source fixture.
2. Claim contradicted by explicit fixture evidence (amount discrepancy & WhatsApp lure).
3. Claim with insufficient evidence (unknown/unindexed scheme).
4. Unavailable official source (bad file path).
5. Invalid input and empty input handling.
6. Malformed source data handling.
7. Suspicious URL safety check (guarantees user URLs are never fetched).
8. Legitimate scheme name paired with a suspicious registration link.
9. Allowlisted domain health probe safety boundary.
"""

import json
import os
import sys
import tempfile
from unittest.mock import patch

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.scheme_verifier import (
    analyze_suspicious_url,
    check_official_portal_health,
    is_domain_allowlisted,
    load_official_sources,
    normalize_text_for_matching,
    verify_scheme_claim,
)


def test_01_claim_supported_by_official_source():
    """Valid claim with correct official details and allowlisted portal."""
    claim = (
        "मुख्यमंत्री माझी लाडकी बहीण योजनेअंतर्गत पात्र महिलांना दरमहा ₹1500 चा थेट लाभ "
        "अधिकृत पोर्टल ladakibahin.maharashtra.gov.in द्वारे दिला जातो."
    )
    result = verify_scheme_claim(claim, suspicious_url="https://ladakibahin.maharashtra.gov.in")
    assert result["classification"] == "SUPPORTED BY OFFICIAL SOURCE"
    assert "Mukhyamantri Majhi Ladki Bahin" in result["matched_scheme_title"]
    assert len(result["supporting_evidence"]) > 0
    assert len(result["conflicting_evidence"]) == 0
    assert len(result["official_sources"]) > 0
    assert "ladakibahin.maharashtra.gov.in" in result["official_sources"][0]["portal_url"]


def test_02_claim_contradicted_by_amount_discrepancy():
    """Real scheme name, but contradictory amount (₹3,000 claimed vs ₹1,500 official)."""
    claim = (
        "Register through this WhatsApp link to receive ₹3,000 under the "
        "Mukhyamantri Majhi Ladki Bahin Yojana."
    )
    result = verify_scheme_claim(claim)
    assert result["classification"] == "CONFLICTING EVIDENCE FOUND"
    assert any("Amount Discrepancy" in ev for ev in result["conflicting_evidence"])
    assert any("Unofficial Channel" in ev for ev in result["conflicting_evidence"])


def test_03_claim_with_insufficient_evidence():
    """Unindexed / fabricated scheme claim that cannot be substantiated."""
    claim = (
        "Maharashtra Golden Citizen Free Laptop Yojana 2026: All college students get a free laptop."
    )
    result = verify_scheme_claim(claim)
    assert result["classification"] == "NOT ENOUGH EVIDENCE"
    assert result["matched_scheme_title"] is None
    assert "No official Maharashtra Government Resolution" in result["summary_en"]


def test_04_unavailable_official_source():
    """Handling when the official sources registry cannot be found."""
    result = verify_scheme_claim(
        claim_text="Ladki Bahin Yojana details",
        registry_path="non_existent_directory/missing_sources.json",
    )
    assert result["classification"] == "SOURCE UNAVAILABLE"
    assert "unavailable" in result["summary_en"].lower()
    assert result["retrieval_metadata"]["source_freshness"] == "Unreachable"


def test_05_invalid_and_empty_inputs():
    """Handles empty strings, whitespace, and None gracefully."""
    res_empty = verify_scheme_claim("")
    assert res_empty["classification"] == "NOT ENOUGH EVIDENCE"
    assert "Please paste" in res_empty["summary_en"]

    res_spaces = verify_scheme_claim("    \n   ")
    assert res_spaces["classification"] == "NOT ENOUGH EVIDENCE"

    res_none = verify_scheme_claim(None)  # type: ignore
    assert res_none["classification"] == "NOT ENOUGH EVIDENCE"


def test_06_malformed_source_data():
    """Handles invalid/corrupted JSON file gracefully."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tmp:
        tmp.write('{"invalid_structure": true}')
        tmp_path = tmp.name

    try:
        loaded = load_official_sources(tmp_path)
        assert loaded["is_valid"] is False
        assert "Malformed registry structure" in loaded["error"]

        res = verify_scheme_claim("Mukhyamantri Ladki Bahin", registry_path=tmp_path)
        assert res["classification"] == "SOURCE UNAVAILABLE"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_07_suspicious_url_must_not_be_fetched():
    """
    CRITICAL SECURITY GUARANTEE:
    Verifies that analyze_suspicious_url and verify_scheme_claim NEVER issue an HTTP request
    to user-supplied arbitrary URLs.
    """
    suspicious_url = "http://phishing-scam-server-malicious.xyz/steal-otp"

    with patch("urllib.request.urlopen") as mock_urlopen:
        analysis = analyze_suspicious_url(suspicious_url, ["maharashtra.gov.in", "gov.in"])
        assert analysis["has_url"] is True
        assert analysis["is_official_domain"] is False
        assert analysis["is_unencrypted"] is True
        assert any("Suspicious Domain Extension" in w for w in analysis["warnings_en"])

        # Also test inside verify_scheme_claim
        _ = verify_scheme_claim(
            claim_text="Apply for Ladki Bahin on this site",
            suspicious_url=suspicious_url,
        )

        # urllib.request.urlopen must NEVER have been called!
        mock_urlopen.assert_not_called()


def test_08_legitimate_scheme_paired_with_suspicious_link():
    """
    Legitimate scheme name (Ladki Bahin), but registration link points to an unofficial .xyz domain.
    Must evaluate link independently and produce CONFLICTING EVIDENCE FOUND.
    """
    claim = "मुख्यमंत्री माझी लाडकी बहीण योजना अर्ज प्रक्रिया"
    suspicious_link = "http://ladkibahin-yojana-registration.xyz/apply"

    result = verify_scheme_claim(claim, suspicious_url=suspicious_link)
    assert result["classification"] == "CONFLICTING EVIDENCE FOUND"
    assert any("Fake/Unofficial Registration Portal" in ev for ev in result["conflicting_evidence"])
    assert result["url_assessment"]["is_official_domain"] is False


def test_09_allowlisted_domain_health_probe_safety():
    """
    Verifies that check_official_portal_health blocks non-allowlisted domains
    and does not send network requests to them.
    """
    allowed_domains = ["maharashtra.gov.in", "gov.in"]

    # Blocked domain
    with patch("urllib.request.urlopen") as mock_urlopen:
        probe_res = check_official_portal_health("https://evil-attacker.com/status", allowed_domains)
        assert probe_res["is_reachable"] is False
        assert "Safety Violation" in probe_res["error"]
        mock_urlopen.assert_not_called()


def test_10_text_normalization_with_zero_width_and_devanagari():
    """Verifies that Devanagari digits and zero-width spaces are normalized cleanly."""
    raw = "लाडकी\u200Cबहीण\u200D योजना ₹१५००"
    normalized = normalize_text_for_matching(raw)
    assert "\u200C" not in normalized
    assert "\u200D" not in normalized
    assert "1500" in normalized
