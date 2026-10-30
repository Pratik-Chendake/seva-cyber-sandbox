"""
Regression and Structural Compliance Test Suite for Android APK Static Analyzer.

Exhaustively verifies:
1. Properly structured compiled AXML element tree parsing.
2. Actual permissions declared using start-element attributes.
3. String-pool-only permissions (unused strings) are NOT treated as declared permissions.
4. Multiple declared permissions parsed accurately.
5. Missing permissions (0 permissions) handled safely as empty list.
6. Unusual but valid permission tags (uses-permission-sdk-23, uses-permission-sdk-m).
7. Invalid string references (out-of-bounds indices) handled defensively without crash.
8. Malformed chunk lengths and offsets rejected with explicit error.
9. Truncated manifests rejected without false "clean" verdict.
10. Missing required elements (header/pool only, no <manifest>) rejected.
11. Valid benign APK with no sensitive permissions scored honestly as Low Risk / Green.
12. Synthetic plain-text XML fixtures labeled honestly and parsed by structure.
13. Corrupt ZIP archives rejected with clear error.
14. Safety limits enforced (upload size, uncompressed member, zip slip, bombs).
15. Output schema compatibility across the sandbox engine and callers.
16. Resource reference attributes (@0x7f...) preserved honestly.
"""

import io
import os
import struct
import zipfile
import pytest

from create_sample_apks import (
    build_compiled_axml_tree_bytes,
    _build_binary_axml_bytes,
)
from src.apk_analyzer import (
    MAX_APK_UPLOAD_BYTES,
    MAX_UNCOMPRESSED_MEMBER_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    MAX_ZIP_ENTRIES,
    analyze_apk_bytes,
)
from src.risk_scorer import score_apk_analysis


def _make_test_apk(
    manifest_bytes: bytes,
    dex_bytes: bytes = b"dex\n035\x00" + b"\x00" * 64,
    extra_files: dict = None,
    compress_type: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    """Helper to wrap manifest and dex bytes into a valid in-memory APK ZIP archive."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compress_type) as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)
        if dex_bytes:
            zf.writestr("classes.dex", dex_bytes)
        if extra_files:
            for fname, fcontent in extra_files.items():
                zf.writestr(fname, fcontent)
    return bio.getvalue()


# ---------------------------------------------------------------------------
# Scenario 1: Properly structured compiled AXML element tree parsing
# ---------------------------------------------------------------------------
def test_scenario_01_properly_structured_compiled_axml():
    axml = build_compiled_axml_tree_bytes(
        package_name="in.gov.maharashtra.citizen.portal",
        app_label="MahaSeva Portal",
        version_name="2.4.1",
        version_code=241,
        permissions=["android.permission.INTERNET"],
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "proper_axml.apk")

    assert res["is_valid_apk"] is True
    assert res["is_synthetic_fixture"] is False
    assert "Compiled Android Binary XML" in res["manifest_format"]
    assert "Spec-Compliant Binary AXML Element Tree Parser" == res["parser_used"]
    assert res["package_name"] == "in.gov.maharashtra.citizen.portal"
    assert res["app_name"] == "MahaSeva Portal"
    assert res["version_name"] == "2.4.1"
    assert str(res["version_code"]) == "241"
    assert res["all_raw_permissions"] == ["android.permission.INTERNET"]


# ---------------------------------------------------------------------------
# Scenario 2: Actual permissions declared using start-element attributes
# ---------------------------------------------------------------------------
def test_scenario_02_actual_permissions_declared_via_attributes():
    declared = [
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ]
    axml = build_compiled_axml_tree_bytes(
        package_name="com.test.sms.listener",
        app_label="SMS Utility",
        permissions=declared,
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "sms_listener.apk")

    assert res["is_valid_apk"] is True
    assert sorted(res["all_raw_permissions"]) == sorted(declared)
    found_names = {p["permission"] for p in res["permissions_found"]}
    assert set(declared) == found_names

    # Check risk scoring on these critical permissions
    scored = score_apk_analysis(res)
    assert scored["score"] >= 50
    assert scored["badge_color"] == "red"


# ---------------------------------------------------------------------------
# Scenario 3: Permissions present ONLY as unused string-pool strings
# (MUST NOT BE TREATED AS DECLARED PERMISSIONS)
# ---------------------------------------------------------------------------
def test_scenario_03_string_pool_only_permissions_not_extracted():
    """
    CRITICAL SECURITY CHECK:
    If a permission string appears in the string pool (e.g. from an unused library,
    obfuscator, or metadata), but is NOT referenced by a <uses-permission> element,
    it MUST NOT be extracted or scored as a declared permission.
    """
    axml = build_compiled_axml_tree_bytes(
        package_name="com.benign.calculator",
        app_label="Simple Calculator",
        permissions=["android.permission.INTERNET"],  # Only INTERNET is declared in AST!
        extra_pool_strings=[
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "calculator_with_unused_strings.apk")

    assert res["is_valid_apk"] is True
    # The declared list must contain ONLY INTERNET!
    assert res["all_raw_permissions"] == ["android.permission.INTERNET"]
    assert len(res["permissions_found"]) == 0  # INTERNET is not in sensitive catalog

    # The phantom permissions must NEVER appear
    assert "android.permission.SEND_SMS" not in res["all_raw_permissions"]
    assert "android.permission.RECEIVE_SMS" not in res["all_raw_permissions"]
    assert "android.permission.BIND_ACCESSIBILITY_SERVICE" not in res["all_raw_permissions"]

    # Scorer must classify this app as low risk / green, not high risk!
    scored = score_apk_analysis(res)
    assert scored["score"] == 0
    assert scored["badge_color"] == "green"


# ---------------------------------------------------------------------------
# Scenario 4: Multiple declared permissions (deduplicated and sorted)
# ---------------------------------------------------------------------------
def test_scenario_04_multiple_declared_permissions():
    perms = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.VIBRATE",
    ]
    axml = build_compiled_axml_tree_bytes(
        package_name="com.multi.perm.app",
        app_label="Feature Rich App",
        permissions=perms,
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "multi_perm.apk")

    assert res["is_valid_apk"] is True
    assert set(res["all_raw_permissions"]) == set(perms)
    assert len(res["all_raw_permissions"]) == len(perms)


# ---------------------------------------------------------------------------
# Scenario 5: Missing permissions (0 declared)
# ---------------------------------------------------------------------------
def test_scenario_05_zero_declared_permissions():
    axml = build_compiled_axml_tree_bytes(
        package_name="com.offline.notes",
        app_label="Offline Notes",
        permissions=[],
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "offline_notes.apk")

    assert res["is_valid_apk"] is True
    assert res["all_raw_permissions"] == []
    assert res["permissions_found"] == []
    scored = score_apk_analysis(res)
    assert scored["score"] == 0
    assert scored["badge_color"] == "green"


# ---------------------------------------------------------------------------
# Scenario 6: Unusual but valid permission elements (uses-permission-sdk-23)
# ---------------------------------------------------------------------------
def test_scenario_06_unusual_permission_tags():
    axml = build_compiled_axml_tree_bytes(
        package_name="com.sdk23.test",
        app_label="SDK23 Audio App",
        permission_tags=[
            ("uses-permission", "android.permission.INTERNET"),
            ("uses-permission-sdk-23", "android.permission.RECORD_AUDIO"),
            ("uses-permission-sdk-m", "android.permission.CAMERA"),
        ],
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "sdk23_app.apk")

    assert res["is_valid_apk"] is True
    assert "android.permission.RECORD_AUDIO" in res["all_raw_permissions"]
    assert "android.permission.CAMERA" in res["all_raw_permissions"]
    assert "android.permission.INTERNET" in res["all_raw_permissions"]


# ---------------------------------------------------------------------------
# Scenario 7: Invalid string references (out-of-bounds indices)
# ---------------------------------------------------------------------------
def test_scenario_07_invalid_string_references_handled_safely():
    axml = build_compiled_axml_tree_bytes(
        package_name="com.corrupt.idx",
        app_label="Corrupt Index App",
        permissions=["android.permission.INTERNET"],
        corrupt_attr_idx=True,  # Points attribute value to index 9999
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "corrupt_idx.apk")

    assert res["is_valid_apk"] is True
    # The out-of-bounds attribute value must NOT crash or be added as permission
    assert "android.permission.INTERNET" not in res["all_raw_permissions"]
    assert len(res["all_raw_permissions"]) == 0


# ---------------------------------------------------------------------------
# Scenario 8: Malformed chunk lengths and offsets
# ---------------------------------------------------------------------------
def test_scenario_08_malformed_chunk_length_rejected():
    axml = build_compiled_axml_tree_bytes(
        package_name="com.bad.chunk",
        app_label="Bad Chunk",
        permissions=["android.permission.INTERNET"],
        corrupt_chunk_len=True,  # Chunk claiming size 4 (< 8)
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "bad_chunk.apk")

    assert res["is_valid_apk"] is False
    assert "Corrupted Android Binary XML" in res["manifest_format"]
    assert "Failed to parse Android Binary XML structure" in res["error_message"]


# ---------------------------------------------------------------------------
# Scenario 9: Truncated manifests
# ---------------------------------------------------------------------------
def test_scenario_09_truncated_manifest_rejected():
    valid_axml = build_compiled_axml_tree_bytes(
        package_name="com.truncated.app",
        app_label="Truncated",
        permissions=["android.permission.RECEIVE_SMS"],
    )
    # Cut manifest in half
    truncated_axml = valid_axml[: len(valid_axml) // 2]
    apk_bytes = _make_test_apk(truncated_axml)
    res = analyze_apk_bytes(apk_bytes, "truncated.apk")

    assert res["is_valid_apk"] is False
    assert "Corrupted Android Binary XML" in res["manifest_format"]
    # Crucially, RECEIVE_SMS must NOT be scraped or marked clean!
    assert len(res["permissions_found"]) == 0


# ---------------------------------------------------------------------------
# Scenario 10: Missing required elements (header/pool only, no <manifest>)
# ---------------------------------------------------------------------------
def test_scenario_10_missing_manifest_element_rejected():
    axml_no_elements = build_compiled_axml_tree_bytes(
        package_name="com.empty.manifest",
        app_label="Empty",
        no_elements=True,  # Header and StringPool only, no AST element chunks
    )
    apk_bytes = _make_test_apk(axml_no_elements)
    res = analyze_apk_bytes(apk_bytes, "no_elements.apk")

    assert res["is_valid_apk"] is False
    assert "Corrupted Android Binary XML" in res["manifest_format"]
    assert "Manifest does not contain a <manifest> element" in res["error_message"]


# ---------------------------------------------------------------------------
# Scenario 11: Valid benign APK with no sensitive permissions (Green rating)
# ---------------------------------------------------------------------------
def test_scenario_11_benign_apk_scored_green():
    axml = build_compiled_axml_tree_bytes(
        package_name="in.gov.maharashtra.water.bill",
        app_label="MahaJal Bill View",
        permissions=["android.permission.INTERNET"],
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "MahaJal_Bill_View.apk")

    assert res["is_valid_apk"] is True
    scored = score_apk_analysis(res)
    assert scored["score"] == 0
    assert scored["badge_color"] == "green"
    assert (
        "No Strong Permission-Risk Indicators" in scored["risk_level"]
        or "Low Heuristic Risk" in scored["risk_level"]
    )


# ---------------------------------------------------------------------------
# Scenario 12: Synthetic text fixtures identified honestly and parsed by structure
# ---------------------------------------------------------------------------
def test_scenario_12_synthetic_text_fixture_identification_and_parsing():
    xml_content = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.fixture.test"
    android:versionName="1.0-fixture">
    <!-- Comment with decoy: android.permission.SEND_SMS should not be extracted -->
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <application android:label="Fixture Test App" />
</manifest>
"""
    apk_bytes = _make_test_apk(xml_content, dex_bytes=b"SYNTHETIC_STUB")
    res = analyze_apk_bytes(apk_bytes, "synthetic_sample.apk")

    assert res["is_valid_apk"] is True
    assert res["is_synthetic_fixture"] is True
    assert res["manifest_format"] == "Synthetic Plain-Text XML Test Fixture"
    assert res["parser_used"] == "Safe Plain-Text XML Element Tree Parser"
    assert res["package_name"] == "com.fixture.test"
    assert res["app_name"] == "Fixture Test App"
    assert res["all_raw_permissions"] == ["android.permission.RECEIVE_SMS"]
    # The decoy in XML comment must NOT be extracted
    assert "android.permission.SEND_SMS" not in res["all_raw_permissions"]


# ---------------------------------------------------------------------------
# Scenario 13: Corrupt ZIP archives
# ---------------------------------------------------------------------------
def test_scenario_13_corrupt_zip_archive_rejection():
    garbage = b"PK\x03\x04" + b"Corrupted randomized bytes that do not form a valid zip" * 20
    res = analyze_apk_bytes(garbage, "corrupt.apk")

    assert res["is_valid_apk"] is False
    assert "not a valid zip/apk archive" in (res["error_message"] or "").lower()


# ---------------------------------------------------------------------------
# Scenario 14: Archive safety limits enforcement
# ---------------------------------------------------------------------------
def test_scenario_14_archive_safety_limits():
    # 1. Oversized upload (> 15 MB)
    oversized = b"P" * (MAX_APK_UPLOAD_BYTES + 50)
    res_oversized = analyze_apk_bytes(oversized, "too_large.apk")
    assert res_oversized["is_valid_apk"] is False
    assert "exceeds the 15 mb safety limit" in res_oversized["error_message"].lower()

    # 2. Oversized uncompressed member (> 10 MB) via ZIP_STORED (ratio = 1.0)
    huge_manifest = b"<manifest package='huge'/>" + (b"A" * (MAX_UNCOMPRESSED_MEMBER_BYTES + 1024))
    apk_huge_member = _make_test_apk(huge_manifest, compress_type=zipfile.ZIP_STORED)
    res_huge = analyze_apk_bytes(apk_huge_member, "huge_member.apk")
    assert res_huge["is_valid_apk"] is False
    assert "exceeds the 10 mb safety limit" in res_huge["error_message"].lower()

    # 3. Zip Slip path traversal sequence
    bio_slip = io.BytesIO()
    with zipfile.ZipFile(bio_slip, "w") as zf:
        zf.writestr("../../etc/passwd", b"malicious traversal")
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
    res_slip = analyze_apk_bytes(bio_slip.getvalue(), "slip.apk")
    assert res_slip["is_valid_apk"] is False
    assert "path traversal" in res_slip["error_message"].lower()


# ---------------------------------------------------------------------------
# Scenario 15: Output schema compatibility
# ---------------------------------------------------------------------------
def test_scenario_15_output_schema_compatibility():
    axml = build_compiled_axml_tree_bytes(
        package_name="com.schema.verify",
        app_label="Schema Verify App",
        permissions=["android.permission.INTERNET"],
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "schema_test.apk")

    required_keys = [
        "filename",
        "is_valid_apk",
        "is_synthetic_fixture",
        "manifest_format",
        "dex_format",
        "error_message",
        "file_size_bytes",
        "sha256_hash",
        "parser_used",
        "package_name",
        "app_name",
        "version_name",
        "version_code",
        "files_inside_zip",
        "has_manifest",
        "has_dex_code",
        "permissions_found",
        "all_raw_permissions",
        "passive_urls",
        "confirmed_observations",
        "heuristic_warnings",
        "observed_facts",
        "heuristic_inferences",
    ]
    for key in required_keys:
        assert key in res, f"Missing required output key: {key}"

    # Verify key types
    assert isinstance(res["is_valid_apk"], bool)
    assert isinstance(res["all_raw_permissions"], list)
    assert isinstance(res["permissions_found"], list)
    assert isinstance(res["passive_urls"], list)
    assert isinstance(res["observed_facts"], list)
    assert isinstance(res["heuristic_inferences"], list)
    assert len(res["sha256_hash"]) == 64


# ---------------------------------------------------------------------------
# Scenario 16: Resource reference attribute preservation (@0x7f...)
# ---------------------------------------------------------------------------
def test_scenario_16_resource_reference_attribute_preservation():
    """Verifies that TYPE_REFERENCE values (e.g. app label = @0x7F0B0012) decode honestly."""
    axml = build_compiled_axml_tree_bytes(
        package_name="com.res.ref.app",
        app_label=None,
        app_label_res=0x7F0B0012,
        permissions=["android.permission.INTERNET"],
    )
    apk_bytes = _make_test_apk(axml)
    res = analyze_apk_bytes(apk_bytes, "res_ref.apk")

    assert res["is_valid_apk"] is True
    assert res["app_name"] == "@0x7F0B0012"
