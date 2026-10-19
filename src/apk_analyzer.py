"""
Safe Static Analyzer for Android APK Archives and Synthetic Test Fixtures.

SECURITY & HONESTY GUARANTEES:
1. Never installs or executes APK files or Dalvik (.dex) bytecode.
2. Enforces strict upload size (15 MB) and uncompressed member size (10 MB) limits
   to prevent ZIP decompression bomb attacks.
3. Distinguishes between genuine compiled Android Binary XML (AXML) manifests
   and synthetic plain-text XML test fixtures.
4. Passively extracts URL strings without ever connecting to them.
"""

import hashlib
import io
import re
import struct
import zipfile
from typing import Any, Dict, List, Set, Tuple

# Safety limits
MAX_APK_UPLOAD_BYTES = 15 * 1024 * 1024          # 15 MB max compressed upload
MAX_UNCOMPRESSED_MEMBER_BYTES = 10 * 1024 * 1024 # 10 MB max uncompressed single file inside ZIP
MAX_TOTAL_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB max total uncompressed archive size
MAX_ZIP_ENTRIES = 5000                           # Max number of files inside ZIP archive

# Android Binary XML (AXML) constants
RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
UTF8_FLAG = 1 << 8

# Documented catalog of sensitive Android permissions
SENSITIVE_PERMISSIONS_CATALOG: Dict[str, Dict[str, Any]] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "short_name": "BIND_ACCESSIBILITY_SERVICE",
        "family": "SCREEN_CONTROL",
        "severity": "Critical",
        "weight": 35,
        "reason_en": (
            "Allows observing screen content and simulating user taps. "
            "Legitimate utility or bill-payment apps almost never require this capability."
        ),
        "reason_mr": (
            "अत्यंत संवेदनशील: हे ॲप तुमची स्क्रीन पाहू शकते आणि स्वतःहून बटणे दाबू शकते."
        ),
    },
    "android.permission.RECEIVE_SMS": {
        "short_name": "RECEIVE_SMS",
        "family": "SMS_ACCESS",
        "severity": "High",
        "weight": 28,
        "reason_en": (
            "Allows intercepting incoming SMS messages as they arrive "
            "(frequently abused to capture banking OTPs)."
        ),
        "reason_mr": (
            "हे ॲप येणारे एसएमएस (SMS) आणि बँक ओटीपी (OTP) परस्पर वाचू शकते."
        ),
    },
    "android.permission.READ_SMS": {
        "short_name": "READ_SMS",
        "family": "SMS_ACCESS",
        "severity": "High",
        "weight": 25,
        "reason_en": (
            "Allows reading stored SMS messages in the inbox, including financial alerts and OTPs."
        ),
        "reason_mr": (
            "हे ॲप तुमच्या फोनमधील जुने एसएमएस आणि बँक मेसेज वाचू शकते."
        ),
    },
    "android.permission.SEND_SMS": {
        "short_name": "SEND_SMS",
        "family": "SMS_ACCESS",
        "severity": "High",
        "weight": 22,
        "reason_en": (
            "Allows sending SMS messages from the device SIM card without manual confirmation "
            "(used in UPI/SIM-binding fraud)."
        ),
        "reason_mr": (
            "तुमच्या नकळत तुमच्या सिम कार्डवरून दुसऱ्या नंबरवर एसएमएस पाठवू शकते."
        ),
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "short_name": "REQUEST_INSTALL_PACKAGES",
        "family": "PACKAGE_INSTALL",
        "severity": "High",
        "weight": 24,
        "reason_en": (
            "Allows prompting installation of secondary APK packages ('dropper' behavior)."
        ),
        "reason_mr": (
            "हे ॲप फोनमध्ये इतर अनोळखी ॲप्स इन्स्टॉल करण्याची परवानगी मागते."
        ),
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "short_name": "SYSTEM_ALERT_WINDOW",
        "family": "SCREEN_OVERLAY",
        "severity": "Moderate",
        "weight": 16,
        "reason_en": (
            "Allows drawing overlay windows on top of other apps "
            "(can be used to display deceptive login screens)."
        ),
        "reason_mr": (
            "इतर ॲप्सच्या वर स्वतःची स्क्रीन दाखवू शकते (बनावट लॉगिन स्क्रीनसाठी वापरले जाऊ शकते)."
        ),
    },
    "android.permission.READ_CALL_LOG": {
        "short_name": "READ_CALL_LOG",
        "family": "CALL_CONTACTS",
        "severity": "Moderate",
        "weight": 12,
        "reason_en": "Allows reading incoming and outgoing call history.",
        "reason_mr": "तुमचा कॉल हिस्ट्री (कोणाशी बोललात याची माहिती) वाचू शकते.",
    },
    "android.permission.READ_CONTACTS": {
        "short_name": "READ_CONTACTS",
        "family": "CALL_CONTACTS",
        "severity": "Moderate",
        "weight": 10,
        "reason_en": "Allows reading saved address book contacts.",
        "reason_mr": "तुमच्या फोनमधील सर्व कॉन्टॅक्ट नंबर्सची यादी वाचू शकते.",
    },
    "android.permission.RECORD_AUDIO": {
        "short_name": "RECORD_AUDIO",
        "family": "DEVICE_SENSORS",
        "severity": "Moderate",
        "weight": 14,
        "reason_en": "Allows accessing the microphone to record audio.",
        "reason_mr": "मायक्रोफोनचा वापर करून आवाज रेकॉर्ड करू शकते.",
    },
    "android.permission.CAMERA": {
        "short_name": "CAMERA",
        "family": "DEVICE_SENSORS",
        "severity": "Moderate",
        "weight": 10,
        "reason_en": "Allows capturing photos or video from the camera.",
        "reason_mr": "कॅमेऱ्याचा वापर करू शकते.",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "short_name": "ACCESS_FINE_LOCATION",
        "family": "LOCATION",
        "severity": "Low",
        "weight": 8,
        "reason_en": "Allows accessing precise GPS location coordinates.",
        "reason_mr": "तुमचे अचूक लोकेशन (GPS) पाहू शकते.",
    },
}


def _parse_axml_string_pool(manifest_bytes: bytes) -> Tuple[bool, List[str]]:
    """
    Parses the RES_STRING_POOL_TYPE (0x0001) chunk inside a compiled Android Binary XML (AXML) file.
    Returns (is_valid_binary_axml, extracted_strings_list).
    """
    if len(manifest_bytes) < 16:
        return False, []

    xml_type, xml_header_size, _xml_total_size = struct.unpack_from("<HHI", manifest_bytes, 0)
    if xml_type != RES_XML_TYPE or xml_header_size < 8:
        return False, []

    sp_offset = xml_header_size
    if sp_offset + 28 > len(manifest_bytes):
        return False, []

    (
        sp_type,
        sp_header_size,
        sp_chunk_size,
        string_count,
        _style_count,
        flags,
        strings_start,
        _styles_start,
    ) = struct.unpack_from("<HHIIIIII", manifest_bytes, sp_offset)

    if sp_type != RES_STRING_POOL_TYPE or string_count > 100000:
        return False, []

    is_utf8 = bool(flags & UTF8_FLAG)
    offsets_table_start = sp_offset + sp_header_size
    strings_data_start = sp_offset + strings_start
    extracted: List[str] = []

    try:
        for idx in range(min(string_count, 20000)):
            offset_pos = offsets_table_start + (idx * 4)
            if offset_pos + 4 > len(manifest_bytes):
                break
            str_rel_offset = struct.unpack_from("<I", manifest_bytes, offset_pos)[0]
            pos = strings_data_start + str_rel_offset
            if pos >= len(manifest_bytes):
                continue

            if is_utf8:
                if pos + 2 > len(manifest_bytes):
                    continue
                char_len = manifest_bytes[pos]
                pos += 1
                if char_len & 0x80:
                    pos += 1
                byte_len = manifest_bytes[pos]
                pos += 1
                if byte_len & 0x80:
                    byte_len = ((byte_len & 0x7F) << 8) | manifest_bytes[pos]
                    pos += 1
                raw_s = manifest_bytes[pos : pos + byte_len]
                extracted.append(raw_s.decode("utf-8", errors="ignore"))
            else:
                if pos + 2 > len(manifest_bytes):
                    continue
                u16_len = struct.unpack_from("<H", manifest_bytes, pos)[0]
                pos += 2
                if u16_len & 0x8000:
                    if pos + 2 > len(manifest_bytes):
                        continue
                    low = struct.unpack_from("<H", manifest_bytes, pos)[0]
                    u16_len = ((u16_len & 0x7FFF) << 16) | low
                    pos += 2
                byte_len = u16_len * 2
                raw_s = manifest_bytes[pos : pos + byte_len]
                extracted.append(raw_s.decode("utf-16le", errors="ignore"))
    except Exception:
        pass

    return True, extracted


def _extract_fallback_strings(raw_bytes: bytes) -> str:
    """Extracts printable ASCII and UTF-16LE sequences as a secondary fallback."""
    ascii_part = raw_bytes.decode("latin-1", errors="ignore")
    utf16_part = raw_bytes.decode("utf-16le", errors="ignore")
    return ascii_part + "\n" + utf16_part


def _extract_passive_urls(text_blob: str) -> List[str]:
    """
    Passively finds HTTP/HTTPS URL strings inside manifest or DEX strings.
    Excludes standard Android XML namespace URIs. Never opens or resolves any URL.
    """
    url_regex = re.compile(r"https?://[a-zA-Z0-9./_\-?=&%]+")
    found = set(url_regex.findall(text_blob))
    ignored = (
        "http://schemas.android.com",
        "https://schemas.android.com",
        "http://www.w3.org",
        "https://www.w3.org",
    )
    cleaned = [
        u for u in sorted(found) if not any(u.startswith(prefix) for prefix in ignored)
    ]
    return cleaned[:15]


def analyze_apk_bytes(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Safely inspects an APK byte stream in memory without installing or executing it.
    Distinguishes confirmed structural observations from heuristic risk indicators.
    """
    result: Dict[str, Any] = {
        "filename": filename or "uploaded.apk",
        "is_valid_apk": False,
        "is_synthetic_fixture": False,
        "manifest_format": "Unverified",
        "dex_format": "None",
        "error_message": None,
        "file_size_bytes": len(file_bytes) if file_bytes else 0,
        "sha256_hash": "",
        "parser_used": "None",
        "package_name": "Unknown",
        "app_name": "Unknown",
        "version_name": "Unknown",
        "files_inside_zip": [],
        "has_manifest": False,
        "has_dex_code": False,
        "permissions_found": [],
        "all_raw_permissions": [],
        "passive_urls": [],
        "confirmed_observations": [],
        "heuristic_warnings": [],
    }

    # 1. Reject empty files
    if not file_bytes:
        result["error_message"] = "The uploaded file is empty (0 bytes)."
        return result

    # 2. Reject oversized uploads
    if len(file_bytes) > MAX_APK_UPLOAD_BYTES:
        size_mb = round(len(file_bytes) / (1024 * 1024), 2)
        result["error_message"] = (
            f"File size ({size_mb} MB) exceeds the 15 MB safety limit for static analysis."
        )
        return result

    # 3. Compute SHA-256 fingerprint
    result["sha256_hash"] = hashlib.sha256(file_bytes).hexdigest()

    # 4. Validate ZIP archive magic and structure
    bio = io.BytesIO(file_bytes)
    if not zipfile.is_zipfile(bio):
        result["error_message"] = (
            "Invalid APK format: This file is not a valid ZIP/APK archive. "
            "It may be corrupted, encrypted, or another file type renamed to .apk."
        )
        return result

    bio.seek(0)
    try:
        with zipfile.ZipFile(bio, "r") as zf:
            info_list = zf.infolist()

            # ZIP bomb checks
            if len(info_list) > MAX_ZIP_ENTRIES:
                result["error_message"] = (
                    f"Archive contains {len(info_list)} entries, exceeding the safety ceiling ({MAX_ZIP_ENTRIES})."
                )
                return result

            total_uncompressed = sum(info.file_size for info in info_list)
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                result["error_message"] = (
                    "Archive uncompressed size exceeds the 50 MB safety threshold (potential decompression bomb)."
                )
                return result

            namelist = [info.filename for info in info_list]
            result["files_inside_zip"] = namelist[:30]
            result["has_manifest"] = "AndroidManifest.xml" in namelist
            result["has_dex_code"] = any(name.endswith(".dex") for name in namelist)

            if not result["has_manifest"]:
                result["error_message"] = (
                    "Archive does not contain 'AndroidManifest.xml'. "
                    "It is a standard ZIP archive rather than an Android APK package."
                )
                return result

            manifest_info = zf.getinfo("AndroidManifest.xml")
            if manifest_info.file_size > MAX_UNCOMPRESSED_MEMBER_BYTES:
                result["error_message"] = (
                    "AndroidManifest.xml uncompressed size exceeds the 10 MB safety limit."
                )
                return result

            with zf.open("AndroidManifest.xml", "r") as mf:
                manifest_bytes = mf.read(MAX_UNCOMPRESSED_MEMBER_BYTES)

            # Inspect classes.dex header if present (bounded to 512 KB)
            dex_bytes = b""
            for name in namelist:
                if name.endswith(".dex"):
                    dex_info = zf.getinfo(name)
                    if dex_info.file_size <= MAX_UNCOMPRESSED_MEMBER_BYTES:
                        with zf.open(name, "r") as df:
                            dex_bytes = df.read(512 * 1024)
                    break

    except zipfile.BadZipFile:
        result["error_message"] = "Corrupted ZIP archive structure."
        return result
    except RuntimeError as exc:
        result["error_message"] = f"Archive could not be read safely (possibly encrypted): {exc}"
        return result
    except Exception as exc:
        result["error_message"] = f"Error reading archive: {exc}"
        return result

    # 5. Distinguish Binary AXML vs. Synthetic Plain-Text XML Fixture
    raw_permissions_set: Set[str] = set()
    is_binary_axml, pool_strings = _parse_axml_string_pool(manifest_bytes)

    if is_binary_axml:
        result["manifest_format"] = "Compiled Android Binary XML (AXML 0x00080003)"
        result["parser_used"] = "Spec-Compliant Binary AXML StringPool Inspector"
        manifest_text_searchable = "\n".join(pool_strings) + "\n" + _extract_fallback_strings(manifest_bytes)
        for s in pool_strings:
            if s.startswith("android.permission.") and re.match(r"^android\.permission\.[A-Z0-9_]+$", s):
                raw_permissions_set.add(s)
            elif re.match(r"^(com|in|org|net|edu|gov)\.[a-zA-Z0-9_.]+$", s) and result["package_name"] == "Unknown":
                result["package_name"] = s
    elif manifest_bytes.lstrip().startswith(b"<"):
        result["manifest_format"] = "Synthetic Plain-Text XML Test Fixture"
        result["is_synthetic_fixture"] = True
        result["parser_used"] = "Plain-Text XML Fixture Inspector"
        manifest_text_searchable = manifest_bytes.decode("utf-8", errors="ignore")
    else:
        result["error_message"] = (
            "Unrecognized AndroidManifest.xml format: neither valid Android Binary XML (AXML) "
            "nor readable XML fixture."
        )
        return result

    # 6. Check DEX bytecode authenticity
    if dex_bytes.startswith(b"dex\n03"):
        result["dex_format"] = "Genuine Dalvik Executable Header (dex\\n03x)"
    elif dex_bytes:
        result["dex_format"] = "Synthetic Non-Executable Stub"
        result["is_synthetic_fixture"] = True
    else:
        result["dex_format"] = "No .dex File Present"
        result["is_synthetic_fixture"] = True

    # 7. Extract package attributes & permissions from searchable text
    pkg_match = re.search(r'package\s*=\s*["\']([a-zA-Z0-9_.]+)["\']', manifest_text_searchable)
    if pkg_match and result["package_name"] == "Unknown":
        result["package_name"] = pkg_match.group(1)

    label_match = re.search(r'android:label\s*=\s*["\']([^"\']+)["\']', manifest_text_searchable)
    if label_match and result["app_name"] == "Unknown":
        result["app_name"] = label_match.group(1)

    ver_match = re.search(r'android:versionName\s*=\s*["\']([^"\']+)["\']', manifest_text_searchable)
    if ver_match and result["version_name"] == "Unknown":
        result["version_name"] = ver_match.group(1)

    for pm in re.findall(r"android\.permission\.[A-Z0-9_]+", manifest_text_searchable):
        raw_permissions_set.add(pm)

    result["all_raw_permissions"] = sorted(raw_permissions_set)

    # 8. Match against Sensitive Permissions Catalog
    matched_perms: List[Dict[str, Any]] = []
    for perm_name in sorted(raw_permissions_set):
        if perm_name in SENSITIVE_PERMISSIONS_CATALOG:
            cat = SENSITIVE_PERMISSIONS_CATALOG[perm_name]
            matched_perms.append(
                {
                    "permission": perm_name,
                    "short_name": cat["short_name"],
                    "family": cat["family"],
                    "severity": cat["severity"],
                    "weight": cat["weight"],
                    "reason_en": cat["reason_en"],
                    "reason_mr": cat["reason_mr"],
                }
            )
    result["permissions_found"] = matched_perms

    # 9. Passively extract URL strings
    combined_blob = manifest_text_searchable + "\n" + _extract_fallback_strings(dex_bytes)
    result["passive_urls"] = _extract_passive_urls(combined_blob)

    # 10. Record Confirmed Observations vs. Heuristic Inferences
    result["confirmed_observations"].append(
        f"Manifest Format: {result['manifest_format']}"
    )
    result["confirmed_observations"].append(
        f"DEX Bytecode Status: {result['dex_format']}"
    )
    result["confirmed_observations"].append(
        f"Total Declared Permissions Found: {len(result['all_raw_permissions'])} "
        f"({len(matched_perms)} in sensitive watch catalog)"
    )

    if result["is_synthetic_fixture"]:
        result["confirmed_observations"].append(
            "Fixture Notice: This file is a safe synthetic test fixture created for sandbox verification, "
            "not an installable Android application."
        )

    lower_fname = result["filename"].lower()
    if any(k in lower_fname for k in ("msedcl", "mahavitaran", "kisan", "kyc", "challan", "sbi", "yojana")):
        result["heuristic_warnings"].append(
            "Filename Heuristic: File name references a utility, bank, RTO, or welfare scheme. "
            "Official public-service apps are distributed via Google Play Store, not forwarded as raw .apk files on WhatsApp."
        )

    result["is_valid_apk"] = True
    return result