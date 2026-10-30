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
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
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

    if sp_type != RES_STRING_POOL_TYPE or string_count > 100000 or sp_chunk_size < 28:
        return False, []

    if sp_offset + sp_chunk_size > len(manifest_bytes):
        return False, []

    is_utf8 = bool(flags & UTF8_FLAG)
    offsets_table_start = sp_offset + sp_header_size
    strings_data_start = sp_offset + strings_start

    if offsets_table_start + (string_count * 4) > sp_offset + sp_chunk_size:
        return False, []

    extracted: List[str] = []

    try:
        for idx in range(min(string_count, 20000)):
            offset_pos = offsets_table_start + (idx * 4)
            if offset_pos + 4 > len(manifest_bytes):
                break
            str_rel_offset = struct.unpack_from("<I", manifest_bytes, offset_pos)[0]
            pos = strings_data_start + str_rel_offset
            if pos >= len(manifest_bytes):
                extracted.append("<offset-out-of-bounds>")
                continue

            if is_utf8:
                if pos + 2 > len(manifest_bytes):
                    extracted.append("<truncated-utf8>")
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
                if pos + byte_len > len(manifest_bytes):
                    extracted.append("<truncated-utf8-data>")
                    continue
                raw_s = manifest_bytes[pos : pos + byte_len]
                extracted.append(raw_s.decode("utf-8", errors="replace"))
            else:
                if pos + 2 > len(manifest_bytes):
                    extracted.append("<truncated-utf16>")
                    continue
                u16_len = struct.unpack_from("<H", manifest_bytes, pos)[0]
                pos += 2
                if u16_len & 0x8000:
                    if pos + 2 > len(manifest_bytes):
                        extracted.append("<truncated-utf16-surrogate>")
                        continue
                    low = struct.unpack_from("<H", manifest_bytes, pos)[0]
                    u16_len = ((u16_len & 0x7FFF) << 16) | low
                    pos += 2
                byte_len = u16_len * 2
                if pos + byte_len > len(manifest_bytes):
                    extracted.append("<truncated-utf16-data>")
                    continue
                raw_s = manifest_bytes[pos : pos + byte_len]
                extracted.append(raw_s.decode("utf-16le", errors="replace"))
    except Exception:
        pass

    return True, extracted


def _parse_axml_element_tree(
    manifest_bytes: bytes, pool_strings: List[str]
) -> Dict[str, Any]:
    """
    Safely walks compiled Android Binary XML (AXML) chunks following the string pool.
    Traverses RES_XML_START_ELEMENT_TYPE (0x0102) records to extract manifest attributes
    (package, label, versionName, versionCode) and declared uses-permission entries
    strictly from the XML AST without falling back to string pool regex scraping.
    """
    tree_result: Dict[str, Any] = {
        "success": False,
        "tree_parsed": False,
        "error": None,
        "package_name": None,
        "app_name": None,
        "version_name": None,
        "version_code": None,
        "permissions": [],
        "elements_seen": 0,
        "has_manifest_tag": False,
    }

    if len(manifest_bytes) < 16 or not pool_strings:
        tree_result["error"] = "Manifest bytes too small or string pool empty."
        return tree_result

    xml_type, xml_header_size, _ = struct.unpack_from("<HHI", manifest_bytes, 0)
    if xml_type != RES_XML_TYPE or xml_header_size < 8:
        tree_result["error"] = f"Invalid XML root chunk (type: 0x{xml_type:04X}, header size: {xml_header_size})."
        return tree_result

    sp_offset = xml_header_size
    if sp_offset + 28 > len(manifest_bytes):
        tree_result["error"] = "StringPool offset overflows manifest bytes."
        return tree_result

    sp_type, _, sp_chunk_size = struct.unpack_from("<HHI", manifest_bytes, sp_offset)
    if sp_type != RES_STRING_POOL_TYPE or sp_chunk_size < 28:
        tree_result["error"] = "Invalid StringPool chunk header."
        return tree_result

    chunk_offset = sp_offset + sp_chunk_size
    chunks_processed = 0
    max_chunks = 20000

    while chunk_offset + 8 <= len(manifest_bytes):
        chunks_processed += 1
        if chunks_processed > max_chunks:
            tree_result["error"] = "Exceeded maximum chunk count safety ceiling (potential loop)."
            return tree_result

        chunk_type, chunk_hdr_size, chunk_size = struct.unpack_from(
            "<HHI", manifest_bytes, chunk_offset
        )

        if chunk_size < 8:
            tree_result["error"] = f"Malformed chunk size ({chunk_size} < 8) at offset {chunk_offset}."
            return tree_result
        if chunk_offset + chunk_size > len(manifest_bytes):
            tree_result["error"] = (
                f"Truncated chunk: chunk size {chunk_size} exceeds manifest length at offset {chunk_offset}."
            )
            return tree_result

        # Skip resource map (0x0180), namespace chunks (0x0100, 0x0101), and CDATA (0x0104) safely
        if chunk_type in (
            RES_XML_RESOURCE_MAP_TYPE,
            RES_XML_START_NAMESPACE_TYPE,
            RES_XML_END_NAMESPACE_TYPE,
            RES_XML_CDATA_TYPE,
        ):
            chunk_offset += chunk_size
            continue

        if chunk_type == RES_XML_START_ELEMENT_TYPE:
            tree_result["elements_seen"] += 1
            if chunk_hdr_size < 16 or chunk_offset + 28 > len(manifest_bytes):
                tree_result["error"] = f"Corrupted START_ELEMENT chunk header at offset {chunk_offset}."
                return tree_result

            try:
                (
                    _line_no,
                    _comment_idx,
                    _ns_idx,
                    name_idx,
                    attr_start,
                    attr_size,
                    attr_count,
                ) = struct.unpack_from("<IIIIHHH", manifest_bytes, chunk_offset + 8)

                if not (0 <= name_idx < len(pool_strings)):
                    tree_result["error"] = f"Element tag name index {name_idx} out of string pool bounds."
                    return tree_result
                tag_name = pool_strings[name_idx]

                if tree_result["elements_seen"] == 1:
                    if tag_name != "manifest":
                        tree_result["error"] = f"Expected root element <manifest>, got <{tag_name}>."
                        return tree_result
                    tree_result["has_manifest_tag"] = True

                if attr_count > 1000:
                    tree_result["error"] = f"Unreasonable attribute count ({attr_count}) in <{tag_name}>."
                    return tree_result
                if attr_count > 0 and attr_size < 20:
                    tree_result["error"] = f"Invalid attribute entry size ({attr_size} < 20) in <{tag_name}>."
                    return tree_result

                first_attr_offset = chunk_offset + (
                    attr_start if attr_start >= 36 else chunk_hdr_size + attr_start
                )

                attrs: Dict[str, str] = {}
                for attr_i in range(attr_count):
                    curr_attr_offset = first_attr_offset + (attr_i * attr_size)
                    if (
                        curr_attr_offset + 20 > chunk_offset + chunk_size
                        or curr_attr_offset + 20 > len(manifest_bytes)
                    ):
                        tree_result["error"] = f"Attribute entry {attr_i} overflows chunk boundary."
                        return tree_result

                    (
                        attr_ns,
                        attr_name_idx,
                        raw_val_idx,
                        _val_size,
                        _val_res0,
                        val_type,
                        val_data,
                    ) = struct.unpack_from("<IIIHBB I", manifest_bytes, curr_attr_offset)

                    attr_name = (
                        pool_strings[attr_name_idx]
                        if 0 <= attr_name_idx < len(pool_strings)
                        else f"unknown_attr_{attr_name_idx}"
                    )

                    # Attribute value decoding
                    if raw_val_idx != 0xFFFFFFFF:
                        if 0 <= raw_val_idx < len(pool_strings):
                            attr_val = pool_strings[raw_val_idx]
                        else:
                            attr_val = f"<invalid-string-ref-0x{raw_val_idx:X}>"
                    elif val_type == 0x01:  # TYPE_REFERENCE
                        attr_val = f"@0x{val_data:08X}"
                    elif val_type == 0x02:  # TYPE_ATTRIBUTE
                        attr_val = f"?0x{val_data:08X}"
                    elif val_type == 0x03:  # TYPE_STRING
                        if 0 <= val_data < len(pool_strings):
                            attr_val = pool_strings[val_data]
                        else:
                            attr_val = f"<invalid-string-ref-0x{val_data:X}>"
                    elif val_type == 0x12:  # TYPE_INT_BOOLEAN
                        attr_val = "true" if val_data != 0 else "false"
                    elif val_type in (0x10, 0x11):  # TYPE_INT_DEC, TYPE_INT_HEX
                        attr_val = str(val_data)
                    else:
                        attr_val = str(val_data)

                    attrs[attr_name] = attr_val
                    if attr_ns != 0xFFFFFFFF and 0 <= attr_ns < len(pool_strings):
                        ns_uri = pool_strings[attr_ns]
                        if "android" in ns_uri and not attr_name.startswith("android:"):
                            attrs[f"android:{attr_name}"] = attr_val

                if tag_name == "manifest":
                    pkg = attrs.get("package") or attrs.get("android:package")
                    if pkg and not pkg.startswith("<invalid"):
                        tree_result["package_name"] = pkg
                    vname = attrs.get("versionName") or attrs.get("android:versionName")
                    if vname and not vname.startswith("<invalid"):
                        tree_result["version_name"] = vname
                    vcode = attrs.get("versionCode") or attrs.get("android:versionCode")
                    if vcode:
                        tree_result["version_code"] = vcode
                elif tag_name in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
                    pname = attrs.get("name") or attrs.get("android:name")
                    if pname and not pname.startswith("<invalid"):
                        tree_result["permissions"].append(pname)
                elif tag_name == "application":
                    app_lbl = attrs.get("label") or attrs.get("android:label")
                    if app_lbl and not app_lbl.startswith("<invalid"):
                        tree_result["app_name"] = app_lbl

            except Exception as exc:
                tree_result["error"] = f"Exception while decoding START_ELEMENT at offset {chunk_offset}: {exc}"
                return tree_result

        chunk_offset += chunk_size

    if not tree_result["has_manifest_tag"]:
        tree_result["error"] = "Manifest does not contain a <manifest> element (incomplete or empty manifest)."
        return tree_result

    tree_result["success"] = True
    tree_result["tree_parsed"] = True
    return tree_result



def _safe_read_zip_member(zf: zipfile.ZipFile, member_name: str, max_bytes: int) -> bytes:
    """Reads up to max_bytes from a zip member, raising ValueError if the member exceeds max_bytes."""
    with zf.open(member_name, "r") as f:
        chunks = []
        total = 0
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(
                    f"Member '{member_name}' decompressed size exceeded safety limit of {max_bytes} bytes."
                )
            chunks.append(chunk)
        return b"".join(chunks)


def _safe_read_zip_member_prefix(
    zf: zipfile.ZipFile, member_name: str, max_prefix_bytes: int
) -> bytes:
    """Reads up to max_prefix_bytes from a zip member without decompressing the entire file into memory."""
    with zf.open(member_name, "r") as f:
        chunks = []
        total = 0
        while total < max_prefix_bytes:
            to_read = min(64 * 1024, max_prefix_bytes - total)
            chunk = f.read(to_read)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)


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
        "version_code": "Unknown",
        "files_inside_zip": [],
        "has_manifest": False,
        "has_dex_code": False,
        "permissions_found": [],
        "all_raw_permissions": [],
        "passive_urls": [],
        "confirmed_observations": [],
        "heuristic_warnings": [],
        "observed_facts": [],
        "heuristic_inferences": [],
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

            # ZIP safety checks
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

            # Path traversal and compression ratio checks
            for info in info_list:
                norm_name = info.filename.replace("\\", "/")
                if (
                    norm_name.startswith("/")
                    or "../" in norm_name
                    or "/.." in norm_name
                    or norm_name == ".."
                    or (len(norm_name) > 1 and norm_name[1] == ":")
                ):
                    result["error_message"] = (
                        f"Archive rejected: entry '{info.filename}' contains path traversal sequences."
                    )
                    return result
                if info.file_size > 1024 * 1024 and info.compress_size > 0:
                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > 100:
                        result["error_message"] = (
                            f"Archive rejected: entry '{info.filename}' exhibits an anomalous compression ratio ({ratio:.1f}x)."
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

            manifest_bytes = _safe_read_zip_member(
                zf, "AndroidManifest.xml", MAX_UNCOMPRESSED_MEMBER_BYTES
            )

            # Inspect classes.dex header if present (bounded to 512 KB prefix)
            dex_bytes = b""
            for name in namelist:
                if name.endswith(".dex"):
                    dex_info = zf.getinfo(name)
                    if dex_info.file_size > MAX_UNCOMPRESSED_MEMBER_BYTES:
                        result["error_message"] = (
                            f"Archive member '{name}' uncompressed size exceeds the 10 MB safety limit."
                        )
                        return result
                    dex_bytes = _safe_read_zip_member_prefix(zf, name, 512 * 1024)
                    break

    except zipfile.BadZipFile:
        result["error_message"] = "Corrupted ZIP archive structure."
        return result
    except ValueError as exc:
        result["error_message"] = str(exc)
        return result
    except RuntimeError as exc:
        result["error_message"] = f"Archive could not be read safely (possibly encrypted): {exc}"
        return result
    except Exception as exc:
        result["error_message"] = f"Error reading archive: {exc}"
        return result

    # 5. Distinguish Binary AXML vs. Synthetic Plain-Text XML Fixture
    raw_permissions_set: Set[str] = set()
    manifest_text_searchable = ""

    # Check magic: Android Binary XML starts with RES_XML_TYPE (0x0003)
    is_axml_header = len(manifest_bytes) >= 4 and struct.unpack_from("<H", manifest_bytes, 0)[0] == RES_XML_TYPE

    if is_axml_header:
        is_binary_axml, pool_strings = _parse_axml_string_pool(manifest_bytes)
        if not is_binary_axml:
            result["manifest_format"] = "Corrupted Android Binary XML (String Pool Error)"
            result["error_message"] = (
                "Failed to parse Android Binary XML (AXML): String pool chunk is corrupted or truncated."
            )
            return result

        tree_result = _parse_axml_element_tree(manifest_bytes, pool_strings)
        if not tree_result["success"]:
            result["manifest_format"] = "Corrupted Android Binary XML (Structural Parsing Failure)"
            result["parser_used"] = "Spec-Compliant Binary AXML Element Tree Parser (Failed)"
            result["error_message"] = (
                f"Failed to parse Android Binary XML structure: {tree_result['error']}"
            )
            return result

        result["manifest_format"] = "Compiled Android Binary XML (AXML 0x00080003)"
        result["parser_used"] = "Spec-Compliant Binary AXML Element Tree Parser"
        if tree_result["package_name"]:
            result["package_name"] = tree_result["package_name"]
        if tree_result["app_name"]:
            result["app_name"] = tree_result["app_name"]
        if tree_result["version_name"]:
            result["version_name"] = tree_result["version_name"]
        if tree_result.get("version_code"):
            result["version_code"] = tree_result["version_code"]

        # Declared permissions extracted STRICTLY from AST elements, never from arbitrary string pool occurrences
        for p in tree_result["permissions"]:
            raw_permissions_set.add(p)

        manifest_text_searchable = "\n".join(pool_strings)

    elif manifest_bytes.lstrip().startswith(b"<"):
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(manifest_bytes)
            root_tag = root.tag.split("}")[-1]
            if root_tag != "manifest":
                result["error_message"] = (
                    f"Plain-text XML fixture rejected: root element is <{root_tag}> instead of <manifest>."
                )
                return result

            result["manifest_format"] = "Synthetic Plain-Text XML Test Fixture"
            result["is_synthetic_fixture"] = True
            result["parser_used"] = "Safe Plain-Text XML Element Tree Parser"

            pkg = root.attrib.get("package")
            if pkg:
                result["package_name"] = pkg

            for k, v in root.attrib.items():
                attr_clean = k.split("}")[-1]
                if attr_clean == "versionName":
                    result["version_name"] = v
                elif attr_clean == "versionCode":
                    result["version_code"] = v

            for elem in root:
                tag_short = elem.tag.split("}")[-1]
                if tag_short in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
                    for k, v in elem.attrib.items():
                        if k.split("}")[-1] == "name" and v:
                            raw_permissions_set.add(v)
                elif tag_short == "application":
                    for k, v in elem.attrib.items():
                        if k.split("}")[-1] == "label" and v:
                            result["app_name"] = v

            manifest_text_searchable = manifest_bytes.decode("utf-8", errors="ignore")
        except Exception as exc:
            result["error_message"] = f"Malformed plain-text XML fixture: {exc}"
            return result
    else:
        result["error_message"] = (
            "Unrecognized AndroidManifest.xml format: neither valid Android Binary XML (AXML) "
            "nor readable XML fixture."
        )
        return result

    # 6. Check DEX bytecode authenticity
    if dex_bytes.startswith(b"dex\n03"):
        result["dex_format"] = "Genuine Dalvik Executable Header (dex\n03x)"
    elif dex_bytes:
        result["dex_format"] = "Synthetic Non-Executable Stub"
        result["is_synthetic_fixture"] = True
    else:
        result["dex_format"] = "No .dex File Present"
        result["is_synthetic_fixture"] = True

    # 7. Record declared permissions strictly from validated element tree
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

    # Strictly separate confirmed static observations from heuristic inferences
    result["observed_facts"] = [
        f"File size: {result['file_size_bytes']} bytes",
        f"SHA-256 fingerprint: {result['sha256_hash']}",
        f"Archive entry count: {len(info_list)}",
        f"Manifest format: {result['manifest_format']}",
        f"Parser used: {result['parser_used']}",
        f"Package name: {result['package_name']}",
        f"App label: {result['app_name']}",
        f"Version name: {result['version_name']}",
        f"Version code: {result['version_code']}",
        f"DEX bytecode: {result['dex_format']}",
        f"Declared permissions count: {len(result['all_raw_permissions'])}",
        f"Sensitive permissions matched: {len(matched_perms)}",
        f"Passive external URLs extracted: {len(result['passive_urls'])}",
    ]
    result["heuristic_inferences"] = [
        f"Permission risk weight sum: {sum(p['weight'] for p in matched_perms)}",
    ]
    if result["heuristic_warnings"]:
        result["heuristic_inferences"].extend(result["heuristic_warnings"])
    if result["is_synthetic_fixture"]:
        result["heuristic_inferences"].append(
            "Synthetic Fixture Inference: Flagged as non-executable test fixture."
        )

    result["is_valid_apk"] = True
    return result