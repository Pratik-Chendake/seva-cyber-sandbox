"""
Safe Test-File Generator for Seva Cyber Sandbox.
Creates 5 test files inside sample_apks/:
1. MSEDCL_Light_Bill_Update_Test.apk (Synthetic fixture - High permission-risk profile)
2. Gram_Panchayat_Directory_Test.apk (Synthetic fixture - Moderate permission-risk profile)
3. Simple_Marathi_Calendar_Test.apk  (Synthetic fixture - Low permission-risk profile)
4. Real_Binary_AXML_Header_Sample.apk (Binary AXML 0x00080003 StringPool test package)
5. Corrupted_Not_A_Real_APK.apk      (Plain text file renamed to .apk to test rejection)

IMPORTANT: None of these files contain malicious code or real spyware.
"""

import os
import struct
import zipfile
from typing import List, Optional, Tuple

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_apks")


def _build_binary_axml_bytes(strings_list: List[str]) -> bytes:
    """
    Constructs a valid Android Binary XML (AXML) header (0x0003) and UTF-16LE StringPool chunk (0x0001)
    so our binary AXML parser can be tested against real binary chunk layouts.
    """
    encoded_blobs: List[bytes] = []
    offsets: List[int] = []
    current_offset = 0

    for s in strings_list:
        offsets.append(current_offset)
        u16_bytes = s.encode("utf-16le")
        char_len = len(s)
        blob = struct.pack("<H", char_len) + u16_bytes + b"\x00\x00"
        encoded_blobs.append(blob)
        current_offset += len(blob)

    strings_data = b"".join(encoded_blobs)
    if len(strings_data) % 4 != 0:
        strings_data += b"\x00" * (4 - (len(strings_data) % 4))

    sp_header_size = 28
    offsets_table = b"".join(struct.pack("<I", off) for off in offsets)
    strings_start = sp_header_size + len(offsets_table)
    sp_chunk_size = strings_start + len(strings_data)

    sp_header = struct.pack(
        "<HHIIIIII",
        0x0001,          # RES_STRING_POOL_TYPE
        sp_header_size,  # header size (28)
        sp_chunk_size,   # chunk size
        len(strings_list),
        0,               # style count
        0,               # flags (0 = UTF-16LE)
        strings_start,
        0,               # styles start
    )

    xml_header_size = 8
    total_xml_size = xml_header_size + sp_chunk_size
    xml_header = struct.pack("<HHI", 0x0003, xml_header_size, total_xml_size)
    return xml_header + sp_header + offsets_table + strings_data


def create_synthetic_xml_fixture(
    filename: str,
    package_name: str,
    app_name: str,
    permissions: List[str],
    embedded_urls: List[str],
) -> str:
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    filepath = os.path.join(SAMPLE_DIR, filename)

    perms_xml = "\n".join(
        f'    <uses-permission android:name="{p}" />' for p in permissions
    )
    manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionName="1.0.0-fixture">
{perms_xml}
    <application android:label="{app_name}">
    </application>
</manifest>
"""
    dex_stub = "SYNTHETIC_FIXTURE_NON_EXECUTABLE_STUB\n" + "\n".join(embedded_urls)

    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", dex_stub.encode("utf-8"))
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nFixture-Type: Synthetic\n")

    return filepath


def build_compiled_axml_tree_bytes(
    package_name: str = "in.gov.maharashtra.service.portal",
    app_label: str = "MahaSeva Official Citizen App",
    version_name: str = "1.0.0",
    version_code: int = 1,
    permissions: List[str] = None,
    permission_tags: List[Tuple[str, str]] = None,
    extra_pool_strings: List[str] = None,
    app_label_res: Optional[int] = None,
    corrupt_chunk_len: bool = False,
    no_elements: bool = False,
    corrupt_attr_idx: bool = False,
) -> bytes:
    """
    Constructs a valid compiled Binary AXML (0x0003) with StringPool (0x0001)
    and full START_ELEMENT (0x0102) / END_ELEMENT (0x0103) AST chunks.
    Allows injecting extra pool strings, custom tags (e.g. uses-permission-sdk-23),
    resource references, and synthetic corruption for robust testing.
    """
    if permissions is None and permission_tags is None:
        permissions = ["android.permission.INTERNET"]
    if permission_tags is None:
        permission_tags = [("uses-permission", p) for p in permissions]

    strings_list = [
        "manifest",
        "package",
        package_name,
        "versionName",
        version_name,
        "versionCode",
        "application",
        "label",
        "name",
    ]
    if app_label is not None and app_label not in strings_list:
        strings_list.append(app_label)
    for tag, p in permission_tags:
        if tag not in strings_list:
            strings_list.append(tag)
        if p not in strings_list:
            strings_list.append(p)
    if extra_pool_strings:
        for s in extra_pool_strings:
            if s not in strings_list:
                strings_list.append(s)

    str_map = {s: i for i, s in enumerate(strings_list)}

    # String pool chunk (UTF-16LE)
    encoded_blobs: List[bytes] = []
    offsets: List[int] = []
    current_offset = 0

    for s in strings_list:
        offsets.append(current_offset)
        u16_bytes = s.encode("utf-16le")
        char_len = len(s)
        blob = struct.pack("<H", char_len) + u16_bytes + b"\x00\x00"
        encoded_blobs.append(blob)
        current_offset += len(blob)

    strings_data = b"".join(encoded_blobs)
    if len(strings_data) % 4 != 0:
        strings_data += b"\x00" * (4 - (len(strings_data) % 4))

    sp_header_size = 28
    offsets_table = b"".join(struct.pack("<I", off) for off in offsets)
    strings_start = sp_header_size + len(offsets_table)
    sp_chunk_size = strings_start + len(strings_data)

    sp_header = struct.pack(
        "<HHIIIIII",
        0x0001,
        sp_header_size,
        sp_chunk_size,
        len(strings_list),
        0,
        0,
        strings_start,
        0,
    )
    sp_full = sp_header + offsets_table + strings_data

    if no_elements:
        xml_header_size = 8
        total_xml_size = xml_header_size + len(sp_full)
        return struct.pack("<HHI", 0x0003, xml_header_size, total_xml_size) + sp_full

    element_chunks = []

    # 1. <manifest package="..." android:versionName="..." android:versionCode="...">
    attr_pkg = struct.pack(
        "<IIIHBB I",
        0xFFFFFFFF,
        str_map["package"],
        str_map[package_name],
        8,
        0,
        3,  # TYPE_STRING
        str_map[package_name],
    )
    attr_vname = struct.pack(
        "<IIIHBB I",
        0xFFFFFFFF,
        str_map["versionName"],
        str_map[version_name],
        8,
        0,
        3,  # TYPE_STRING
        str_map[version_name],
    )
    attr_vcode = struct.pack(
        "<IIIHBB I",
        0xFFFFFFFF,
        str_map["versionCode"],
        0xFFFFFFFF,
        8,
        0,
        0x10,  # TYPE_INT_DEC
        version_code,
    )
    manifest_attrs = attr_pkg + attr_vname + attr_vcode
    manifest_start_size = 16 + 20 + len(manifest_attrs)
    manifest_start = (
        struct.pack("<HHI", 0x0102, 16, manifest_start_size)
        + struct.pack("<IIIIHHH", 1, 0xFFFFFFFF, 0xFFFFFFFF, str_map["manifest"], 20, 20, 3)
        + struct.pack("<HHH", 0, 0, 0)
        + manifest_attrs
    )
    element_chunks.append(manifest_start)

    # 2. Permissions elements (<uses-permission ...> or <uses-permission-sdk-23 ...>)
    for tag, p in permission_tags:
        p_val_idx = 9999 if corrupt_attr_idx else str_map[p]
        attr_perm = struct.pack(
            "<IIIHBB I",
            0xFFFFFFFF,
            str_map["name"],
            p_val_idx,
            8,
            0,
            3,
            p_val_idx,
        )
        p_start = (
            struct.pack("<HHI", 0x0102, 16, 56)
            + struct.pack("<IIIIHHH", 1, 0xFFFFFFFF, 0xFFFFFFFF, str_map[tag], 20, 20, 1)
            + struct.pack("<HHH", 0, 0, 0)
            + attr_perm
        )
        p_end = struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, str_map[tag])
        element_chunks.append(p_start)
        element_chunks.append(p_end)

    # 3. <application label="...">
    if app_label_res is not None:
        attr_app = struct.pack(
            "<IIIHBB I",
            0xFFFFFFFF,
            str_map["label"],
            0xFFFFFFFF,
            8,
            0,
            1,  # TYPE_REFERENCE
            app_label_res,
        )
    else:
        attr_app = struct.pack(
            "<IIIHBB I",
            0xFFFFFFFF,
            str_map["label"],
            str_map[app_label],
            8,
            0,
            3,
            str_map[app_label],
        )
    app_start = (
        struct.pack("<HHI", 0x0102, 16, 56)
        + struct.pack("<IIIIHHH", 1, 0xFFFFFFFF, 0xFFFFFFFF, str_map["application"], 20, 20, 1)
        + struct.pack("<HHH", 0, 0, 0)
        + attr_app
    )
    app_end = struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, str_map["application"])
    element_chunks.append(app_start)
    element_chunks.append(app_end)

    # 4. </manifest>
    manifest_end = struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, str_map["manifest"])
    element_chunks.append(manifest_end)

    if corrupt_chunk_len:
        # Corrupt the manifest start chunk length to 4 (< 8)
        element_chunks[0] = struct.pack("<HHI", 0x0102, 16, 4) + element_chunks[0][8:]

    body = sp_full + b"".join(element_chunks)
    xml_header_size = 8
    total_xml_size = xml_header_size + len(body)
    xml_header = struct.pack("<HHI", 0x0003, xml_header_size, total_xml_size)
    return xml_header + body


_build_compiled_axml_tree_bytes = build_compiled_axml_tree_bytes


def create_binary_axml_sample(filename: str) -> str:
    """Creates an APK archive with a compiled Binary AXML (0x00080003) manifest with AST element chunks."""
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    filepath = os.path.join(SAMPLE_DIR, filename)

    axml_bytes = build_compiled_axml_tree_bytes(
        package_name="com.demo.binaryaxml.verifier",
        app_label="Binary AXML Verifier Sample",
        version_name="1.0.0",
        version_code=1,
        permissions=[
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET",
        ],
        extra_pool_strings=[
            "http://demo-binary-axml-check.xyz/status",
        ],
    )
    dex_header_bytes = b"dex\n035\x00" + b"\x00" * 64 + b"http://demo-binary-axml-check.xyz/status"

    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", axml_bytes)
        zf.writestr("classes.dex", dex_header_bytes)

    return filepath


def create_compiled_binary_axml_sample(filename: str) -> str:
    """Creates an APK archive with full AST element chunks to verify element-tree parsing."""
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    filepath = os.path.join(SAMPLE_DIR, filename)

    axml_bytes = build_compiled_axml_tree_bytes(
        package_name="in.gov.maharashtra.service.portal",
        app_label="MahaSeva Official Citizen App",
        version_name="1.0.0",
        version_code=1,
        permissions=[
            "android.permission.INTERNET",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
    )
    dex_header_bytes = b"dex\n035\x00" + b"\x00" * 64

    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", axml_bytes)
        zf.writestr("classes.dex", dex_header_bytes)

    return filepath


def main() -> List[str]:
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    created: List[str] = []

    # 1. High-risk synthetic fixture
    created.append(
        create_synthetic_xml_fixture(
            filename="MSEDCL_Light_Bill_Update_Test.apk",
            package_name="com.msedcl.billupdate.unverified.fixture",
            app_name="MSEDCL Bill Update Helper (Synthetic Fixture)",
            permissions=[
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.REQUEST_INSTALL_PACKAGES",
            ],
            embedded_urls=["http://msedcl-bill-kyc-verify.xyz/sms-sync"],
        )
    )

    # 2. Moderate-risk synthetic fixture
    created.append(
        create_synthetic_xml_fixture(
            filename="Gram_Panchayat_Directory_Test.apk",
            package_name="org.demo.gramdirectory.fixture",
            app_name="Village Contact Directory (Synthetic Fixture)",
            permissions=[
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
            embedded_urls=["https://example-directory-service.org/api"],
        )
    )

    # 3. Low-risk synthetic fixture
    created.append(
        create_synthetic_xml_fixture(
            filename="Simple_Marathi_Calendar_Test.apk",
            package_name="in.edu.student.marathicalendar.fixture",
            app_name="Marathi Dindarshika Offline (Synthetic Fixture)",
            permissions=["android.permission.VIBRATE"],
            embedded_urls=[],
        )
    )

    # 4. Binary AXML (0x00080003) StringPool test package
    created.append(create_binary_axml_sample("Real_Binary_AXML_Header_Sample.apk"))

    # 5. Compiled Binary AXML with full AST Element Tree chunks
    created.append(create_compiled_binary_axml_sample("Compiled_Binary_AXML_Tree_Sample.apk"))

    # 6. Invalid non-ZIP file renamed to .apk
    corrupt_path = os.path.join(SAMPLE_DIR, "Corrupted_Not_A_Real_APK.apk")
    with open(corrupt_path, "w", encoding="utf-8") as f:
        f.write("This is a plain text file renamed to .apk to test error handling.")
    created.append(corrupt_path)

    return created


if __name__ == "__main__":
    paths = main()
    print(f"Generated {len(paths)} safe test files in {SAMPLE_DIR}:")
    for p in paths:
        print(f" - {os.path.basename(p)}")