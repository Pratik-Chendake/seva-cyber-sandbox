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
from typing import List

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


def create_binary_axml_sample(filename: str) -> str:
    """Creates an APK archive with a compiled Binary AXML (0x00080003) manifest and Dalvik header."""
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    filepath = os.path.join(SAMPLE_DIR, filename)

    axml_bytes = _build_binary_axml_bytes(
        [
            "com.demo.binaryaxml.verifier",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET",
            "http://demo-binary-axml-check.xyz/status",
        ]
    )
    dex_header_bytes = b"dex\n035\x00" + b"\x00" * 64 + b"http://demo-binary-axml-check.xyz/status"

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

    # 4. Binary AXML (0x00080003) + Dalvik header test package
    created.append(create_binary_axml_sample("Real_Binary_AXML_Header_Sample.apk"))

    # 5. Invalid non-ZIP file renamed to .apk
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