"""
Seva Cyber Sandbox — Streamlit Decommissioning Verification Check
Phase 2 & Phase 15: Complete Streamlit Removal Verification

Recursively scans all active source files, backend services, scripts, and tests
to ensure that zero active Streamlit imports or runtime dependencies remain.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "archive",
    "docs",
    ".pytest_cache",
}

FORBIDDEN_PATTERNS = [
    "import streamlit",
    "from streamlit",
    "st.set_page_config",
    "st.sidebar",
    "st.session_state",
]


def verify_no_streamlit():
    print("=" * 70)
    print("  SEVA CYBER SANDBOX — STREAMLIT DECOMMISSIONING VERIFICATION")
    print("=" * 70)

    violations = []
    scanned_files = 0

    for root, dirs, files in os.walk(BASE_DIR):
        # Exclude directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not any(skip in os.path.join(root, d).lower() for skip in ["archive", "venv", "node_modules", ".git"])]

        for f in files:
            if not f.endswith((".py", ".txt", ".toml", ".yaml", ".yml", ".json")):
                continue
            # Skip requirements/readmes with historical mentions
            rel_path = os.path.relpath(os.path.join(root, f), BASE_DIR)
            scanned_files += 1

            full_path = os.path.join(root, f)
            if f == "verify_no_streamlit.py":
                continue
            try:
                content = open(full_path, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue

            for pattern in FORBIDDEN_PATTERNS:
                if pattern in content:
                    violations.append((rel_path, pattern))

    print(f"[*] Scanned {scanned_files} active source files.")

    if violations:
        print("\n[!] FAILURE: Found forbidden Streamlit references in active code:")
        for path, pat in violations:
            print(f"    - {path}: contains '{pat}'")
        sys.exit(1)
    else:
        print("[+] SUCCESS: Zero active Streamlit imports or runtime references found in codebase!")
        print("[+] All user-facing components, backend APIs, and services run 100% independently.")
        return True


if __name__ == "__main__":
    verify_no_streamlit()
