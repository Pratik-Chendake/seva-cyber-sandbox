# SEVA CYBER SANDBOX — PHASE 7.1.0
# UNIFIED EVIDENCE INTAKE AND MULTI-ARTIFACT CYBERSECURITY ANALYSIS WORKSPACE REPORT

**Date:** 2026-10-31  
**Project:** Seva Cyber Sandbox  
**Repository:** `C:\Users\prati\seva-cyber-sandbox`  
**Phase Baseline:** Phase 7.1.0  
**Operating Mode:** `shadow`  
**Execution Status:** FULLY OPERATIONAL & VERIFIED  

---

## 1. EXECUTIVE SUMMARY

Phase 7.1.0 successfully eliminates siloed evidence intake across Seva Cyber Sandbox by introducing the **Unified Evidence Analysis Workspace** (`01 // UNIFIED EVIDENCE ANALYSIS`). 

Previously, users were required to navigate between distinct tabs to analyze suspicious messages, APK files, and URLs. In Phase 7.1.0, a unified central workspace empowers investigators and citizens to submit diverse cybersecurity evidence simultaneously:
- Suspicious vernacular messages (WhatsApp, SMS, Email; Marathi, Hindi, English).
- Multiple target URLs and web links.
- Multiple Android APK application packages.
- Supporting documents (.pdf, .txt).
- Suspicious screenshots and images (.png, .jpg).
- General attachments and binary files.

Seva executes isolated local security analysis across all submitted artifacts, correlates cross-evidence findings (e.g., links between messages, APK static strings, URLs, and local threat intelligence), produces a consolidated investigation report, and saves parent-linked evidence investigations into the persistent SQLite case repository.

---

## 2. REUSED EXISTING ANALYSIS ENGINES

In strict compliance with architectural guidelines, Phase 7.1.0 created zero redundant analysis engines and reused working components:

1. **Phishing & Vernacular Message Engine:** Reused [`src/phishing_detector.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/phishing_detector.py) (`analyze_message_text`) for script detection, urgency markers, banking fraud triggers, and official Maharashtra Government Resolution verification.
2. **Deterministic Risk Scorer:** Reused [`src/risk_scorer.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/risk_scorer.py) (`score_message_analysis` and `score_apk_analysis`) to compute authoritative risk scores and bilingual advice.
3. **Static URL Radar:** Reused [`src/url_analyzer.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/url_analyzer.py) (`analyze_url`) for domain lexical analysis, IP host checks, punycode/homoglyph detection, brand impersonation, and allowlist lookups.
4. **Static APK Analyzer:** Reused [`src/apk_analyzer.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/apk_analyzer.py) (`analyze_apk_bytes`) for zero-execution binary AXML parsing, dangerous permission combinations, and passive URL extraction.
5. **Neural Shadow Classifier:** Reused [`src/hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py) (`evaluate_message_hybrid`) to run `custom-mlp-v4.0.0-seed42` purely in shadow mode (score delta = 0.00).
6. **Privacy & Redaction Gate:** Reused [`src/privacy_gate.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py) (`prepare_for_local_analysis`) for Aadhaar ID, phone number, and credential masking.
7. **Case Repository & Provenance:** Reused [`src/case_manager.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_manager.py) (`SessionCaseStore.add_case`) and [`src/case_repository.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py) for evidence provenance, campaign clustering, and audit trails.

---

## 3. UNIFIED UI & WORKSPACE ARCHITECTURE

The new primary workspace [`src/unified_workspace_ui.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/unified_workspace_ui.py) is integrated directly as the first tab in [`app.py`](file:///c:/Users/prati/seva-cyber-sandbox/app.py):

```
+------------------------------------------------------------------------------------------------+
| 01 // UNIFIED EVIDENCE ANALYSIS WORKSPACE                                                      |
+------------------------------------------------------------------------------------------------+
| [Section A: Message / Text Input]            | [Section B: Target URLs Input]                  |
| Text Area (WhatsApp, SMS, Marathi, English)   | Multiple URLs (newline-separated)               |
+------------------------------------------------------------------------------------------------+
| [Section C: Drag-and-Drop Artifacts Upload] (APKs, PDFs, Images, Plaintext)                    |
+------------------------------------------------------------------------------------------------+
| [Section D: Interactive Staged Artifacts Inventory]                                            |
| File Icon | Filename | Size | SHA-256 Digest | Detected Type (Override Dropdown) | Include Box |
+------------------------------------------------------------------------------------------------+
| [Section E: Governance & Analysis Controls]                                                    |
| [x] Enable Shadow AI  [ ] Citizen Feature Staging Consent  [🔍 ANALYZE ALL SUBMITTED EVIDENCE]  |
+------------------------------------------------------------------------------------------------+
| CONSOLIDATED INVESTIGATION REPORT                                                              |
| - Overall Authoritative Risk Index & Driving Artifact                                          |
| - Key Security Observations                                                                    |
| - Cross-Evidence Correlation Findings (Matched domains, APK strings, Threat Intel)             |
| - Per-Artifact Detailed Deep-Dives (Expandable Accordions)                                     |
| - AI & Rule-Engine Shadow Comparison (Delta == 0.00)                                           |
| - [💾 SAVE INVESTIGATION AS LINKED EVIDENCE CASE]                                              |
+------------------------------------------------------------------------------------------------+
```

---

## 4. SUPPORTED EVIDENCE TYPES & EXTRACTION CAPABILITIES

| Evidence Category | File Formats | Processing Capability | Local Tooling / Engine | Limitations Disclosed |
|:---|:---|:---|:---|:---|
| **Message / Communication** | Raw Text | **Fully Implemented** | `src.phishing_detector` | Rule-based token matching; regional dialect edge cases. |
| **Web URLs & Domains** | Strings / URLs | **Fully Implemented** | `src.url_analyzer` | Static lexical analysis; no remote HTTP connections made. |
| **Android Applications** | `.apk` | **Fully Implemented** | `src.apk_analyzer` | Static manifest & permission inspection; zero execution. |
| **PDF Documents** | `.pdf` | **Fully Implemented** | `pypdf` local library | Safe text & embedded link extraction; no external APIs. |
| **Plaintext Attachments** | `.txt`, `.log`, `.csv` | **Fully Implemented** | Built-in UTF-8 parser | Max 50,000 characters ceiling (ReDoS boundary). |
| **Screenshots / Images** | `.png`, `.jpg`, `.jpeg` | **Partially Supported** | `PIL` (`Pillow`) | **Format & dimensions inspected. OCR unavailable locally; zero cloud APIs used; zero text fabricated.** |
| **Other Binaries** | Any format | **Unsupported** | Cryptographic Hashing | Filename, size, and SHA-256 recorded. Content extraction unsupported without cloud services. |

---

## 5. AUTOMATIC EVIDENCE TYPE DETECTION

The function `detect_evidence_type()` in [`src/unified_analyzer.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/unified_analyzer.py) performs non-destructive type detection:
1. **String Inputs:** Differentiates between URLs (HTTP/HTTPS schemes, domain heuristics) and raw message text.
2. **Binary Inputs:**
   - PDF magic bytes: `%PDF-` $\rightarrow$ `pdf_document`.
   - ZIP magic bytes: `PK\x03\x04` with `AndroidManifest.xml` $\rightarrow$ `apk`.
   - Image magic bytes: `\x89PNG\r\n\x1a\n`, `\xff\xd8\xff`, `GIF87a`/`GIF89a`, `RIFF...WEBP` $\rightarrow$ `image`.
   - Valid UTF-8 decodable data with text extensions $\rightarrow$ `text_file`.
   - Unknown magic bytes $\rightarrow$ `unsupported`.
3. **User Override Control:** The UI presents a dropdown for every staged file, allowing investigators to correct or override the automatically detected type prior to analysis.

---

## 6. CROSS-EVIDENCE CORRELATION ENGINE

The correlation engine identifies relationships across submitted artifacts without modifying authoritative scores:

1. **`MESSAGE_URL_SHARED_DOMAIN`:** Discovers when a message references a domain matching a submitted URL.
2. **`APK_DOMAIN_CROSS_REFERENCE`:** Detects when passive URLs or domains inside an APK manifest/string pool match submitted URLs or message domains.
3. **`MESSAGE_APK_TOKEN_MATCH`:** Identifies app name or package tokens referenced in messages that match an uploaded APK's package name.
4. **`KNOWN_THREAT_INTEL_HASH_MATCH`:** Alerts when an uploaded APK's SHA-256 matches an active indicator in the local threat intelligence database.
5. **`KNOWN_THREAT_INTEL_DOMAIN_MATCH`:** Alerts when a submitted URL or message domain matches a reviewed threat indicator.
6. **`DECEPTIVE_IMPERSONATION_CONFLICT`:** Detects when an official government domain (`.gov.in`, `mahadiscom.in`) is submitted alongside a deceptive lookalike domain (`.top`, `.cc`, `.xyz`), flagging potential credential-harvesting lures.
7. **Safe Governance Guarantees:** Every correlation item displays confidence (`HIGH`, `MEDIUM`, `LOW`), supporting artifact IDs, and an explicit limitation disclaimer: *"Shared technical indicators or similar phrasing do not constitute conclusive proof of a unified threat campaign. User reports require independent corroboration."*

---

## 7. PARENT INVESTIGATION & LINKED ARTIFACT ARCHITECTURE

When saving an investigation, `save_investigation_cases()` creates a parent-child relationship graph in SQLite:
- **Child Artifact Cases:** Individual cases are generated for each artifact (`CASE-MSG-...`, `CASE-URL-...`, `CASE-APK-...`, etc.) using existing factory functions.
- **Parent Investigation Case:** A parent case `CASE-UNIF-YYYYMMDD-XXXX` is created with `analysis_type: "Unified Evidence Multi-Artifact Investigation"`.
- **Bidirectional Metadata Linking:**
  - Parent `metadata_json` records: `child_case_ids`, `child_evidence_ids`, `correlations`, and `summary_stats`.
  - Each child `metadata_json` records: `parent_investigation_id`.
- **Zero Database Migration Required:** The existing v3 schema natively supports parent-child graphs via `metadata_json` and `evidence_id`, preserving 100% database stability and compatibility.

---

## 8. PRIVACY, FILE SECURITY, AND GOVERNANCE CONTROLS

- **Zero Outbound Network Traffic:** Analysis runs 100% locally. Zero remote sockets or cloud APIs are invoked.
- **Fail-Closed ReDoS Boundary:** Text inputs exceeding 50,000 characters are rejected at the intake gate.
- **Aadhaar and Phone Redaction:** `prepare_for_local_analysis()` sanitizes sensitive Indian phone numbers and 12-digit Aadhaar numbers before evidence records are written.
- **Zip-Bomb & Traversal Defenses:** APK processing enforces existing uncompressed member ceilings (10 MB) and total archive ceilings (50 MB).
- **Zero In-Memory Leaks:** All file bytes are processed via in-memory buffers (`io.BytesIO`) and cleaned up immediately. Zero temporary files are left on disk.

---

## 9. MODEL GOVERNANCE INVARIANTS

- **Active Model:** `custom-mlp-v4.0.0-seed42` (Operating mode: `shadow`).
- **Production Authoritative:** `false`.
- **Authoritative Score Delta:** Identically `0.00`.
- **Last-Known-Good Target:** `custom-mlp-v1.1.0-preproc`.
- **Score Integrity:** The consolidated investigation risk score is strictly driven by the maximum deterministic rule score across completed artifacts. Adding benign artifacts never dilutes or alters critical risk scores.

---

## 10. TEST VERIFICATION AND TEST SUITE EXECUTION

A dedicated test suite [`tests/test_phase7_1_0_unified_workspace.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_phase7_1_0_unified_workspace.py) was implemented covering all 23 required scenarios:

| Test Case | Description | Result |
|:---|:---|:---:|
| `test_01_message_only_submission` | Single vernacular message submission and risk scoring | **PASSED** |
| `test_02_url_only_submission` | Single suspicious URL submission and lexical analysis | **PASSED** |
| `test_03_apk_only_submission` | Single Android APK upload and static permission analysis | **PASSED** |
| `test_04_message_plus_url` | Combined message and URL submission | **PASSED** |
| `test_05_message_plus_apk` | Combined message and APK submission | **PASSED** |
| `test_06_url_plus_apk` | Combined URL and APK submission | **PASSED** |
| `test_07_message_url_apk_together` | Tri-artifact submission (Message + URL + APK) | **PASSED** |
| `test_08_multiple_urls` | Multiple newline-separated URLs | **PASSED** |
| `test_09_multiple_apks_within_safe_limits` | Multiple APK archives analyzed independently | **PASSED** |
| `test_10_screenshot_upload` | Image dimensions, format, and local OCR limitation notice | **PASSED** |
| `test_11_pdf_upload` | PDF page count, text extraction, and link extraction | **PASSED** |
| `test_12_unsupported_file_types` | Non-supported binary handling with SHA-256 | **PASSED** |
| `test_13_malformed_files` | Truncated/corrupted PDF and APK handling without crash | **PASSED** |
| `test_14_duplicate_attachments` | Duplicate URL deduplication | **PASSED** |
| `test_15_partial_analysis_failures` | Fail-soft: valid items succeed when one artifact is corrupt | **PASSED** |
| `test_16_cross_evidence_correlation` | Message-to-URL domain cross-reference detection | **PASSED** |
| `test_17_case_creation_with_multiple_linked_artifacts` | Parent investigation case and linked child evidence cases | **PASSED** |
| `test_18_evidence_withdrawal` | Citizen consent withdrawal cascades through linked records | **PASSED** |
| `test_19_consent_enforcement` | Opt-in flag correctly sets `consent_given` on evidence | **PASSED** |
| `test_20_privacy_leakage` | Aadhaar IDs and phone numbers redacted from observed evidence | **PASSED** |
| `test_21_temporary_file_cleanup` | Zero temporary files leaked to disk | **PASSED** |
| `test_22_shadow_model_invariance` | Neural model runs in shadow mode with 0.00 score delta | **PASSED** |
| `test_23_deterministic_score_invariance` | Adding benign artifacts does not dilute critical risk scores | **PASSED** |

### Complete Regression Suite Execution:
- **Command:** `python -m pytest -q`
- **Total Tests Collected:** 847
- **Tests Passed:** 847
- **Tests Failed:** 0
- **Tests Skipped:** 0
- **Execution Time:** 163.67 seconds (2m 43s)
- **Pass Rate:** 100.0% (Zero regressions across all existing and new test suites)

---

## 11. MANUAL TESTING INSTRUCTIONS

To verify the Unified Evidence Analysis Workspace locally:

1. **Launch Application:**
   ```powershell
   streamlit run app.py --server.address 127.0.0.1 --server.port 8501
   ```
2. **Access Workspace:**
   - Open browser to `http://127.0.0.1:8501`.
   - The application opens directly to **`01 // UNIFIED EVIDENCE ANALYSIS`**.
3. **Multi-Artifact Test Submission:**
   - **Message Text:** Paste:
     ```text
     तात्काळ महावितरण वीज बिल भरा नाहीतर आज रात्री वीज तोडली जाईल. Pay at http://msedcl-bill-update.cc
     ```
   - **Target URLs:** Enter:
     ```text
     https://mahadiscom.in
     http://msedcl-bill-update.cc/login
     ```
   - **File Upload:** Attach `sample_apks/Simple_Marathi_Calendar_Test.apk` and any sample `.pdf` or screenshot.
4. **Inspect Inventory:**
   - Verify that file icons, sizes, SHA-256 hashes, and detected types are displayed.
5. **Run Analysis:**
   - Click **`🔍 ANALYZE ALL SUBMITTED EVIDENCE`**.
   - Verify overall risk banner, metric cards, cross-evidence correlation findings (deceptive impersonation alert), and expandable deep-dive accordions for each artifact.
6. **Save Case:**
   - Click **`💾 SAVE INVESTIGATION`**.
   - Verify that parent case ID and child case IDs are displayed.
   - Switch to **`05 // THREAT CASES`** to inspect the stored forensic investigation.
