# Seva Cyber Sandbox — Phase 1.2 Security Fix Implementation Report

**Document Date:** October 29, 2026  
**Auditor & Implementation Roles:** Senior Cybersecurity Architect, Principal Python Engineer, Test Verification Specialist  
**Repository Location:** `c:/Users/prati/seva-cyber-sandbox`  
**Execution Context:** Strict Phase 1.2 Remediations (No Phase 2 Work Initiated)  
**Prior Phase Reports:**
- [PHASE_0_REPOSITORY_AUDIT.md](file:///c:/Users/prati/seva-cyber-sandbox/docs/PHASE_0_REPOSITORY_AUDIT.md)
- [PHASE_1_IMPLEMENTATION_REPORT.md](file:///c:/Users/prati/seva-cyber-sandbox/docs/PHASE_1_IMPLEMENTATION_REPORT.md)
- [PHASE_1_1_SECURITY_VERIFICATION.md](file:///c:/Users/prati/seva-cyber-sandbox/docs/PHASE_1_1_SECURITY_VERIFICATION.md)

---

## 1. Executive Summary & Remediation Outcome

In Phase 1.1, an independent read-only security audit uncovered two security findings:
1. **SEC-01 (Severity: MEDIUM):** Hardcoded development fallback key in [`src/case_repository.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py).
2. **SEC-02 (Severity: LOW-MEDIUM):** Formatted Aadhaar numbers and OTPs written with Devanagari numerals (`०-९`) were detected by category in [`src/privacy_gate.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py) but not replaced in the returned `sanitized_text` due to ASCII-only regex substitution on unnormalized text.

Both vulnerabilities have been completely resolved, validated with dedicated regression tests, and certified across the full project test suite.

### Test Suite Metric Summary:
- **Prior Test Baseline (Phase 1.1):** 171 tests passed.
- **New Tests Added (Phase 1.2):** 3 new regression tests (+2 in `tests/test_privacy_gate.py`, +1 comprehensive in `tests/test_threat_intelligence.py`).
- **Current Test Suite (Phase 1.2):** **174 of 174 passed in 12.91s**.
- **Locked Test Evaluation Dataset:** SHA-256 verified match (`9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`). Zero data alteration or cross-set leakage.
- **WhatsApp Cloud API Integration:** 10/10 tests passed without regressions.

---

## 2. Root Cause Analysis & Detailed Fixes

### Fix for SEC-01: Hardcoded Fallback Key Removal & Key Management Isolation

#### 2.1 Root Cause
In Phase 1, [`get_default_hmac_secret()`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py#L157-L160) returned a static hardcoded fallback string `"SEVA_CYBER_HMAC_SECRET_KEY_MAHARASHTRA_2026"` when environment variables were absent. Additionally, [`compute_phone_indicator_hmac`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py#L422) fell back to `WHATSAPP_SENDER_SALT`, conflating two separate security boundaries (threat intelligence phone observables vs. WhatsApp webhook sender privacy).

#### 2.2 Technical Fix
1. **Complete Removal of Static Secret:** Removed the hardcoded fallback constant string.
2. **Dedicated Key Resolver ([`get_threat_intel_hmac_secret`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py#L160)):**
   - Order of precedence:
     1. Explicit `secret` parameter (if passed).
     2. `os.environ.get("SEVA_THREAT_INTEL_KEY")`
     3. `os.environ.get("SEVA_HMAC_SECRET")`
   - Does **not** fall back to `WHATSAPP_SENDER_SALT` or any static secret.
   - Enforces a minimum key length of 16 characters (`MIN_HMAC_SECRET_LENGTH = 16`).
   - If missing, empty, blank, or $< 16$ characters, raises [`ThreatIntelligenceKeyError`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py#L39) with a safe, actionable error message.
   - Secret material is never formatted into exceptions, warnings, or logs.
3. **Fail-Closed Matching ([`match_indicators`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py#L1330)):**
   - Catches [`ThreatIntelligenceKeyError`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py#L39) when phone lookups are attempted without a configured key.
   - Safely omits phone candidate lookups, resulting in 0 phone matches without crashing or leaking state.
4. **Isolated Sender Display Salt ([`keyed_phone_hmac`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py#L278)):**
   - Dedicated exclusively to evidence masking text in historical case logs; completely decoupled from threat intelligence matching.
5. **Fixture Isolation in Tests:**
   - In [`tests/test_threat_intelligence.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_threat_intelligence.py), the `repo` fixture isolates `SEVA_THREAT_INTEL_KEY = "TestFixtureThreatIntelSecret2026"` strictly within test processes.

---

### Fix for SEC-02: Devanagari Aadhaar & OTP Exact In-Place Redaction

#### 2.1 Root Cause
In Phase 1, [`src/privacy_gate.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py) compiled [`RE_AADHAAR_FORMATTED`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L110) with ASCII `[2-9]\d{3}` and [`RE_OTP`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L140) with ASCII `[0-9]{4,8}`. During sanitization, detection was checked against `normalize_devanagari_numerals(working_text)`, which correctly detected categories like `"aadhaar_number"` and `"otp"`. However, the subsequent replacement call `RE_*.sub(...)` ran directly against `working_text` (which still contained Devanagari numerals `[०-९]`). As a result, the replacement failed to match, leaving the original Devanagari digits unredacted in `sanitized_text`. Additionally, Python's `\b` word boundary does not match after Devanagari combining vowel signs (matras like `ी` in `ओटीपी`).

#### 2.2 Technical Fix
1. **Multilingual Word Boundaries & Character Sets:**
   ```python
   WORD_START = r"(?<![A-Za-z0-9\u0900-\u097F])"
   WORD_END = r"(?![A-Za-z0-9\u0900-\u097F])"
   DIGIT_CHAR = r"[0-9०-९]"
   AADHAAR_FIRST_DIGIT = r"[2-9२-९]"
   ```
2. **Updated Pattern Definitions:**
   - **Formatted Aadhaar ([`RE_AADHAAR_FORMATTED`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L110)):** Matches 4-4-4 formatted groups using ASCII `[2-9]` or Devanagari `[२-९]` for the initial digit, and `[0-9०-९]` for all subsequent digits, separated by spaces or hyphens.
   - **Contextual Aadhaar ([`RE_AADHAAR_CONTEXTUAL`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L114)):** Matches unformatted 12-digit numbers preceded by keywords `aadhaar`, `uidai`, `आधार`, or `aadhar`.
   - **Vernacular OTPs ([`RE_OTP`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L140)):** Matches Marathi labels (`ओटीपी`, `सत्यापन कोड`, `सुरक्षा कोड`, `OTP`), Marathi/English connectors (`आहे`, `is`, `code`, `क्रमांक`, `:`, `-`), and 4-8 digit codes in either ASCII or Devanagari digits.
   - **PINs & CVVs ([`RE_PIN`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L143), [`RE_CVV`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L149)):** Expanded to support Devanagari numerals.
3. **In-Place Substring Redaction:**
   - Redaction operates directly on `working_text` using callable lambda substitutions (e.g. `working_text = RE_OTP.sub(lambda m: f"{m.group(1)}: {CREDENTIAL_REDACTION_TOKEN}", working_text)`).
   - This guarantees that the original secret value is removed from `sanitized_text` while preserving surrounding Marathi grammar and context.
   - Zero index-offset translations between different normalized strings, avoiding Unicode shift bugs.
4. **Devanagari Residual Ambiguity Guard:**
   - Step 9 checks for unclassified contiguous sequences of $\ge 9$ digits across both ASCII and Devanagari numerals (`(?<![0-9०-९])[0-9०-९]{9,}(?![0-9०-९])`). Any residual sequence is replaced with `[PII_REDACTED]` and forces `safe_to_send = False`.

---

## 3. Required Key Configuration & Windows/PowerShell Deployment Guide

### 3.1 Developer & Operator Setup (₹0 Local Execution)
The threat intelligence component requires an explicit HMAC secret key configured in the environment.

#### In Windows PowerShell:
```powershell
# Set for current PowerShell session
$env:SEVA_THREAT_INTEL_KEY = "YourHighEntropySecretKeyHere_AtLeast16Chars!"

# Or configure persistently for the current user
[Environment]::SetEnvironmentVariable("SEVA_THREAT_INTEL_KEY", "YourHighEntropySecretKeyHere_AtLeast16Chars!", "User")
```

#### In `.env` Configuration File:
Copy [`.env.example`](file:///c:/Users/prati/seva-cyber-sandbox/.env.example) to `.env` (never committed to Git):
```bash
# Section 8: Threat Intelligence HMAC Secret Key
SEVA_THREAT_INTEL_KEY="your_secure_random_threat_intelligence_hmac_secret_here_min_16_chars"
```

### 3.2 Key Management Lifecycle & Disaster Recovery
- **Key Loss:** If the HMAC secret key is lost, historical phone-number threat indicators cannot be matched with incoming submissions because the SHA-256 HMAC digest cannot be reversed. To recover, indicators must be re-ingested from original verified case manifests under a newly established key.
- **Key Rotation:** When rotating the key, existing indicator records in `threat_indicators` must be re-computed with the new secret during a planned maintenance migration.
- **Missing Key Behavior:** If the key is absent or blank, the application safely fails closed: no crash occurs, and phone numbers simply yield zero indicator matches.

---

## 4. Test Verification & Exact Results

### 4.1 Focused Threat Intelligence Tests
**Command:**
```powershell
.\venv\Scripts\python.exe -m pytest tests/test_threat_intelligence.py -v
```
**Output:**
```
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\prati\seva-cyber-sandbox
configfile: pytest.ini
collected 16 items

tests/test_threat_intelligence.py::test_01_idempotent_database_initialization_and_schema PASSED [  6%]
tests/test_threat_intelligence.py::test_02_indicator_input_validation PASSED [ 12%]
tests/test_threat_intelligence.py::test_03_domain_normalization_and_exact_matching PASSED [ 18%]
tests/test_threat_intelligence.py::test_04_url_canonicalization_and_bounded_matching PASSED [ 25%]
tests/test_threat_intelligence.py::test_05_apk_hash_normalization_and_matching PASSED [ 31%]
tests/test_threat_intelligence.py::test_06_phone_indicator_hmac_and_fail_closed_key PASSED [ 37%]
tests/test_threat_intelligence.py::test_07_duplicate_indicator_handling PASSED [ 43%]
tests/test_threat_intelligence.py::test_08_inactive_indicator_not_matched PASSED [ 50%]
tests/test_threat_intelligence.py::test_09_expired_indicator_not_matched PASSED [ 56%]
tests/test_threat_intelligence.py::test_10_unreviewed_vs_reviewed_decision_boundary PASSED [ 62%]
tests/test_threat_intelligence.py::test_11_audit_log_contains_no_raw_secrets PASSED [ 68%]
tests/test_threat_intelligence.py::test_12_concurrent_indicator_insertions PASSED [ 75%]
tests/test_threat_intelligence.py::test_13_additive_risk_score_integration PASSED [ 81%]
tests/test_threat_intelligence.py::test_14_existing_cases_preserved_across_migrations PASSED [ 87%]
tests/test_threat_intelligence.py::test_15_strict_offline_zero_network_calls PASSED [ 93%]
tests/test_threat_intelligence.py::test_16_sec_01_comprehensive_key_security PASSED [100%]

============================= 16 passed in 0.82s ==============================
```

### 4.2 Focused Privacy Gate Tests
**Command:**
```powershell
.\venv\Scripts\python.exe -m pytest tests/test_privacy_gate.py -v
```
**Output:**
```
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\prati\seva-cyber-sandbox
configfile: pytest.ini
collected 20 items

tests/test_privacy_gate.py::test_01_phone_number_formats_redacted PASSED [  5%]
tests/test_privacy_gate.py::test_02_devanagari_numerals_phone_redacted PASSED [ 10%]
tests/test_privacy_gate.py::test_03_aadhaar_identifier_variations_redacted PASSED [ 15%]
tests/test_privacy_gate.py::test_04_labelled_bank_account_and_ifsc_redacted PASSED [ 20%]
tests/test_privacy_gate.py::test_05_marathi_labelled_bank_account_redacted PASSED [ 25%]
tests/test_privacy_gate.py::test_06_credit_debit_card_redacted PASSED    [ 30%]
tests/test_privacy_gate.py::test_07_otps_passwords_and_tokens_redacted PASSED [ 35%]
tests/test_privacy_gate.py::test_08_labelled_personal_names_and_honorifics_redacted PASSED [ 40%]
tests/test_privacy_gate.py::test_09_marathi_labelled_name_redacted PASSED [ 45%]
tests/test_privacy_gate.py::test_10_email_addresses_redacted PASSED      [ 50%]
tests/test_privacy_gate.py::test_11_multiple_sensitive_values_in_single_message PASSED [ 55%]
tests/test_privacy_gate.py::test_12_benign_messages_remain_usable PASSED [ 60%]
tests/test_privacy_gate.py::test_13_external_sharing_disabled_by_default PASSED [ 65%]
tests/test_privacy_gate.py::test_14_fail_closed_on_ambiguous_long_numeric PASSED [ 70%]
tests/test_privacy_gate.py::test_15_fail_closed_on_none_and_invalid_types PASSED [ 75%]
tests/test_privacy_gate.py::test_16_no_sensitive_values_in_errors_or_categories PASSED [ 80%]
tests/test_privacy_gate.py::test_17_prepare_for_local_analysis_does_not_block PASSED [ 85%]
tests/test_privacy_gate.py::test_18_strict_offline_zero_network_calls PASSED [ 90%]
tests/test_privacy_gate.py::test_19_sec_02_devanagari_aadhaar_and_otp_exact_redaction PASSED [ 95%]
tests/test_privacy_gate.py::test_20_sec_02_benign_marathi_and_ambiguous_numerics PASSED [100%]

============================= 20 passed in 0.33s ==============================
```

### 4.3 Full Test Suite Execution
**Command:**
```powershell
.\venv\Scripts\python.exe -m pytest -v
```
**Output:**
```
============================ 174 passed in 12.91s =============================
```

### 4.4 Evaluation Dataset & Locked Test Verification
**Command:**
```powershell
.\venv\Scripts\python.exe evaluation/evaluate_phishing.py
```
**Output:**
```
============================================================================
SEVA CYBER SANDBOX — THREE-ROLE PHISHING EVALUATION HARNESS
============================================================================
[+] Total Records: 39 across 18 campaigns.
    Roles: Development=19 | Validation=10 | Locked Test=10
    Locked Test SHA-256: 9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda
    Leak-Free Guarantee: Strict campaign isolation: campaigns(dev) & campaigns(val) & campaigns(locked) = empty (zero campaign overlap)
--- 1. RULE-BASED DETECTOR ON LOCKED TEST PARTITION (10 Binary Samples) ---
    Accuracy: 100.0% (10/10) | Precision: 100.0% | Recall: 100.0% | F1: 100.0%
--- 2. EXPERIMENTAL ML BASELINE ON LOCKED TEST (Train: 20, Test: 10) ---
    Accuracy: 70.0% (7/10) | Precision: 70.0% | Recall: 100.0% | F1: 82.4%
============================================================================
```

---

## 5. Remaining Security Limitations & Scope Boundaries

While SEC-01 and SEC-02 are fully resolved, the following architectural boundaries are explicitly documented:
1. **Unlabelled Arbitrary Names:** Regular expressions cannot reliably identify every arbitrary citizen name mentioned informally in free-form vernacular prose without grammatical structure or honorific markers.
2. **Unlabelled Bank Account Numbers:** Bare 11-digit numbers appearing without keywords (`खाते`, `A/C`) trigger the $\ge 9$ digit residual guard and fail closed (`safe_to_send = False`).
3. **Phishing in Non-Text Media:** Obfuscated lures rendered purely as image attachments require OCR, which is not part of this text-based privacy gate.

---

## 6. Git Status and Working Tree State

### 6.1 `git status --short`
```
 M .gitignore
 M README.md
 M app.py
 M create_sample_apks.py
 M sample_apks/Gram_Panchayat_Directory_Test.apk
 M sample_apks/MSEDCL_Light_Bill_Update_Test.apk
 M sample_apks/Real_Binary_AXML_Header_Sample.apk
 M sample_apks/Simple_Marathi_Calendar_Test.apk
 M src/__init__.py
 M src/apk_analyzer.py
 M src/audio_alert.py
 M src/ml_classifier.py
 M src/phishing_detector.py
 M src/risk_scorer.py
 M tests/test_sandbox.py
?? .env.example
?? Seva-First-Innovation-Challenge-PPT-Template.pptx
?? Seva_Cyber_Sandbox_Submission.pptx
?? build_ppt.py
?? data/locked_test_manifest.json
?? data/official_sources.json
?? data/phishing_eval_dataset.json
?? docs/
?? evaluation/
?? pytest.ini
?? sample_apks/Compiled_Binary_AXML_Tree_Sample.apk
?? screenshot_1_phishing.png.png
?? screenshot_2_safeguard.png.png
?? screenshot_3_apk.png.png
?? src/case_manager.py
?? src/case_repository.py
?? src/dataset_validator.py
?? src/privacy_gate.py
?? src/scheme_verifier.py
?? src/url_analyzer.py
?? src/whatsapp_handler.py
?? src/whatsapp_webhook.py
?? tests/conftest.py
?? tests/independent_fixtures/
?? tests/test_apk_structural_parser.py
?? tests/test_case_manager.py
?? tests/test_case_repository.py
?? tests/test_dataset_provenance.py
?? tests/test_independent_apk_validation.py
?? tests/test_integration.py
?? tests/test_phishing_evaluation.py
?? tests/test_privacy_gate.py
?? tests/test_scheme_verifier.py
?? tests/test_threat_intelligence.py
?? tests/test_url_analyzer.py
?? tests/test_whatsapp_integration.py
```

### 6.2 Modified & Created Files in Phase 1.2
- **Modified:**
  - [`.env.example`](file:///c:/Users/prati/seva-cyber-sandbox/.env.example): Added section 8 template for `SEVA_THREAT_INTEL_KEY`.
  - [`src/case_repository.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py): Removed hardcoded HMAC secret; enforced $\ge 16$ characters; decoupled from WhatsApp salt; fail-closed key management.
  - [`src/privacy_gate.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py): Implemented exact in-place Devanagari Aadhaar and OTP redaction; added multilingual word boundary logic.
  - [`tests/test_privacy_gate.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_privacy_gate.py): Added `test_19` and `test_20` (exact text assertions for Devanagari Aadhaar, OTPs, and benign Marathi).
  - [`tests/test_threat_intelligence.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_threat_intelligence.py): Updated fixture with test key; added comprehensive `test_16` covering all 7 SEC-01 verification requirements.
- **Created:**
  - [`docs/PHASE_1_2_SECURITY_FIX_REPORT.md`](file:///c:/Users/prati/seva-cyber-sandbox/docs/PHASE_1_2_SECURITY_FIX_REPORT.md): This report.

---

## 7. Sign-Off & Verification Conclusion

All requirements of Phase 1.2 are met:
- **SEC-01 Resolved:** Static fallback secret removed; key validation and fail-closed behavior verified.
- **SEC-02 Resolved:** Devanagari Aadhaar and OTP values are redacted in `sanitized_text`; benign text is preserved; ambiguous numeric data fails closed.
- **Budget Integrity:** ₹0 spent; no external network requests made; zero cloud services or external AI APIs introduced.
- **Test Baseline:** 174 tests passing (100% pass rate).
- **Ready for Review:** Phase 1.2 is complete and verified. Awaiting user instructions before Phase 2.
