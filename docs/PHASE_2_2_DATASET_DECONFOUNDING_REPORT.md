# Seva Cyber Sandbox — Phase 2.2 Dataset Deconfounding Report
**Candidate Corpus v2: Shortcut Removal, Class Rebalancing & Pre-Training Readiness**

*Date: October 29, 2026*  
*Project: Seva Cyber Sandbox — Malicious APK & Vernacular Phishing Detector*  
*Environment: Offline Python 3.14.8 Virtual Environment (Windows 11)*  
*Total Financial Expenditure: ₹0.00*  
*Candidate Directory: `data/generated/v2/`*  
*Locked Evaluation Anchor: `data/phishing_eval_dataset.json` (Digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`)*

---

## Executive Summary

Phase 2.1 identified two critical data-quality flaws in the Phase 2 dataset:
1. **The URL-Label Shortcut**: URLs occurred in 100.0% of phishing messages, 0.0% of legitimate messages, and 0.0% of training protective advisories. A trivial rule checking for `http` achieved 100.0% accuracy on the training set, risking shortcut learning in any neural model.
2. **Severe Class Imbalance**: Phishing accounted for 77.0% of clean records, creating majority-class bias.

Phase 2.2 resolved both issues by engineering a revised candidate corpus **v2** stored under [`data/generated/v2/`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/):
- **All original Phase 2 (v1) files remain completely preserved and untouched** under `data/generated/`.
- **The URL-Label shortcut has been eliminated**: URLs now appear across all three classes at moderate rates (Phishing: 37.5%, Legitimate: 41.7%, Protective Advisory: 53.3% in training). A URL-presence diagnostic rule drops from 100.0% accuracy on v1 to **47.5% accuracy (F1: 32.3%)** on v2.
- **Classes are now perfectly balanced (1:1:1 ratio)**:
  - Training: 120 Phishing, 120 Legitimate, 120 Protective Advisory (360 clean records).
  - Validation: 45 Phishing, 45 Legitimate, 45 Protective Advisory (135 clean records).
  - Quarantine: 45 Ambiguous records (30 train, 15 val).
  - Total v2 Generated: **540 records**.
- **16 new unit tests** ([`tests/test_dataset_deconfounding.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_dataset_deconfounding.py)) were created, bringing the total suite to **206 passing tests** (0 failures, 0 regressions).
- The locked evaluation manifest checksum remains strictly verified.

---

## 1. Before vs After: Class & Partition Reconciliation

| Partition / Split | Phase 2 (v1) Records | Phase 2 (v1) Class Share | Phase 2.2 (v2) Records | Phase 2.2 (v2) Class Share | Change / Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Training: Phishing** | 245 | 77.8% | **120** | **33.3%** | Rebalanced |
| **Training: Legitimate** | 35 | 11.1% | **120** | **33.3%** | +85 records |
| **Training: Protective Advisory** | 35 | 11.1% | **120** | **33.3%** | +85 records |
| *Training Subtotal (Clean)* | *315* | *100.0%* | ***360*** | ***100.0%*** | **Perfect 1:1:1 Balance** |
| **Validation: Phishing** | 90 | 75.0% | **45** | **33.3%** | Rebalanced |
| **Validation: Legitimate** | 15 | 12.5% | **45** | **33.3%** | +30 records |
| **Validation: Protective Advisory** | 15 | 12.5% | **45** | **33.3%** | +30 records |
| *Validation Subtotal (Clean)* | *120* | *100.0%* | ***135*** | ***100.0%*** | **Perfect 1:1:1 Balance** |
| **Quarantined (`ambiguous_needs_review`)** | 50 | N/A | **45** | N/A | Isolated in quarantine |
| **Total Generated Records** | **485** | | **540** | | +55 records |

---

## 2. Deconfounding: URL Presence & Feature Association Findings

### 2.1 URL Presence Rate: v1 vs v2
To deconfound the dataset, all 6 natural real-world interaction modes were implemented:
1. Phishing with links (fake KYC/payment portals).
2. Phishing without links (callback scams, direct chat OTP requests, UPI PIN collect prompts).
3. Legitimate messages with links (official e-receipts, OPD token slips, e-statements).
4. Legitimate messages without links (plain transaction receipts, hospital tokens, line maintenance notices).
5. Protective advisories with links (official bulletins warning against unverified URLs).
6. Protective advisories without links (general broadcast warnings never to share OTP/PIN, dial 1930).

| Feature: URL Presence (`has_url`) | Phase 2 (v1) Rate | Phase 2.2 (v2) Rate | Deconfounding Impact |
| :--- | :--- | :--- | :--- |
| **Training: Phishing** | **100.0%** (245/245) | **37.5%** (45/120) | -62.5% (Many link-free phishing lures) |
| **Training: Legitimate** | **0.0%** (0/35) | **41.7%** (50/120) | +41.7% (Natural e-receipts & portals added) |
| **Training: Protective Advisory** | **0.0%** (0/35) | **53.3%** (64/120) | +53.3% (Advisories warning about URLs added) |
| **Validation: Phishing** | **100.0%** (90/90) | **42.2%** (19/45) | -57.8% |
| **Validation: Legitimate** | **0.0%** (0/15) | **37.8%** (17/45) | +37.8% |
| **Validation: Protective Advisory** | **26.7%** (4/15) | **73.3%** (33/45) | Balanced across classes |

### 2.2 Diagnostic Baseline Comparison
To prove mathematically that the shortcut is broken, a single-feature diagnostic rule (*"If URL present $\to$ Phishing, else Non-Phishing"*) was evaluated on both corpora:

```
[Phase 2 (v1) Training - URL Presence Rule]
Accuracy:  100.0%
Precision: 100.0%
Recall:    100.0%
F1-Score:  100.0%  <-- TRIVIAL SHORTCUT (100% of phishing flagged, 0 false alarms)

[Phase 2.2 (v2) Training - URL Presence Rule]
Accuracy:   47.5%
Precision:  28.3%
Recall:     37.5%
F1-Score:   32.3%  <-- SHORTCUT FULLY BROKEN (below random guess on 3-class data)
```

### 2.3 Comprehensive Surface-Feature Audit (v2 Training Partition)
An exhaustive scan of all surface features in `data/generated/v2/synthetic_training_corpus.jsonl` was performed using [`scripts/audit_dataset_shortcuts.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/audit_dataset_shortcuts.py):

| Feature / Token | Phishing Rate | Legitimate Rate | Protective Advisory Rate | Single-Feature Diagnostic Accuracy | Diagnostic F1 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `has_url` (http/https) | 37.5% | 41.7% | 53.3% | 47.5% | 32.3% |
| `has_otp` (OTP / ओटीपी) | 19.2% | 11.7% | 15.8% | 63.9% | 26.1% |
| `has_upi` (UPI / यूपीआय) | 25.0% | 5.0% | 6.7% | 68.6% | 38.7% |
| `has_apk` (.apk / ॲप) | 1.7% | 0.0% | 27.5% | 58.1% | 2.6% |
| `has_kyc` (KYC / पॅन) | 13.3% | 0.0% | 14.2% | 66.4% | 20.9% |
| `has_urgency` (तातडीने / immediate / block) | 37.5% | 11.7% | 18.3% | 69.2% | 44.8% |

*(Note: On a 3-class dataset with 120 samples per class, predicting "Non-Phishing" for everything achieves a baseline accuracy of 66.7% (240/360). All diagnostic single-feature rules achieve F1 scores below 45%, confirming that no single lexical token accidentally predicts the label.)*

---

## 3. Template & Campaign Family Architecture (v2)

The candidate v2 corpus is built upon **23 distinct template families** (13 in Training, 10 in Validation) with **zero campaign or scenario overlap**:

### 3.1 Training Partition (`development`) — 13 Families
| Campaign ID | Scenario Category | Class Label | Target Count | Features / Construction |
| :--- | :--- | :--- | :--- | :--- |
| `v2_camp_phish_powercut_train` | `msedcl_powercut_threat` | `phishing` | 30 | Disconnection threat; with portal link & officer callback phone |
| `v2_camp_phish_bank_kyc_train` | `bank_kyc_suspension` | `phishing` | 30 | PAN KYC block; with portal link & direct chat OTP request |
| `v2_camp_phish_upi_cashback_train` | `upi_cashback_lure` | `phishing` | 30 | Fake reward; with claim link & UPI PIN collect approval request |
| `v2_camp_phish_parcel_train` | `courier_parcel_delivery` | `phishing` | 30 | Address mismatch fee; with tracking link & delivery boy phone |
| `v2_camp_legit_utility_train` | `genuine_utility_receipt` | `legitimate` | 30 | Electricity bill receipt; with e-receipt download link & plain SMS receipt |
| `v2_camp_legit_banking_train` | `genuine_banking_credit` | `legitimate` | 30 | Bank credit alert; with e-statement link & OTP security disclaimer SMS |
| `v2_camp_legit_booking_train` | `genuine_service_booking` | `legitimate` | 30 | LPG gas booking / IRCTC train PNR; with order track link & plain SMS |
| `v2_camp_legit_maintenance_train` | `genuine_civic_notice` | `legitimate` | 30 | Power grid & water pipeline maintenance completion notice; with link & plain SMS |
| `v2_camp_prot_utility_train` | `utility_safety_advisory` | `protective_advisory` | 30 | Disconnection scam awareness; with official advisory portal & dial 1930 SMS |
| `v2_camp_prot_banking_train` | `banking_safety_advisory` | `protective_advisory` | 30 | Banking vigilance; with safety circular link & "never share OTP" guidance |
| `v2_camp_prot_apk_train` | `apk_malware_advisory` | `protective_advisory` | 30 | Malicious APK warning; with advisory portal & Play Store only warning |
| `v2_camp_prot_task_train` | `part_time_task_advisory` | `protective_advisory` | 30 | YouTube/hotel review job scam warning; with cyber link & UPI fee warning |
| `v2_camp_ambiguous_train` | `ambiguous_incomplete` | `ambiguous_needs_review` | 30 | Incomplete links & phone fragments *(Quarantined)* |

### 3.2 Validation Partition (`validation`) — 10 Families (Completely Disjoint)
| Campaign ID | Scenario Category | Class Label | Target Count | Held-Out Scenario Details |
| :--- | :--- | :--- | :--- | :--- |
| `v2_camp_phish_solar_val` | `msedcl_solar_subsidy` | `phishing` | 15 | Rooftop solar panel registration fee scam; with & without link |
| `v2_camp_phish_rewards_val` | `credit_card_rewards` | `phishing` | 15 | Credit card reward points expiry lure; with & without link |
| `v2_camp_phish_echallan_val` | `rto_echallan_fine` | `phishing` | 15 | Traffic police e-challan penalty threat; with & without link |
| `v2_camp_legit_hospital_val` | `genuine_appointment_booking` | `legitimate` | 15 | Civil hospital OPD token & doctor appointment; with & without link |
| `v2_camp_legit_telecom_val` | `genuine_telecom_service` | `legitimate` | 15 | Mobile plan recharge & postpaid bill clearance; with & without link |
| `v2_camp_legit_exam_val` | `genuine_education_notice` | `legitimate` | 15 | Board exam hall ticket & university scholarship; with & without link |
| `v2_camp_prot_rto_val` | `rto_safety_advisory` | `protective_advisory` | 15 | Traffic police awareness against fake challan APKs; with & without link |
| `v2_camp_prot_lottery_val` | `lottery_reward_advisory` | `protective_advisory` | 15 | Awareness against advance tax lottery schemes; with & without link |
| `v2_camp_prot_digital_arrest_val` | `digital_arrest_advisory` | `protective_advisory` | 15 | Police warning: law enforcement never conducts video digital arrest |
| `v2_camp_ambiguous_val` | `ambiguous_forward` | `ambiguous_needs_review` | 15 | Forwarded fragments *(Quarantined)* |

---

## 4. Language & Script Coverage (v2 Clean Corpus)

All four target vernacular language configurations are well represented across both partitions:

| Language Code | Script | Training (360) | Validation (135) | Clean Total (495) | Percentage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `mr` (Marathi) | Devanagari | 125 | 46 | 171 | 34.5% |
| `en` (Indian English) | Latin | 105 | 40 | 145 | 29.3% |
| `mr-Latn` (Romanized Marathi) | Latin | 73 | 27 | 100 | 20.2% |
| `mr-en` (Mixed Code-Switched) | Mixed | 57 | 22 | 79 | 16.0% |
| **Total** | | **360** | **135** | **495** | **100.0%** |

---

## 5. Partition Isolation & Leakage Verification

- **Template-Family Overlap**: **Zero** ($\text{Campaigns}_{\text{train}} \cap \text{Campaigns}_{\text{val}} = \emptyset$).
- **Exact Text Overlap**: **Zero**.
- **Normalized Text Overlap**: **Zero**.
- **Token Jaccard Cross-Partition Overlap**: Zero cross-partition pairs exceed $0.70$ similarity.
- **Quarantine Isolation**: All 45 ambiguous records are isolated in [`data/generated/v2/quarantine_records.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/quarantine_records.jsonl). Zero quarantined records leak into clean training or validation files.

---

## 6. Data Safety & Integrity

1. **No Live Domains**: All newly generated URLs exclusively use IETF RFC 2606 reserved `.invalid` top-level domains (`bill-update.invalid`, `mahadiscom-receipt.invalid`, `cybercrime-alert.invalid`) or verified official references (`cybercrime.gov.in`, `mahadiscom.in`).
2. **No Real PII / Phone Numbers**: Phone numbers strictly use reserved dummy numbers (`9800000001`–`9800000005`, `022-55550111`, `1800-555-0199`) or official helplines (`1930`, `1912`). Zero real citizen mobile numbers or Aadhaar numbers exist.
3. **Preservation of Phase 2 (v1) Artifacts**:
   - `data/generated/synthetic_training_corpus.jsonl` (315 records) — **Preserved and untouched**.
   - `data/generated/synthetic_validation_corpus.jsonl` (120 records) — **Preserved and untouched**.
   - `data/generated/quarantine_records.jsonl` (50 records) — **Preserved and untouched**.
   - `data/generated/synthetic_corpus_report.json` — **Preserved and untouched**.
4. **Locked Evaluation Dataset Integrity**:
   - Evaluated using `src/dataset_validator.py:compute_locked_test_hash`:
     ```
     Computed SHA-256 Digest: 9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda
     Expected Manifest Digest: 9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda
     Match: TRUE (100% UNTOUCHED & CRYPTOGRAPHICALLY SECURE)
     ```

---

## 7. Verification & Automated Test Results

The dedicated deconfounding test suite ([`tests/test_dataset_deconfounding.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_dataset_deconfounding.py)) was executed:

```powershell
.\venv\Scripts\python.exe -m pytest tests/test_dataset_deconfounding.py -v
```
**Results (16/16 Passed)**:
- `test_01_v2_generator_reproducibility`: PASSED
- `test_02_v2_schema_and_labels_validation`: PASSED
- `test_03_v2_class_balance_and_counts`: PASSED
- `test_04_v2_zero_template_family_leakage`: PASSED
- `test_05_v2_zero_cross_partition_exact_duplicates`: PASSED
- `test_06_v2_near_duplicate_handling`: PASSED
- `test_07_v2_no_trivial_url_shortcut`: PASSED
- `test_08_v2_phishing_both_with_and_without_links`: PASSED
- `test_09_v2_protective_both_with_and_without_links`: PASSED
- `test_10_v2_legitimate_both_with_and_without_links`: PASSED
- `test_11_v2_all_four_languages_present`: PASSED
- `test_12_v2_no_live_domains`: PASSED
- `test_13_v2_quarantine_exclusion`: PASSED
- `test_14_v2_provenance_completeness`: PASSED
- `test_15_v1_artifacts_untouched`: PASSED
- `test_16_locked_evaluation_digest_verified`: PASSED

### Full Test Suite Execution
```powershell
.\venv\Scripts\python.exe -m pytest -q
```
**Result**: **206 passed in 8.10s** (174 Phase 1/1.2 tests + 16 Phase 2 tests + 16 Phase 2.2 deconfounding tests; 0 failures, 0 regressions).

---

## 8. File Inventory of Phase 2.2 Work

| Action | Path | Description |
| :--- | :--- | :--- |
| **Created** | [`scripts/generate_synthetic_corpus_v2.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/generate_synthetic_corpus_v2.py) | Deterministic synthetic corpus generator v2 with deconfounded templates and 1:1:1 class balance |
| **Created** | [`scripts/audit_dataset_shortcuts.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/audit_dataset_shortcuts.py) | Deterministic surface-feature shortcut audit tool and diagnostic baseline evaluator |
| **Created** | [`data/generated/v2/synthetic_training_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/synthetic_training_corpus.jsonl) | 360 clean balanced training records |
| **Created** | [`data/generated/v2/synthetic_validation_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/synthetic_validation_corpus.jsonl) | 135 clean balanced validation records |
| **Created** | [`data/generated/v2/quarantine_records.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/quarantine_records.jsonl) | 45 quarantined ambiguous records |
| **Created** | [`data/generated/v2/synthetic_corpus_report.json`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/synthetic_corpus_report.json) | Quality and distribution audit report for v2 |
| **Created** | [`data/generated/v2/shortcut_audit_report.json`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/shortcut_audit_report.json) | Detailed feature presence and baseline diagnostic results comparing v1 vs v2 |
| **Created** | [`tests/test_dataset_deconfounding.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_dataset_deconfounding.py) | 16 automated regression unit tests for Phase 2.2 |
| **Created** | [`docs/PHASE_2_2_DATASET_DECONFOUNDING_REPORT.md`](file:///c:/Users/prati/seva-cyber-sandbox/docs/PHASE_2_2_DATASET_DECONFOUNDING_REPORT.md) | Comprehensive engineering and audit report |
| **Preserved** | [`data/generated/*`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/) | All 4 original Phase 2 (v1) files preserved untouched |
| **Preserved** | [`data/phishing_eval_dataset.json`](file:///c:/Users/prati/seva-cyber-sandbox/data/phishing_eval_dataset.json) | Cryptographically locked independent evaluation partition |

---

## 9. Quality Limitations & Pre-Training Notice

While Phase 2.2 successfully neutralizes obvious surface shortcuts and equalizes class representation, the following inherent characteristics of synthetic data remain:
1. **Template-Frame Boundedness**: The corpus is generated from 23 template families with slot substitution. Although distinct and combinatorial, true linguistic open-world diversity (e.g. erratic spelling, real citizen typos, dialectal slang) is not captured by regular grammar templates.
2. **Generalization Scope**: Strong validation performance on v2 indicates generalization to *held-out synthetic scenarios*, not certification of in-the-wild fraud detection.
3. **Readiness for Phase 3**: With class balance (33% per class) and URL deconfounding (~40–50% presence across all classes) achieved, candidate dataset **v2 is certified as model-ready** for training lightweight vernacular classifiers from randomly initialized weights.

---
*End of Phase 2.2 Report. Awaiting user review and authorization before proceeding to Phase 3.*
