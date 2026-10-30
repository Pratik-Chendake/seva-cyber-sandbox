# Seva Cyber Sandbox — Phase 2 Dataset Report
**Vernacular Dataset Expansion, Data Cleaning & Preprocessing**

*Date: October 29, 2026*  
*Project: Seva Cyber Sandbox — Malicious APK & Vernacular Phishing Detector*  
*Environment: Offline Python 3.14.8 Virtual Environment (Windows 11)*  
*Total Financial Expenditure: ₹0.00*

---

## Executive Summary

Phase 2 successfully designed and implemented an offline, deterministic vernacular dataset generator and quality preprocessing pipeline tailored for Maharashtra cyber-fraud scenarios. The system expands training and validation data across Marathi in Devanagari (`mr`), Romanized Marathi (`mr-Latn`), Indian English (`en`), and Mixed code-switched Marathi-English (`mr-en`), with strict campaign-level partitioning to ensure zero data leakage.

### Key Milestones Achieved
1. **Deterministic Offline Synthetic Generator** ([`scripts/generate_synthetic_corpus.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/generate_synthetic_corpus.py)):
   - Generated **485 total raw records** using seeded pseudo-random sampling over 19 distinct template families (10 training families, 9 validation families).
   - Produced **315 clean training records**, **120 clean validation records**, and **50 quarantined records** (ambiguous/needs review).
   - Achieved 100% reproducible output with fixed seeds and zero external network calls.
2. **Preprocessing & Quality Pipeline** ([`src/dataset_preprocessing.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/dataset_preprocessing.py)):
   - Unicode NFC canonical normalization.
   - Zero-width evasion character stripping (`[\u200b\u200c\u200d\u200e\u200f\ufeff]`).
   - Devanagari numeral translation to ASCII digits (`०-९` $\rightarrow$ `0-9`).
   - Preservation of unaltered input text in `text` alongside normalized representation in `normalized_text`.
   - Exact duplicate detection (found 0 exact duplicates).
   - Near-duplicate token-level Jaccard similarity warnings.
   - Automated routing of ambiguous and invalid submissions to quarantine.
3. **Strict Partitioning & Leak-Free Guarantee**:
   - Campaign families between training and validation are 100% disjoint:
     $$\text{Campaigns}_{\text{train}} \cap \text{Campaigns}_{\text{val}} = \emptyset$$
   - The original locked evaluation dataset ([`data/phishing_eval_dataset.json`](file:///c:/Users/prati/seva-cyber-sandbox/data/phishing_eval_dataset.json)) remains completely untouched.
   - Locked test manifest checksum verified: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`.
4. **Comprehensive Test Suite**:
   - 16 new automated unit tests ([`tests/test_dataset_preprocessing.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_dataset_preprocessing.py)) covering all 16 required test scenarios.
   - Total test suite expanded to **190 passing tests** (174 existing + 16 new Phase 2 tests), passing in 7.81s.

---

## 1. Corpus Architecture & Distribution

The generated corpora are persisted as JSON Lines (`.jsonl`) files in [`data/generated/`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/):
- **Training Corpus**: [`data/generated/synthetic_training_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/synthetic_training_corpus.jsonl) (315 records)
- **Validation Corpus**: [`data/generated/synthetic_validation_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/synthetic_validation_corpus.jsonl) (120 records)
- **Quarantine Records**: [`data/generated/quarantine_records.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/quarantine_records.jsonl) (50 records)
- **Quality Audit Report**: [`data/generated/synthetic_corpus_report.json`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/synthetic_corpus_report.json)

### Class Label Distribution (Clean Usable Set)
| Ground Truth Label | Training Count | Validation Count | Total Clean Count | Percentage |
| :--- | :--- | :--- | :--- | :--- |
| `phishing` | 245 | 90 | 335 | 77.0% |
| `protective_advisory` | 35 | 15 | 50 | 11.5% |
| `legitimate` | 35 | 15 | 50 | 11.5% |
| **Total Clean** | **315** | **120** | **435** | **100.0%** |
| *Quarantined (`ambiguous_needs_review`)* | *35* | *15* | *50* | *N/A (quarantined)* |

### Language & Script Distribution (Clean Usable Set)
| Language Code | Script | Training Count | Validation Count | Total Count |
| :--- | :--- | :--- | :--- | :--- |
| `mr` (Marathi) | Devanagari | 86 | 33 | 119 |
| `mr-Latn` (Romanized Marathi) | Latin | 84 | 31 | 115 |
| `en` (Indian English) | Latin | 81 | 30 | 111 |
| `mr-en` (Mixed Code-Switched) | Mixed | 64 | 26 | 90 |
| **Total** | | **315** | **120** | **435** |

### Scenario Breakdown (17 Scenarios Across 19 Families)
| Campaign ID | Scenario Category | Partition | Target Records | Clean Count |
| :--- | :--- | :--- | :--- | :--- |
| `syn_camp_msedcl_powercut_train` | `msedcl_powercut_threat` | Train | 35 | 35 |
| `syn_camp_bank_pan_kyc_train` | `bank_kyc_suspension` | Train | 35 | 35 |
| `syn_camp_upi_cashback_train` | `upi_cashback_lure` | Train | 35 | 35 |
| `syn_camp_ladki_bahin_train` | `govt_scheme_lure` | Train | 35 | 35 |
| `syn_camp_part_time_job_train` | `part_time_job_scam` | Train | 35 | 35 |
| `syn_camp_parcel_delivery_train` | `courier_parcel_delivery` | Train | 35 | 35 |
| `syn_camp_apk_update_train` | `apk_sideload_utility` | Train | 35 | 35 |
| `syn_camp_protective_advisories_train` | `official_safety_warning` | Train | 35 | 35 |
| `syn_camp_legitimate_receipts_train` | `genuine_receipt_transaction` | Train | 35 | 35 |
| `syn_camp_ambiguous_short_train` | `ambiguous_incomplete` | Train | 35 | 35 *(Quarantined)* |
| `syn_camp_msedcl_solar_val` | `msedcl_solar_subsidy` | Val | 15 | 15 |
| `syn_camp_credit_card_points_val` | `credit_card_rewards` | Val | 15 | 15 |
| `syn_camp_rto_echallan_val` | `rto_echallan_fine` | Val | 15 | 15 |
| `syn_camp_hotel_rating_task_val` | `hotel_rating_scam` | Val | 15 | 15 |
| `syn_camp_telecom_5g_sim_val` | `telecom_sim_block` | Val | 15 | 15 |
| `syn_camp_pm_mudra_loan_val` | `pm_mudra_loan_lure` | Val | 15 | 15 |
| `syn_camp_protective_advisories_val` | `rto_banking_advisory` | Val | 15 | 15 |
| `syn_camp_legitimate_appointments_val` | `genuine_appointment_booking` | Val | 15 | 15 |
| `syn_camp_ambiguous_forward_val` | `ambiguous_forward` | Val | 15 | 15 *(Quarantined)* |

---

## 2. Record Schema & Provenance Compliance

Every record in the generated dataset strictly adheres to the Seva Cyber Sandbox dataset contract:

```json
{
  "record_id": "syn_train_0001",
  "text": "महावितरण तातडीची नोटीस: मागील बिल थकीत असल्याने आज आज रात्री ९:३० वाजता वीज पुरवठा खंडित केला जाईल. कनेक्शन चालू ठेवण्यासाठी MSEDCL_Support_v3.apk डाउनलोड करा: http://bill-update.invalid किंवा संपर्क: 9800000001.",
  "normalized_text": "महावितरण तातडीची नोटीस: मागील बिल थकीत असल्याने आज आज रात्री 9:30 वाजता वीज पुरवठा खंडित केला जाईल. कनेक्शन चालू ठेवण्यासाठी MSEDCL_Support_v3.apk डाउनलोड करा: http://bill-update.invalid किंवा संपर्क: 9800000001.",
  "ground_truth_label": "phishing",
  "language": "mr",
  "script": "Devanagari",
  "provenance_category": "synthetic_test_case",
  "provenance_verification_status": "synthetic_fixture",
  "source_reference": "Seva Synthetic Corpus Generator v1.0",
  "license_info": "CC0 1.0 Public Domain / Synthetic Generated",
  "collection_date": "2026-10-29",
  "review_status": "reviewed",
  "campaign_id": "syn_camp_msedcl_powercut_train",
  "dataset_role": "development",
  "scenario_category": "msedcl_powercut_threat",
  "character_count": 217,
  "normalized_character_count": 217,
  "detected_script": "Devanagari"
}
```

### Privacy & Synthetic Realism Guarantees
- **No Real Personal Phone Numbers**: Uses reserved fictitious series (`9800000001`-`9800000005`, `022-55550111`, `1800-555-0199`) and verified official public helplines (`1930`, `1912`).
- **No Live Scam Domains**: Uses IETF reserved `.invalid` top-level domains (e.g., `bill-update.invalid`, `mahabill-support.invalid`), preventing accidental traffic to malicious infrastructure.
- **No Embedded Self-Identifying Labels**: Synthetic phishing lures emulate realistic deceptive framing without mentioning that they are scams or tests.

---

## 3. Preprocessing & Quality Verification Pipeline

The preprocessing module ([`src/dataset_preprocessing.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/dataset_preprocessing.py)) executes six sequential pipeline stages:

```
[Raw Records] 
     │
     ▼
[Stage 1: Schema & Format Validation] ──(Invalid)──> [Quarantine File]
     │
     ▼
[Stage 2: Label Filtering] ──(ambiguous_needs_review)──> [Quarantine File]
     │
     ▼
[Stage 3: Normalization & Evasion Cleaning] (NFC + strip zero-width + digit translation)
     │
     ▼
[Stage 4: Exact Duplicate Detection] (Hash set matching on normalized text)
     │
     ▼
[Stage 5: Near-Duplicate Similarity Analysis] (Token Jaccard index >= 0.85 alerts)
     │
     ▼
[Stage 6: Cross-Partition Leakage Verification] (Ensures disjoint campaign families)
     │
     ▼
[Clean Training & Validation Corpora]
```

---

## 4. Verification & Test Suite Results

### Automated Preprocessing Test Suite
The dedicated test module ([`tests/test_dataset_preprocessing.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_dataset_preprocessing.py)) implements 16 comprehensive test cases:

```powershell
.\venv\Scripts\python.exe -m pytest tests/test_dataset_preprocessing.py -v
```
**Results:**
- `test_01_generator_reproducibility_with_fixed_seed`: PASSED
- `test_02_different_seeds_produce_valid_schema_records`: PASSED
- `test_03_every_generated_record_passes_schema_validation`: PASSED
- `test_04_invalid_labels_rejected`: PASSED
- `test_05_unicode_and_marathi_text_survive_preprocessing`: PASSED
- `test_06_normalization_preserves_raw_text_separately`: PASSED
- `test_07_exact_duplicates_detected`: PASSED
- `test_08_near_duplicate_warnings_emitted_without_silently_dropping`: PASSED
- `test_09_zero_campaign_template_family_leakage`: PASSED
- `test_10_quarantined_records_excluded_from_usable_training_set`: PASSED
- `test_11_empty_and_malformed_inputs_produce_safe_errors`: PASSED
- `test_12_missing_provenance_identified`: PASSED
- `test_13_synthetic_examples_contain_no_real_pii`: PASSED
- `test_14_repeated_pipeline_runs_produce_consistent_results`: PASSED
- `test_15_original_evaluation_data_and_locked_manifest_untouched`: PASSED
- `test_16_locked_test_partition_integrity`: PASSED
**Summary:** 16 passed in 0.11s.

### Full Repository Regression Verification
```powershell
.\venv\Scripts\python.exe -m pytest -q
```
**Result:** **190 passed in 7.81s** (0 regressions, 0 skipped, 0 failures).

### Evaluation Harness Verification
```powershell
.\venv\Scripts\python.exe evaluation/evaluate_phishing.py
```
**Result:**
- Total evaluation records: 39 across 18 campaigns (dev=19, val=10, locked test=10).
- Locked test checksum: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` (100% match).
- Zero campaign overlap between evaluation partitions.

---

## 5. Beginner-Friendly PowerShell Reproduction Commands

To reproduce the Phase 2 dataset generation and verify all checks locally:

```powershell
# 1. Activate Virtual Environment
.\venv\Scripts\Activate.ps1

# 2. Run Corpus Generator (Deterministic Seed: 42)
.\venv\Scripts\python.exe scripts/generate_synthetic_corpus.py --seed 42

# 3. Run Preprocessing Unit Tests (16 Tests)
.\venv\Scripts\python.exe -m pytest tests/test_dataset_preprocessing.py -v

# 4. Run Entire Repository Test Suite (190 Tests)
.\venv\Scripts\python.exe -m pytest -q

# 5. Run Evaluation Harness (Verifies Locked Partition Integrity)
.\venv\Scripts\python.exe evaluation/evaluate_phishing.py
```

---

## 6. Phase Status & Next Step Handoff

Phase 2 is fully implemented, verified, tested, and documented.
- **₹0 budget preserved.**
- **Zero external network requests or dependencies introduced.**
- **No model weights downloaded or trained.**
- **Locked evaluation dataset and test manifest completely preserved.**

Per instructions, work halts here awaiting user review before beginning Phase 3.
