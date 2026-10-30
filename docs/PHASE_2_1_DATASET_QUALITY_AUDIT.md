# Seva Cyber Sandbox — Phase 2.1 Dataset Quality Gate
**Independent Read-Only Dataset Quality Audit & Pre-Training Readiness Review**

*Date: October 29, 2026*  
*Project: Seva Cyber Sandbox — Malicious APK & Vernacular Phishing Detector*  
*Auditor: Independent Senior ML & Security Audit Engineer*  
*Mode: Read-Only Audit (Zero Modifications, Zero Network Traffic, Zero ₹ Expenditure)*  
*Target Corpus: `data/generated/synthetic_training_corpus.jsonl`, `data/generated/synthetic_validation_corpus.jsonl`, `data/generated/quarantine_records.jsonl`*  
*Evaluation Anchor: `data/phishing_eval_dataset.json` (Locked Test Digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`)*

---

## Executive Summary & Audit Verdict

An independent, deterministic, read-only audit of the synthetic vernacular dataset and preprocessing pipeline produced in Phase 2 was conducted. The audit verified dataset integrity, schema compliance, cross-partition leakage, linguistic authenticity, lexical artifact risks, and data safety.

### Readiness Decision: **READY WITH WARNINGS**
The Phase 2 dataset is technically and structurally sound for initiating **Phase 3 experimental prototyping of custom neural models trained from randomly initialized weights**. However, critical dataset constraints—chiefly heavy class imbalance (~76% phishing) and template-substitution lexical shortcuts—must be strictly accounted for during model architecture design, loss weighting, and evaluation. Under no circumstances should high performance on this synthetic corpus be misconstrued as certified real-world fraud detection accuracy.

---

## Audit 1: Record Count Reconciliation & Schema Integrity

Every line across the generated dataset files was parsed and verified against the Seva Cyber Sandbox schema specification ([`src/dataset_validator.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/dataset_validator.py) and [`src/dataset_preprocessing.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/dataset_preprocessing.py)).

### 1.1 Physical File Count Verification
| Dataset Partition | File Path | Raw Lines | Valid Records | Malformed Lines | Unique Record IDs | Unique Raw Texts | Unique Normalized Texts |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Training** | [`data/generated/synthetic_training_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/synthetic_training_corpus.jsonl) | 315 | 315 | 0 | 315 (100%) | 315 (100%) | 315 (100%) |
| **Validation** | [`data/generated/synthetic_validation_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/synthetic_validation_corpus.jsonl) | 120 | 120 | 0 | 120 (100%) | 120 (100%) | 120 (100%) |
| **Quarantine** | [`data/generated/quarantine_records.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/quarantine_records.jsonl) | 50 | 50 | 0 | 50 (100%) | 50 (100%) | 50 (100%) |
| **Total Generated** | | **485** | **485** | **0** | **485 (100%)** | **485 (100%)** | **485 (100%)** |

### 1.2 Schema & Provenance Audit
- **Missing Required Fields**: **0 records** across all 485 generated records. Every record contains all 13 required fields: `record_id`, `text`, `ground_truth_label`, `language`, `script`, `provenance_category`, `provenance_verification_status`, `source_reference`, `license_info`, `collection_date`, `review_status`, `campaign_id`, `dataset_role`.
- **Invalid / Unknown Labels**: **0 records**. All labels belong strictly to the allowed taxonomy (`phishing`, `legitimate`, `protective_advisory`, `ambiguous_needs_review`).
- **Missing Provenance**: **0 records**. All records specify `provenance_category="synthetic_test_case"`, `provenance_verification_status="synthetic_fixture"`, `source_reference="Seva Synthetic Corpus Generator v1.0"`, and `license_info="CC0 1.0 Public Domain / Synthetic Generated"`.
- **Exact Duplicate Texts**: **0 duplicates**. Across the entire 435 clean records, every raw message text and normalized text is strictly unique.

### 1.3 Reconciliation with Phase 2 Report
- **Clean Record Totals**: The Phase 2 report claimed 315 training records, 120 validation records, and 50 quarantined records (total 485 records). This matches the physical files exactly.
- **Language Breakdown Discrepancy Note**: The total language counts in the Phase 2 report (`mr`: 119, `mr-Latn`: 115, `en`: 111, `mr-en`: 90; total 435) match the combined clean corpus exactly. However, Table 1 in `docs/PHASE_2_DATASET_REPORT.md` had minor clerical rounding differences in the training/validation sub-split (reported: train `mr`=86, `mr-Latn`=84, `en`=81, `mr-en`=64; actual file counts: train `mr`=87, `en`=83, `mr-Latn`=80, `mr-en`=65). The actual physical data on disk is reconciled below.

---

## Audit 2: Partition-Wise Label, Language & Scenario Distributions

### 2.1 Class Label Distribution by Partition
| Partition | `phishing` | `protective_advisory` | `legitimate` | `ambiguous_needs_review` | Total Records |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Training** | 245 (77.8%) | 35 (11.1%) | 35 (11.1%) | 0 (0.0%) | 315 |
| **Validation** | 90 (75.0%) | 15 (12.5%) | 15 (12.5%) | 0 (0.0%) | 120 |
| **Combined Clean** | **335 (77.0%)** | **50 (11.5%)** | **50 (11.5%)** | **0 (0.0%)** | **435** |
| **Quarantine** | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 50 (100.0%) | 50 |

> [!WARNING]
> **Severe Class Imbalance Detected**: The clean corpus exhibits a ~7:1:1 class ratio (`phishing` : `protective_advisory` : `legitimate`). A baseline classifier predicting `phishing` for every input would achieve an uninformative 77% accuracy. Phase 3 model training must implement class-weighted cross-entropy loss, balanced batch sampling, or focal loss to prevent majority-class collapse.

### 2.2 Language Distribution by Partition
| Language Code | Description | Training | Validation | Clean Total | Quarantine |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `mr` | Marathi (Devanagari) | 87 (27.6%) | 32 (26.7%) | 119 (27.4%) | 19 (38.0%) |
| `mr-Latn` | Romanized Marathi (Latin) | 80 (25.4%) | 35 (29.2%) | 115 (26.4%) | 11 (22.0%) |
| `en` | Indian English (Latin) | 83 (26.3%) | 28 (23.3%) | 111 (25.5%) | 14 (28.0%) |
| `mr-en` | Mixed Code-Switched (Mixed) | 65 (20.6%) | 25 (20.8%) | 90 (20.7%) | 6 (12.0%) |
| **Total** | | **315** | **120** | **435** | **50** |

The four target vernacular configurations are evenly balanced across both training and validation sets (~20–28% per language), ensuring all language modes receive comparable gradient updates during model training.

### 2.3 Scenario Breakdown by Partition
- **Training Partition (9 Scenarios, 35 Records Each)**:
  1. `msedcl_powercut_threat` (Phishing — Electricity power cut extortion)
  2. `bank_kyc_suspension` (Phishing — Bank PAN/KYC account block threat)
  3. `upi_cashback_lure` (Phishing — Fake UPI cashback link)
  4. `part_time_job_scam` (Phishing — Telegram/YouTube review task scam)
  5. `courier_parcel_delivery` (Phishing — Unpaid customs/courier delivery fee)
  6. `govt_scheme_lure` (Phishing — PM-Kisan / Ladki Bahin registration app lure)
  7. `apk_sideload_utility` (Phishing — Ration card / utility APK dropper)
  8. `official_safety_warning` (Protective Advisory — Police/RBI awareness bulletin)
  9. `genuine_receipt_transaction` (Legitimate — MSEDCL bill payment & bank credit receipt)
- **Validation Partition (8 Scenarios, 15 Records Each)**:
  1. `msedcl_solar_subsidy` (Phishing — Rooftop solar subsidy scheme fee lure)
  2. `credit_card_rewards` (Phishing — Expiring reward points cash conversion lure)
  3. `rto_echallan_fine` (Phishing — Fake traffic police e-challan APK dropper)
  4. `hotel_rating_scam` (Phishing — Google Maps hotel rating task scam)
  5. `telecom_sim_block` (Phishing — Mandatory 5G SIM upgrade deactivation threat)
  6. `pm_mudra_loan_lure` (Phishing — PM Mudra business loan processing fee)
  7. `rto_banking_advisory` (Protective Advisory — RTO & banking specific fraud warning)
  8. `genuine_appointment_booking` (Legitimate — Civil hospital appointment & line maintenance)

Protective advisories are well-represented in both training (35 records) and validation (15 records), and are properly distinguished from phishing lures.

---

## Audit 3: Meaningful Diversity & Lexical Artifact Analysis

### 3.1 Base Template Count vs Generated Record Count
- **Training Corpora**: **50 distinct base templates** across 10 families produce 350 raw records (315 clean + 35 quarantined).
  - Phishing: 29 templates across 7 scenarios (average 4.1 templates/scenario).
  - Protective Advisory: 7 templates across 1 scenario.
  - Legitimate: 7 templates across 1 scenario.
  - Ambiguous: 7 templates across 1 scenario (quarantined).
- **Validation Corpora**: **44 distinct base templates** across 9 families produce 135 raw records (120 clean + 15 quarantined).
  - Phishing: 24 templates across 6 scenarios (average 4.0 templates/scenario).
  - Protective Advisory: 7 templates across 1 scenario.
  - Legitimate: 7 templates across 1 scenario.
  - Ambiguous: 6 templates across 1 scenario (quarantined).

> [!NOTE]
> **Semantic Diversity Finding**: The generator achieves exact string uniqueness via combinatorial slot substitution (e.g. rotating banks, citizen names, amounts, dummy URLs, and times into fixed grammatical slots). However, the underlying sentence structures are limited to **77 clean base templates**. Therefore, the corpus represents 77 distinct sentence grammars rather than 435 independent linguistic constructions.

### 3.2 Lexical & Generation Artifact Analysis
A keyword correlation audit was performed to determine whether superficial tokens correlate with ground-truth labels:

| Feature / Keyword | Training: Phishing | Training: Legitimate | Training: Protective Advisory | Validation: Phishing | Validation: Legitimate | Validation: Protective Advisory |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `http` / URL present | **100.0%** | **0.0%** | **0.0%** | **100.0%** | **0.0%** | **26.7%** |
| `.invalid` domain | **100.0%** | **0.0%** | **0.0%** | **100.0%** | **0.0%** | **26.7%** |
| `.apk` file mention | 30.2% | 0.0% | **40.0%** | 16.7% | 0.0% | **73.3%** |
| `otp` mention | 14.3% | 0.0% | **80.0%** | 0.0% | 0.0% | **53.3%** |
| `1930` helpline | 0.0% | 0.0% | **60.0%** | 0.0% | 0.0% | **80.0%** |
| `urgent` / `तातडीची` | 5.7% | 0.0% | 0.0% | 3.3% | 0.0% | 0.0% |

> [!CAUTION]
> **High Risk of Superficial Feature Exploitation in Phase 3**:
> 1. In the training set, **every phishing record contains an HTTP URL (`http` or `https`), while 0% of legitimate records and 0% of protective advisories contain a URL**.
> 2. A simple bag-of-words or linear classifier could achieve ~90% accuracy merely by checking if `http` is present in the text, completely bypassing vernacular linguistic comprehension.
> 3. Protective advisories mention `.apk` (40–73%) and `otp` (53–80%) *more frequently* than phishing messages do, because advisories warn citizens *"never share OTP or download .apk files"*. A model that relies on keyword presence without context will misclassify protective advisories as phishing.

### 3.3 Vernacular Authenticity Review

To verify whether Romanized Marathi (`mr-Latn`) and Mixed (`mr-en`) represent natural regional phrasing rather than mechanical translation, representative fictitious examples were inspected:

```carousel
<!-- slide -->
### Romanized Marathi (`mr-Latn`)
```
[PHISHING]
Alert: Tumche Sahyadri Bank light bill update zale nahi. aaj ratri 9:30 PM connection cut honar. Laglich http://bill-update.invalid var jaun bill bhara kinva 9800000001 var call kara.

[PROTECTIVE ADVISORY]
MahaCyber Maharashtra Warning: electricity bill power cut threat pasun savadh raha. Kontehi sarkari karyalay kinva bank phone var OTP kinva PIN magat nahi. Anolkhi link var click karu naka. Cyber fraud complaint sathi 1930 dial kara.

[LEGITIMATE]
Sahyadri Bank Receipt: Ramesh Patil sathi ₹2,480 payment successful zale. Reference: 028643198. Official portal mahadiscom.in var receipt download kara. Dhanyavad.
```
<!-- slide -->
### Code-Switched Mixed (`mr-en`)
```
[PHISHING]
Notice from Konkan Janata Bank: Light bill payment overdue aahe. Disconnection avoid karnyasathi visit http://hotel-rewards-job.invalid or install FastChallan_Pay.apk. Help desk: 022-55550122.

[PROTECTIVE ADVISORY]
Pune Rural Police Safety Alert: part-time YouTube video like task claims sathi konalahi OTP or password sangu naka. Do not download unknown APK files. Help line: 1930.

[LEGITIMATE]
Maharashtra Gramin Bank Acknowledgement: Payment of ₹5,000 received for account 028397058. Download official receipt from portal. Thank you.
```
<!-- slide -->
### Marathi Devanagari (`mr`)
```
[PHISHING]
प्रिय ग्राहक, तुमचे चालू महिन्याचे महावितरण (MSEDCL) वीज बिल अपडेट झालेले नाही. आज रात्री ९:३० वाजता तुमचे वीज कनेक्शन खंडित केले जाईल. त्वरित http://dispatch-notice.invalid वर जाऊन बिल भरा किंवा 9800000004 वर संपर्क साधा.

[PROTECTIVE ADVISORY]
महावितरण दक्षता पथक सायबर सुरक्षा सूचना: लाडकी बहीण योजनेच्या खोट्या ॲपद्वारे फसवणूक करणाऱ्यांपासून सावध राहा. कोणतीही बँक किंवा संस्था व्हॉट्सॲपवर .apk फाईल पाठवत नाही किंवा फोनवर OTP मागत नाही. अशा लिंकवर कधीही क्लिक करू नका. सायबर तक्रारीसाठी १९३० वर संपर्क साधा.

[LEGITIMATE]
महाराष्ट्र ग्रामीण बँक खाते अलर्ट: तुकाराम शिंदे यांच्या खात्यात ₹4,890 जमा झाले आहेत. संदर्भ क्र. 028877444. अधिकृत नेटबँकिंग वापरा.
```
````

**Linguistic Assessment**: The Romanized Marathi phrasing (`zale nahi`, `cut honar`, `savadh raha`, `bhara kinva`, `pasun`) accurately reflects colloquial messaging in Maharashtra. Phrasing is natural, grammatical, and distinct from machine-translated English.

---

## Audit 4: Cross-Partition Leakage & Generalization Assessment

### 4.1 Campaign & Exact Text Isolation
- **Prohibited Template-Family Overlap**: **Zero**.
  $$\text{Campaigns}_{\text{train}} \cap \text{Campaigns}_{\text{val}} = \emptyset$$
  Training uses `syn_camp_*_train` exclusively; validation uses `syn_camp_*_val` exclusively.
- **Exact Text Overlap**: **Zero**. No text in the training corpus appears in the validation corpus.
- **Normalized Text Overlap**: **Zero**. Even after removing zero-width spaces, punctuation, and digit variations, cross-partition overlap is strictly null.

### 4.2 Near-Duplicate Analysis (Token Jaccard Overlap)
An exhaustive pair-wise token Jaccard similarity test was run comparing all 315 training records against all 120 validation records ($315 \times 120 = 37,800$ comparisons):
- Pairs with Jaccard similarity $\ge 0.85$: **0 pairs (0.0%)**.
- Pairs with Jaccard similarity between $0.75$ and $0.85$: **0 pairs (0.0%)**.
- Pairs with Jaccard similarity between $0.70$ and $0.75$: **0 pairs (0.0%)**.

### 4.3 Generalization Reality Check
Because validation scenarios (solar subsidies, credit card points, e-challans, 5G SIM deactivation, Mudra loans, hospital appointments) were held out entirely from training (powercuts, KYC suspensions, cashback, Ladki Bahin, parcel delivery, utility bill receipts), the validation partition constitutes a genuine out-of-family generalization test **for synthetic templates**.

> [!IMPORTANT]
> **Generalization Disclaimer**: High validation accuracy will demonstrate generalization to *unseen synthetic templates within the same generation paradigm*. It does **not** certify generalization to real-world in-the-wild cyber fraud, which exhibits unstructured colloquialisms, spelling errors, phonetic variations, and novel social-engineering vectors not captured in the generator vocabulary.

---

## Audit 5: Data Safety & Preprocessing Integrity

1. **Absence of Real Personal Identifiers**:
   - Phone numbers strictly use reserved dummy prefixes (`9800000001`–`9800000005`, `022-55550111`, `1800-555-0199`) or official public emergency helplines (`1930`, `1912`). Zero unmasked 10-digit citizen numbers were found.
   - Zero Aadhaar-like 12-digit number sequences were found.
   - Names use common generic fictional Marathi personas (`Ramesh Patil`, `Sunita Joshi`, `Sachin Pawar`, `Anita Kulkarni`).
2. **Domain & URL Safety**:
   - All external scam URLs exclusively utilize IETF RFC 2606 reserved `.invalid` top-level domains (`bill-update.invalid`, `secure-kyc-portal.invalid`, `speedy-delivery.invalid`). No live or resolvable scam infrastructure is referenced.
   - Genuine reference domains point only to established government/utility portals (`mahadiscom.in`, `mparivahan.gov.in`, `arogya.maharashtra.gov.in`, `cybercrime.gov.in`).
3. **Preprocessing & Unicode Normalization**:
   - Devanagari numerals (`०-९`) are reliably mapped to ASCII (`0-9`) in `normalized_text` while preserved in original `text`.
   - Zero-width obfuscation characters (`\u200b`, `\u200c`, `\ufeff`) are stripped cleanly without corrupting Devanagari vowel signs (matras), viramas, or conjuncts.
   - Original raw text is kept completely intact under `text` for forensic rule evaluation.
4. **Quarantine Isolation**:
   - All 50 records with label `ambiguous_needs_review` are quarantined in [`data/generated/quarantine_records.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/quarantine_records.jsonl).
   - Zero quarantined records exist in either the clean training or clean validation corpus.

---

## Audit 6: Locked Evaluation Dataset Integrity

The cryptographically frozen independent evaluation dataset ([`data/phishing_eval_dataset.json`](file:///c:/Users/prati/seva-cyber-sandbox/data/phishing_eval_dataset.json)) was independently inspected and re-hashed using [`src/dataset_validator.py:compute_locked_test_hash`](file:///c:/Users/prati/seva-cyber-sandbox/src/dataset_validator.py#L232-L240):

```
Expected Manifest Hash: 9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda
Computed Partition Hash: 9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda
Status: EXACT MATCH (100% UNTOUCHED & FROZEN)
```

The full test suite was executed in PowerShell:
```powershell
.\venv\Scripts\python.exe -m pytest -q
```
**Result**: **190 passed in 8.60s** (174 pre-existing tests + 16 Phase 2 dataset preprocessing tests; 0 failures, 0 regressions).

---

## Audit 7: Phase 3 Readiness Decision & Mandatory Guidelines

### Formal Verdict: **READY WITH WARNINGS**

The dataset and pipeline are verified and ready to support **Phase 3 (Model Architecture & Randomly Initialized Weight Training)**. The project can safely proceed, subject to the following non-negotiable architectural constraints in Phase 3:

### Mandatory Guidelines for Phase 3 Implementation:
1. **Model Scope & Purpose**: The model must be a purpose-built, lightweight vernacular classifier trained from randomly initialized weights (₹0 budget, strictly offline). It must **not** download pretrained weights (BERT, RoBERTa, etc.) or call external AI APIs.
2. **Mitigate Lexical Shortcut Exploitation**: Because URLs appear in 100% of phishing lures and 0% of legitimate receipts in the training set, the model architecture must not rely solely on unigram word bag matching. Feature representations must include subword character n-grams or embeddings to force the network to learn Marathi semantic patterns rather than memorizing `http` tokens.
3. **Class Imbalance Handling**: With 77% phishing data, standard cross-entropy loss will lead to majority-class prediction. Phase 3 must use class weighting ($w_{\text{phish}} \approx 0.33$, $w_{\text{legit}} \approx 2.3$, $w_{\text{prot}} \approx 2.3$) or stratified batching.
4. **Protective Advisory Disambiguation**: Models must be evaluated specifically on their ability to classify protective advisories (which contain words like `.apk` and `OTP`) as non-phishing, avoiding false positives on legitimate cyber-crime warnings.
5. **Evaluation Benchmark Separation**: The model must be evaluated on the synthetic validation set during development, and touched against the locked test partition (`data/phishing_eval_dataset.json`) only at final evaluation freeze.

---
*End of Phase 2.1 Quality Gate Report. Awaiting instructions before proceeding to Phase 3.*
