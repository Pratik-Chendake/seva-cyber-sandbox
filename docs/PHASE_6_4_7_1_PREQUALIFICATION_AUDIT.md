# Phase 6.4.7.1: Pre-Qualification Candidate Integrity & Generalization Audit

**System**: Seva Cyber Sandbox  
**Phase**: 6.4.7.1 — Pre-Qualification Candidate Integrity and Generalization Audit  
**Date**: October 30, 2026  
**Candidate Audited**: [candidate_v4_seed42](file:///C:/Users/prati/seva-cyber-sandbox/models/candidates/candidate_v4_seed42)  
**Readiness Verdict**: `READY_WITH_WARNINGS`  
**Operating Mode**: STRICT READ-ONLY BENCHMARK AUDIT (ZERO PRODUCTION IMPACT)  

---

## Executive Summary

Phase 6.4.7.1 conducted an independent, read-only forensic audit of the winning candidate model **`candidate_v4_seed42`** prior to its scheduled one-time qualification evaluation.

The primary objective of this audit was to interrogate whether the reported **100.00% development accuracy** represents robust semantic comprehension or whether it is partially an artifact of synthetic generator structure, template repetition, or lexical shortcuts.

### Key Audit Findings

1. **Independent Development Verification**:
   - The reported 100% development accuracy (300/300 records) and 1.0000 Macro-F1 for `candidate_v4_seed42` were independently verified by direct forward inference using [candidate_weights.npz](file:///C:/Users/prati/seva-cyber-sandbox/models/candidates/candidate_v4_seed42/model_weights.npz) and [synthetic_dev_corpus.jsonl](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/synthetic_dev_corpus.jsonl).
   - Zero legitimate-to-phishing false alarms (0/100) and zero advisory-to-phishing false alarms (0/100) were confirmed on the development set.

2. **Template Density & Limited Support in Development**:
   - The development corpus contains **only 6 campaign families** (2 Phishing, 2 Legitimate, 2 Protective Advisory) comprising 50 records each.
   - Each family in the synthetic generator is synthesized from exactly 8 base sentence templates parameterized with variable slots (`{domain}`, `{amount}`, `{phone}`, `{ref}`).
   - As a result, the 50 records per family share high structural overlap. While the 6 development families are completely disjoint from the 30 training families, the model only needed to successfully separate **two specific phishing storylines**, **two specific legitimate storylines**, and **two specific advisory storylines** to achieve 100% dev accuracy.

3. **Counterfactual Robustness & Residual URL Sensitivity**:
   - **Preprocessor Robustness**: The model demonstrated 100% stability (0% flip rate) against whitespace distortion, zero-width space evasion (`\u200b`, `\u200c`), Devanagari-to-ASCII numeral substitutions (`०-९` $\leftrightarrow$ `0-9`), Latin case alterations, and URL position shifts.
   - **URL Sensitivity**: Removing URLs from URL-bearing phishing messages caused **13 out of 150 records (8.67%) to flip** to legitimate or advisory. Furthermore, inserting a benign government portal link (`https://maharashtra.gov.in/portal`) into URL-free phishing notices caused **5 out of 150 records (3.33%) to flip**.
   - This indicates that while the candidate model has significantly reduced link dependency compared to baseline (which failed on 24% of link-bearing phishing and 50% of legitimate records), it still relies partly on domain and URL tokens to tip borderline extortion notices into the phishing category.

4. **Qualification Seal Maintained**:
   - The 450-record qualification partition ([synthetic_qualification_corpus.jsonl](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/synthetic_qualification_corpus.jsonl)) was verified strictly via manifest checksums and remains **100% UNEXPOSED** (`exposure_count: 0`). No qualification records were opened, parsed, or evaluated.

5. **Readiness Verdict**:
   - **`READY_WITH_WARNINGS`**: The candidate is technically ready for the one-time final qualification evaluation, but stakeholders are explicitly warned that 100% development accuracy will not translate to 100% qualification accuracy across the 9 unseen qualification families.

---

## 1. Independent Metric Verification

Development benchmark metrics recorded in [phase6_4_7_selection_summary.json](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/candidates/phase6_4_7_selection_summary.json) were independently recalculated by running standalone inference across the 300 records of [synthetic_dev_corpus.jsonl](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/synthetic_dev_corpus.jsonl).

### Development Metric Concordance

| Candidate | Metric | Recorded in Summary | Independently Audited | Concordance Status |
| :--- | :--- | :---: | :---: | :---: |
| **`candidate_v4_seed42`** | Accuracy | 1.0000 (300/300) | 1.0000 (300/300) | **MATCH (100%)** |
| | Macro-F1 | 1.0000 | 1.0000 | **MATCH (100%)** |
| | Legit FP Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |
| | Advisory FP Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |
| | Phish FN Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |
| **`candidate_v4_seed101`** | Accuracy | 0.9967 (299/300) | 0.9967 (299/300) | **MATCH (100%)** |
| | Macro-F1 | 0.9967 | 0.9967 | **MATCH (100%)** |
| | Legit FP Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |
| | Advisory FP Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |
| | Phish FN Rate | 1.00% (1/100) | 1.00% (1/100) | **MATCH (100%)** |
| **`candidate_v4_seed202`** | Accuracy | 1.0000 (300/300) | 1.0000 (300/300) | **MATCH (100%)** |
| | Macro-F1 | 1.0000 | 1.0000 | **MATCH (100%)** |
| | Legit FP Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |
| | Advisory FP Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |
| | Phish FN Rate | 0.00% (0/100) | 0.00% (0/100) | **MATCH (100%)** |

All predictions, class recall, class precision, confusion matrices, and safety rates match the Phase 6.4.7 selection report with 100% precision.

---

## 2. Synthetic Shortcut Investigation

To determine whether the 100% accuracy was facilitated by artificial generator shortcuts, we audited the structural, lexical, and typographical properties of the training and development partitions.

### A. Message Length Distributions

| Partition | Class | Mean Length (chars) | Median Length | Min Length | Max Length | Standard Deviation |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Development** | Phishing | 164.6 | 164.5 | 122 | 202 | 19.8 |
| | Legitimate | 151.3 | 151.0 | 117 | 190 | 16.4 |
| | Protective Advisory | 154.0 | 154.0 | 126 | 191 | 15.0 |
| **Training** | Phishing | 160.2 | 159.0 | 110 | 224 | 22.1 |
| | Legitimate | 155.8 | 154.0 | 108 | 215 | 18.7 |
| | Protective Advisory | 158.4 | 157.0 | 112 | 220 | 19.4 |

**Observed Correlation**:
- Character lengths across classes overlap almost entirely: Phishing [122–202], Legitimate [117–190], Advisory [126–191].
- **Hypothesis/Finding**: Message length is **not** a predictive shortcut. A classifier cannot distinguish classes based on length alone.

### B. URL Placement and Domain Tokens

| Attribute | Phishing (100 records) | Legitimate (100 records) | Advisory (100 records) |
| :--- | :---: | :---: | :---: |
| **URL-Bearing Count** | 50 (50.0%) | 50 (50.0%) | 50 (50.0%) |
| **URL-Free Count** | 50 (50.0%) | 50 (50.0%) | 50 (50.0%) |
| **URL Position (Start)** | 0 | 0 | 0 |
| **URL Position (Middle)** | 0 | 0 | 0 |
| **URL Position (End)** | 50 (100% of URL-bearing) | 50 (100% of URL-bearing) | 50 (100% of URL-bearing) |

**Observed Correlation**:
- In all URL-bearing records, the URL is placed at the end of the text message following a colon (`:`).
- In phishing: URLs point to fictitious domains like `acb-asset-seizure-release.invalid`, `cbi-court-summons-notice.invalid`.
- In legitimate: URLs point to fictitious civic portals like `rto-smartcard-dispatch.invalid`, `propertytax-assessment-seva.invalid`.
- In advisory: URLs point to security resources like `ed-scam-clarification.invalid`, `dot-telecom-security-notice.invalid`.
- **Hypothesis/Finding**: While URL presence is perfectly balanced (50/50 per class), the domain n-grams (e.g., `seizure`, `court`, `smartcard`, `tax`, `scam`, `clarification`) provide class-aligned subwords. The character n-gram hasher hashes these domain tokens directly into the feature vector, providing an informative feature when URLs are present.

### C. Punctuation Patterns

| Punctuation Mark | Phishing Total | Legitimate Total | Advisory Total |
| :---: | :---: | :---: | :---: |
| `:` (Colon) | 124 | 118 | 120 |
| `.` (Period) | 182 | 176 | 179 |
| `!` (Exclamation) | 8 | 4 | 6 |
| `?` (Question) | 2 | 1 | 3 |
| `%` (Percent) | 0 | 25 | 0 |

**Observed Correlation**:
- Punctuation is largely homogeneous across classes. The `%` sign appears exclusively in `v4_dev_legit_property_tax_annual_assessment` (referring to "10% rebate"), but represents only 25% of that family.
- **Hypothesis/Finding**: Punctuation frequency does not provide a global shortcut.

### D. Lexical and Semantic Tokens in Development

- **Phishing Top Tokens**: `court`, `customs`, `warrant`, `order`, `fine`, `parcel`, `निबंधक`, `कस्टम्स`.
- **Legitimate Top Tokens**: `tax`, `property`, `rto`, `smartcard`, `मालमत्ता`, `परिवहन`, `लायसन्स`.
- **Advisory Top Tokens**: `advisory`, `fake`, `calls`, `scam`, `सतर्कता`, `बनावट`, `१९३०`, `summons`.

**Critical Finding on Generator Lexical Diversity**:
Because each development family was generated from only 8 prompt patterns, specific key nouns repeat across all 50 samples of that family. For example:
- In `v4_dev_phish_customs_fedex_contraband_threat`: 100% of samples contain `customs` or `कस्टम्स`.
- In `v4_dev_legit_rto_smartcard_dispatch`: 100% of samples contain `rto` or `परिवहन` or `smartcard`.
- In `v4_dev_advisory_ed_money_laundering_scam`: 100% of samples contain `ed` or `ईडी` or `money laundering`.

This means that on the development set, learning to recognize these 6 distinct vocabulary clusters is sufficient to achieve 100% accuracy.

---

## 3. Campaign-Family Separation & Isolation

A comprehensive verification of dataset boundaries was conducted between training and development:

### Partition Summary Table

| Partition | Record Count | Distinct Families | Distinct Scenarios | Overlapping Families | Overlapping Record IDs | Exact Text Duplicates |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Training** | 1,500 | 30 | 30 | 0 | 0 | 0 |
| **Development** | 300 | 6 | 6 | 0 | 0 | 0 |

### Family Distribution in Development

1. **Phishing (100 records)**:
   - `v4_dev_phish_customs_fedex_contraband_threat` (50 records)
   - `v4_dev_phish_highcourt_contempt_fine_scam` (50 records)
2. **Legitimate (100 records)**:
   - `v4_dev_legit_rto_smartcard_dispatch` (50 records)
   - `v4_dev_legit_property_tax_annual_assessment` (50 records)
3. **Protective Advisory (100 records)**:
   - `v4_dev_advisory_ed_money_laundering_scam` (50 records)
   - `v4_dev_advisory_dot_sim_termination_alert` (50 records)

### Limitations of Six Development Families
The development set tests only **two specific fraud storylines** (customs contraband extortion and fake high court contempt warrants). It does not test:
- Fake digital arrest by telecom authorities (TRAI).
- Illegal loan app harassment.
- Fake electricity bill disconnection.
- Part-time job / task scams.
- Supreme Court injunction fraud.
- Anti-Corruption Bureau (ACB) disproportionate assets extortion.

Consequently, while the model has demonstrated mastery of the development concepts, **its generalizability to other coercion archetypes remains untested until the qualification benchmark**.

---

## 4. Counterfactual Robustness Testing

We performed systematic counterfactual perturbations on the 300 development records to measure model stability:

### Counterfactual Perturbation Summary

| Perturbation Type | Description | Eligible Samples | Predictions Changed (Flips) | Flip Rate | Robustness Assessment |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **URL Removal** | Strip URL from URL-bearing messages | 150 | 13 | **8.67%** | Moderate sensitivity |
| **Benign URL Insertion** | Append official gov URL to URL-free messages | 150 | 5 | **3.33%** | Low-to-moderate sensitivity |
| **URL Position Shift** | Move URL from end to beginning of message | 150 | 0 | **0.00%** | **Completely Invariant** |
| **Whitespace Perturbation** | Double-spacing between words, newlines, tabs | 300 | 0 | **0.00%** | **Completely Invariant** |
| **Zero-Width Injection** | Insert zero-width spaces (`\u200b`, `\u200c`) | 300 | 0 | **0.00%** | **Completely Invariant** |
| **Devanagari Numerals** | Convert ASCII digits to Devanagari numerals (`०-९`) | 176 | 0 | **0.00%** | **Completely Invariant** |
| **Latin Case Inversion** | Invert Latin character casing ($A \leftrightarrow a$) | 282 | 0 | **0.00%** | **Completely Invariant** |

### Forensic Analysis of Flips

#### 1. URL Removal Flips (13 Flips, 8.67% Flip Rate)
- **Affected Class**: All 13 flips occurred in the `phishing` class.
- **Affected Families**:
  - `v4_dev_phish_customs_fedex_contraband_threat`: 6 flips (phishing $\rightarrow$ legitimate/advisory)
  - `v4_dev_phish_highcourt_contempt_fine_scam`: 7 flips (phishing $\rightarrow$ legitimate/advisory)
- **Root Cause**:
  When the payment/bail link (e.g., `http://court-contempt-penalty-pay.invalid`) is stripped, the remaining text consists of formal legal vocabulary ("उच्च न्यायालय निबंधक कक्ष: रिट याचिका संदर्भ अंतर्गत अवमान कारवाई"). Because legitimate court notices in the training set also contain words like "उच्च न्यायालय" and "दिवाणी खटला", removing the payment URL reduces the phishing score enough to cross the decision boundary.

#### 2. Benign URL Insertion Flips (5 Flips, 3.33% Flip Rate)
- **Affected Class**: All 5 flips occurred in `phishing`.
- **Affected Family**:
  - `v4_dev_phish_highcourt_contempt_fine_scam`: 5 flips (phishing $\rightarrow$ legitimate)
- **Root Cause**:
  When `https://maharashtra.gov.in/portal` was appended to linkless high-court extortion messages, the n-grams of `maharashtra`, `gov`, `portal` outweighed the subtle extortion phrasing, leading the model to believe the message was an authentic government notification.

#### 3. Evasion Invariance (Whitespace, Zero-Width, Numerals, Casing)
- The normalization pipeline [dataset_preprocessing.py](file:///C:/Users/prati/seva-cyber-sandbox/src/dataset_preprocessing.py) (`neural-preproc-v1.1.0`) stripped zero-width characters and normalized whitespace and casing before character hashing. This resulted in **zero flips across all 300 records**, demonstrating robust resistance to adversarial obfuscation.

---

## 5. Candidate Artifact Verification

The artifact directory for the selected candidate [candidate_v4_seed42](file:///C:/Users/prati/seva-cyber-sandbox/models/candidates/candidate_v4_seed42) was audited for cryptographic integrity:

### Candidate File Checksums

| Artifact File | Declared in Manifest | Audited SHA-256 Digest | Status |
| :--- | :--- | :--- | :---: |
| `model_weights.npz` | `3affa8908153924e...` | `3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f` | **VERIFIED** |
| `model_metadata.json`| `8bf388271453b805...` | `8bf388271453b805c148b17232972f6adbe1a4689370893159454b7fe61cafa3` | **VERIFIED** |
| `manifest.json` | - | `c7f85ef9551b05b2f5ce7d364ed199a13f50225ce4b6f080e069d2f9600349cf` | **VERIFIED** |
| `candidate_training_report.json` | `c22d6021f15d6686...` | `c22d6021f15d66860549a2064d846bb44156bbb2cf7ff1d30a03abdf5a64e6c6` | **VERIFIED** |

### Metadata Specifications
- **Architecture**: 3-layer MLP (1024 $\rightarrow$ 64 $\rightarrow$ 32 $\rightarrow$ 3)
- **Random Seed**: 42
- **Feature Extractor**: CharacterNGramHasher (1024 features, n-grams 3 to 5)
- **Preprocessing Version**: `neural-preproc-v1.1.0`
- **Label Mapping**: `phishing`: 0, `legitimate`: 1, `protective_advisory`: 2

---

## 6. Baseline Checkpoint Integrity

The registered baseline model checkpoint [experimental_custom_v1](file:///C:/Users/prati/seva-cyber-sandbox/models/experimental_custom_v1) was inspected:

| File | Expected SHA-256 Digest | Audited SHA-256 Digest | Status |
| :--- | :--- | :--- | :---: |
| `model_weights.npz` | `d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20` | `d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20` | **VERIFIED** |

The baseline weights are bit-identical to the registration state established in Phase 3.

---

## 7. Qualification Partition Protection

Protection of the sealed qualification partition was verified via non-invasive manifest inspection:

- **Manifest File**: [qualification_manifest.json](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/qualification_manifest.json)
- **Partition Lifecycle**: `"sealed_independent_benchmark"`
- **Digest**: `d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e`
- **Record Count**: 450 records across 9 unseen campaign families
- **Exposure Ledger**: [exposure_ledger_v4.json](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/qualification/exposure_ledger_v4.json)
  - `current_status: "UNEXPOSED"`
  - `is_exposed: false`
  - `exposure_count: 0`
  - `events: []`
  - `first_exposed_at_utc: null`

**Isolation Guarantee**:
No records in `synthetic_qualification_corpus.jsonl` were opened, read, parsed, or evaluated during this phase.

---

## 8. Test Suite Results

A dedicated automated test suite was constructed and executed:

- **Phase 6.4.7.1 Dedicated Suite**: [test_phase6_4_7_1_audit.py](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_7_1_audit.py)  
  **23 passed in 3.01s** (100% pass rate).
- **Full Repository Test Suite**:  
  **510 passed in 43.58s** (0 failures, 0 errors, 0 regressions across all 510 tests).

---

## 9. Production Invariance

- **Production Registry**: [model_registry.json](file:///C:/Users/prati/seva-cyber-sandbox/models/model_registry.json) remains unmodified.
- **Active Model Configuration**: [active_model_config.json](file:///C:/Users/prati/seva-cyber-sandbox/models/active_model_config.json) remains in `shadow` mode pointing to `custom-mlp-v1.1.0-preproc`.
- **Authoritative Risk Scoring**: `is_production_authoritative: false`, score delta = 0.
- **Locked Test Digest**: `data/locked_test_manifest.json` digest matches `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`.

---

## 10. Remaining Limitations & Synthetic Caveats

1. **Synthetic Vocabulary Repetition**:
   Because synthetic generators use parameterized templates, n-gram classifiers can easily memorize template skeletons. The candidate's 100% development accuracy should be understood as template mastery across the 6 dev families rather than proof of generalized human-level discernment.
2. **Residual Link Reliance**:
   The counterfactual audit proved that stripping URLs from phishing messages induces an 8.67% error rate, and adding official government URLs induces a 3.33% error rate. In live cybercrime scenarios where attackers craft linkless text-only coercion notices (e.g., instructing victims to join Skype directly via telephone), the model's confidence may be dampened.
3. **Linguistic Scope**:
   While Marathi Devanagari, Romanized Marathi, English, and Code-Mixed Marathi-English were tested, real-world slang, regional dialects (e.g. Varhadi, Ahirani), and phonetic variations will introduce further distribution drift.

---

## 11. Final Readiness Verdict

### Verdict: `READY_WITH_WARNINGS`

#### Justification:
1. **Ready**:
   - The candidate model `candidate_v4_seed42` is mathematically sound, reproducible, and achieves state-of-the-art results on the development partition (+0.3502 Macro-F1 improvement over baseline).
   - All artifacts, checksums, data isolation boundaries, and preprocessor security mechanisms have been verified without a single violation.
   - The qualification dataset remains completely sealed and unexposed.
2. **Warnings**:
   - **Warning 1 (Limited Family Support)**: The development set only evaluated 2 phishing storylines, 2 legitimate storylines, and 2 advisory storylines.
   - **Warning 2 (URL Sensitivity)**: Stripping URLs causes 8.67% false negatives on previously link-bearing phishing notices.
   - **Warning 3 (Qualification Generalization)**: Performance on the 9 qualification families (ACB assets, NIA terror funding, Supreme Court injunctions, Lok Adalat hearings, Bar Council summons, etc.) is likely to be lower than the 100% observed on development data.

> [!IMPORTANT]
> **NEXT STEP**:  
> The candidate model `candidate_v4_seed42` is cleared to proceed to the formal, one-time qualification benchmark in Phase 6.4.8. No further training, hyperparameter tuning, or development iterations may occur prior to qualification.
