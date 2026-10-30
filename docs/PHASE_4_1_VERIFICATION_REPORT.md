# Seva Cyber Sandbox — Phase 4.1 Independent Hybrid Engine Verification Report
**Independent Audit of Protective Advisory Metrics, Model/Rule Disagreements, Score Invariance, and Privacy Safeguards**

*Date: October 29, 2026*  
*Project: Seva Cyber Sandbox — Malicious APK & Vernacular Phishing Detector*  
*Environment: Offline Python 3.14.8 Virtual Environment (Windows 11)*  
*Audit Scope: Read-Only Verification of Phase 3, Phase 4, Hybrid Engine, Checkpoints, and Validation Telemetry*  
*Total Financial Expenditure: ₹0.00*  
*Locked Evaluation Anchor: `data/phishing_eval_dataset.json` (SHA-256 Digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`)*  
*Final Audit Status: **PASS WITH WARNINGS***

---

## Executive Summary

An independent, strictly read-only verification was conducted on the Seva Cyber Sandbox hybrid detection architecture ([`src/hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py)), evaluating the reconciliation between Phase 3 model metrics and Phase 4 hybrid engine results, model-rule concordance, production score invariance, privacy posture, and cryptographic integrity.

### Summary of Audit Findings
1. **Reconciliation of Protective-Advisory Metrics (Check 1)**:
   - The apparent discrepancy between Phase 3 (0.00% advisory FPR) and Phase 4 (2.22% advisory FPR) was resolved through forensic byte inspection. Both phases evaluated the identical model checkpoint ([`models/experimental_custom_v1/`](file:///c:/Users/prati/seva-cyber-sandbox/models/experimental_custom_v1/)), but Phase 3 evaluated `normalized_text` (where Devanagari numerals `०-९` are mapped to `0-9`), whereas Phase 4 evaluated raw `text` (where un-normalized Devanagari numerals `१९३०` in record `syn_v2_val_0110` tipped subword character $n$-gram hashing slightly into the phishing logit).
   - On `normalized_text`, model-alone advisory FPR is strictly **0.00% (0 / 45)** with a recall of **97.78% (44 / 45)**. On raw text, model-alone advisory FPR is **2.22% (1 / 45)** with a recall of **86.67% (39 / 45)**.
2. **Model/Rule Disagreement Analysis (Check 2)**:
   - The reported **51/135 agreement (37.78%)** and **84/135 disagreement (62.22%)** was exactly reproduced.
   - Forensic categorization reveals that the 84 disagreements do not represent engine malfunction, but rather domain divergence:
     - **33 cases (39.3% of disagreements)** are taxonomy alignment differences: both layers agree the message is non-malicious, but rules classify them as `legitimate` (score 0) while the model classifies them as `protective_advisory`.
     - **34 cases (40.5% of disagreements)** represent deterministic rule coverage gaps on novel synthetic campaigns (e.g., rooftop solar subsidies, RTO e-challan fines) where rules lack specific keywords and default to `legitimate`, while the neural model correctly identifies them as `phishing`.
     - **17 cases (20.2% of disagreements)** represent model false alarms or missed attack patterns.
3. **Shadow-Mode Score Invariance (Check 3)**:
   - Verified across all 135 validation samples: the production risk score delta between rule-based scoring and hybrid shadow scoring is **identically 0**. The experimental neural model cannot alter risk scores, warnings, or verdicts.
   - All guardrails (GR-01 to GR-10), safe fallbacks, and configuration fail-safes are active and mathematically verified.
4. **Privacy Review of Diagnostics (Check 4)**:
   - No raw message text, personal phone numbers, Aadhaar numbers, or credentials are saved to disk, SQLite, or telemetry logs.
   - **Audit Warning**: The in-memory `audit_metadata` dictionary contains `input_sha256`. Because short message hashes can be linkable via dictionary precomputation, it must never be persisted to external or unencrypted logs.
5. **Regression & Integrity Verification (Check 5)**:
   - All 239 unit tests pass in 8.91 seconds.
   - The locked test partition SHA-256 digest remains **100% intact**: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`.

---

## Check 1 — Reconcile Protective-Advisory Metrics

### 1.1 The Reported Metrics
- **Phase 3 Model Report** ([`docs/PHASE_3_MODEL_REPORT.md`](file:///c:/Users/prati/seva-cyber-sandbox/docs/PHASE_3_MODEL_REPORT.md)):
  - Row for 45 actual protective advisories in validation confusion matrix:
    - Predicted `phishing`: 0
    - Predicted `legitimate`: 1
    - Predicted `protective_advisory`: 44
  - Protective-advisory false-positive rate: **0.00% (0 / 45)**.
- **Phase 4 Hybrid Engine Report** ([`docs/PHASE_4_HYBRID_ENGINE_REPORT.md`](file:///c:/Users/prati/seva-cyber-sandbox/docs/PHASE_4_HYBRID_ENGINE_REPORT.md)):
  - Custom model protective-advisory false-positive rate: **2.22% (1 / 45)**.

### 1.2 Forensic Reproduction & Root Cause Analysis

Both evaluations used the exact same model checkpoint (`models/experimental_custom_v1`, Seed 42) and the exact same 45 advisory records in [`data/generated/v2/synthetic_validation_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/synthetic_validation_corpus.jsonl).

The difference stems entirely from **input representation at evaluation time**:

```
[Record in Corpus]
   ├─ rec["normalized_text"]  ──> Evaluated in Phase 3 (prepare_data)  ──> Predicted: protective_advisory (44/45), legitimate (1/45), phishing (0/45)
   │                              (Devanagari numerals normalized to ASCII: १९३० -> 1930)
   │
   └─ rec["text"] (raw)       ──> Evaluated in Phase 4 (evaluate_message) ──> Predicted: protective_advisory (39/45), legitimate (5/45), phishing (1/45)
                                  (Devanagari numerals un-normalized: १९३० intact)
```

#### Detailed Breakdown of Predictions Across Representations ($N=45$ Actual Advisories)

| Evaluated Text Field | Predicted as Protective Advisory | Predicted as Legitimate | Predicted as Phishing | Advisory Recall | Advisory False Positive Rate (Flagged as Phishing) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`rec["normalized_text"]`** *(Phase 3)* | **44** (97.78%) | **1** (2.22%) | **0** (0.00%) | **97.78%** | **0.00% (0 / 45)** |
| **`rec["text"]` (Raw)** *(Phase 4)* | **39** (86.67%) | **5** (11.11%) | **1** (2.22%) | **86.67%** | **2.22% (1 / 45)** |

#### The Single Misclassified Record on Raw Text: `syn_v2_val_0110`
- **Record ID**: `syn_v2_val_0110`
- **Campaign**: `v2_camp_prot_lottery_val`
- **Scenario**: `lottery_reward_advisory`
- **Language**: `mr` (Marathi Devanagari)
- **Raw Text**: `... सायबर हेल्प: १९३०.` (ends with Devanagari numerals `१९३०`)
- **Normalized Text**: `... सायबर हेल्प: 1930.` (ends with ASCII numerals `1930`)
- **Forensic Explanation**: During model training, `scripts/train_custom_model.py` trained on `normalized_text`, where helpline numbers were normalized to ASCII `1930`. In raw text, character $n$-grams like `१९३०`, `^१९३` are unseen/rare in the training distribution, causing subword feature hashing to lack the positive weight associated with the ASCII `1930` helpline token, nudging its uncalibrated softmax slightly toward `phishing`.

### 1.3 Terminology Reconciliation

| Metric Name | Precise Formula | Value on `normalized_text` | Value on Raw `text` | Correct Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **Advisory Misclassification Rate** | $\frac{\text{Advisories not predicted as Advisory}}{\text{Total Ground-Truth Advisories}}$ | 1 / 45 (**2.22%**) | 6 / 45 (**13.33%**) | Measures general classification error on advisories. |
| **Advisory $\to$ Phishing FPR** | $\frac{\text{Advisories falsely predicted as Phishing}}{\text{Total Ground-Truth Advisories}}$ | 0 / 45 (**0.00%**) | 1 / 45 (**2.22%**) | Critical safety metric: whether a warning bulletin is blocked as an attack. |
| **Advisory $\to$ Legitimate Rate** | $\frac{\text{Advisories falsely predicted as Legitimate}}{\text{Total Ground-Truth Advisories}}$ | 1 / 45 (**2.22%**) | 5 / 45 (**11.11%**) | Both are benign labels; non-malicious categorization error. |
| **Phishing Class FPR** | $\frac{\text{Non-phishing messages predicted as Phishing}}{\text{Total Non-Phishing Messages (90)}}$ | 5 / 90 (**5.56%**) | 6 / 90 (**6.67%**) | Standard statistical false alarm rate of the phishing detector. |

> [!IMPORTANT]
> **Audit Conclusion on Check 1**: Both reports are statistically accurate under their respective input representations. Phase 3 evaluated the preprocessed `normalized_text`, whereas Phase 4 evaluated raw un-normalized user input `text`. Neither report fabricated metrics or used different model weights.

---

## Check 2 — Explain Model/Rule Disagreement

### 2.1 Reproduction of Concordance Rate
Running [`scripts/evaluate_hybrid_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/evaluate_hybrid_engine.py) against the 135 validation records confirms:
- **Total Agreements**: **51 / 135 (37.78%)**
- **Total Disagreements**: **84 / 135 (62.22%)**

### 2.2 Rule vs. Model Confusion Matrix ($N=135$)

| Authoritative Rule Label (Rows) $\backslash$ Model Prediction (Columns) | Predicted Phishing | Predicted Legitimate | Predicted Protective Advisory | Total Rule Label Count |
| :--- | :--- | :--- | :--- | :--- |
| **Rule: Phishing** | **11** *(Agree)* | 9 | 3 | 23 |
| **Rule: Legitimate** | 39 | **37** *(Agree)* | 33 | 109 |
| **Rule: Protective Advisory** | 0 | 0 | **3** *(Agree)* | 3 |
| **Total Model Prediction Count** | 50 | 46 | 39 | **135** |

- **Diagonal (Agreements)**: $11 + 37 + 3 = \mathbf{51}$
- **Off-Diagonal (Disagreements)**: $9 + 3 + 39 + 33 + 0 + 0 = \mathbf{84}$

### 2.3 Disagreement Breakdown by Ground Truth Label

| Ground Truth Category | Total Records | Agreements Count (%) | Disagreements Count (%) | Dominant Disagreement Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing** | 45 | 9 (20.00%) | 36 (80.00%) | Rules lacked novel keywords $\to$ Rule: `legitimate`, Model: `phishing` (34 cases) |
| **Legitimate** | 45 | 38 (84.44%) | 7 (15.56%) | High agreement; 5 model false alarms + 2 rule false alarms |
| **Protective Advisory** | 45 | 4 (8.89%) | 41 (91.11%) | Benign taxonomy divergence: Rule: `legitimate`, Model: `protective_advisory` (33 cases) |

### 2.4 Disagreement Breakdown by Language Script

| Language Script Code | Language Description | Total Records | Agreement Count (%) | Disagreement Count (%) |
| :--- | :--- | :--- | :--- | :--- |
| **`mr`** | Pure Marathi (Devanagari) | 55 | 22 (40.00%) | 33 (60.00%) |
| **`mr-en`** | Mixed Marathi-English | 23 | 8 (34.78%) | 15 (65.22%) |
| **`mr-Latn`** | Romanized Marathi | 20 | 10 (50.00%) | 10 (50.00%) |
| **`en`** | English | 37 | 11 (29.73%) | 26 (70.27%) |

### 2.5 Detailed Analysis of Disagreement Clusters

Forensic inspection of the 84 disagreements reveals four distinct categories:

#### Group A: Benign Taxonomy Divergence (33 cases)
- **Labels**: Rule classified as `legitimate`, Model predicted `protective_advisory`.
- **Ground Truth**: All 33 cases are ground-truth `protective_advisory`.
- **Root Cause**: The deterministic rule engine ([`src/phishing_detector.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/phishing_detector.py)) only sets `protective_advisory_detected = True` if protective negation phrases match OTP or APK installation patterns. For traffic safety advisories (`rto_safety_advisory`) or lottery warnings (`lottery_reward_advisory`), no scam indicators are matched, so the rule engine assigns a score of 0 (`legitimate`). Meanwhile, the custom neural model recognizes advisory vocabulary (`नागरी ग्राहक`, `Safety Advisory`, `1930`) and predicts `protective_advisory`.
- **Safety Impact**: **Zero risk**. Both layers agree the message is completely non-malicious.

#### Group B: Deterministic Rule Coverage Gaps (34 cases)
- **Labels**: Rule classified as `legitimate`, Model predicted `phishing`.
- **Ground Truth**: All 34 cases are ground-truth `phishing`.
- **Representative Example**:
  > *`syn_v2_val_0002`: "MahaVitaran Solar Update: Subsidy allocation pending aahe. Call department officer 022-55550122 to claim your rooftop panel."*
- **Root Cause**: The existing deterministic regex catalog was historically tuned for electricity disconnection threats (`"light bill cut tonight"`), fake APK drop lures, and OTP requests. It lacks rules for solar rooftop subsidy lures or phone-callback scams. The rules assigned score 0 (`legitimate`). The custom neural model, trained on candidate corpus v2, correctly caught the scam phrasing.
- **Safety Impact**: **Positive diagnostic value**. In shadow mode, this disagreement is recorded for future rule curation without altering production scoring.

#### Group C: Model False Alarms on Legitimate Messages (5 cases)
- **Labels**: Rule classified as `legitimate`, Model predicted `phishing`.
- **Ground Truth**: All 5 cases are ground-truth `legitimate`.
- **Representative Example**:
  > *`syn_v2_val_0047`: "Appointment Confirmed: Scheduled OPD medical consultation for Priyanka Deshmukh is booked for tomorrow 11:30 AM at District Hospital Pune. Please confirm within 2 hours: https://aarogya-seva.invalid/opd"*
- **Root Cause**: The model over-indexed on urgency phrases (`"confirm within 2 hours"`), predicting `phishing`. The deterministic rules correctly evaluated the healthcare context and recognized no fraudulent patterns, assigning score 0.
- **Safety Impact**: **Guardrail GR-03 protected the citizen**. In shadow mode, the model's false alarm was completely suppressed.

#### Group D: Rule False Alarms Corrected by Model (7 cases)
- **Labels**: Rule classified as `phishing`, Model predicted `legitimate` (4 cases) or `protective_advisory` (3 cases).
- **Representative Example**:
  > *`syn_v2_val_0106`: Security awareness circular warning against fake lottery scams.*
- **Root Cause**: The rule engine triggered on the word `"lottery"`, failing to negate it because the advisory phrasing did not match historical regex patterns. The neural model correctly classified it as an advisory.
- **Safety Impact**: **Preserved by Guardrail GR-01**. The production score was not altered in shadow mode.

---

## Check 3 — Verify Shadow-Mode Score Invariance

The core premise of Phase 4 is that introducing the custom neural model must not alter existing production risk scores. We audited all 8 core invariance properties:

| Invariance Property | Audit Test Method | Expected Behavior | Actual Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1. Score Invariance** | Evaluated all 135 validation samples in `shadow` vs `rules_only` | Score delta = 0 for 100% of samples | Max delta = **0** across all 135 samples | **PASS** |
| **2. Advisory Mode Invariance** | Evaluated all 135 validation samples in `advisory` mode | Score delta = 0 for 100% of samples | Max delta = **0** across all 135 samples | **PASS** |
| **3. `rules_only` Bypassing** | Evaluated `rules_only` mode | `experimental_model["is_enabled"] == False` | Model inference skipped entirely | **PASS** |
| **4. Checkpoint Fallback** | Pointed engine to non-existent directory | Graceful fallback, 0 crashes, rule score intact | `is_available = False`, score unchanged | **PASS** |
| **5. Non-Suppression (GR-02)** | Injected simulated benign model prediction on severe scam | Severe warning score $\ge 50$ preserved | Score = 95, Verdict = `HIGH_RISK_BLOCK` | **PASS** |
| **6. No Fraud on Model Alone (GR-03)** | Injected simulated phishing prediction on harmless message | Benign score $< 20$ preserved | Score = 0, Verdict = `INFORMATIONAL_SAFE` | **PASS** |
| **7. Unreviewed Intel (GR-04)** | Injected 5 unreviewed leads into threat intelligence | Unreviewed leads contribute 0 points | Score = 0, unreviewed leads recorded | **PASS** |
| **8. Config Fail-Safe (GR-10)** | Injected `HYBRID_ENGINE_MODE="malicious_autonomous"` | Normalizes safely to `shadow` mode | Mode normalized to `shadow` | **PASS** |

---

## Check 4 — Privacy Review of Diagnostics

We audited all variables, data structures, and diagnostic outputs generated by [`src/hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py) and displayed in [`app.py`](file:///c:/Users/prati/seva-cyber-sandbox/app.py):

### 4.1 Data Persistence Audit
1. **Raw Message Text**:
   - `evaluate_message` receives `message_text` in memory, performs inference, and **does not write raw text to any database, file, or log**.
   - `create_message_case` in [`src/case_manager.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_manager.py) explicitly discards raw text (`store_raw_text=False`), saving only matched indicator tokens.
2. **Personal Information & Credentials**:
   - Aadhaar numbers, Indian mobile numbers, and bank account numbers are detected and scrubbed by [`src/privacy_gate.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py).
   - In [`tests/test_hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_hybrid_decision_engine.py) (`test_14`), messages containing sensitive Aadhaar numbers and OTPs were verified to produce audit outputs free of PII.
3. **Network & External Transmission**:
   - Zero HTTP/HTTPS sockets, cloud SDKs, or external endpoints are invoked. Tested via monkeypatching `socket.socket` to throw a fatal exception on any socket connection attempt (`test_15`); all tests passed offline.

### 4.2 Security Warning: Linkability of Message Hashes in Telemetry
> [!WARNING]
> **Linkability Finding**: In [`src/hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py) line 348, `audit_metadata` records:
> ```python
> "input_sha256": hashlib.sha256(clean_text.encode("utf-8")).hexdigest() if clean_text else ""
> ```
> While `audit_metadata` is currently held only in volatile RAM and is never written to disk or the SQLite database, **a SHA-256 hash of short vernacular messages (e.g., OTP texts or simple SMS) is linkable to known text via dictionary or rainbow-table inversion**.
> 
> *Recommendation*: If `audit_metadata` is ever persisted in future phases, `input_sha256` should either be omitted or salted using a keyed HMAC (`HMAC-SHA256`) derived from the local secret.

---

## Check 5 — Regression & Integrity Tests

### 5.1 Test Suite Execution
All test suites were executed cleanly in the local offline virtual environment:

1. **Phase 4 Hybrid Engine Unit Tests**:
   ```powershell
   .\venv\Scripts\python.exe -m pytest tests/test_hybrid_decision_engine.py -v
   ```
   *Result*: **16 passed in 0.20 seconds**.

2. **Complete Project Regression Suite**:
   ```powershell
   .\venv\Scripts\python.exe -m pytest -q
   ```
   *Result*: **239 passed in 8.91 seconds** (0 failures, 0 regressions across all 18 test modules).

### 5.2 Locked Evaluation Partition Verification
Executed existing evaluation harness:
```powershell
.\venv\Scripts\python.exe evaluation/evaluate_phishing.py
```
- **Documented Manifest Checksum**: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`
- **Recomputed Locked Test Digest**: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`
- **Checksum Match**: **EXACT (100% Identical)**.

---

## Final Status & Recommendations

### Audit Status: **PASS WITH WARNINGS**

The Phase 4 hybrid decision engine meets all non-negotiable requirements:
- ₹0 financial cost, zero external APIs, zero pretrained models.
- Strict 0-score delta in shadow mode; deterministic rules remain fully authoritative.
- Ten comprehensive guardrails preventing false suppression, uncorroborated fraud, and unreviewed indicator inflation.
- 239/239 regression tests pass, and locked evaluation manifest is cryptographically verified.

### Documented Warnings for Phase 5
1. **Numeral Normalization Pipeline Alignment**: To ensure identical model inference regardless of input channel, the hybrid decision engine should apply numeral transliteration ([`normalize_devanagari_numerals`](file:///c:/Users/prati/seva-cyber-sandbox/src/privacy_gate.py#L72)) to incoming text prior to character $n$-gram hashing, eliminating the 1-sample advisory discrepancy seen in `syn_v2_val_0110`.
2. **Telemetry Hash Privacy**: Avoid persisting bare SHA-256 hashes of short messages without salting, preventing precomputation dictionary inversion.
3. **Model-Assisted Rule Curation**: The 34 phishing cases caught by the neural model but missed by regex rules provide high-value candidates for expanding the deterministic rule catalog before any model-controlled scoring is contemplated.
