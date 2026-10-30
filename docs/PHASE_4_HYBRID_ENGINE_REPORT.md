# Seva Cyber Sandbox — Phase 4 Hybrid Decision Engine & Safety Guardrails Report
**Additive Hybrid Architecture, Multi-Mode Execution & Rigorous Safety Guardrails**

*Date: October 29, 2026*  
*Project: Seva Cyber Sandbox — Malicious APK & Vernacular Phishing Detector*  
*Environment: Offline Python 3.14.8 Virtual Environment (Windows 11)*  
*Total Financial Expenditure: ₹0.00*  
*Evaluated Checkpoint: `models/experimental_custom_v1/`*  
*Validation Corpus: `data/generated/v2/synthetic_validation_corpus.jsonl` (135 records)*  
*Locked Evaluation Anchor: `data/phishing_eval_dataset.json` (SHA-256 Digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`)*

---

## Executive Summary

Phase 4 introduces an additive hybrid decision engine ([`src/hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py)) and comprehensive safety guardrails for the Seva Cyber Sandbox. The engine fuses deterministic vernacular pattern rules, reviewed threat intelligence indicators, and the custom neural classifier (developed in Phase 3) into a single, cohesive, fail-closed architecture without compromising production reliability.

Key accomplishments in Phase 4:
1. **Rule Primacy & Production Score Invariance**: In the default `shadow` mode, production risk scores are determined strictly by deterministic rules and verified threat intelligence. Across all 135 validation samples, the production score delta between rule-based scoring and hybrid shadow scoring is **identically 0**. The experimental model cannot alter risk scores, warnings, or verdicts.
2. **Multi-Mode Execution**:
   - `shadow` (default): Authoritative deterministic rules with parallel, read-only diagnostic evaluation by the custom neural model.
   - `rules_only`: Completely disables model loading and inference for restricted or low-resource deployments.
   - `advisory`: Provides dual-perspective contextual explanations for human analysts without altering trusted production scores.
3. **Ten Comprehensive Safety Guardrails (GR-01 through GR-10)**: Strict boundaries guarantee that strong rule-based evidence is never suppressed, model predictions alone cannot confirm fraud, unreviewed intelligence leads remain non-scoring, protective advisories are preserved, and non-finite outputs trigger safe fallbacks.
4. **Resilient Safe Fallback**: Missing checkpoints, corrupted files, malformed metadata, or non-finite outputs (NaN/Inf) automatically trigger a safe fallback to deterministic rules with **100.0% reliability and zero system crashes**.
5. **Zero Data Retention**: Diagnostic telemetry stores non-sensitive metrics only (script type, length, token counts, SHA-256 digests). Raw message texts, uploaded files, and personal identifiers (PII) are never retained.
6. **Full Test Suite & Digest Integrity**: 16 new unit tests ([`tests/test_hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_hybrid_decision_engine.py)) were added, bringing the total repository test suite to **239 passing tests** (0 failures, 0 regressions). The locked evaluation partition SHA-256 digest remains strictly unchanged (`9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`).

---

## 1. Hybrid Architecture & Decision Flow

The hybrid engine coordinates three distinct evidence layers with explicit separation of authority:

```
                      CITIZEN INPUT MESSAGE (WhatsApp / SMS)
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
       [Layer 1: Deterministic Rules]    [Layer 2: Threat Intelligence]
       - Vernacular pattern matching     - Local SQLite indicator store
       - Protective negation checks      - Reviewed: Corroborating (+20 max)
       - Capability context suppression   - Unreviewed: Investigative lead only
                     │                               │
                     └───────────────┬───────────────┘
                                     ▼
                      [Authoritative Production Score]
                        (Heuristic severity: 0-100)
                                     │
         ┌───────────────────────────┴───────────────────────────┐
         │ Operating Mode: 'shadow' (Default)                    │
         ▼                                                       │
  [Layer 3: Experimental Custom Model]                           │
  - Character n-gram feature hashing (1024-dim)                  │
  - 3-Layer MLP from random initialization                       │
  - Diagnostic prediction & uncalibrated softmax                 │
         │                                                       │
         ▼                                                       │
  [Concordance Analysis]                                         │
  - Agreement / Disagreement detection                           │
  - Diagnostic explanation logging                               │
         │                                                       │
         ▼                                                       ▼
  [Decision Guardrails (GR-01 to GR-10)] ───────────────> [FINAL HYBRID DECISION]
  - Production score difference = 0                       - Final score: unchanged
  - Non-suppression of rule alerts                        - Risk badge: unchanged
  - Safe fallback on errors                               - Action verdict: unchanged
                                                          - Concordance & advisory telemetry
```

### 1.1 Layer Decomposition
- **Layer 1 (Deterministic Rules — Authoritative)**: Implemented in [`src/phishing_detector.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/phishing_detector.py) and [`src/risk_scorer.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/risk_scorer.py). Evaluates 7 threat categories across Marathi, Romanized Marathi, mixed vernacular, and English. Evaluates protective negations and single-utility context safeguards.
- **Layer 2 (Threat Intelligence — Corroborating)**: Implemented in [`src/case_repository.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/case_repository.py). Queries active, unexpired indicators (domains, URLs, phone HMACs). Strictly differentiates between *reviewed* indicators (which can add up to +20 corroborating risk points) and *unreviewed* leads (which are logged for analyst investigation but add 0 points).
- **Layer 3 (Custom Neural Classifier — Diagnostic)**: Implemented in [`src/custom_model.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/custom_model.py) and evaluated from [`models/experimental_custom_v1/`](file:///c:/Users/prati/seva-cyber-sandbox/models/experimental_custom_v1/). Runs locally on CPU without external dependencies. Evaluates subword morphological features without pretrained models.

---

## 2. Operating Modes & Configuration

The engine supports three mutually exclusive operating modes configured via the `HYBRID_ENGINE_MODE` environment variable or programmatically:

| Mode Name | Authoritative Decision Maker | Custom Model Activity | Production Score Change | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`shadow`** *(Default)* | Deterministic Rules + Reviewed Intel | Runs in parallel as diagnostic | **Strictly 0 (Invariant)** | Production deployment, continuous model telemetry & validation |
| **`rules_only`** | Deterministic Rules + Reviewed Intel | Completely disabled / bypassed | **Strictly 0 (Invariant)** | Minimal-footprint embedded environments, offline fallback |
| **`advisory`** | Deterministic Rules + Reviewed Intel | Proposes analyst advisory notes | **Strictly 0 (Invariant)** | Analyst workbench, assisted incident triaging |

### 2.1 Configuration Fail-Safe Logic
If `HYBRID_ENGINE_MODE` is unset, empty, or configured with an unknown value (e.g., `"autonomous"`, `"production_model"`, `"invalid"`), the engine automatically and conservatively falls back to `shadow` mode. Malformed configuration can never silently grant decision-making authority to the experimental neural model.

---

## 3. Decision Guardrails Specification

The engine enforces ten strict, automated guardrails:

| Guardrail ID | Guardrail Name | Enforcement Logic & Safety Guarantee |
| :--- | :--- | :--- |
| **GR-01** | **Rule Primacy & Score Invariance** | In `shadow` mode, `final_risk_score == production_score`. The model cannot alter the score by even 1 point. Score delta is verified to be 0. |
| **GR-02** | **Non-Suppression of Evidence** | If deterministic rules indicate high risk (`score >= 50` or high-severity indicators), a model prediction of `legitimate` or `protective_advisory` cannot suppress the alert or downgrade the score. |
| **GR-03** | **No Uncorroborated Fraud** | If deterministic rules find no scam indicators (`score < 20`, green) and no reviewed threat indicators match, a model prediction of `phishing` cannot establish confirmed fraud or turn the badge red. |
| **GR-04** | **Threat Intelligence Tiering** | Only `reviewed` threat indicators adjust risk scores (up to +20 pts). `unreviewed` or `provisional` indicators remain investigative leads and add 0 risk points. |
| **GR-05** | **Protective Advisory Grounding** | If rules detect protective negation phrasing (e.g., official police alert), a model phishing prediction cannot override it unless active attack indicators (e.g., an APK lure) are present. |
| **GR-06** | **No Keyword Overreaction** | Legitimate messages mentioning utility names (MSEDCL, SBI) or containing generic terms without coercive phrasing are preserved as safe via context safeguards. |
| **GR-07** | **Safe Checkpoint Fallback** | Missing checkpoint directories, corrupted weights archives, invalid metadata schemas, or non-finite outputs fail safe to rule-based evaluation without crashing. |
| **GR-08** | **Zero Raw Data Retention** | Diagnostic audit records contain non-sensitive metrics only: input length, script type, URL count, indicator count, and SHA-256 hash. Raw text and PII are never persisted. |
| **GR-09** | **Strict Score Bounds** | The final risk score is mathematically guaranteed to remain an integer strictly within $[0, 100]$. |
| **GR-10** | **Configuration Fail-Safe** | Any unparseable or unexpected operating mode value safely defaults to `shadow` mode. |

---

## 4. Integration Points & Files Modified

### 4.1 New Modules & Scripts
- [`src/hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py): Core hybrid decision engine, `SafeModelHolder` caching manager, `HybridOperatingMode` enum, guardrail evaluator, and `evaluate_message_hybrid` API.
- [`scripts/evaluate_hybrid_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/evaluate_hybrid_engine.py): Validation harness executing dual-mode evaluation across 135 synthetic records, computing concordance, FPRs, and verifying score invariance.
- [`tests/test_hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_hybrid_decision_engine.py): 16 unit tests covering all guardrails, operating modes, and failure modes.

### 4.2 Updated Modules
- [`src/custom_model.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/custom_model.py): Added `load_custom_model` top-level convenience helper and updated `predict_one` to accept an optional hasher parameter.
- [`app.py`](file:///c:/Users/prati/seva-cyber-sandbox/app.py): Added additive, non-disruptive expander in Tab 1 showing real-time hybrid diagnostics (operating mode, rule score, model prediction, concordance status, and active guardrails) without altering the user experience or saving raw text.

---

## 5. Empirical Evaluation Results (Synthetic Validation Partition)

The evaluation script ([`scripts/evaluate_hybrid_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/evaluate_hybrid_engine.py)) systematically evaluated all 135 records of [`data/generated/v2/synthetic_validation_corpus.jsonl`](file:///c:/Users/prati/seva-cyber-sandbox/data/generated/v2/synthetic_validation_corpus.jsonl).

### 5.1 Shadow Mode Score Invariance
- **Total Samples Evaluated**: 135
- **Maximum Observed Score Delta**: **0**
- **Records with Altered Score**: **0 (0.0%)**
- **Strict Invariance Guarantee**: **VERIFIED (True)**

### 5.2 Model-Rule Concordance
- **Agreements**: 51 / 135 (**37.78%**)
- **Disagreements**: 84 / 135 (**62.22%**)
- *Analysis*: In candidate corpus v2, the custom neural model exhibits superior sensitivity on short vernacular phrasing where keyword regex rules have not yet been explicitly tuned. In `shadow` mode, these disagreements provide rich diagnostic telemetry for future rule curation while ensuring 0 risk of production disruption.

### 5.3 False Positive Safety Rates

| Evidence Layer / Mode | Protective Advisory FPR (Advisory $\to$ Phishing) | Legitimate Message FPR (Legitimate $\to$ Phishing) |
| :--- | :--- | :--- |
| **Rule-Based Engine (Alone)** | 20.00% (9 / 45) | 8.89% (4 / 45) |
| **Custom Neural Model (Alone)** | **2.22% (1 / 45)** | 11.11% (5 / 45) |
| **Hybrid Engine (Shadow Mode)** | 20.00% (9 / 45)* | 8.89% (4 / 45)* |

*\*Note: In shadow mode, hybrid FPR strictly mirrors rule-based FPR by design, guaranteeing zero production deviation until Phase 5 calibration and threshold gating are authorized.*

### 5.4 Language-Wise Performance Breakdown

| Language Code | Language Description | Sample Count | Rule Accuracy | Model Accuracy | Concordance Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`mr`** | Pure Marathi (Devanagari) | 55 | 43.64% | 83.64% | 40.00% |
| **`mr-en`** | Mixed Marathi-English | 23 | 39.13% | 95.65% | 34.78% |
| **`mr-Latn`** | Romanized Marathi | 20 | 50.00% | 90.00% | 50.00% |
| **`en`** | English | 37 | 29.73% | 100.00% | 29.73% |

### 5.5 Resilient Fallback Verification
- Evaluated against 10 test records using a non-existent checkpoint path.
- **Successful Safe Fallbacks**: 10 / 10 (**100.0%**)
- **Crashes / Exceptions**: **0**
- **Fallback Reliability**: 100.0% fail-safe transition to rule-based evaluation.

---

## 6. Repository Integrity & Digest Verification

### 6.1 Locked Evaluation Partition Anchor
- **Locked Test Records**: 10 records across 8 segregated campaigns.
- **SHA-256 Digest**: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`
- **Integrity Status**: **STRICTLY VERIFIED & UNCHANGED**.

### 6.2 Full Test Suite Results
- Baseline (Phase 3 completion): 223 passing tests.
- Phase 4 Tests Added: 16 unit tests in [`tests/test_hybrid_decision_engine.py`](file:///c:/Users/prati/seva-cyber-sandbox/tests/test_hybrid_decision_engine.py).
- **Current Total Test Suite**: **239 passing tests in 8.97 seconds** (0 failures, 0 regressions).

### 6.3 Git Diff Stat Summary
```
 .gitignore                                     |  10 +-
 README.md                                      | 267 +++++++++-
 app.py                                         | 739 ++++++++++++++++++++++++-
 create_sample_apks.py                          | 254 ++++++++-
 sample_apks/Gram_Panchayat_Directory_Test.apk  | Bin 739 -> 739 bytes
 sample_apks/MSEDCL_Light_Bill_Update_Test.apk  | Bin 785 -> 785 bytes
 sample_apks/Real_Binary_AXML_Header_Sample.apk | Bin 492 -> 731 bytes
 sample_apks/Simple_Marathi_Calendar_Test.apk   | Bin 675 -> 675 bytes
 src/apk_analyzer.py                            | 449 ++++++++++++++--
 src/audio_alert.py                             |  18 +-
 src/ml_classifier.py                           |  49 +-
 src/phishing_detector.py                       |  64 ++-
 src/risk_scorer.py                             |  62 ++-
 tests/test_sandbox.py                          | 129 ++++-
 14 files changed, 1931 insertions(+), 110 deletions(-)
```

### 6.4 Git Status (Short)
All pre-existing user files, fixtures, presentations, and datasets remain preserved and uncommitted:
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
?? data/generated/
?? data/locked_test_manifest.json
?? data/official_sources.json
?? data/phishing_eval_dataset.json
?? docs/
?? evaluation/
?? models/
?? pytest.ini
?? sample_apks/Compiled_Binary_AXML_Tree_Sample.apk
?? screenshot_1_phishing.png.png
?? screenshot_2_safeguard.png.png
?? screenshot_3_apk.png.png
?? scripts/
?? src/case_manager.py
?? src/case_repository.py
?? src/custom_model.py
?? src/dataset_preprocessing.py
?? src/dataset_validator.py
?? src/hybrid_decision_engine.py
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
?? tests/test_custom_model.py
?? tests/test_dataset_deconfounding.py
?? tests/test_dataset_preprocessing.py
?? tests/test_dataset_provenance.py
?? tests/test_hybrid_decision_engine.py
?? tests/test_independent_apk_validation.py
?? tests/test_integration.py
?? tests/test_phishing_evaluation.py
?? tests/test_privacy_gate.py
?? tests/test_scheme_verifier.py
?? tests/test_threat_intelligence.py
?? tests/test_url_analyzer.py
?? tests/test_whatsapp_integration.py
```

---

## 7. Beginner-Friendly Reproduction Guide (PowerShell)

To independently test and verify the Phase 4 hybrid decision engine in an offline Windows PowerShell environment:

### Step 1: Run All Phase 4 Unit Tests
```powershell
.\venv\Scripts\python.exe -m pytest tests/test_hybrid_decision_engine.py -v
```
*Expected: 16 passed in <0.5s.*

### Step 2: Run Full Regression Test Suite
```powershell
.\venv\Scripts\python.exe -m pytest -q
```
*Expected: 239 passed in ~9-10s.*

### Step 3: Run Systematic Hybrid Engine Validation Evaluation
```powershell
.\venv\Scripts\python.exe scripts/evaluate_hybrid_engine.py
```
*Verifies shadow score invariance (max delta = 0), concordance metrics, and safe fallback behavior.*

### Step 4: Verify Locked Test Partition Integrity
```powershell
.\venv\Scripts\python.exe evaluation/evaluate_phishing.py
```
*Confirms locked test partition digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`.*

### Step 5: Test Python Interactive Hybrid Inference
```powershell
.\venv\Scripts\python.exe -c "from src.hybrid_decision_engine import evaluate_message_hybrid; res = evaluate_message_hybrid('तातडीने बिल भरा http://fake.in'); print('Mode:', res['operating_mode'], '| Score:', res['final_decision']['final_risk_score'], '| Concordance:', res['concordance']['status'])"
```

---

## 8. Completion Boundary & Phase 5 Readiness

- **Strict ₹0 Budget & Offline Operation**: Zero network calls, zero external AI APIs, zero cloud compute, and zero pretrained models were used.
- **No Background Learning**: No background retraining, automatic learning from user inputs, or autonomous model replacement has been implemented.
- **Safety Boundary**: The experimental custom neural model remains strictly advisory and diagnostic in `shadow` mode. It has not been granted authority to modify production risk scores or suppress deterministic alerts.
- **Phase 5 Prerequisites**: Any transition to calibrated hybrid decision scoring requires explicit review and approval in Phase 5.
