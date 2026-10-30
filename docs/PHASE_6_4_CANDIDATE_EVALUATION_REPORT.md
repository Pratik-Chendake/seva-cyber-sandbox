# Seva Cyber Sandbox — Phase 6.4: Automated Candidate Model Evaluation and Benchmark Gate Report

**Document Reference:** `docs/PHASE_6_4_CANDIDATE_EVALUATION_REPORT.md`  
**Execution Timestamp:** 2026-10-30T17:21:00+05:30  
**Target Project:** Seva Cyber Sandbox (`C:\Users\prati\seva-cyber-sandbox`)  
**Phase Objective:** Build an automated evaluation framework that compares experimental candidate neural-network models against the registered baseline model on identical validation data, calculates comprehensive metrics with Wilson confidence intervals, conducts subgroup and counterfactual robustness analysis, evaluates an objective benchmark gate, and guarantees complete production isolation.  
**Implementation Status:** COMPLETE  
**Final Test Verdict:** **PASS** (372/372 tests passing)  
**Evaluated Candidate Benchmark Gate Verdict:** **FAIL** (Demonstration candidate; objective failure on macro-F1 retention and false-positive tolerances)

---

## 1. Executive Summary

Phase 6.4 establishes an automated, local-only candidate evaluation pipeline and safety benchmark gate for experimental neural network classifiers. 

### Key Accomplishments
1. **Candidate & Dataset Provenance Audit:** Successfully verified candidate `candidate_custom_v1.0.0` (trained under `synthetic_only` policy from random seed 42) and active baseline model `custom-mlp-v1.1.0-preproc`.
2. **Strict Dataset & Partition Isolation:** Authorized validation corpus `data/generated/v2/synthetic_validation_corpus.jsonl` (135 records). Verified zero record overlap with the training corpus and complete isolation from the locked evaluation dataset. Cryptographic digest of the locked partition remains unchanged (`9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`).
3. **Artifact Integrity & Security Checks:** Enforced SHA-256 verification of weights, metadata, and manifests prior to model execution. Prohibited path traversal and loaded NumPy checkpoints with `allow_pickle=False`.
4. **Fair Comparative Evaluation:** Evaluated baseline and candidate on identical 135 validation samples with identical feature extraction (`CharacterNGramHasher`, 1024-d, 3-5 subwords) and preprocessing (`neural-preproc-v1.1.0`).
5. **Comprehensive Metrics & Statistical Uncertainty:** Calculated accuracy, macro precision, macro recall, macro-F1, balanced accuracy, weighted-F1, 3x3 confusion matrices, per-class metrics, safety metrics with raw denominators (e.g., `7/45`), and 95% Wilson score confidence intervals.
6. **Subgroup Analysis:** Broken down by language (`mr`, `mr-Latn`, `en`, `mr-en`), script (`Devanagari`, `Latin`, `Mixed`), and messaging mode (with URLs vs. without URLs).
7. **Counterfactual Robustness Testing:** Evaluated prediction stability against whitespace expansion, zero-width character evasion, Devanagari numeral translation, URL stripping, and URL insertion.
8. **Configurable Benchmark Gate:** Evaluated candidate against versioned safety policy `v1.0.0`. The gate deterministically rendered a **FAIL** verdict due to macro-F1 retention drop (-0.0211 vs allowed -0.0200) and elevated false positive rates, demonstrating that the gate operates objectively without rubber-stamping.
9. **Zero Production Interference:** Zero models activated, registered, or promoted. `models/active_model_config.json` and `models/model_registry.json` remain untouched. Production risk score delta = 0. Zero models retrained during this phase.

---

## 2. Models Under Evaluation

| Attribute | Registered Baseline Model | Experimental Candidate Model |
| :--- | :--- | :--- |
| **Model Version** | `custom-mlp-v1.1.0-preproc` | `candidate_custom_v1.0.0` |
| **Lifecycle State** | `approved_for_shadow` | `experimental` |
| **Checkpoint Directory** | `models/experimental_custom_v1` | `models/candidates/candidate_custom_v1.0.0` |
| **Operating Mode** | `shadow` (Non-authoritative) | Isolated candidate sandbox |
| **Production Authority** | `false` | `false` |
| **Weights SHA-256** | `d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20` | `5a1e50a1a9bde3355a1f48c9faa2a3ca14b6f04b9628266cb5d887f548d275ee` |
| **Metadata SHA-256** | `23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8` | `eae87e974763dad10fdbf48f802b331d0516dc35fc6b5aa1270b19a1cace3dbb` |
| **Manifest SHA-256** | N/A (Registry Entry) | `48de7e0a6eec088003bed5de3d72608fe9ebf4acbe7d531a489799761ce825d1` |
| **Architecture** | 3-Layer MLP (1024 -> 64 -> 32 -> 3) | 3-Layer MLP (1024 -> 64 -> 32 -> 3) |
| **Activation** | LeakyReLU ($\alpha = 0.01$) | LeakyReLU ($\alpha = 0.01$) |
| **Feature Extraction** | Hashed Char n-grams (3-5), 1024-d | Hashed Char n-grams (3-5), 1024-d |
| **Preprocessing Version** | `neural-preproc-v1.1.0` | `neural-preproc-v1.1.0` |
| **Training Policy** | Synthetic Seed Corpus v2 (50 epochs) | Synthetic Anchor Corpus (`synthetic_only`, 5 epochs) |
| **Weight Initialization** | Random He-normal / Xavier (Seed 42) | Random He-normal / Xavier (Seed 42) |

---

## 3. Dataset Provenance and Strict Isolation

### 3.1 Validation Dataset Identity
- **File:** `data/generated/v2/synthetic_validation_corpus.jsonl`
- **SHA-256 Checksum:** `77911f9db811de13c5e89f7f756cb13bbc73c4ad9c13c0d401a62287052cf777`
- **Total Validated Records:** 135
- **Class Balance:** Perfectly balanced:
  - Phishing: 45 records (33.33%)
  - Legitimate: 45 records (33.33%)
  - Protective Advisory: 45 records (33.33%)
- **Source Reference:** Seva Synthetic Corpus Generator v2.0 (Deconfounded)

### 3.2 Partition Isolation Guarantees
1. **Training / Validation Overlap Check:**
   - Evaluated candidate training set: `data/generated/v2/synthetic_training_corpus.jsonl` (360 records, SHA-256: `8871bf7ffec30cd486add55c1f860c4313e530d183f832281ddf2fbd9357f4b9`).
   - Overlap between validation IDs and training IDs: **0 records** (verified mathematically).
2. **Locked Evaluation Partition Protection:**
   - Manifest: `data/locked_test_manifest.json`
   - Locked partition SHA-256 digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`
   - Overlap between validation IDs and locked test records: **0 records**.
   - Code-level gate strictly forbids passing `phishing_eval_dataset.json` into validation routines.

---

## 4. Overall Comparative Benchmark Metrics

Both models were evaluated on the identical 135 validation samples using preprocessed character n-gram feature hashing (1024 dimensions).

| Metric | Registered Baseline (`custom-mlp-v1.1.0-preproc`) | Candidate Model (`candidate_custom_v1.0.0`) | Delta |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 0.9481 (128/135) [95% CI: 0.8968, 0.9747] | 0.9259 (125/135) [95% CI: 0.8690, 0.9593] | -0.0222 |
| **Macro-F1** | 0.9482 | 0.9271 | -0.0211 |
| **Macro Precision** | 0.9501 | 0.9394 | -0.0107 |
| **Macro Recall** | 0.9482 | 0.9259 | -0.0223 |
| **Balanced Accuracy** | 0.9481 | 0.9259 | -0.0222 |
| **Weighted-F1** | 0.9482 | 0.9271 | -0.0211 |
| **Total Incorrect** | 7/135 (5.19%) | 10/135 (7.41%) | +3 errors |

---

## 5. Confusion Matrices

### 5.1 Baseline Model (`custom-mlp-v1.1.0-preproc`)
```
Actual \ Predicted       Phishing    Legitimate    Protective Advisory    Total
Phishing                       44             1                      0       45
Legitimate                      5            40                      0       45
Protective Advisory             0             1                     44       45
Total                          49            42                     44      135
```

### 5.2 Candidate Model (`candidate_custom_v1.0.0`)
```
Actual \ Predicted       Phishing    Legitimate    Protective Advisory    Total
Phishing                       45             0                      0       45
Legitimate                      7            38                      0       45
Protective Advisory             3             0                     42       45
Total                          55            38                     42      135
```

---

## 6. Per-Class Performance Breakdown

### 6.1 Baseline Model
| Class | Support | TP | FP | FN | Precision (Raw) | Precision [95% CI] | Recall (Raw) | Recall [95% CI] | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing** | 45 | 44 | 5 | 1 | 0.8980 (44/49) | [0.7824, 0.9556] | 0.9778 (44/45) | [0.8843, 0.9961] | 0.9362 |
| **Legitimate** | 45 | 40 | 2 | 5 | 0.9524 (40/42) | [0.8421, 0.9872] | 0.8889 (40/45) | [0.7650, 0.9519] | 0.9195 |
| **Protective Advisory** | 45 | 44 | 0 | 1 | 1.0000 (44/44) | [0.9197, 1.0000] | 0.9778 (44/45) | [0.8843, 0.9961] | 0.9888 |

### 6.2 Candidate Model
| Class | Support | TP | FP | FN | Precision (Raw) | Precision [95% CI] | Recall (Raw) | Recall [95% CI] | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing** | 45 | 45 | 10 | 0 | 0.8182 (45/55) | [0.6974, 0.8989] | 1.0000 (45/45) | [0.9213, 1.0000] | 0.9000 |
| **Legitimate** | 45 | 38 | 0 | 7 | 1.0000 (38/38) | [0.9082, 1.0000] | 0.8444 (38/45) | [0.7122, 0.9228] | 0.9157 |
| **Protective Advisory** | 45 | 42 | 0 | 3 | 1.0000 (42/42) | [0.9163, 1.0000] | 0.9333 (42/45) | [0.8215, 0.9774] | 0.9655 |

---

## 7. Safety Metrics Analysis

Safety metrics monitor high-consequence failure modes: legitimate messages incorrectly flagged as phishing (causing citizen panic or loss of legitimate notices) and phishing messages slipping through as benign.

| Safety Metric | Baseline Model | Candidate Model | Delta |
| :--- | :--- | :--- | :--- |
| **Legitimate False-Positive Rate** | 0.1111 (5/45) [95% CI: 0.0481, 0.2350] | 0.1556 (7/45) [95% CI: 0.0776, 0.2878] | +0.0445 |
| **Protective-Advisory False-Positive Rate** | 0.0000 (0/45) [95% CI: 0.0000, 0.0787] | 0.0667 (3/45) [95% CI: 0.0226, 0.1793] | +0.0667 |
| **Phishing False-Negative Rate** | 0.0222 (1/45) [95% CI: 0.0039, 0.1157] | 0.0000 (0/45) [95% CI: 0.0000, 0.0787] | -0.0222 |
| **Prediction Distribution** | Phish: 49, Legit: 42, Adv: 44 | Phish: 55, Legit: 38, Adv: 42 | Skewed toward Phishing |

> [!NOTE]
> The candidate model achieves **100% recall on phishing messages (0 false negatives)**. However, this aggressive boundary comes at the cost of higher false positives on legitimate messages (7/45) and protective advisories (3/45).

---

## 8. Subgroup Analysis

> [!IMPORTANT]
> **SYNTHETIC BENCHMARK NOTICE:** All evaluated records originate from the deconfounded synthetic v2 corpus. Performance on synthetic subgroups provides structural diagnostics but does not constitute certified proof of real-world vernacular generalization.

### 8.1 Performance by Language
| Language | Samples (N) | Sample Sufficiency ($N \ge 15$) | Baseline Accuracy | Candidate Accuracy | Accuracy Delta |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **English (`en`)** | 37 | SUFFICIENT | 1.0000 (37/37) | 1.0000 (37/37) | 0.0000 |
| **Marathi (`mr`)** | 55 | SUFFICIENT | 0.9273 (51/55) | 0.8364 (46/55) | -0.0909 |
| **Romanized Marathi (`mr-Latn`)** | 20 | SUFFICIENT | 0.9000 (18/20) | 1.0000 (20/20) | +0.1000 |
| **Mixed Marathi-English (`mr-en`)** | 23 | SUFFICIENT | 0.9565 (22/23) | 0.9565 (22/23) | 0.0000 |

### 8.2 Performance by Script
| Script | Samples (N) | Sample Sufficiency ($N \ge 15$) | Baseline Accuracy | Candidate Accuracy | Accuracy Delta |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Latin** | 57 | SUFFICIENT | 0.9649 (55/57) | 1.0000 (57/57) | +0.0351 |
| **Devanagari** | 55 | SUFFICIENT | 0.9273 (51/55) | 0.8364 (46/55) | -0.0909 |
| **Mixed** | 23 | SUFFICIENT | 0.9565 (22/23) | 0.9565 (22/23) | 0.0000 |

### 8.3 Performance by Messaging Mode (URL Presence)
| Mode | Samples (N) | Sample Sufficiency ($N \ge 15$) | Baseline Accuracy | Candidate Accuracy | Accuracy Delta |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Messages with URLs** | 69 | SUFFICIENT | 0.9710 (67/69) | 0.9565 (66/69) | -0.0145 |
| **Messages without URLs** | 66 | SUFFICIENT | 0.9242 (61/66) | 0.8939 (59/66) | -0.0303 |

---

## 9. Counterfactual Robustness Testing

Counterfactual mutations evaluate whether benign cosmetic changes or evasive perturbations cause unintended model prediction flips.

| Robustness Scenario | Evaluated Samples (N) | Baseline Prediction Flips | Candidate Prediction Flips | Candidate Invariance |
| :--- | :---: | :---: | :---: | :---: |
| **Whitespace Invariance** (Leading/trailing/collapsed spaces) | 135 | 0 / 135 (0.0%) | 0 / 135 (0.0%) | **PERFECT (100%)** |
| **Zero-Width Character Evasion** (Obfuscation insertions) | 135 | 0 / 135 (0.0%) | 0 / 135 (0.0%) | **PERFECT (100%)** |
| **Devanagari Numeral Normalization** (ASCII $\leftrightarrow$ Devanagari) | 128 | 0 / 128 (0.0%) | 0 / 128 (0.0%) | **PERFECT (100%)** |
| **URL Stripping from Phishing** (Removing link from phish) | 19 | 1 / 19 (5.26%) | 0 / 19 (0.0%) | **PERFECT (100%)** |
| **URL Insertion into Legitimate** (Appending neutral link) | 28 | 3 / 28 (10.71%) | 3 / 28 (10.71%) | 89.29% |
| **Irrelevant URL Replacement** (Altering benign domain) | 69 | 7 / 69 (10.14%) | 12 / 69 (17.39%) | 82.61% |

---

## 10. Benchmark Gate Evaluation

The benchmark gate enforces objective criteria declared prior to evaluation.

### 10.1 Benchmark Policy Configuration (`v1.0.0`)
- `min_validation_samples`: $\ge 100$
- `min_class_samples`: $\ge 30$ per class
- `min_macro_f1`: $\ge 0.9000$
- `max_macro_f1_drop`: $\le 0.0200$ relative to baseline
- `max_legitimate_fp_rate`: $\le 0.1500$
- `max_protective_advisory_fp_rate`: $\le 0.0500$
- `max_phishing_fn_rate`: $\le 0.0500$
- `max_whitespace_flip_rate`: $= 0.0000$
- `max_zerowidth_flip_rate`: $= 0.0000$
- `max_numeral_flip_rate`: $= 0.0000$

### 10.2 Gate Checklist & Results
| Evaluation Check | Requirement | Observed Value | Status |
| :--- | :--- | :--- | :---: |
| **Total Validation Samples** | $\ge 100$ | 135 | **PASS** |
| **Class Sample Support** | $\ge 30$ each | Phishing: 45, Legit: 45, Adv: 45 | **PASS** |
| **Macro-F1 Absolute Floor** | $\ge 0.9000$ | 0.9271 | **PASS** |
| **Macro-F1 Baseline Retention** | Drop $\le 0.0200$ | Drop = 0.0211 (0.9482 $\rightarrow$ 0.9271) | **FAIL** |
| **Legitimate False-Positive Rate** | $\le 0.1500$ | 0.1556 (7/45) | **FAIL** |
| **Protective-Advisory False-Positive Rate**| $\le 0.0500$ | 0.0667 (3/45) | **FAIL** |
| **Phishing False-Negative Rate** | $\le 0.0500$ | 0.0000 (0/45) | **PASS** |
| **Whitespace Invariance** | Flip Rate $\le 0.0$ | 0.0000 | **PASS** |
| **Zero-Width Invariance** | Flip Rate $\le 0.0$ | 0.0000 | **PASS** |
| **Numeral Invariance** | Flip Rate $\le 0.0$ | 0.0000 | **PASS** |

### 10.3 Gate Verdict
# **VERDICT: FAIL**

**Failure Reasons:**
1. Candidate macro-F1 dropped by 0.0211 compared to baseline (exceeds allowed tolerance of 0.0200).
2. Legitimate false-positive rate (0.1556, 7/45) exceeds maximum safety threshold (0.1500).
3. Protective-advisory false-positive rate (0.0667, 3/45) exceeds maximum safety threshold (0.0500).

> [!CAUTION]
> **Safety Notice:** Candidate `candidate_custom_v1.0.0` was trained for only 5 demonstration epochs in Phase 6.3. The benchmark gate functioned correctly and refused to qualify an under-trained candidate. This model is **NOT eligible** for shadow deployment consideration.

---

## 11. Production Safety & Zero-Side-Effect Guarantees

Phase 6.4 strictly enforces that evaluation never alters operational state:
1. **Zero Model Promotion:** The candidate was not registered in `models/model_registry.json`.
2. **Zero Runtime Mutation:** `models/active_model_config.json` was not modified. Active model remains `custom-mlp-v1.1.0-preproc` in shadow mode.
3. **Zero Risk Score Delta:** `HybridDecisionEngine` was tested and verified to yield `production_score_difference == 0`.
4. **Zero Model Retraining:** No weights or hyperparameters were modified. Checkpoint timestamps and SHA-256 digests were verified before and after evaluation.
5. **Locked Partition Integrity:** Locked test manifest checksum was verified (`9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`).

---

## 12. Verification & Regression Suite

All 372 automated test cases pass cleanly across the repository.

```
pytest test run summary:
collected 372 items
372 passed in 22.81s (100%)
Exit code: 0
```

- New automated test file: `tests/test_phase6_4_candidate_evaluation.py` (24 test cases).
- Verification command: `python -m pytest tests/test_phase6_4_candidate_evaluation.py` (24 passed in 4.74s).

---

## 13. Limitations and Risk Disclosures

1. **Synthetic Data Constraint:** The benchmark relies on the synthetic v2 validation corpus (135 records). It cannot replace human field evaluations or live telemetry.
2. **Confidence Intervals and Sample Scale:** With $N=45$ per class, Wilson 95% intervals remain moderately wide (e.g., legitimate FP rate of 0.1556 has a confidence interval of [0.0776, 0.2878]). Large-scale operational claims cannot be made.
3. **Training Policy Impact:** Candidate `candidate_custom_v1.0.0` was produced via synthetic anchor data only (0 citizen feedback records). Its performance reflects early epoch optimization rather than feedback learning.

---

## 14. Next Phase Recommendations (Phase 6.5)

- **Phase 6.5: Offline Shadow Integration Gate & Multi-Epoch Candidate Trainer:**
  - Permit extended candidate training epochs (e.g. 30-50 epochs) with early stopping to allow candidate models to meet benchmark gate criteria.
  - Establish a formal human-signoff gate before any model may be added as an inactive or shadow entry in `models/model_registry.json`.

---

## 15. Final Signoff

# **PHASE 6.4 COMPLETE**
All requirements of Phase 6.4 have been implemented, tested, verified, and documented with zero budget, 100% local CPU execution, and complete production isolation.
