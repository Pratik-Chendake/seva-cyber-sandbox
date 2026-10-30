# Seva Cyber Sandbox — Phase 6.4.3: Controlled Multi-Seed Candidate Training Report

**Document Reference:** `docs/PHASE_6_4_3_CONTROLLED_TRAINING_REPORT.md`  
**Execution Timestamp:** 2026-10-30T18:15:00+05:30  
**Target Project:** Seva Cyber Sandbox (`C:\Users\prati\seva-cyber-sandbox`)  
**Phase Objective:** Execute multi-seed controlled training of the custom neural classifier using the fresh v3 synthetic training corpus (`data/generated/v3/synthetic_training_corpus.jsonl`, 1,200 records), using the development partition (`data/generated/v3/synthetic_dev_corpus.jsonl`, 300 records) strictly for early stopping and model selection (zero gradient updates), holding the final qualification partition (`data/generated/v3/synthetic_qualification_corpus.jsonl`, 450 records) completely sealed and inaccessible, and applying a deterministic candidate selection policy.  
**Implementation Status:** COMPLETE  
**Repository Test Suite:** **413/413 passing tests** (`python -m pytest`, 100% pass rate in 24.73s)  
**Phase Test Suite:** **21/21 passing tests** (`tests/test_phase6_4_3_controlled_training.py` in 0.74s)  
**Locked Evaluation Partition Digest:** `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` (VERIFIED UNCHANGED)  
**Selected Candidate Winner:** `candidate_v3_seed202` (Macro-F1: 0.9599, Accuracy: 0.9600, Advisory FP Rate: 0.0000, Phishing FN Rate: 0.0000, Legit FP Rate: 0.1200)  
**Production Scoring Invariance:** Score delta = 0 (Authoritative rule primacy preserved, registry and active configuration untouched)

---

## 1. Executive Summary

Phase 6.4.3 operationalizes the findings from the Phase 6.4.1 forensic failure analysis and leverages the clean, leak-free Synthetic Dataset v3 produced in Phase 6.4.2. In previous phases, candidate models suffered from catastrophic false positives on legitimate messages and protective advisories due to shortcut learning on URL presence, token frequency artifacts, and lack of regularization.

To solve this, Phase 6.4.3 implements an offline, autonomous, multi-seed training pipeline with the following rigorous controls:

1. **Controlled Multi-Seed Training Across 3 Random Seeds:**
   - Independent runs initialized from scratch using random He-normal / Xavier-uniform distributions with seeds **42**, **101**, and **202**.
   - Zero initialization from production checkpoints or pretrained embeddings.
2. **Strict Development Partition Isolation (Zero Gradient Updates):**
   - The 300-record development partition (`synthetic_dev_corpus.jsonl`) is used exclusively for early stopping, learning rate monitoring, and candidate comparison.
   - Forward pass in eval mode only (`training=False`); no backpropagation cache or gradient updates are ever computed on development data.
3. **Qualification Partition Sealed & Inaccessible:**
   - The 450-record qualification benchmark (`synthetic_qualification_corpus.jsonl`) remained strictly inaccessible throughout the entire phase. Path guards reject any invocation referencing qualification data.
4. **Enhanced Regularization & Early Stopping:**
   - Weight decay ($L_2$) increased to $0.0005$ (suppressing single token dominance).
   - Dropout rate maintained at $0.20$.
   - Batch size increased to 32 (smoother gradient estimates across 1,200 training examples).
   - Early stopping with patience of 10 epochs monitoring development Macro-F1, restoring the best checkpoint parameters.
5. **Deterministic Candidate Selection:**
   - All 3 seeds dramatically outperformed the baseline model (`custom-mlp-v1.1.0-preproc`), which achieved only 0.7384 Macro-F1 with a 35% legitimate false positive rate.
   - All 3 seeds passed all safety and performance benchmark gates.
   - **`candidate_v3_seed202`** won selection with **0.9599 development Macro-F1**, **0.9600 accuracy**, **0.0000 advisory false positives**, and **0.0000 phishing false negatives**.

```mermaid
flowchart TD
    subgraph Data["Dataset Governance (v3.0.0)"]
        TR["Training Partition (1,200 records)<br>SHA-256: f8143880..."]
        DEV["Development Partition (300 records)<br>SHA-256: 55e9357a..."]
        QUAL["Qualification Partition (450 records)<br>SHA-256: 197c62e7...<br>SEALED & INACCESSIBLE"]
    end

    subgraph Pipeline["Multi-Seed Training Controller"]
        TR -->|Gradient Updates| S42["Seed 42<br>(MLP 1024-64-32-3)"]
        TR -->|Gradient Updates| S101["Seed 101<br>(MLP 1024-64-32-3)"]
        TR -->|Gradient Updates| S202["Seed 202<br>(MLP 1024-64-32-3)"]
        
        DEV -.->|Eval Only / Early Stopping| S42
        DEV -.->|Eval Only / Early Stopping| S101
        DEV -.->|Eval Only / Early Stopping| S202
    end

    subgraph Evaluation["Benchmark Gate & Selection Policy"]
        BASE["Baseline Model<br>custom-mlp-v1.1.0-preproc<br>Macro-F1: 0.7384 | FP: 0.3500"]
        S42 --> C42["Candidate v3 Seed 42<br>Macro-F1: 0.9565 | FP: 0.1300"]
        S101 --> C101["Candidate v3 Seed 101<br>Macro-F1: 0.9499 | FP: 0.1200"]
        S202 --> C202["Candidate v3 Seed 202<br>Macro-F1: 0.9599 | FP: 0.1200"]
        
        BASE -.-> GATE{"Deterministic Gate Policy<br>Macro-F1 >= 0.9000<br>Legit FP <= 0.1500<br>Advisory FP <= 0.0500<br>Phish FN <= 0.0500"}
        C42 --> GATE
        C101 --> GATE
        C202 --> GATE
        
        GATE -->|WINNER (Rank 1)| WIN["candidate_v3_seed202<br>Selected for Phase 6.4.4 Qualification"]
    end
```

---

## 2. Training Architecture & Hyperparameters

The candidate models were trained strictly using NumPy on local CPU with zero cloud dependencies or paid APIs.

### 2.1 Neural Architecture Specification
- **Model Type:** 3-layer Feed-Forward Multi-Layer Perceptron (MLP) over deterministic character n-gram feature hashing.
- **Input Dimension:** $D = 1024$ hashed character subwords ($n \in [3, 5]$) with independent sign hashing and $L_2$ normalization.
- **Input Preprocessing:** Canonical `neural-preproc-v1.1.0` (NFC Unicode composition, zero-width evasion stripping, Devanagari numeral ASCII translation, and whitespace collapse).
- **Hidden Layer 1:** 64 units, LeakyReLU activation ($\alpha = 0.01$), Dropout ($p = 0.20$), He-normal random initialization.
- **Hidden Layer 2:** 32 units, LeakyReLU activation ($\alpha = 0.01$), Dropout ($p = 0.20$), He-normal random initialization.
- **Output Layer:** 3 units (Softmax), Xavier-uniform random initialization.
- **Output Taxonomy:**
  - Index 0: `phishing`
  - Index 1: `legitimate`
  - Index 2: `protective_advisory`

### 2.2 Hyperparameter Configuration
| Parameter | Value | Rationale |
| :--- | :---: | :--- |
| **Random Seeds** | `[42, 101, 202]` | Investigates optimization landscape and initialization sensitivity |
| **Max Epochs** | `50` | Upper limit for convergence |
| **Early Stopping Patience** | `10 epochs` | Prevents overfitting; restores parameters from best development epoch |
| **Monitored Metric** | `dev_macro_f1` | Balanced objective across all three vernacular classes |
| **Batch Size** | `32` | $37.5$ mini-batches per epoch on 1,200 training examples (smooth gradients) |
| **Initial Learning Rate** | `0.005` | Fast initial exploration with Adam optimizer |
| **LR Schedule** | Step decay | Epoch 1–20: $0.005$; Epoch 21–35: $0.002$; Epoch 36–50: $0.001$ |
| **Weight Decay ($L_2$)** | `0.0005` | Penalizes large weights, preventing single token n-gram overfitting |
| **Dropout Rate** | `0.20` | Encourages distributed feature representations across 1024 hashing buckets |
| **Loss Function** | Categorical Cross-Entropy | Numerically stable with Softmax clipping ($\epsilon = 10^{-9}$) |
| **Optimizer** | Adam | $\beta_1 = 0.9, \beta_2 = 0.999, \epsilon = 10^{-8}$ implemented in pure NumPy |

---

## 3. Dataset Provenance & Partition Isolation Verification

Before executing any training routines, the experiment controller (`scripts/run_phase6_4_3_experiments.py`) conducted a mandatory provenance audit:

### 3.1 Partition Verification Matrix
| Partition | File Path | Record Count | Campaign Families | SHA-256 Digest | Status |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Training** | `data/generated/v3/synthetic_training_corpus.jsonl` | 1,200 | 24 | `f8143880f3d5d13e5f10c14ca2d07c3a736726979f93a53dd864d59fdaee2473` | AUTHORIZED FOR TRAINING |
| **Development** | `data/generated/v3/synthetic_dev_corpus.jsonl` | 300 | 6 | `55e9357abae0de2ebc71535374f079bdb146ea746278471b03797f0941c85e4d` | AUTHORIZED FOR EARLY STOPPING |
| **Qualification** | `data/generated/v3/synthetic_qualification_corpus.jsonl` | 450 | 9 | `197c62e7f0b305ce5965cf7bbeba8543fcd542a4a026d07dbd1172b3656f4a0f` | **SEALED & INACCESSIBLE** |
| **Locked Test** | `data/phishing_eval_dataset.json` | 10 | 8 | `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` | **LOCKED BENCHMARK (UNTOUCHED)** |

### 3.2 Partition Isolation Guarantees
1. **Zero Record Overlap:** Exact ID intersection between training and dev sets: **0 records**.
2. **Zero Text Leakage:** Exact normalized text intersection between training and dev sets: **0 records**.
3. **Zero Campaign Overlap:** Training families (`v3_train_*`) and Dev families (`v3_dev_*`) are 100% disjoint.
4. **Qualification Partition Isolation:** Zero calls to load or evaluate `synthetic_qualification_corpus.jsonl`. Path guards in `verify_phase6_4_3_isolation` explicitly throw `DatasetIsolationViolation` if any argument contains forbidden keywords.
5. **Locked Test Partition Checksum Invariance:** The canonical SHA-256 checksum `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` was verified before and after the pipeline execution.

---

## 4. Baseline Model Evaluation on Development Partition

The production baseline checkpoint (`models/experimental_custom_v1`, registered as `custom-mlp-v1.1.0-preproc` in shadow mode) was evaluated on the 300 development records to establish the performance benchmark.

### 4.1 Baseline Performance Metrics
- **Model Version:** `custom-mlp-v1.0.0`
- **Total Development Samples:** 300 (100 phishing, 100 legitimate, 100 protective advisory)
- **Overall Accuracy:** **0.7333** (220/300) [95% Wilson CI: 0.6806, 0.7802]
- **Macro-F1 Score:** **0.7384**
- **Balanced Accuracy:** **0.7333**

### 4.2 Baseline Per-Class Breakdown
| Class | Support | TP | FP | FN | Precision (95% CI) | Recall (95% CI) | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing** | 100 | 70 | 41 | 30 | 0.6306 [0.5379, 0.7146] | 0.7000 [0.6042, 0.7811] | 0.6635 |
| **Legitimate** | 100 | 64 | 37 | 36 | 0.6337 [0.5364, 0.7211] | 0.6400 [0.5424, 0.7273] | 0.6368 |
| **Protective Advisory** | 100 | 86 | 2 | 14 | 0.9773 [0.9209, 0.9937] | 0.8600 [0.7786, 0.9147] | 0.9149 |

### 4.3 Baseline Safety Failure Modes
- **Legitimate False Positive Rate:** **0.3500** (35 out of 100 legitimate messages misclassified as phishing!)
- **Protective Advisory False Positive Rate:** **0.0600** (6 out of 100 advisories misclassified as phishing)
- **Phishing False Negative Rate:** **0.3000** (30 out of 100 phishing attacks completely missed)
- **Confusion Matrix:**
  $$\begin{pmatrix} 70 & 29 & 1 \\ 35 & 64 & 1 \\ 6 & 8 & 86 \end{pmatrix}$$

> [!WARNING]
> **Forensic Finding Confirmed:** The baseline model, trained on v2 synthetic data with URL confounders and high token overlap, fails dramatically on fresh v3 campaign families. A 35% false positive rate on ordinary citizen messages would cause severe user friction if deployed in production.

---

## 5. Multi-Seed Training Trajectory & Convergence Analysis

Three candidates were trained independently from random He/Xavier initialization using seeds 42, 101, and 202.

### 5.1 Training Convergence Summary
| Candidate | Random Seed | Best Epoch | Total Epochs | Stop Reason | Train Loss (Best) | Train Acc (Best) | Dev Loss (Best) | Dev Acc (Best) | Best Dev Macro-F1 |
| :--- | :---: | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| `candidate_v3_seed42` | 42 | **8** | 18 | Early Stop (Patience 10) | 0.1745 | 0.9633 | 0.1982 | 0.9567 | **0.9565** |
| `candidate_v3_seed101` | 101 | **12** | 22 | Early Stop (Patience 10) | 0.1388 | 0.9742 | 0.2014 | 0.9500 | **0.9499** |
| `candidate_v3_seed202` | 202 | **10** | 20 | Early Stop (Patience 10) | 0.1502 | 0.9708 | 0.1876 | 0.9600 | **0.9599** |

### 5.2 Observations on Optimization Dynamics
1. **Rapid Initial Learning:** All three seeds achieved $> 92\%$ training accuracy and $> 90\%$ dev Macro-F1 within the first 5 epochs.
2. **Early Stopping Peak:** The best development generalization occurred between epochs 8 and 12, well before the scheduled learning rate decay at epoch 21. Beyond epoch 12, training loss continued to decline toward $\sim 0.05$ while dev loss leveled off at $\sim 0.19$, demonstrating that early stopping successfully prevented overfitting to training phrasing patterns.
3. **Weight Restoration:** The controller restored the exact parameter snapshot from the best epoch before writing candidate artifacts to disk.

---

## 6. Per-Candidate Evaluation & Statistical Uncertainty

All three candidates were evaluated on the 300 development records using their restored best-epoch checkpoints.

### 6.1 Performance Comparison Matrix
| Metric | Baseline (`custom-mlp-v1.1.0-preproc`) | Candidate Seed 42 | Candidate Seed 101 | Candidate Seed 202 |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy (95% CI)** | 0.7333 [0.6806, 0.7802] | **0.9567** [0.9273, 0.9745] | **0.9500** [0.9192, 0.9695] | **0.9600** [0.9314, 0.9770] |
| **Macro-F1** | 0.7384 | **0.9565** (+0.2181) | **0.9499** (+0.2115) | **0.9599** (+0.2215) |
| **Phishing F1** | 0.6635 | **0.9390** | **0.9282** | **0.9434** |
| **Legitimate F1** | 0.6368 | **0.9305** | **0.9263** | **0.9362** |
| **Advisory F1** | 0.9149 | **1.0000** | **0.9950** | **1.0000** |
| **Legitimate FP Rate** | 0.3500 (35/100) | **0.1300** (13/100) | **0.1200** (12/100) | **0.1200** (12/100) |
| **Advisory FP Rate** | 0.0600 (6/100) | **0.0000** (0/100) | **0.0000** (0/100) | **0.0000** (0/100) |
| **Phishing FN Rate** | 0.3000 (30/100) | **0.0000** (0/100) | **0.0300** (3/100) | **0.0000** (0/100) |

### 6.2 Confusion Matrices
- **Candidate Seed 42:**
  $$\begin{pmatrix} 100 & 0 & 0 \\ 13 & 87 & 0 \\ 0 & 0 & 100 \end{pmatrix}$$
  - Phishing: 100/100 detected (100% recall), 0 false negatives.
  - Legitimate: 87/100 detected, 13 misclassified as phishing, 0 misclassified as advisory.
  - Advisory: 100/100 detected (100% recall, 100% precision), 0 false alarms.

- **Candidate Seed 101:**
  $$\begin{pmatrix} 97 & 2 & 1 \\ 12 & 88 & 0 \\ 0 & 0 & 100 \end{pmatrix}$$
  - Phishing: 97/100 detected, 2 misclassified as legitimate, 1 misclassified as advisory.
  - Legitimate: 88/100 detected, 12 misclassified as phishing, 0 misclassified as advisory.
  - Advisory: 100/100 detected (100% recall), 1 phishing misclassified as advisory.

- **Candidate Seed 202 (WINNER):**
  $$\begin{pmatrix} 100 & 0 & 0 \\ 12 & 88 & 0 \\ 0 & 0 & 100 \end{pmatrix}$$
  - Phishing: 100/100 detected (100% recall), 0 false negatives.
  - Legitimate: 88/100 detected, 12 misclassified as phishing, 0 misclassified as advisory.
  - Advisory: 100/100 detected (100% recall, 100% precision), 0 false alarms.

### 6.3 Resolution of Prior Failure Modes
1. **Zero Protective Advisory False Alarms:** In Phase 6.4, the candidate model misclassified protective advisories as phishing due to warning terms ("alert", "threat", "police"). In Phase 6.4.3, **both Seed 42 and Seed 202 achieved 0.0000 advisory false positive rates** (100/100 advisories correctly recognized, F1 = 1.0000).
2. **Drastic Legitimate False Alarm Reduction:** Reduced legitimate false positive rate from **0.3500** in the baseline to **0.1200** in Seed 202 and Seed 101.
3. **Flawless Phishing Recall:** Both Seed 42 and Seed 202 captured **100 out of 100 phishing attacks** (0.0000 false negative rate) across all unseen development campaign families.

---

## 7. Deterministic Candidate Selection Policy & Benchmark Gate

The deterministic candidate selection policy was executed across all three candidate models against the baseline.

### 7.1 Selection Policy Rules & Gates
1. **Gate 1 (Performance):** Development Macro-F1 $\ge 0.9000$.
2. **Gate 2 (Regression Protection):** Candidate Macro-F1 drop vs baseline $\le 0.0200$ (i.e. Macro-F1 $\ge 0.7184$).
3. **Gate 3 (Civilian Usability):** Legitimate False Positive Rate $\le 0.1500$.
4. **Gate 4 (Advisory Integrity):** Protective Advisory False Positive Rate $\le 0.0500$.
5. **Gate 5 (Safety Gate):** Phishing False Negative Rate $\le 0.0500$.

### 7.2 Gate Compliance Audit
| Candidate | Dev Macro-F1 | Gate 1 ($\ge 0.90$) | Gate 2 ($\Delta \ge -0.02$) | Gate 3 ($\text{FP}_{\text{legit}} \le 0.15$) | Gate 4 ($\text{FP}_{\text{adv}} \le 0.05$) | Gate 5 ($\text{FN}_{\text{phish}} \le 0.05$) | Eligible? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `candidate_v3_seed42` | 0.9565 | **PASS** | **PASS** (+0.2181) | **PASS** (0.1300) | **PASS** (0.0000) | **PASS** (0.0000) | **YES** |
| `candidate_v3_seed101` | 0.9499 | **PASS** | **PASS** (+0.2115) | **PASS** (0.1200) | **PASS** (0.0000) | **PASS** (0.0300) | **YES** |
| `candidate_v3_seed202` | 0.9599 | **PASS** | **PASS** (+0.2215) | **PASS** (0.1200) | **PASS** (0.0000) | **PASS** (0.0000) | **YES** |

### 7.3 Deterministic Winner Selection
- **Ranking Criteria:**
  1. Primary: Highest development Macro-F1.
  2. Tie-Breaker 1: Lowest total false positive rate ($\text{FP}_{\text{legit}} + \text{FP}_{\text{adv}}$).
  3. Tie-Breaker 2: Lowest seed integer.
- **Rank 1 (WINNER):** **`candidate_v3_seed202`** (Dev Macro-F1 = 0.9599, Total FP = 0.1200, Phish FN = 0.0000).
- **Rank 2:** `candidate_v3_seed42` (Dev Macro-F1 = 0.9565, Total FP = 0.1300, Phish FN = 0.0000).
- **Rank 3:** `candidate_v3_seed101` (Dev Macro-F1 = 0.9499, Total FP = 0.1200, Phish FN = 0.0300).

The full selection audit trail was serialized to [`evaluation/candidates/phase6_4_3_selection_summary.json`](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/candidates/phase6_4_3_selection_summary.json).

---

## 8. Candidate Model Artifacts & Cryptographic Integrity

Each candidate was saved in an isolated, immutable directory under `models/candidates/` with complete metadata, training history, and cryptographic manifests.

### 8.1 Candidate Artifact Directories
```
models/candidates/
├── candidate_custom_v1.0.0/           # Phase 6.3 historical candidate
├── candidate_v3_seed42/               # Phase 6.4.3 Seed 42
│   ├── candidate_training_report.json # Detailed epoch metrics, CIs, provenance
│   ├── manifest.json                  # Cryptographic SHA-256 hashes
│   ├── model_metadata.json            # Model architecture & hyperparameters
│   └── model_weights.npz              # Weights (allow_pickle=False)
├── candidate_v3_seed101/              # Phase 6.4.3 Seed 101
│   ├── candidate_training_report.json
│   ├── manifest.json
│   ├── model_metadata.json
│   └── model_weights.npz
└── candidate_v3_seed202/              # Phase 6.4.3 Seed 202 (WINNER)
    ├── candidate_training_report.json
    ├── manifest.json
    ├── model_metadata.json
    └── model_weights.npz
```

### 8.2 Cryptographic Checksum Registry
| Candidate | Artifact | File Path | SHA-256 Digest |
| :--- | :--- | :--- | :--- |
| **`candidate_v3_seed42`** | Weights | `models/candidates/candidate_v3_seed42/model_weights.npz` | `2229f3b8181d2291afa8dcae543ae95425edd1e8d9125268723d4bba5e7f8d06` |
| | Metadata | `models/candidates/candidate_v3_seed42/model_metadata.json` | `7cb62719ea45e9944675bf2a0e2389104fa28aa648934ae8d0be45d2f8319e6b` |
| | Manifest | `models/candidates/candidate_v3_seed42/manifest.json` | `9d554a99dbe637dbec178fa6ee6aa0d592a8326c7104b281f953ef054ba91d29` |
| | Report | `models/candidates/candidate_v3_seed42/candidate_training_report.json` | `ebf0e21a220556f8742b5ba476839bfe00c8724cb1ee4b1ea9be12117fc0434b` |
| **`candidate_v3_seed101`** | Weights | `models/candidates/candidate_v3_seed101/model_weights.npz` | `b4f743137be0b216827d0f528f77d6880b4cc7f8e7267257f81ee33037fa6eab` |
| | Metadata | `models/candidates/candidate_v3_seed101/model_metadata.json` | `c37b60098dfc38a16ffc9e3bc848148b8c56cbe0eb79b9409893d56226f9872e` |
| | Manifest | `models/candidates/candidate_v3_seed101/manifest.json` | `d550e58bcda6944e2fa2ee1be0b7a8a1eb3d526804595858cfd7be150e70a3e8` |
| | Report | `models/candidates/candidate_v3_seed101/candidate_training_report.json` | `d690a290a61858a74ec3ca0ff4f44fa7672224523c035e5d3269225725f0e34b` |
| **`candidate_v3_seed202`** | Weights | `models/candidates/candidate_v3_seed202/model_weights.npz` | `fce2b252a62c5142ba4cd0e3430fc44ffd6a66d02c05cd840d9a2fa4774f03dd` |
| | Metadata | `models/candidates/candidate_v3_seed202/model_metadata.json` | `5c3701620a28f7fcb5b5ca7845348bb95b2938a1005ca6fc52e1f26a1aa34e9e` |
| | Manifest | `models/candidates/candidate_v3_seed202/manifest.json` | `29fb15eb13a3d5b0340c4a4e1017ef33f5d5272a08f515ee36aaee989ae00ae2` |
| | Report | `models/candidates/candidate_v3_seed202/candidate_training_report.json` | `5ff46e45f94aeb53c16ee0a701e74f1784ca1213fe1df3feff0a96f8c7b80980` |

---

## 9. Verification of Governance Guarantees & Production Invariance

The system underwent rigorous audit to guarantee zero impact on runtime production behavior:

1. **Production Registry Unchanged:**
   - [`models/model_registry.json`](file:///C:/Users/prati/seva-cyber-sandbox/models/model_registry.json) was not modified.
   - Only `custom-mlp-v1.0.0` and `custom-mlp-v1.1.0-preproc` are registered. None of the v3 candidates were added to the registry.
2. **Active Runtime Configuration Unchanged:**
   - [`models/active_model_config.json`](file:///C:/Users/prati/seva-cyber-sandbox/models/active_model_config.json) remains set to `custom-mlp-v1.1.0-preproc` in `shadow` operating mode.
   - `is_production_authoritative` remains `false`.
3. **Production Risk Score Invariance:**
   - Evaluated messages through [`HybridDecisionEngine.evaluate_message()`](file:///C:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py).
   - In shadow operating mode, the authoritative risk score is computed strictly by deterministic heuristic rules (`score_message_analysis`).
   - Production score difference = **0**.
4. **Locked Test Partition Checksum Invariance:**
   - [`data/phishing_eval_dataset.json`](file:///C:/Users/prati/seva-cyber-sandbox/data/phishing_eval_dataset.json) was not opened or modified during training.
   - Verified digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` (MATCH).
5. **Qualification Partition Invariance:**
   - [`data/generated/v3/synthetic_qualification_corpus.jsonl`](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v3/synthetic_qualification_corpus.jsonl) remained completely sealed on disk with zero read access during this phase.

---

## 10. Test Suite Execution & Audit Trail

A comprehensive test suite [`tests/test_phase6_4_3_controlled_training.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_3_controlled_training.py) comprising 21 automated tests was implemented and executed:

```
tests/test_phase6_4_3_controlled_training.py::test_01_locked_evaluation_digest_preserved PASSED
tests/test_phase6_4_3_controlled_training.py::test_02_v3_corpus_manifests_integrity PASSED
tests/test_phase6_4_3_controlled_training.py::test_03_qualification_corpus_blocked_from_training PASSED
tests/test_phase6_4_3_controlled_training.py::test_04_qualification_corpus_not_accessed PASSED
tests/test_phase6_4_3_controlled_training.py::test_05_locked_eval_partition_blocked PASSED
tests/test_phase6_4_3_controlled_training.py::test_06_dev_data_not_in_gradient_updates PASSED
tests/test_phase6_4_3_controlled_training.py::test_07_zero_train_dev_overlap PASSED
tests/test_phase6_4_3_controlled_training.py::test_08_three_independent_seeds_trained PASSED
tests/test_phase6_4_3_controlled_training.py::test_09_candidate_directories_unique_and_isolated PASSED
tests/test_phase6_4_3_controlled_training.py::test_10_candidate_weights_npz_safe_serialization PASSED
tests/test_phase6_4_3_controlled_training.py::test_11_candidate_manifest_sha256_integrity PASSED
tests/test_phase6_4_3_controlled_training.py::test_12_candidate_metadata_schema_validity PASSED
tests/test_phase6_4_3_controlled_training.py::test_13_candidate_training_reports_exist_and_complete PASSED
tests/test_phase6_4_3_controlled_training.py::test_14_seed_reproducibility PASSED
tests/test_phase6_4_3_controlled_training.py::test_15_different_seeds_produce_different_weights PASSED
tests/test_phase6_4_3_controlled_training.py::test_16_baseline_model_evaluation_on_dev PASSED
tests/test_phase6_4_3_controlled_training.py::test_17_candidate_selection_policy_execution PASSED
tests/test_phase6_4_3_controlled_training.py::test_18_candidate_selection_policy_logic_unit PASSED
tests/test_phase6_4_3_controlled_training.py::test_19_model_registry_unmodified PASSED
tests/test_phase6_4_3_controlled_training.py::test_20_active_model_config_unmodified PASSED
tests/test_phase6_4_3_controlled_training.py::test_21_production_score_delta_zero PASSED

============================= 21 passed in 0.74s ==============================
```

Following the unit test pass, the entire repository regression test suite was executed:
```
============================ 413 passed in 24.73s =============================
```
All 413 automated tests pass with 100% success rate and zero regressions.

---

## 11. Conclusion & Transition to Phase 6.4.4

Phase 6.4.3 successfully demonstrated that:
1. Controlled multi-seed training on the clean v3 synthetic dataset eliminates the catastrophic failure modes observed in Phase 6.4.1.
2. Increasing $L_2$ regularization to $0.0005$ combined with early stopping on development Macro-F1 prevents shortcut learning on individual tokens.
3. Protective advisories are now classified with **100% precision and 100% recall** (zero false alarms).
4. Phishing attacks are classified with **100% recall** (zero false negatives).
5. The deterministic selection policy selected **`candidate_v3_seed202`** as the winning candidate.

### Next Step: Phase 6.4.4 (Candidate Qualification Benchmark)
In Phase 6.4.4, the selected candidate (`candidate_v3_seed202`) will be unsealed and evaluated against the pristine, independent **qualification partition** (`synthetic_qualification_corpus.jsonl`, 450 records across 9 unseen campaign families) in a single-shot evaluation to make a definitive determination on shadow deployment eligibility.

> [!IMPORTANT]
> **Zero Production Modification Guarantee:** In accordance with project governance, no models have been promoted, activated, or deployed. Execution stops here pending user instruction for Phase 6.4.4.
