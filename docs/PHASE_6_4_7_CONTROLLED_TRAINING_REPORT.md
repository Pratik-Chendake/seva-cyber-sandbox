# Phase 6.4.7: Controlled Multi-Seed Candidate Training Report

**System**: Seva Cyber Sandbox  
**Phase**: 6.4.7 — Controlled Multi-Seed Candidate Training Using Synthetic Dataset v4  
**Date**: October 30, 2026  
**Status**: COMPLETED (Winner Selected: `candidate_v4_seed42`)  
**Operating Mode**: STRICT EXPERIMENTAL ISOLATION (ZERO PRODUCTION IMPACT)  

---

## Executive Summary

Phase 6.4.7 executed a controlled, multi-seed training and benchmark evaluation cycle for the Seva Cyber Sandbox custom feed-forward neural network. Training was conducted using the newly curated **Synthetic Dataset v4**, engineered specifically in Phase 6.4.6 to address the digital-arrest, law-enforcement impersonation, and linkless extortion vulnerabilities uncovered in Phase 6.4.5.

Three independent candidate models were initialized from scratch and trained across random seeds **42**, **101**, and **202**:
- [candidate_v4_seed42](file:///C:/Users/prati/seva-cyber-sandbox/models/candidates/candidate_v4_seed42)
- [candidate_v4_seed101](file:///C:/Users/prati/seva-cyber-sandbox/models/candidates/candidate_v4_seed101)
- [candidate_v4_seed202](file:///C:/Users/prati/seva-cyber-sandbox/models/candidates/candidate_v4_seed202)

All training was restricted exclusively to the authorized training partition (1,500 records across 30 campaign families). Hyperparameter tuning and early stopping operated strictly on the independent development partition (300 records across 6 campaign families). The final qualification partition (450 records across 9 campaign families) remained completely **UNEXPOSED** and untouched, with its cryptographic status preserved in [exposure_ledger_v4.json](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/qualification/exposure_ledger_v4.json).

### High-Level Benchmark Comparison

| Model | Dev Accuracy | Dev Macro-F1 | Legit False Positive | Advisory False Positive | Phishing False Negative | Eligible? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline (`custom-mlp-v1.1.0-preproc`)** | 65.33% (196/300) | 0.6498 | 50.00% (50/100) | 15.00% (15/100) | 24.00% (24/100) | Baseline |
| **Candidate Seed 42** | **100.00% (300/300)** | **1.0000** | **0.00% (0/100)** | **0.00% (0/100)** | **0.00% (0/100)** | **WINNER** |
| **Candidate Seed 101** | 99.67% (299/300) | 0.9967 | 0.00% (0/100) | 0.00% (0/100) | 1.00% (1/100) | Passed |
| **Candidate Seed 202** | **100.00% (300/300)** | **1.0000** | **0.00% (0/100)** | **0.00% (0/100)** | **0.00% (0/100)** | Tied |

Under the deterministic governance selection policy, **`candidate_v4_seed42`** was selected as the winning candidate via the lowest-seed tiebreaking rule.

---

## 1. Dataset Preflight Verification

Prior to model initialization or vector extraction, a strict preflight integrity audit was executed against the Synthetic Dataset v4 repository.

### Dataset Partition Audit Summary

| Partition | File Path | Record Count | Unique Families | SHA-256 Digest | Status |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Training** | [synthetic_training_corpus.jsonl](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/synthetic_training_corpus.jsonl) | 1,500 | 30 | `6abd8b2b2daa25d6f8bc0263e588d0a3410fd9bae8fb82632b5fe826cb1cc93f` | Verified & Loaded |
| **Development** | [synthetic_dev_corpus.jsonl](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/synthetic_dev_corpus.jsonl) | 300 | 6 | `4814d15a93119eb9934d0ef4127612009b60dc3f5ab607e58d45f349723f9930` | Verified & Evaluated |
| **Qualification** | [synthetic_qualification_corpus.jsonl](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/synthetic_qualification_corpus.jsonl) | 450 | 9 | `d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e` | **SEALED (UNREAD)** |

### Governance Preflight Checklist
- Manifest files present and verified: [training_manifest.json](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/training_manifest.json), [dev_manifest.json](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/dev_manifest.json), [qualification_manifest.json](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/qualification_manifest.json), and [v4_corpus_manifest.json](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/v4_corpus_manifest.json).
- Training record ID and development record ID sets are strictly disjoint ($1500 \cap 300 = \emptyset$).
- Campaign family sets between training and development are mutually exclusive ($30 \cap 6 = \emptyset$).
- Qualification partition was **NOT opened, read, or parsed** during this phase.
- Qualification exposure ledger at [exposure_ledger_v4.json](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/qualification/exposure_ledger_v4.json) was inspected in read-only mode and confirmed `current_status: "UNEXPOSED"`, `exposure_count: 0`.

---

## 2. Training Configuration

All three candidate models were trained with an identical training configuration, differing only in random initial seed:

- **Input Dimension**: 1,024 features
- **Hidden Layer 1**: 64 neurons (LeakyReLU $\alpha = 0.01$, Inverted Dropout rate $p = 0.2$)
- **Hidden Layer 2**: 32 neurons (LeakyReLU $\alpha = 0.01$, Inverted Dropout rate $p = 0.2$)
- **Output Layer**: 3 neurons (Softmax activation: `phishing` [0], `legitimate` [1], `protective_advisory` [2])
- **Loss Function**: Categorical Cross-Entropy with $L_2$ weight regularization ($\lambda = 1 \times 10^{-4}$)
- **Optimization Algorithm**: Adam Optimizer ($\beta_1 = 0.9, \beta_2 = 0.999, \epsilon = 1 \times 10^{-8}$)
- **Learning Rate**: $\eta = 0.005$
- **Batch Size**: 32 records per mini-batch
- **Maximum Epochs**: 30 epochs
- **Early Stopping**: Development Macro-F1 monitoring, patience = 10 epochs, best checkpoint restoration
- **Feature Vector Extraction**: Character $n$-gram hashing (`CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)`) coupled with preprocessing normalization pipeline `preprocess_for_neural_model` (v1.1.0-preproc).

---

## 3. Model Architecture

The custom model is a pure NumPy-based three-layer feed-forward neural network designed for sub-millisecond local CPU execution:

### Mathematical Formulation

1. **Input Representation**:
   Given raw text message $T$, normalization yields $T_{\text{norm}}$. Character $n$-grams ($n \in [3, 5]$) are hashed into 1,024 buckets with MurmurHash-style signs and $L_2$ unit normalization:
   $$X = \frac{v}{\|v\|_2} \in \mathbb{R}^{1 \times 1024}$$

2. **Hidden Layer 1**:
   $$Z_1 = X W_1 + b_1, \quad W_1 \in \mathbb{R}^{1024 \times 64}, \; b_1 \in \mathbb{R}^{1 \times 64}$$
   $$A_1 = \max(Z_1, \alpha Z_1), \quad \alpha = 0.01$$
   During training: $A_{1,\text{dropped}} = \frac{A_1 \odot M_1}{1 - p}$ where $M_{1,j} \sim \text{Bernoulli}(1 - p)$ with $p = 0.2$.

3. **Hidden Layer 2**:
   $$Z_2 = A_{1,\text{dropped}} W_2 + b_2, \quad W_2 \in \mathbb{R}^{64 \times 32}, \; b_2 \in \mathbb{R}^{1 \times 32}$$
   $$A_2 = \max(Z_2, \alpha Z_2), \quad \alpha = 0.01$$
   During training: $A_{2,\text{dropped}} = \frac{A_2 \odot M_2}{1 - p}$ where $M_{2,k} \sim \text{Bernoulli}(1 - p)$ with $p = 0.2$.

4. **Output Classification Layer**:
   $$Z_3 = A_{2,\text{dropped}} W_3 + b_3, \quad W_3 \in \mathbb{R}^{32 \times 3}, \; b_3 \in \mathbb{R}^{1 \times 3}$$
   $$\hat{Y} = \text{softmax}(Z_3) = \frac{\exp(Z_{3,c} - \max_k Z_{3,k})}{\sum_{j=1}^3 \exp(Z_{3,j} - \max_k Z_{3,k})}$$

5. **Objective Function**:
   $$\mathcal{L} = -\frac{1}{B} \sum_{i=1}^B \sum_{c=1}^3 Y_{i,c} \log(\hat{Y}_{i,c} + \epsilon) + \frac{\lambda}{2} \left( \|W_1\|_F^2 + \|W_2\|_F^2 + \|W_3\|_F^2 \right)$$

---

## 4. Training Provenance

To guarantee mathematical reproducibility and prevent inadvertent memorization:
- **Zero Pre-Trained Weights**: Every candidate began with freshly seeded pseudo-random weight initializations. No parameters were inherited from baseline `custom-mlp-v1.1.0-preproc` or `candidate_v3_seed202`.
- **Initialization Distributions**:
  - $W_1$: He (Kaiming) normal distribution with $\sigma_1 = \sqrt{\frac{2}{1024}} \approx 0.04419$
  - $W_2$: He normal distribution with $\sigma_2 = \sqrt{\frac{2}{64}} = 0.17678$
  - $W_3$: Xavier (Glorot) uniform distribution in $\left[-\sqrt{\frac{6}{35}}, \sqrt{\frac{6}{35}}\right] \approx [-0.4140, +0.4140]$
  - Biases $b_1, b_2, b_3$ initialized to zeros.
- **Strict Gradient Isolation**: Development records were utilized exclusively for forward inference during end-of-epoch evaluation. No development records ever entered mini-batch loss computation or backpropagation.
- **Data Integrity**: Training partition was verified to contain exactly 1,500 unique records across 30 campaign families. No oversampling, synthetic smote, or record duplication was employed.

---

## 5. Epoch and Early-Stopping Results

Each training run was configured with an early-stopping monitor evaluating development set Macro-F1 after every epoch, with a patience parameter of 10 epochs. When patience expired or 30 epochs completed, the parameters from the optimal epoch were restored.

### Epoch Summary Table

| Candidate | Seed | Best Epoch | Best Dev Macro-F1 | Total Epochs | Stop Reason | Training Time |
| :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| `candidate_v4_seed42` | 42 | **Epoch 7** | **1.0000** | 17 | Early stopping (Patience 10 exhausted) | 1.05s |
| `candidate_v4_seed101` | 101 | **Epoch 3** | **0.9967** | 13 | Early stopping (Patience 10 exhausted) | 0.81s |
| `candidate_v4_seed202` | 202 | **Epoch 3** | **1.0000** | 13 | Early stopping (Patience 10 exhausted) | 0.82s |

---

## 6. Multi-Seed Candidate Results

The three trained candidate models were systematically benchmarked on the 300-record development partition:

### Development Performance Across Seeds

| Metric | Baseline (`custom-mlp-v1.1.0-preproc`) | Candidate Seed 42 | Candidate Seed 101 | Candidate Seed 202 |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | 0.6533 (196/300) | **1.0000 (300/300)** | 0.9967 (299/300) | **1.0000 (300/300)** |
| **95% Wilson CI** | [0.5978, 0.7049] | [0.9874, 1.0000] | [0.9814, 0.9994] | [0.9874, 1.0000] |
| **Macro-F1** | 0.6498 | **1.0000** | 0.9967 | **1.0000** |
| **Macro-Precision** | 0.6739 | **1.0000** | 0.9967 | **1.0000** |
| **Macro-Recall** | 0.6533 | **1.0000** | 0.9967 | **1.0000** |
| **Balanced Accuracy** | 0.6533 | **1.0000** | 0.9967 | **1.0000** |
| **Weighted F1** | 0.6498 | **1.0000** | 0.9967 | **1.0000** |
| **Total Incorrect** | 104 / 300 | **0 / 300** | 1 / 300 | **0 / 300** |

All three seeds demonstrated remarkable convergence, indicating that the semantic balance introduced in Synthetic Dataset v4 provided unambiguous, well-separated feature representations.

---

## 7. Baseline Comparison

The registered baseline model `custom-mlp-v1.1.0-preproc` was evaluated on the identical v4 development partition. Because the baseline model was trained prior to the inclusion of digital arrest, extortion, and police impersonation families, it exhibited severe degradation:
- **Baseline Accuracy**: 65.33% (104 errors out of 300 messages).
- **Legitimate False Alarm Rate**: 50.00% (50 out of 100 legitimate messages misclassified as phishing).
- **Phishing False Negative Rate**: 24.00% (24 out of 100 phishing messages missed).

### Comparison vs Baseline Delta

| Candidate | Macro-F1 Delta vs Baseline | Accuracy Delta vs Baseline | Legit FP Rate Reduction | Phish FN Rate Reduction |
| :--- | :---: | :---: | :---: | :---: |
| `candidate_v4_seed42` | **+0.3502** | **+34.67%** | **-50.00%** (0.0% vs 50.0%) | **-24.00%** (0.0% vs 24.0%) |
| `candidate_v4_seed101` | **+0.3469** | **+34.34%** | **-50.00%** (0.0% vs 50.0%) | **-23.00%** (1.0% vs 24.0%) |
| `candidate_v4_seed202` | **+0.3502** | **+34.67%** | **-50.00%** (0.0% vs 50.0%) | **-24.00%** (0.0% vs 24.0%) |

---

## 8. Confusion Matrices

### Baseline Model (`custom-mlp-v1.1.0-preproc`)
```
                     Predicted Phishing  Predicted Legit  Predicted Advisory    Total
Actual Phishing:                     76               14                  10      100
Actual Legit:                        50               44                   6      100
Actual Advisory:                     15                9                  76      100
Total Predicted:                    141               67                  92      300
```

### Candidate Seed 42 (`candidate_v4_seed42`)
```
                     Predicted Phishing  Predicted Legit  Predicted Advisory    Total
Actual Phishing:                    100                0                   0      100
Actual Legit:                         0              100                   0      100
Actual Advisory:                      0                0                 100      100
Total Predicted:                    100              100                 100      300
```

### Candidate Seed 101 (`candidate_v4_seed101`)
```
                     Predicted Phishing  Predicted Legit  Predicted Advisory    Total
Actual Phishing:                     99                1                   0      100
Actual Legit:                         0              100                   0      100
Actual Advisory:                      0                0                 100      100
Total Predicted:                     99              101                 100      300
```
*(Single error: 1 Devanagari Marathi high-court contempt extortion message misclassified as legitimate).*

### Candidate Seed 202 (`candidate_v4_seed202`)
```
                     Predicted Phishing  Predicted Legit  Predicted Advisory    Total
Actual Phishing:                    100                0                   0      100
Actual Legit:                         0              100                   0      100
Actual Advisory:                      0                0                 100      100
Total Predicted:                    100              100                 100      300
```

---

## 9. Per-Class Metrics

### Class Metrics Breakdown

| Category | Model | Precision | Recall | F1-Score | Support | Precision 95% CI | Recall 95% CI |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing** | Baseline | 0.5390 (76/141) | 0.7600 (76/100) | 0.6307 | 100 | [0.4568, 0.6192] | [0.6677, 0.8331] |
| | **Seed 42** | **1.0000 (100/100)** | **1.0000 (100/100)** | **1.0000** | 100 | [0.9630, 1.0000] | [0.9630, 1.0000] |
| | Seed 101 | 1.0000 (99/99) | 0.9900 (99/100) | 0.9950 | 100 | [0.9626, 1.0000] | [0.9455, 0.9982] |
| | **Seed 202** | **1.0000 (100/100)** | **1.0000 (100/100)** | **1.0000** | 100 | [0.9630, 1.0000] | [0.9630, 1.0000] |
| **Legitimate** | Baseline | 0.6567 (44/67) | 0.4400 (44/100) | 0.5269 | 100 | [0.5373, 0.7591] | [0.3467, 0.5377] |
| | **Seed 42** | **1.0000 (100/100)** | **1.0000 (100/100)** | **1.0000** | 100 | [0.9630, 1.0000] | [0.9630, 1.0000] |
| | Seed 101 | 0.9901 (100/101) | 1.0000 (100/100) | 0.9950 | 100 | [0.9460, 0.9983] | [0.9630, 1.0000] |
| | **Seed 202** | **1.0000 (100/100)** | **1.0000 (100/100)** | **1.0000** | 100 | [0.9630, 1.0000] | [0.9630, 1.0000] |
| **Advisory** | Baseline | 0.8261 (76/92) | 0.7600 (76/100) | 0.7917 | 100 | [0.7360, 0.8900] | [0.6677, 0.8331] |
| | **Seed 42** | **1.0000 (100/100)** | **1.0000 (100/100)** | **1.0000** | 100 | [0.9630, 1.0000] | [0.9630, 1.0000] |
| | Seed 101 | 1.0000 (100/100) | 1.0000 (100/100) | 1.0000 | 100 | [0.9630, 1.0000] | [0.9630, 1.0000] |
| | **Seed 202** | **1.0000 (100/100)** | **1.0000 (100/100)** | **1.0000** | 100 | [0.9630, 1.0000] | [0.9630, 1.0000] |

---

## 10. Citizen-Safety False Alarm Metrics

In Seva Cyber Sandbox governance, false alarms against citizens (blocking authentic government messages) and false positives against protective police advisories are categorized as high-severity risks:

### Governance Safety Thresholds

| Safety Metric | Governance Cap | Baseline | Seed 42 | Seed 101 | Seed 202 | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Legitimate False Alarm Rate** (flagged as phishing) | $\le 15.0\%$ | 50.00% (50/100) | **0.00% (0/100)** | **0.00% (0/100)** | **0.00% (0/100)** | **ALL PASS** |
| **Advisory False Alarm Rate** (flagged as phishing) | $\le 5.0\%$ | 15.00% (15/100) | **0.00% (0/100)** | **0.00% (0/100)** | **0.00% (0/100)** | **ALL PASS** |
| **Phishing False Negative Rate** (missed fraud) | $\le 5.0\%$ | 24.00% (24/100) | **0.00% (0/100)** | **1.00% (1/100)** | **0.00% (0/100)** | **ALL PASS** |

Baseline failed all three safety caps catastrophically. Candidates eliminated false alarms completely.

---

## 11. Language-Level Results

The development partition spans four distinct linguistic distributions representative of Maharashtra cyberspace:

### Performance Across Language Slices

| Language Code | Description | Sample Count | Baseline Accuracy | Seed 42 Accuracy | Seed 101 Accuracy | Seed 202 Accuracy |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `mr` | Marathi Devanagari script | 78 | 69.23% (54/78) | **100.00% (78/78)** | 98.72% (77/78) | **100.00% (78/78)** |
| `mr-Latn` | Romanized Marathi | 78 | 62.82% (49/78) | **100.00% (78/78)** | **100.00% (78/78)** | **100.00% (78/78)** |
| `en` | Indian English | 72 | 61.11% (44/72) | **100.00% (72/72)** | **100.00% (72/72)** | **100.00% (72/72)** |
| `mr-en` | Code-Mixed Marathi-English | 72 | 68.06% (49/72) | **100.00% (72/72)** | **100.00% (72/72)** | **100.00% (72/72)** |

All three candidates achieved 100% accuracy in Romanized Marathi (`mr-Latn`), Indian English (`en`), and Code-Mixed Marathi-English (`mr-en`). In Devanagari Marathi (`mr`), Seed 42 and Seed 202 achieved 100%, while Seed 101 achieved 98.72% due to a single missed extortion threat.

---

## 12. URL-Bearing versus URL-Free Performance

A key vulnerability uncovered during Phase 6.4.5 was model over-reliance on clickable URLs as a primary feature for phishing detection. In Dataset v4, URL presence was strictly balanced at 50% across every class and campaign family:

### Structural URL Analysis

| Subgroup | Sample Count | Baseline Accuracy | Seed 42 Accuracy | Seed 101 Accuracy | Seed 202 Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **URL-Bearing** (`has_url = True`) | 150 | 54.67% (82/150) | **100.00% (150/150)** | **100.00% (150/150)** | **100.00% (150/150)** |
| **URL-Free** (`has_url = False`) | 150 | 76.00% (114/150) | **100.00% (150/150)** | 99.33% (149/150) | **100.00% (150/150)** |

Candidates achieved perfect 100% accuracy on URL-bearing messages and near-perfect (100% in seeds 42 and 202) on URL-free messages. This confirms that the model has internalized semantic, contextual, and psychological coercion cues rather than relying on hyperlinked shortcuts.

---

## 13. Digital-Arrest and Extortion Results

Phishing campaigns in Dataset v4 dev set focused on coercive legal and law-enforcement impersonation:

1. **Customs FedEx Contraband Threat (`v4_dev_phish_customs_fedex_contraband_threat`)**:
   - Fabricated drug parcel allegations, demands for Skype video verification, and extortionate RBI verification demands.
   - Baseline Accuracy: 82.00% (41/50).
   - Candidate Seeds 42, 101, 202 Accuracy: **100.00% (50/50)**.

2. **High Court Contempt Fine Scam (`v4_dev_phish_highcourt_contempt_fine_scam`)**:
   - Fabricated summons, threats of non-bailable warrants, and urgent demands for payment via UPI QR codes.
   - Baseline Accuracy: 70.00% (35/50).
   - Candidate Seeds 42 and 202 Accuracy: **100.00% (50/50)**.
   - Candidate Seed 101 Accuracy: 98.00% (49/50).

These results confirm that the model now accurately recognizes linkless digital-arrest tactics without confusing them with legitimate court or administrative notifications.

---

## 14. Campaign-Family Results

The development partition contains six campaign families that were entirely excluded from training:

### Performance by Campaign Family

| Campaign Family | True Class | Count | Baseline Accuracy | Seed 42 | Seed 101 | Seed 202 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `v4_dev_advisory_dot_sim_termination_alert` | Advisory | 50 | 58.00% (29/50) | **100.00% (50/50)** | **100.00% (50/50)** | **100.00% (50/50)** |
| `v4_dev_advisory_ed_money_laundering_scam` | Advisory | 50 | 94.00% (47/50) | **100.00% (50/50)** | **100.00% (50/50)** | **100.00% (50/50)** |
| `v4_dev_legit_property_tax_annual_assessment` | Legit | 50 | 72.00% (36/50) | **100.00% (50/50)** | **100.00% (50/50)** | **100.00% (50/50)** |
| `v4_dev_legit_rto_smartcard_dispatch` | Legit | 50 | 16.00% (8/50) | **100.00% (50/50)** | **100.00% (50/50)** | **100.00% (50/50)** |
| `v4_dev_phish_customs_fedex_contraband_threat`| Phishing | 50 | 82.00% (41/50) | **100.00% (50/50)** | **100.00% (50/50)** | **100.00% (50/50)** |
| `v4_dev_phish_highcourt_contempt_fine_scam` | Phishing | 50 | 70.00% (35/50) | **100.00% (50/50)** | 98.00% (49/50) | **100.00% (50/50)** |

Notably, on `v4_dev_legit_rto_smartcard_dispatch`, the baseline collapsed to 16% accuracy because legitimate dispatch notices contained tracking identifiers and administrative language that the uncalibrated baseline mistook for phishing URLs. Candidates 42, 101, and 202 achieved 100% accuracy on this family.

---

## 15. Candidate Selection and Rationale

The benchmark governance framework mandates a five-gate decision policy executed in deterministic sequence:

1. **Gate 1 (Macro-F1 Absolute)**: Macro-F1 $\ge 0.85$.
2. **Gate 2 (Macro-F1 Degradation)**: Macro-F1 $\ge \text{Baseline} - 0.02$.
3. **Gate 3 (Legitimate False Alarm Cap)**: Legitimate FP rate $\le 0.15$.
4. **Gate 4 (Advisory False Alarm Cap)**: Advisory FP rate $\le 0.05$.
5. **Gate 5 (Phishing False Negative Cap)**: Phishing FN rate $\le 0.05$.

### Gating Evaluation Results

| Candidate | Gate 1 | Gate 2 | Gate 3 | Gate 4 | Gate 5 | Overall Eligible? | Failing Gates |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `candidate_v4_seed42` | Pass (1.0000) | Pass (+0.3502) | Pass (0.00%) | Pass (0.00%) | Pass (0.00%) | **ELIGIBLE** | None |
| `candidate_v4_seed101` | Pass (0.9967) | Pass (+0.3469) | Pass (0.00%) | Pass (0.00%) | Pass (1.00%) | **ELIGIBLE** | None |
| `candidate_v4_seed202` | Pass (1.0000) | Pass (+0.3502) | Pass (0.00%) | Pass (0.00%) | Pass (0.00%) | **ELIGIBLE** | None |

### Tiebreaking Resolution
Both `candidate_v4_seed42` and `candidate_v4_seed202` achieved equal top Macro-F1 (1.0000) and identical zero false alarm / false negative metrics. Under Section 10 of the governance protocol, ties are broken deterministically by selecting the **lowest random seed**.

**Selected Candidate**: **`candidate_v4_seed42`**  
**Selected Checkpoint**: [candidate_v4_seed42](file:///C:/Users/prati/seva-cyber-sandbox/models/candidates/candidate_v4_seed42)

---

## 16. Artifact Paths and Cryptographic Hashes

Every candidate was saved under an immutable directory structure containing weights, model metadata, cryptographic manifest, and training provenance report:

### Candidate Artifact Hashes

| Candidate | Artifact File | File Size | SHA-256 Digest |
| :--- | :--- | :---: | :--- |
| **`candidate_v4_seed42`** | `candidate_weights.npz` | 277 KB | `3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f` |
| | `candidate_metadata.json` | 1.8 KB | `8bf388271453b805c148b17232972f6adbe1a4689370893159454b7fe61cafa3` |
| | `candidate_manifest.json` | 954 B | `c7f85ef9551b05b2f5ce7d364ed199a13f50225ce4b6f080e069d2f9600349cf` |
| | `candidate_training_report.json` | 4.8 KB | `c22d6021f15d66860549a2064d846bb44156bbb2cf7ff1d30a03abdf5a64e6c6` |
| **`candidate_v4_seed101`** | `candidate_weights.npz` | 277 KB | `987836c39771ea8bfa687ffd25de53f247fa19e62d4b4a97de8d68957638640e` |
| | `candidate_metadata.json` | 1.8 KB | `99867524b52f60d178e71890d2f671ac4193dcf631971aa8923606f5cfcef6e9` |
| | `candidate_manifest.json` | 954 B | `e753de044d25b597b57dbf31fba5d7aba706b0d43d1a6808b72d2ba8e9decd32` |
| | `candidate_training_report.json` | 4.8 KB | `46e01fff1bfa869fcdab9d32df07e9ebe03faa2c62729ab89353c328f17ccee5` |
| **`candidate_v4_seed202`** | `candidate_weights.npz` | 277 KB | `9c66012e2fdc548ab1df55b76daefba238d459fb36072e8593bbd0dd5085ed71` |
| | `candidate_metadata.json` | 1.8 KB | `04cdef00165d4244c0616c63d3f51d4ab95a6ba86256b30de12bceaf8e6ab24a` |
| | `candidate_manifest.json` | 954 B | `7ed1a3d31ec0c2a1ab5d253f244fed328931384b0bf78278fd82236796c6e0ee` |
| | `candidate_training_report.json` | 4.8 KB | `4c8ee14cf7803d88007d54978945a8598c4e435b295e43e6b9d5b93c68c8c607` |

### Pipeline Selection Summary
The comprehensive execution report was recorded to [phase6_4_7_selection_summary.json](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/candidates/phase6_4_7_selection_summary.json).

---

## 17. Test-Suite Results

A dedicated automated test suite was developed and executed to rigorously validate all governance, data isolation, model training, and selection policies:

- **Phase 6.4.7 Test Suite**: [test_phase6_4_7_controlled_training.py](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_7_controlled_training.py)  
  - Result: **22 passed in 0.46s** (100% pass rate)
  - Scenarios verified:
    1. Training manifest integrity and SHA-256 match.
    2. Development manifest integrity and SHA-256 match.
    3. Qualification records not loaded or accessed.
    4. Qualification exposure ledger remains strictly `UNEXPOSED`.
    5. Training and development record ID sets are mutually exclusive.
    6. Training and development campaign families are mutually exclusive.
    7. Correct canonical class index mappings.
    8. Random initialization produces distinct initial weight matrices across seeds.
    9. Seed reproducibility: identical seeds produce bit-identical weight matrices.
    10. No active-model checkpoint parameters loaded during candidate initialization.
    11. Zero development set gradient updates.
    12. Early stopping accurately monitors dev metrics and restores optimal epoch.
    13. No oversampling or artificial record duplication.
    14. Non-finite inputs (NaN / Inf) are rejected (fail closed).
    15. Non-finite losses are rejected (fail closed).
    16. Candidate directory paths are unique and isolated.
    17. Candidate artifacts match manifest cryptographic hashes.
    18. Existing production model checkpoints remain unchanged.
    19. Production model registry remains unchanged.
    20. Active model configuration remains unchanged.
    21. Production risk score delta remains zero.
    22. Candidate selection policy execution and deterministic tiebreaking.

- **Full Repository Test Suite**:
  - Result: **487 passed in 39.81s** (0 failed, 0 errors, 0 skipped, 0 regressions).

---

## 18. Qualification Isolation Confirmation

Governance rules strictly forbid evaluating candidate models against the sealed qualification partition during training and selection phases.

- **File Path**: [synthetic_qualification_corpus.jsonl](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/synthetic_qualification_corpus.jsonl)
- **Record Count**: 450 records across 9 unseen campaign families.
- **SHA-256 Digest**: `d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e`
- **Verification**: The qualification file was never opened, read, preprocessed, vectorized, or scored.
- **Exposure Ledger**: [exposure_ledger_v4.json](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/qualification/exposure_ledger_v4.json) was audited and confirmed unmodified:
  ```json
  "d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e": {
    "partition_file_name": "synthetic_qualification_corpus.jsonl",
    "partition_sha256": "d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e",
    "first_exposed_at_utc": null,
    "exposure_count": 0,
    "events": [],
    "is_exposed": false,
    "current_status": "UNEXPOSED"
  }
  ```

---

## 19. Locked Evaluation Integrity

The Phase 5 locked evaluation benchmark manifest at [locked_test_manifest.json](file:///C:/Users/prati/seva-cyber-sandbox/data/locked_test_manifest.json):
- **Digest**: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`
- **Integrity**: Preserved and untouched. Not accessed during candidate training or development evaluation.

---

## 20. Production Invariance

Phase 6.4.7 operated strictly as an offline experimental training phase. Production detection guarantees were rigorously maintained:

1. **Model Registry Invariance**:
   [model_registry.json](file:///C:/Users/prati/seva-cyber-sandbox/models/model_registry.json) was not modified. No candidate models were added to the production registry.
2. **Active Configuration Invariance**:
   [active_model_config.json](file:///C:/Users/prati/seva-cyber-sandbox/models/active_model_config.json) remains in `shadow` operating mode pointing to baseline `custom-mlp-v1.1.0-preproc`.
3. **Production Risk Score Delta**:
   Risk scoring delta remains strictly `0`. The candidate models have zero influence on live message classification or risk scoring.
4. **Existing Checkpoint Invariance**:
   Pre-existing checkpoints `models/custom_mlp_v1.0.0/` and `models/experimental_custom_v1/` were verified bit-for-bit unchanged.

---

## 21. Remaining Limitations

While candidate models achieved 100% development set accuracy, several technical boundaries remain:

1. **Development Set Size**: The development partition comprises 300 records across 6 campaign families. While this establishes clear superiority over baseline on these specific templates, true multi-family generalization across unseen variants can only be determined through independent qualification testing.
2. **Devanagari Formal Legal Phrasing**: Seed 101 missed 1 Devanagari high-court extortion record, illustrating that nuanced Marathi legal vocabulary remains sensitive to random initialization variance.
3. **Offline Synthetic Constraints**: All training and development records were generated synthetically following Phase 6.4.6 templates. Real-world distribution shifts in adversarial attacker phrasing will require continuous monitoring through privacy-preserving feedback ingestion once deployed.

---

## 22. Statement on Qualification Evaluation

> [!IMPORTANT]
> **QUALIFICATION BENCHMARK HAS NOT OCCURRED**  
> In accordance with Seva Cyber Sandbox governance, no qualification evaluation was performed during Phase 6.4.7. The sealed partition `data/generated/v4/synthetic_qualification_corpus.jsonl` has not been opened, loaded, vectorized, or evaluated against any candidate model. Candidate `candidate_v4_seed42` is qualified solely on development data and is strictly awaiting authorized qualification benchmarking in a future phase.
