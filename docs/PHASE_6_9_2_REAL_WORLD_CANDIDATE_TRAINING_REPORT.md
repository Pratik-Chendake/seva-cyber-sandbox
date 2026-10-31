# Phase 6.9.2 — Controlled Real-World Candidate Model Training Report

**Project:** Seva Cyber Sandbox  
**Execution Date:** 2026-10-31  
**Phase Verdict:** **PASS**  
**Operational Training Status:** **`PAUSED_BLOCKED_BY_GATE`** (Gate Verdict: `BLOCKED_INSUFFICIENT_EVIDENCE`)  
**Operating Mode:** `shadow`  
**Active Model (Preserved):** `custom-mlp-v4.0.0-seed42` (Inference Authoritative: `false`, Score Delta: `0.00`)  
**Baseline Model:** `custom-mlp-v1.1.0-preproc`  
**Target Operational Database:** `instance/seva_cases.sqlite3`  
**Candidate Trainer:** [src/real_world_candidate_trainer.py](file:///c:/Users/prati/seva-cyber-sandbox/src/real_world_candidate_trainer.py)  
**Test Suite:** `tests/test_phase6_9_2_candidate_training.py` (3/3 passing)  

---

## 1. Executive Summary

Phase 6.9.2 implements and verifies the controlled candidate neural model trainer ([src/real_world_candidate_trainer.py](file:///c:/Users/prati/seva-cyber-sandbox/src/real_world_candidate_trainer.py)). The training engine provides a reproducible, local-first pipeline to train candidate neural networks on verified dataset splits while strictly enforcing all governance and safety invariants.

In strict adherence to the **Real-World Evidence Blocker Rule**, operational candidate retraining is currently paused and blocked because the production database holds 0 citizen evidence records. Attempting operational training without gate clearance raises `TrainingBlockedError`.

The underlying neural architecture, random initialization guarantees, 1024-dimensional feature extraction, and artifact serialization were validated through isolated test fixtures with 3 passing tests.

---

## 2. Key Architecture Implementations

### 2.1 Pre-Flight Gate Enforcement
- **Gate Call:** Before allocating training resources or reading dataset files, `RealWorldCandidateTrainer.train_from_dataset()` evaluates `TrainingReadinessGate`.
- **Hard Blocker:** If the gate returns `allow_training == False`, execution halts immediately with `TrainingBlockedError`.
- **Zero Production Intrusion:** Active configuration files (`models/active_model_config.json`) and runtime registries are never modified during training attempts.

### 2.2 Neural Architecture & Random Initialization
- **Architecture:** 3-layer feedforward Multi-Layer Perceptron (1024 input features $\to$ 64 $\to$ 32 $\to$ 3 classes).
- **Feature Pipeline:** 1024-dimensional character n-gram hashing with `CharacterNGramHasher` over multilingual text inputs.
- **Random Initialization Guarantee:** Parameters ($W_1, b_1, W_2, b_2, W_3, b_3$) are initialized strictly from scratch using He normal and Xavier uniform distributions governed by an explicit seed. Zero pretrained weights are utilized.
- **Loss & Optimizer:** Categorical Cross-Entropy with Adam optimization, leaky ReLU activations ($\alpha=0.01$), and L2 weight decay ($0.0001$).
- **Environment:** Pure local CPU execution with NumPy. ₹0 budget, zero external APIs, zero GPU dependencies.

### 2.3 Artifact Serialization & Cryptographic Verification
Candidate checkpoints are saved under immutable directories in `models/candidates/<candidate_version>/`:
1. `model_weights.npz`: Compressed NumPy weight arrays serialized with `allow_pickle=False`.
2. `training_metadata.json`: Complete provenance metadata including random seed, training sample counts, epoch histories, train/dev accuracy metrics, and the SHA-256 digest of `model_weights.npz`.
3. `status`: Set strictly to `"candidate_unqualified"` with `is_active_model: false` and `is_production_authoritative: false`.

### 2.4 Model Governance Invariant Guarantee
The trainer programmatically asserts that the production active model configuration remains:
- `active_model_version`: `custom-mlp-v4.0.0-seed42`
- `operating_mode`: `shadow`
- `is_production_authoritative`: `false`
- Score delta vs deterministic engine: `0.00`

---

## 3. Test Suite Verification

| Test Name | Focus | Result |
| :--- | :--- | :--- |
| `test_operational_candidate_training_blocked_by_gate` | Operational training attempt raises `TrainingBlockedError` and leaves active model config untouched | **PASS** |
| `test_candidate_training_on_valid_dataset` | Trains candidate model from random init on valid dataset, verifies SHA-256 and metadata invariants | **PASS** |
| `test_empty_training_split_rejection` | Rejects missing or unpopulated dataset directories with `FileNotFoundError` | **PASS** |

**Phase 6.9.2 Test Summary:** 3/3 tests passed (1.48s).

---

## 4. Phase Verdict

**VERDICT: PASS**  
The candidate retraining engine is fully implemented, verified, and adheres strictly to the Real-World Evidence Blocker Rule. Active model `custom-mlp-v4.0.0-seed42` remains safely preserved in shadow mode.
