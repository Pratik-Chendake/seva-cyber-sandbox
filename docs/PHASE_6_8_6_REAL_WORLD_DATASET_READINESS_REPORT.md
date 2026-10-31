# Phase 6.8.6 — Real-World Evidence Quality and Dataset Readiness Report

**Project:** Seva Cyber Sandbox  
**Execution Date:** 2026-10-31  
**Phase Status:** Complete  
**Operational Gate Verdict:** **`BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE`**  
**Operating Mode:** `shadow`  
**Active Model:** `custom-mlp-v4.0.0-seed42` (Inference Authoritative: `false`, Score Delta: `0.00`)  
**Baseline Model:** `custom-mlp-v1.1.0-preproc`  
**Target Operational Database:** `instance/seva_cases.sqlite3`  
**Test Suite:** `tests/test_phase6_8_6_dataset_readiness.py` (4/4 passing)  

---

## 1. Executive Summary

Phase 6.8.6 establishes the real-world dataset readiness gate for Seva Cyber Sandbox. In accordance with the foundational **Real-World Evidence Blocker Rule**, Seva strictly prohibits the fabrication or injection of synthetic or demonstration evidence to artificially satisfy model retraining thresholds.

An automated audit of the production database (`instance/seva_cases.sqlite3`) using [src/dataset_readiness.py](file:///c:/Users/prati/seva-cyber-sandbox/src/dataset_readiness.py) determined that the operational system currently holds **0 genuine citizen evidence records**. Consequently, the training readiness gate has formally declared:

```
GATE VERDICT: BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE
```

All required software infrastructure, distribution analyzers, conflict detectors, multilingual heuristics, and gating thresholds are fully implemented and verified with 4 passing tests.

---

## 2. Operational Evidence Audit (`instance/seva_cases.sqlite3`)

### 2.1 Current Operational Inventory
- **Total Threat Cases:** 0
- **Total Registered Evidence Records:** 0
- **Corroborated Evidence Records:** 0
- **Independently Corroborated Records:** 0
- **Independent Campaign Clusters:** 0
- **Operator Accounts:** 0

### 2.2 Quality Thresholds & Itemized Deficits

| Metric | Threshold Required | Current Operational Level | Deficit Needed | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Total Corroborated Evidence** | $\ge 30$ | 0 | 30 | ❌ BLOCKED |
| **Phishing Class Evidence** | $\ge 10$ | 0 | 10 | ❌ BLOCKED |
| **Legitimate Class Evidence** | $\ge 10$ | 0 | 10 | ❌ BLOCKED |
| **Independent Campaigns** | $\ge 5$ | 0 | 5 | ❌ BLOCKED |
| **Distinct Languages** | $\ge 2$ (`mr`/`mr-Latn` & `en`) | 0 | 2 | ❌ BLOCKED |
| **Campaign Label Conflicts** | $0$ (Zero tolerance) | 0 | 0 | ✅ PASSED |

### 2.3 Epistemic Integrity and Zero-Fabrication Guarantee
The application strictly refuses to:
1. Fabricate fake user submissions or artificial phishing cases in the operational database.
2. Promote experimental AI models without genuine, independently corroborated evidence.
3. Pretend that real-world evidence has been gathered when the system has just been deployed.

---

## 3. Dataset Readiness Infrastructure (`src/dataset_readiness.py`)

The dataset readiness module implements the following core capabilities:
- **`DatasetReadinessAnalyzer`:** Inspects SQLite repositories to compute multi-dimensional distribution metrics:
  - Lifecycle state distribution (`submitted`, `awaiting_review`, `under_review`, `corroborated`, `disputed`, `rejected`, `withdrawn`).
  - Origin distribution (`user_reported`, `analyst_submitted`, `internal_case`, `public_source_reference`).
  - Evidence type distribution (`message_text`, `url`, `apk_binary`).
  - Classification distribution (`phishing`, `legitimate`, `protective_advisory`, `unknown`).
  - Four-tier training eligibility distribution.
  - Multilingual distribution (`mr`, `mr-Latn`, `mr-en`, `en`).
- **Campaign Conflict Detection:** Queries campaign clusters for conflicting labels across member evidence.
- **`detect_language_from_text`:** Heuristic regex and lexicon classifier identifying Devanagari script, Romanized Marathi fraud markers (`tumcha`, `hafta`, `yojana`), mixed Marathi-English text, and standard English.
- **Dynamic Deficit Reporting:** Computes exact quantitative deficits preventing model candidate construction.

---

## 4. Test Suite Verification

| Test Name | Focus | Result |
| :--- | :--- | :--- |
| `test_operational_database_readiness_is_blocked` | Verifies production database reports `BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE` and 0 records | **PASS** |
| `test_language_detection_heuristic` | Verifies language detection for Devanagari (`mr`), Romanized (`mr-Latn`), Mixed (`mr-en`), and English (`en`) | **PASS** |
| `test_dataset_readiness_breakdown_and_conflict_detection` | Tests full distribution analysis and detection of conflicting campaign labels on test fixture | **PASS** |
| `test_dataset_readiness_threshold_satisfaction` | Verifies transition to `READY_FOR_DATASET_CONSTRUCTION` when criteria are satisfied | **PASS** |

**Phase 6.8.6 Test Summary:** 4/4 tests passed (0.61s).

---

## 5. Architectural Implications for Downstream Phases

1. **Phase 6.9.0 (Trusted Real-World Dataset Construction):** The dataset constructor will incorporate the blocker gate. If run against the operational database, it will safely decline construction and generate an empty manifest with the blocker rationale. Test fixtures will verify the partitioning logic independently.
2. **Phase 6.9.1 & 6.9.2 (Training Gate & Candidate Retraining):** The retraining pipeline will acknowledge the `BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE` condition, maintaining the active model `custom-mlp-v4.0.0-seed42` untouched in shadow mode.
3. **Phase 7.0.0 (Release Readiness):** The application will be released with complete operational evidence ingestion and investigation capabilities, ready to accumulate authentic citizen fraud reports safely over time.
