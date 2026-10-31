# Phase 6.9.0 — Trusted Real-World Dataset Construction Report

**Project:** Seva Cyber Sandbox  
**Execution Date:** 2026-10-31  
**Phase Verdict:** **PASS**  
**Operational Status:** **`CONSTRUCTION_BLOCKED`** (In adherence to Real-World Evidence Blocker Rule)  
**Operating Mode:** `shadow`  
**Active Model:** `custom-mlp-v4.0.0-seed42` (Inference Authoritative: `false`, Score Delta: `0.00`)  
**Baseline Model:** `custom-mlp-v1.1.0-preproc`  
**Target Operational Database:** `instance/seva_cases.sqlite3`  
**Blocked Manifest:** `data/real_world_datasets/manifest_blocked.json`  
**Test Suite:** `tests/test_phase6_9_0_dataset_construction.py` (4/4 passing)  

---

## 1. Executive Summary

Phase 6.9.0 implements the trusted real-world dataset construction engine ([src/dataset_constructor.py](file:///c:/Users/prati/seva-cyber-sandbox/src/dataset_constructor.py)) for Seva Cyber Sandbox. The constructor safely partitions corroborated evidence into isolated training, development, sealed evaluation, and excluded datasets with strict campaign-family boundary enforcement and cryptographic SHA-256 manifest generation.

In compliance with the foundational **Real-World Evidence Blocker Rule**, running the constructor against the live operational database (`instance/seva_cases.sqlite3`) correctly triggered the Phase 6.8.6 readiness gate, issuing `CONSTRUCTION_BLOCKED` without fabricating artificial records. Independent partitioning logic, campaign isolation, and cryptographic integrity were fully verified on isolated test fixtures with 4 passing tests.

---

## 2. Key Architecture Implementations

### 2.1 Campaign-Family Isolation Architecture
To prevent overoptimistic evaluation metrics and campaign-level data leakage between training and evaluation splits:
- **Campaign Grouping:** All evidence items belonging to the same `campaign_id` cluster are treated as an indivisible atomic unit.
- **Deterministic Partitioning:** Whole campaign families are assigned to exactly one split (`train`, `dev`, or `sealed_eval`).
- **Disjointness Guarantees:**
  $$\text{Campaigns}_{\text{train}} \cap \text{Campaigns}_{\text{dev}} = \emptyset$$
  $$\text{Campaigns}_{\text{train}} \cap \text{Campaigns}_{\text{eval}} = \emptyset$$
  $$\text{Campaigns}_{\text{dev}} \cap \text{Campaigns}_{\text{eval}} = \emptyset$$
- Evaluated models are therefore tested against genuinely unseen threat campaigns rather than familiar lures from seen campaigns.

### 2.2 Four-Tier Eligibility Filter & Exclusion Pipeline
Only high-assurance evidence items may enter training or evaluation splits:
- **Eligible Splits (`train`, `dev`, `sealed_eval`):** Requires `lifecycle_status == 'corroborated'`, active citizen consent (`consent_given == True`), unwithdrawn state, and definitive ground truth classification (`phishing`, `legitimate`, `protective_advisory`).
- **Excluded Split (`excluded.jsonl`):** Records with uncorroborated status, revoked/missing consent, withdrawn state, or conflicting/unknown labels are routed to `excluded.jsonl` with an explicit diagnostic `exclusion_reason`.

### 2.3 Cryptographic SHA-256 Manifest Generation
For reproducible and tamper-evident dataset generation:
- Each split file is written with strict byte-level newline uniformity (`newline="\n"`).
- The constructor computes incremental SHA-256 hashes for every file.
- `manifest.json` encapsulates per-split counts, class distributions, campaign tallies, random seed, and cryptographic hashes.

---

## 3. Operational Blocker Verification

When executed against the actual operational database (`instance/seva_cases.sqlite3`):
```json
{
  "manifest_version": "1.0.0",
  "status": "CONSTRUCTION_BLOCKED",
  "reason": "BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE",
  "total_records": 0,
  "deficits": {
    "corroborated_samples_needed": 30,
    "phishing_samples_needed": 10,
    "legitimate_samples_needed": 10,
    "independent_campaigns_needed": 5
  }
}
```
The constructor refuses to generate empty or pseudo-trained splits from production data, preserving epistemic integrity.

---

## 4. Test Suite Verification

| Test Name | Focus | Result |
| :--- | :--- | :--- |
| `test_operational_database_dataset_construction_blocked` | Operational DB triggers blocked manifest and zero-record output | **PASS** |
| `test_campaign_family_isolation_and_zero_leakage` | Validates complete campaign disjointness across train, dev, and sealed eval | **PASS** |
| `test_ineligible_records_routed_to_excluded` | Verifies uncorroborated, unconsented, and withdrawn records route to `excluded.jsonl` | **PASS** |
| `test_split_cryptographic_hashes_match_files` | Verifies byte-for-byte SHA-256 hash matching between manifest and disk artifacts | **PASS** |

**Phase 6.9.0 Test Summary:** 4/4 tests passed (1.61s).

---

## 5. Phase Verdict

**VERDICT: PASS**  
The dataset construction engine is fully operational, mathematically enforces campaign isolation, generates cryptographic manifests, and strictly respects the Real-World Evidence Blocker Rule.
