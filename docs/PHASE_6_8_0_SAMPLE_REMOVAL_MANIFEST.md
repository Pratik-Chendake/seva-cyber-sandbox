# Seva Cyber Sandbox — Phase 6.8.0
# Sample Removal and Asset Governance Manifest

**Date:** 2026-10-31  
**Project:** `C:\Users\prati\seva-cyber-sandbox`  
**Phase:** 6.8.0 — Product Conversion from Simulation into Real Cybersecurity Application  
**Authoritative Status:** Purely local, offline asset audit and governance tracking  

---

## 1. Executive Summary

This manifest documents the classification, removal, archival, and retention of all demonstration, simulated, and synthetic assets across the Seva Cyber Sandbox repository. 

As part of Phase 6.8.0, all user-facing demonstration artifacts, sample dropdown selectors, simulation toggles, and pre-filled scenarios have been removed from the operational application (`app.py`). The application now operates exclusively on genuine inputs submitted by actual users. Historical research datasets and qualification partitions remain cryptographically locked and preserved for scientific reproducibility and regression testing.

---

## 2. Complete Asset Classification Inventory

Every sample, synthetic, test, or operational artifact is classified according to the 7 required categories:

| Artifact Path | Classification Category | Action Taken | Rationale & Governance Rule |
| :--- | :--- | :--- | :--- |
| `app.py` (Tab 1 Sample Selector) | 1. User-Facing Demo / Sample | **REMOVED** | Removed selectbox and sample messages dropdown. Replaced with clean text area and file uploader for exported messages (`.txt`). |
| `app.py` (Tab 1 WhatsApp Webhook Simulator) | 1. User-Facing Demo / Sample | **REMOVED** | Removed simulated inbound webhook trigger and mock outbox display. Replaced with operational status expander detailing manual submission workflow and helpline links. |
| `app.py` (Tab 2 Pre-Generated APKs Selector) | 1. User-Facing Demo / Sample | **REMOVED** | Removed selector allowing users to choose sample APKs. Replaced with genuine `.apk` file uploader only (max 15 MB) with strict static validation. |
| `app.py` (Tab 3 Sample URLs Selector) | 1. User-Facing Demo / Sample | **REMOVED** | Removed selectbox containing MSEDCL lookalike, Bank KYC, and shortener samples. Replaced with genuine URL text input and passive offline analysis. |
| `app.py` (Tab 4 Quick-Fill Scheme Claims Selector) | 1. User-Facing Demo / Sample | **REMOVED** | Removed selectbox containing pre-filled Ladki Bahin, Namo Shetkari, and Free Laptop lures. Replaced with genuine input fields for claims and links. |
| `app.py` (Tab 6 Legacy 20-Sample Baseline) | 1. User-Facing Demo / Sample | **REMOVED** | Removed Section 3 which executed `train_and_evaluate_local_model()` on `sample_messages.json`. The UI now displays leak-free benchmark statistics only. |
| `instance/seva_cases.sqlite3` (12 test session rows) | 4. Automated Test Fixture / Demo Data | **CLEANED** | Backed up to `instance/seva_cases.sqlite3.bak_phase6_8_0` and removed from `threat_cases`. Ensures fresh application starts with 0 cases. |
| `data/sample_messages.json` | 2. Synthetic Training Data | **ARCHIVED** | Archived to `data/archive/legacy_samples/sample_messages.json` and documented in `data/archive/notes/ARCHIVE_NOTES.md`. Decoupled from runtime imports in `app.py`. |
| `data/archive/legacy_samples/sample_messages.json` | 7. Historical Audit Artifact | **RETAINED** | Retained in archive for historical provenance and regression verification (`test_03_sample_messages_json_has_expected_structure_when_present`). |
| `data/archive/notes/ARCHIVE_NOTES.md` | 7. Historical Audit Artifact | **CREATED** | Documents governance notes, origin, and boundaries of the archived legacy demonstration dataset. |
| `data/generated/` (v1, v2, v3, v4 synthetic corpora) | 2. Synthetic Training Data | **RETAINED (ISOLATED)** | Retained strictly in offline research directories for reproducible candidate training. Completely decoupled from operational application. |
| `data/phishing_eval_dataset.json` (39 records) | 3. Synthetic / Benchmark Evaluation Data | **RETAINED (FROZEN)** | Retained as leak-free benchmark evaluation dataset. Hash verified by `data/locked_test_manifest.json`. Never opened or modified. |
| `data/locked_test_manifest.json` | 7. Historical Audit Artifact | **RETAINED (LOCKED)** | Cryptographic manifest securing the 39-record benchmark dataset. Immutable. |
| `data/generated/v3/qualification_manifest.json` | 7. Historical Audit Artifact | **RETAINED (LOCKED)** | Retired qualification partition manifest for v3 candidate evaluation. Never reopened. |
| `data/generated/v4/qualification_manifest.json` | 7. Historical Audit Artifact | **RETAINED (LOCKED)** | One-time independent qualification manifest for Phase 6.4.8. Immutable and sealed. |
| `data/official_sources.json` | 5. Actual Application Code / Data | **RETAINED (ACTIVE)** | Verified catalog of official Government of Maharashtra Resolutions and state portals. Used for deterministic scheme verification. |
| `sample_apks/` (5 test APK packages) | 4. Automated Test Fixture | **RETAINED (ISOLATED)** | Retained strictly as non-executable static test fixtures for automated regression tests (`test_apk_structural_parser.py`). |
| `tests/` (Unit & Integration test suites) | 4. Automated Test Fixture | **RETAINED (ACTIVE)** | All test suites run against isolated temporary SQLite databases (`conftest.py`), ensuring zero operational database pollution. |
| `tests/test_phase6_8_0_product_conversion.py` | 4. Automated Test Fixture | **CREATED** | 45 new automated tests verifying genuine inputs, empty-state readiness, database-backed metrics, and sample data absence. |
| `models/candidates/candidate_v4_seed42/` | 5. Actual Application Code / Checkpoint | **RETAINED (ACTIVE)** | Qualified candidate weights and metadata. Active model operating in `shadow` mode (`is_production_authoritative: false`). |
| `models/active_model_config.json` | 5. Actual Application Code / Config | **RETAINED (ACTIVE)** | Active configuration confirming `custom-mlp-v4.0.0-seed42` in `shadow` mode, LKG `custom-mlp-v1.1.0-preproc`. |

---

## 3. Safe Deletion & Archival Verification

1. **Backup Verification:**
   - Database pre-cleanup state backed up to: `instance/seva_cases.sqlite3.bak_phase6_8_0`.
   - File size: 200,704 bytes.
2. **Provenance-Based Selective Pruning:**
   - Rows removed from `threat_cases`: exactly 12 records, each positively matching test sessions (`integration-session-01`, `integration-session-02`, `webhook-case-store-test`, `session-user-alice`, `test-export-session`).
   - Active database row count: `0` threat cases, `0` indicators, `0` human reviews, `0` disagreement events.
3. **No Accidental Data Loss:**
   - No user-generated records existed prior to cleanup; all removed rows were test execution leftovers.
   - All schema tables (`threat_cases`, `threat_indicators`, `human_reviews`, `training_feature_records`, `model_disagreement_events`, `disagreement_reviews`, etc.) remain fully initialized and ready.

---

## 4. Operational Application Boundaries

- **Zero Hardcoded Statistics:** All metrics on the Bento overview, threat cases tab, review desk, and feedback analytics originate from live SQLite database queries.
- **Fail-Closed Privacy:** Real submissions undergo sanitization via `src/privacy_gate.py` before case creation or feature extraction.
- **Authoritative Determinism:** The active neural model operates strictly in `shadow` mode with a permanent score delta of `0.00`. Production scoring authority remains 100% governed by deterministic cybersecurity rules.
