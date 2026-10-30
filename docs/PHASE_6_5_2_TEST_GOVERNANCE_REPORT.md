# Seva Cyber Sandbox — Phase 6.5.2
# Historical Test Isolation and Regression Governance Hardening Report

**Project:** Seva Cyber Sandbox  
**Phase:** 6.5.2 (Historical Test Isolation and Regression Governance Hardening)  
**Date:** October 30, 2026  
**Auditor / Engineer:** Antigravity Agentic Security & Quality Assurance  
**Operating Mode:** `shadow`  
**Active Neural Model:** `custom-mlp-v4.0.0-seed42`  
**Last Known Good (Rollback Target):** `custom-mlp-v1.1.0-preproc`  
**Locked Test Manifest Hash:** `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`  
**Execution Budget:** ₹0 (100% Local CPU, Zero Network Calls)  

---

## 1. Executive Summary

During the Phase 6.5.1 Independent Security and Regression Audit, a governance defect was identified:
- **Finding ID SEC-6.5.1-01 (Medium):** Historical test suites (`test_phase6_4_*.py`) directly read mutable workspace configuration (`models/active_model_config.json`) and live exposure ledgers. When candidate `custom-mlp-v4.0.0-seed42` was promoted to active shadow status in Phase 6.5, tests designed to verify earlier baseline configurations failed, causing assertions to be temporarily broadened to tuple memberships (e.g., `in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")`). Furthermore, certain unit tests in `tests/test_phase6_5_shadow_promotion.py` executed live rollback and reactivation commands directly against the workspace config.

Phase 6.5.2 has successfully resolved this coupling:
1. **Isolated Test Fixtures:** Created hermetic, immutable test fixtures under [`tests/fixtures/model_configs/`](file:///C:/Users/prati/seva-cyber-sandbox/tests/fixtures/model_configs/) and [`tests/fixtures/exposure_ledgers/`](file:///C:/Users/prati/seva-cyber-sandbox/tests/fixtures/exposure_ledgers/).
2. **Exact Historical Assertions Restored:** Eliminated permissive tuple assertions; restored strict scenario-specific equality checks (`== "custom-mlp-v1.1.0-preproc"`, `exposure_count == 0`, `current_status == "UNEXPOSED"`).
3. **Test-Induced Mutation Prevention:** Refactored tests 17 and 23 in `tests/test_phase6_5_shadow_promotion.py` to operate strictly on isolated temporary registries in `tmp_path`, guaranteeing zero runtime writes to live workspace configs.
4. **Dedicated Governance Suite:** Implemented [`tests/test_phase6_5_2_test_governance.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_5_2_test_governance.py) covering all 16 governance, isolation, entropy, and cryptographic integrity requirements.
5. **Telemetry Privacy Terminology Review:** Clarified docstrings and comments regarding pseudorandom `uuid.uuid4()` event IDs, documenting local operational log correlation boundaries and prohibiting claims of unconditional anonymity.
6. **Full Regression Clean Pass:** All **575 tests** (100%) passed in 27.14s with zero failures, zero warnings, and zero skipped tests.

---

## 2. Historical Test Coupling Findings

A forensic review of the historical test files revealed two primary mechanisms of state coupling:

### A. Live Active Configuration Permeation
Historical tests written in Phases 6.4.3 through 6.4.8 were designed to verify that candidate training, candidate evaluation, or pre-qualification audits did not modify the then-active baseline model (`custom-mlp-v1.1.0-preproc`). However, these tests directly read the mutable live workspace file [`models/active_model_config.json`](file:///C:/Users/prati/seva-cyber-sandbox/models/active_model_config.json). When Phase 6.5 legally updated this file to promote candidate v4, the historical tests broke because the workspace state had evolved.

### B. Live Exposure Ledger Permeation
Tests in Phase 6.4.6 and 6.4.7 verified that the v4 qualification partition remained unexposed. When Phase 6.4.8 executed the sealed evaluation, the qualification exposure ledger was transitioned to `EVALUATION_COMPLETED` (exposure count = 1). When earlier dataset generation tests re-inspected this live ledger, they detected `exposure_count == 1`, requiring an assertion broadening to `in (0, 1)`.

### C. In-Test Mutation of Live Configuration
In `tests/test_phase6_5_shadow_promotion.py`:
- `test_17_rollback_to_previous_shadow_model`: Instantiated default `RollbackController()`, rolled back the live workspace config, and then reactivated candidate v4 with `operator_label="test_suite"`.
- `test_23_shadow_disable_control`: Switched the live workspace config to `rules_only` mode and restored it in a `finally` block.
If either test was interrupted or failed midway, the live production configuration would remain corrupted or disabled.

---

## 3. Exact Assertions Corrected

All broadened assertions across the historical test suites were replaced with strict, scenario-specific assertions backed by isolated fixtures:

| Test File | Test Name | Broadened Assertion (Phase 6.5) | Corrected Strict Assertion (Phase 6.5.2) | Fixture / Snapshot Used |
| :--- | :--- | :--- | :--- | :--- |
| [`tests/test_phase6_4_candidate_evaluation.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_candidate_evaluation.py#L72-L79) | `test_01_correct_baseline_model_identification` | `assert base_info["model_version"] in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")` | `assert base_info["model_version"] == "custom-mlp-v1.1.0-preproc"` | `tests/fixtures/model_configs/pre_phase6_5_baseline.json` via `evaluator.discover_baseline_model(active_config_path=...)` |
| [`tests/test_phase6_4_3_controlled_training.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_3_controlled_training.py#L452-L461) | `test_20_active_model_config_unmodified` | `assert config.get("active_model_version") in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")` | `assert config.get("active_model_version") == "custom-mlp-v1.1.0-preproc"` | `tests/fixtures/model_configs/pre_phase6_5_baseline.json` |
| [`tests/test_phase6_4_4_qualification.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_4_qualification.py#L514-L522) | `test_24_active_model_configuration_remains_unchanged` | `assert cfg.get("active_model_version") in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")` | `assert cfg.get("active_model_version") == "custom-mlp-v1.1.0-preproc"` | `tests/fixtures/model_configs/pre_phase6_5_baseline.json` |
| [`tests/test_phase6_4_6_dataset_v4.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_6_dataset_v4.py#L384-L394) | `test_21_qualification_lifecycle_and_exposure_ledger_unexposed` | `assert entry["current_status"] in ("UNEXPOSED", "EVALUATION_COMPLETED")`<br>`assert entry["exposure_count"] in (0, 1)` | `assert entry["exposure_count"] == 0`<br>`assert entry["is_exposed"] is False`<br>`assert entry["current_status"] == "UNEXPOSED"`<br>`assert entry["first_exposed_at_utc"] is None`<br>`assert len(entry["events"]) == 0` | Pristine generation ledger [`data/generated/v4/exposure_ledger.json`](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/exposure_ledger.json) |
| [`tests/test_phase6_4_6_dataset_v4.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_6_dataset_v4.py#L461-L473) | `test_26_model_registry_and_active_config_unchanged` | `assert cfg["active_model_version"] in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")` | `assert cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"` | `tests/fixtures/model_configs/pre_phase6_5_baseline.json` |
| [`tests/test_phase6_4_7_controlled_training.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_7_controlled_training.py#L146-L157) | `test_04_qualification_ledger_remains_unexposed` | `assert entry["current_status"] in ("UNEXPOSED", "EVALUATION_COMPLETED")`<br>`assert entry["exposure_count"] in (0, 1)` | `assert entry["exposure_count"] == 0`<br>`assert entry["is_exposed"] is False`<br>`assert entry["current_status"] == "UNEXPOSED"`<br>`assert entry["first_exposed_at_utc"] is None`<br>`assert len(entry["events"]) == 0` | Pristine generation ledger [`data/generated/v4/exposure_ledger.json`](file:///C:/Users/prati/seva-cyber-sandbox/data/generated/v4/exposure_ledger.json) |
| [`tests/test_phase6_4_7_controlled_training.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_7_controlled_training.py#L411-L420) | `test_20_active_model_config_remains_unchanged` | `assert cfg["active_model_version"] in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")` | `assert cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"` | `tests/fixtures/model_configs/pre_phase6_5_baseline.json` |
| [`tests/test_phase6_4_7_1_audit.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_7_1_audit.py#L502-L509) | `test_22_active_model_config_invariance` | `assert cfg.get("active_model_version") in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")` | `assert cfg.get("active_model_version") == "custom-mlp-v1.1.0-preproc"` | `tests/fixtures/model_configs/pre_phase6_5_baseline.json` |
| [`tests/test_phase6_4_8_qualification.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_8_qualification.py#L483-L490) | `test_22_active_model_config_unchanged` | `assert cfg["active_model_version"] in ("custom-mlp-v1.1.0-preproc", "custom-mlp-v4.0.0-seed42")` | `assert cfg["active_model_version"] == "custom-mlp-v1.1.0-preproc"` | `tests/fixtures/model_configs/pre_phase6_5_baseline.json` |

---

## 4. Fixture Architecture

To establish clear isolation boundaries, dedicated test fixtures were created under `tests/fixtures/`:

### A. Model Configuration Fixtures (`tests/fixtures/model_configs/`)
1. **[`pre_phase6_5_baseline.json`](file:///C:/Users/prati/seva-cyber-sandbox/tests/fixtures/model_configs/pre_phase6_5_baseline.json):**
   Frozen snapshot representing the system configuration prior to Phase 6.5 candidate promotion:
   ```json
   {
     "active_model_version": "custom-mlp-v1.1.0-preproc",
     "last_known_good_version": "custom-mlp-v1.0.0",
     "operating_mode": "shadow",
     "checkpoint_rel_path": "models/experimental_custom_v1",
     "preprocessing_version": "neural-preproc-v1.1.0",
     "is_production_authoritative": false
   }
   ```
2. **[`phase6_5_shadow_candidate.json`](file:///C:/Users/prati/seva-cyber-sandbox/tests/fixtures/model_configs/phase6_5_shadow_candidate.json):**
   Frozen snapshot representing the approved Phase 6.5 shadow configuration:
   ```json
   {
     "active_model_version": "custom-mlp-v4.0.0-seed42",
     "last_known_good_version": "custom-mlp-v1.1.0-preproc",
     "operating_mode": "shadow",
     "checkpoint_rel_path": "models/candidates/candidate_v4_seed42",
     "preprocessing_version": "neural-preproc-v1.1.0",
     "is_production_authoritative": false
   }
   ```
3. **[`rules_only_config.json`](file:///C:/Users/prati/seva-cyber-sandbox/tests/fixtures/model_configs/rules_only_config.json):**
   Standard fixture representing operator-disabled shadow diagnostics (`rules_only` mode).
4. **[`corrupt_config.json`](file:///C:/Users/prati/seva-cyber-sandbox/tests/fixtures/model_configs/corrupt_config.json):**
   Malformed/invalid configuration used for testing fail-safe and fail-closed error handling.

### B. Qualification Exposure Fixtures (`tests/fixtures/exposure_ledgers/`)
1. **[`unexposed_v4_ledger.json`](file:///C:/Users/prati/seva-cyber-sandbox/tests/fixtures/exposure_ledgers/unexposed_v4_ledger.json):**
   Pristine snapshot of the qualification ledger at dataset authoring time (`exposure_count: 0`, `current_status: "UNEXPOSED"`).

### C. System Integration Support
Underlying classes were updated to seamlessly support fixture redirection without breaking existing default paths:
- `CandidateEvaluator(active_config_path=...)` allows programmatic override.
- `ModelRegistry`, `SafeModelHolder`, and `HybridDecisionEngine` honor the optional environment variable `SEVA_ACTIVE_CONFIG_PATH`.
- When `SEVA_ACTIVE_CONFIG_PATH` is unset, all modules strictly default to `models/active_model_config.json`.

---

## 5. Current Model-State Integration Tests

A dedicated test suite [`tests/test_phase6_5_2_test_governance.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_5_2_test_governance.py) was implemented with 16 automated checks:

1. **`test_01_current_registered_candidate_version_and_provenance`:** Verifies `custom-mlp-v4.0.0-seed42` is registered in `models/model_registry.json` with exact checkpoint path and hashes.
2. **`test_02_current_lifecycle_state`:** Verifies lifecycle state is `approved_for_shadow`.
3. **`test_03_active_shadow_operating_mode`:** Verifies active configuration operates in `shadow` mode.
4. **`test_04_production_authoritative_flag_is_false`:** Confirms all registered neural models have `is_production_authoritative == False`.
5. **`test_05_last_known_good_model_identity`:** Confirms `last_known_good_version` is `custom-mlp-v1.1.0-preproc`.
6. **`test_06_candidate_artifact_hashes`:** Verifies weights SHA-256 (`3affa890...`) and metadata SHA-256 (`8bf38827...`).
7. **`test_07_deterministic_rules_authoritative_and_score_invariance`:** Verifies `production_score_difference == 0` across phishing, legitimate, and protective messages.
8. **`test_08_shadow_disable_preserves_deterministic_detection`:** Verifies `rules_only` mode disables neural inference while keeping deterministic rules fully functional.
9. **`test_09_rollback_restores_intended_previous_shadow_model`:** Tests rollback controller in an isolated fixture, confirming clean return to `custom-mlp-v1.1.0-preproc`.
10. **`test_10_historical_fixtures_exact_assertions_isolated`:** Verifies fixture isolation independence.
11. **`test_11_temporary_registry_and_active_config_isolation`:** Verifies `ModelRegistry(project_root=tmp_path)` confines all I/O to temporary space.
12. **`test_12_test_induced_mutation_prevention`:** Asserts byte-for-byte SHA-256 invariance of production config and registry before and after test operations.
13. **`test_13_random_telemetry_event_id_verification`:** Verifies `diagnostic_event_id` is 16 characters (`EVT-` + 12 hex) and non-message-derived (identical inputs yield distinct IDs).
14. **`test_14_corrupt_config_fallback_safety`:** Confirms engine fails safe to rules-only behavior when given `corrupt_config.json`.
15. **`test_15_model_artifacts_cryptographic_preservation`:** Verifies candidate and baseline weights and metadata SHA-256 digests.
16. **`test_16_locked_evaluation_manifest_digest_preservation`:** Verifies locked test manifest digest matches `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`.

---

## 6. Test-Induced Mutation Prevention

In `tests/test_phase6_5_shadow_promotion.py`:
- **`test_17_rollback_to_previous_shadow_model`:** Refactored to use pytest's `tmp_path`. It copies the models directory to temporary storage, runs `RollbackController(registry=reg)`, verifies the rollback behavior, and asserts that the real `models/active_model_config.json` remains completely untouched.
- **`test_23_shadow_disable_control`:** Refactored to operate on an isolated registry and temporary metrics file in `tmp_path`.

### Verification of Production Configuration Invariance:
Before running tests, the live `models/active_model_config.json` was restored to its official governance operator state:
```json
{
  "active_model_version": "custom-mlp-v4.0.0-seed42",
  "last_known_good_version": "custom-mlp-v1.1.0-preproc",
  "operating_mode": "shadow",
  "activated_at_utc": "2026-10-30T17:15:00.000000+00:00",
  "activated_by": "phase6_5_governance_operator",
  "activation_reason": "Promoted independently qualified Phase 6.4.8 candidate to approved shadow mode",
  "checkpoint_rel_path": "models/candidates/candidate_v4_seed42",
  "preprocessing_version": "neural-preproc-v1.1.0",
  "is_production_authoritative": false
}
```
After executing the entire test suite (575 tests), SHA-256 hash checks confirmed that `models/active_model_config.json` and `models/model_registry.json` were **0% modified**.

---

## 7. Telemetry Identifier Review

Diagnostic event identifiers generated in [`src/hybrid_decision_engine.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py#L617-L623) and reported to [`src/shadow_controller.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/shadow_controller.py) were audited:

### Findings:
1. **Random Generation Verified:** Event IDs are generated via `f"EVT-{uuid.uuid4().hex[:12].upper()}"`. They are strictly pseudorandom and have zero mathematical relationship to message text, sender details, or case IDs. Consecutive identical messages produce completely different IDs.
2. **Clarification of Anonymity Claims:** Docstrings and code comments were corrected. Pseudorandom event IDs should **not** be characterized as "inherently non-linkable" or "anonymous" in an absolute sense:
   - If an operational logging layer logs both the raw message text and the returned audit dictionary in the same log record or trace context, correlation is possible within local logs.
   - Documentation was added emphasizing that local operational log retention must be restricted to the minimum required operational period (e.g., debugging session or 30-day rotation), and external log export is prohibited.
3. **Aggregate Telemetry Metrics Store:** [`models/shadow_metrics.json`](file:///C:/Users/prati/seva-cyber-sandbox/models/shadow_metrics.json) stores **zero event IDs**, **zero text**, and **zero message hashes**; it stores only coarse integer aggregate counts (total evaluations, agreements, disagreements, breakdown categories).

---

## 8. Local-Only Security Boundary Verification

The application security perimeter was inspected:

1. **Loopback Binding ([`.streamlit/config.toml`](file:///C:/Users/prati/seva-cyber-sandbox/.streamlit/config.toml)):**
   ```toml
   [server]
   address = "127.0.0.1"
   port = 8501
   headless = true
   enableCORS = false
   enableXsrfProtection = true
   ```
2. **Network Isolation:** No network sockets, external HTTP requests, or third-party telemetry libraries exist in the project.
3. **Operator Controls Boundary:** Administrative functions (`enable_shadow_inference`, `disable_shadow_inference`, `rollback_model`) execute strictly via local Python calls on localhost.
4. **Authentication Limitation Note:** As documented in SEC-6.5.1-02, the local Streamlit dashboard currently lacks password/token authentication. It is safe exclusively because it is bound to `127.0.0.1`. Binding to `0.0.0.0` or exposing via reverse proxy without an enterprise authentication layer remains strictly prohibited.

---

## 9. Model and Registry Integrity Verification

Every model artifact, registry entry, and sealed evaluation dataset was verified against its canonical cryptographic SHA-256 digest:

| Artifact | File Path | Registered / Expected SHA-256 Digest | Verified File SHA-256 Digest | Status |
| :--- | :--- | :--- | :--- | :---: |
| Candidate Weights | `models/candidates/candidate_v4_seed42/model_weights.npz` | `3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f` | `3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f` | **MATCH** |
| Candidate Metadata | `models/candidates/candidate_v4_seed42/model_metadata.json` | `8bf388271453b805c148b17232972f6adbe1a4689370893159454b7fe61cafa3` | `8bf388271453b805c148b17232972f6adbe1a4689370893159454b7fe61cafa3` | **MATCH** |
| Baseline Weights | `models/experimental_custom_v1/model_weights.npz` | `d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20` | `d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20` | **MATCH** |
| Baseline Metadata | `models/experimental_custom_v1/model_metadata.json` | `23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8` | `23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8` | **MATCH** |
| Sealed v4 Qual Corpus | `data/generated/v4/synthetic_qualification_corpus.jsonl` | `d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e` | `d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e` | **MATCH** |
| Locked Test Manifest | `data/locked_test_manifest.json` (`sha256_checksum`) | `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` | `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` | **MATCH** |

---

## 10. Full Regression Test Execution Results

- **Test Command:** `& "C:\Users\prati\AppData\Local\Programs\Python\Python314\python.exe" -m pytest -q`
- **Exit Code:** `0`
- **Execution Time:** `27.14 seconds`
- **Total Tests Collected:** `575`
- **Total Tests Passed:** `575` (100.0%)
- **Total Tests Failed:** `0`
- **Total Tests Skipped:** `0`
- **Growth from Phase 6.5.1 Baseline:** `+16 tests` (559 -> 575)

---

## 11. Remaining Risks

1. **Synthetic Nature of Evaluated Distributions:**
   While candidate v4 passed the benchmark and historical tests are now hermetically isolated, all neural models were trained on synthetic corpora. Real-world vernacular variations in rural Maharashtra may produce unexpected false alarms or missed detections in shadow diagnostics.
2. **Disagreement Telemetry Interpretation:**
   Model-rule disagreements reflect differing statistical distributions, not verified ground truth. The deterministic rules remain authoritative, and diagnostic disagreements should inform future training data curation rather than automated policy decisions.
3. **Localhost Single-User Assumption:**
   The Streamlit operator dashboard is intended solely for local workstation inspection by authorized operators. It must not be deployed in shared multi-user environments without session authentication.

---

## 12. Final Verdict

All historical test state-coupling issues (finding `SEC-6.5.1-01`) have been resolved. Hermetic fixtures have been established, strict exact assertions have been restored across all historical test files, test-induced mutations of live production configuration have been completely prevented, telemetry privacy terminology has been clarified, and the entire test suite of 575 tests passes with 100% success.

```
================================================================================
                    PHASE 6.5.2 AUDIT FINAL VERDICT
                                [ PASS ]
================================================================================
```

---
*End of Report. In accordance with governance instructions, Phase 6.5.2 is complete and execution is halted. Phase 6.6 will not proceed without explicit operator authorization.*
