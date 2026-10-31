# Data Archive Governance Notes — Phase 6.8.0

## Overview
As part of **Phase 6.8.0 — Product Conversion**, Seva Cyber Sandbox has transitioned from an educational demonstration and synthetic simulation sandbox into a genuine local cybersecurity application.

Operational application workflows now accept and process real evidence submitted directly by users. All sample messages and synthetic demonstration datasets have been removed from user-facing workflows.

## Archived Artifacts

### 1. Legacy Educational Messages (`data/archive/legacy_samples/sample_messages.json`)
- **Origin:** Phase 1 demonstration dataset containing 20 curated synthetic examples (Marathi, Romanized Marathi, Mixed Marathi-English, and English).
- **Status:** Archived. Removed from operational UI selectors, pre-filled inputs, and import-time execution in `app.py`.
- **Integrity:** Preserved as an immutable historical artifact for auditability and regression verification (`test_03_sample_messages_json_has_expected_structure_when_present`).
- **Safety Boundary:** These records must never be exposed as active threat intelligence or preloaded user cases in the operational system.

## Governance Guarantees
1. **Zero Contamination:** Archived legacy samples are not auto-loaded by `app.py` or `SessionCaseStore`.
2. **Audit Preservation:** Hashes and historical reports referencing `sample_messages.json` remain verifiable.
3. **Empty-State Verification:** Fresh installations start with 0 threat cases, 0 reviews, and 0 indicators.
