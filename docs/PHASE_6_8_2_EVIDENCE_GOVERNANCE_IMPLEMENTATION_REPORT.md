# PHASE 6.8.2 IMPLEMENTATION REPORT
## Real-World Evidence Collection, Provenance Tracking, Lifecycle Governance, and Reviewer Accountability

**Project:** Seva Cyber Sandbox  
**Repository Path:** `C:\Users\prati\seva-cyber-sandbox`  
**Execution Date:** 2026-10-31  
**Budget:** ₹0.00 (Zero external API, cloud, or network dependencies)  
**Host Binding:** Strictly bound to `127.0.0.1`  
**Active Model:** `custom-mlp-v4.0.0-seed42` (Operating Mode: `shadow`, Production Authoritative: `false`, Score Delta: `0.00`)  
**Baseline / Rollback Model:** `custom-mlp-v1.1.0-preproc`  
**Production Authority:** Deterministic Detection Rules and Maharashtra Government Resolutions  
**Full Test Suite Status:** **734 / 734 passing** (100% pass rate in 38.88s)

---

### Executive Summary

Phase 6.8.2 establishes a hardened, offline, ₹0-budget evidence collection, provenance tracking, lifecycle state machine, reviewer authentication, and training eligibility gating architecture for Seva Cyber Sandbox.

Prior to Phase 6.8.2, user submissions were stored as raw cases with unauthenticated operator attribution (`local_operator_unauthenticated`) and lacked formal origin categorisation, append-only state transition auditing, independent corroboration guarantees, or poisoned data prevention for candidate model training.

Phase 6.8.2 introduces:
1. **Traceable Evidence Provenance:** Controlled attribution across 6 origins (`user_reported`, `analyst_submitted`, `internal_case`, `public_source_reference`, `system_generated`, `synthetic_test_data`).
2. **7-Stage Evidence Lifecycle State Machine:** Strict state transition validation (`submitted -> awaiting_review -> under_review -> corroborated | disputed | rejected | withdrawn`) with an append-only SQLite audit log. Direct jumps (e.g. `submitted -> corroborated`) are programmatically blocked.
3. **Local Operator PBKDF2-HMAC-SHA256 Authentication:** Reviewer accountability powered by standard library cryptography (200,000 iterations, 32-byte salts, constant-time `hmac.compare_digest` verification, and cryptographic 256-bit session tokens). Safe initial operator bootstrap without hardcoded default passwords.
4. **Independent Corroboration Engine:** Requires non-empty rationale ($\ge 15$ characters), definitive outcome classification (`phishing`, `legitimate`, `protective_advisory`), and authenticated reviewer identity.
5. **Strict 8-Point Training Eligibility Gate:** Prevents unconsented, unverified, disputed, withdrawn, or conflicting evidence from ever entering candidate model training datasets.
6. **Campaign Clustering & Conflict Detection:** Automatic clustering by APK SHA-256 and domain, with automated conflict detection for mixed human labels.
7. **Safe SQLite Migration v2 & Rollback:** Transaction-enclosed schema migration with pre-migration atomic file backups and safe restoration.

---

### 1. Existing Architecture Reused

Phase 6.8.2 builds directly upon the existing Seva Cyber Sandbox codebase without duplicating components:

| Component | File Path | Phase Reused From | Role in Phase 6.8.2 |
|---|---|---|---|
| `CaseRepository` | `src/case_repository.py` | Phase 1 & 5 | Persistent SQLite storage, WAL mode, transaction isolation, retention pruning. Extended with schema v2 tables. |
| `SessionCaseStore` | `src/case_manager.py` | Phase 5 & 6.8.0 | Session-isolated case management and factory methods (`create_apk_case`, `create_message_case`, `create_url_case`, `create_scheme_case`). Extended with provenance hooks. |
| `PrivacyGate` | `src/privacy_gate.py` | Phase 6.1.1 | Fail-closed PII redaction (`[PHONE_REDACTED]`, `[AADHAAR_REDACTED]`). Safe external transmission remains permanently disabled (`safe_to_send = False`). |
| `DisagreementEngine` | `src/disagreement_engine.py` | Phase 6.6 | Shadow inference discrepancy detection between deterministic rules and `custom-mlp-v4.0.0-seed42`. |
| `FeedbackAnalytics` | `src/feedback_analytics.py` | Phase 6.6 | Agreement rate tracking and comparative accuracy assessment between rules and shadow models. |
| `ModelRegistry` | `src/model_registry.py` | Phase 5.2 | Model checkpoint verification, metadata governance, and atomic rollback controls. |
| `Streamlit UI` | `app.py` | Phase 6.8.0 | Real cybersecurity workbench UI. Extended with Tab 07 Operator Authentication bar, Evidence Queue, and Governance Inspector. |

---

### 2. New Provenance Implementation

Every case logged in the system now possesses traceable evidence provenance recorded in the `evidence_provenance` SQLite table.

#### Controlled Evidence Origins (`ALLOWED_EVIDENCE_ORIGINS`):
- `user_reported`: Genuine submissions from external citizen/user ingress.
- `analyst_submitted`: Direct submissions by verified security analysts.
- `internal_case`: Internally identified investigation findings.
- `public_source_reference`: Public advisories (e.g. Cert-In, Mumbai Cyber Cell).
- `system_generated`: Automated telemetry or scheduled monitors.
- `synthetic_test_data`: Synthetic test fixtures. Strictly excluded from operational evidence and training.

#### Provenance Schema (`evidence_provenance`):
```sql
CREATE TABLE IF NOT EXISTS evidence_provenance (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_origin TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    lifecycle_status TEXT NOT NULL DEFAULT 'submitted',
    user_classification TEXT,
    model_prediction TEXT,
    rule_assessment TEXT,
    reviewer_classification TEXT,
    corroborated_conclusion TEXT,
    corroboration_rationale TEXT NOT NULL DEFAULT '',
    campaign_id TEXT,
    consent_given INTEGER NOT NULL DEFAULT 0,
    consent_timestamp_utc TEXT,
    sanitization_status TEXT NOT NULL DEFAULT 'unverified',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
```

#### Privacy & Data Integrity Guarantees:
- **Zero Raw Text Stored in Provenance:** Original message texts and APK binaries are never stored in `evidence_provenance`.
- **Foreign Key Integration:** Linked directly to `threat_cases.case_id`.

---

### 3. Evidence Lifecycle State Machine

The evidence lifecycle enforces a strict state machine to prevent unverified citizen reports from masquerading as verified threat intelligence.

#### Supported Lifecycle States (`ALLOWED_LIFECYCLE_STATUSES`):
1. `submitted`: Initial state upon user or analyst submission.
2. `awaiting_review`: Triage queue, ready for analyst assignment.
3. `under_review`: Active human analyst investigation underway.
4. `corroborated`: Independently verified with non-empty rationale and definitive classification.
5. `disputed`: Conflicting evidence or contested indicator attribution.
6. `rejected`: Corrupted, unparseable, or invalid submission.
7. `withdrawn`: Submitter revoked consent or requested erasure. **Terminal State.**

#### State Transition Graph:
```
[submitted] ───────► [awaiting_review] ───────► [under_review]
     │                      │                          │
     │                      │                          ├──────► [corroborated] ───► [disputed]
     │                      │                          ├──────► [disputed]    ───► [under_review]
     │                      │                          ├──────► [rejected]    ───► [under_review]
     │                      │                          └──────► [awaiting_review]
     ▼                      ▼                                      │
[withdrawn] ◄──────────────┴───────────────────────────────────────┘
  (Terminal)
```

#### Enforced Transition Rules:
- Direct jump from `submitted` to `corroborated` raises `InvalidStateTransitionError`.
- Direct jump from `awaiting_review` to `corroborated` raises `InvalidStateTransitionError`.
- Once `withdrawn`, all outgoing transitions raise `InvalidStateTransitionError`.
- Every transition is written to `evidence_lifecycle_audit`.

---

### 4. Local Operator Authentication and Reviewer Accountability

To replace unauthenticated operator labels (`local_operator_unauthenticated`) without introducing paid external SaaS dependencies or cloud IAM:

#### Cryptographic Architecture (`src/operator_auth.py`):
1. **Password Hashing:** PBKDF2-HMAC-SHA256 with **200,000 iterations** via Python standard library `hashlib.pbkdf2_hmac`.
2. **Cryptographic Salt:** 32 bytes (256 bits) of cryptographically secure randomness generated via `secrets.token_bytes(32)`.
3. **Constant-Time Verification:** Password comparisons strictly use `hmac.compare_digest` to prevent timing side-channel attacks.
4. **Session Tokens:** 256-bit hexadecimal tokens (`secrets.token_hex(32)`) stored in `operator_sessions` with configurable expiration (default 8 hours) and explicit revocation on logout.
5. **Zero Plaintext Storage:** Plaintext passwords are never persisted to disk, logs, session state, or export dumps.
6. **Safe Initial Setup:** If no operator accounts exist, the system permits the registration of an initial administrator account. Once registered, initial setup locks permanently. No hardcoded default credentials exist.

---

### 5. Multi-Layer Evidence Classification

The platform maintains strict separation across all five analytical layers without overwriting:

| Layer | Source | Valid Values | Mutability | Overwritten By Other Layers? |
|---|---|---|---|---|
| User Classification | User report | `phishing`, `legitimate`, `unknown` | Immutable | **NO** |
| Model Prediction | Shadow Neural Model | `phishing`, `legitimate`, `advisory` | Immutable | **NO** |
| Rule Assessment | Deterministic Rules | `Critical`, `High`, `Suspicious`, `Safe` | Immutable | **NO** |
| Reviewer Classification | Authenticated Operator | `phishing`, `legitimate`, `advisory`, `unknown` | Mutable by Operator | **NO** |
| Corroborated Conclusion | Independent Verification | `phishing`, `legitimate`, `advisory` | Gated by Corroboration | **NO** |

---

### 6. Independent Corroboration Engine

Corroboration represents verified cybersecurity intelligence, distinct from repeated submissions of the same lure.

#### Mandatory Corroboration Requirements:
1. **Active State:** Current lifecycle status must be `under_review` (or `disputed`).
2. **Authenticated Operator:** State transition must be executed by an authenticated reviewer account.
3. **Substantive Verification Rationale:** Must provide `corroboration_rationale` of **at least 15 characters** detailing independent verification (e.g. DNS analysis, malware hashes, official portal confirmation).
4. **Definitive Label:** `corroborated_conclusion` must be `phishing`, `legitimate`, or `protective_advisory`. An `unknown` label raises `CorroborationError`.

---

### 7. Training Eligibility Gate

To protect future neural models from data poisoning, ambiguous lures, and privacy violations, Phase 6.8.2 defines an 8-point gate in `CaseRepository.check_training_eligibility()`:

```python
checks = {
    "consent_valid": bool,               # 1. Affirmative user consent granted and not revoked
    "provenance_valid": bool,            # 2. Genuine origin (not synthetic or system-generated)
    "human_review_completed": bool,      # 3. Status is strictly 'corroborated'
    "classification_definitive": bool,   # 4. Label is phishing, legitimate, or advisory (NOT unknown)
    "not_withdrawn": bool,               # 5. Status is NOT 'withdrawn'
    "privacy_sanitization_passed": bool, # 6. Sanitization status is 'passed'
    "conflict_resolved": bool,           # 7. No conflicting labels within assigned campaign
    "feature_vector_available": bool,    # 8. 1024-d derived feature vector exists in DB
}
```

If **any** check fails, `is_eligible` is `False`, and descriptive governance assessment notes are returned.

---

### 8. Campaign Clustering and Duplicate Handling

To prevent multiple reports of the same campaign from skewing evaluation or poisoning training:
1. **Automated Clustering:**
   - APK files are clustered by `apk_sha256`.
   - URLs and domains are clustered by normalized `domain`.
2. **Conflict Detection (`get_campaign_conflict_status`):**
   - If different analysts or submissions within the same campaign assign conflicting labels (e.g. one `phishing` and one `legitimate`), `is_conflict` is set to `True`.
   - Conflicted campaigns fail Check #7 of the Training Eligibility Gate.
3. **Operator Reassignment:**
   - Authenticated analysts can reassign evidence items to different campaigns or correct false cluster linkages.

---

### 9. Safe SQLite Database Migration and Rollback

Database schema upgrades follow strict zero-data-loss standards:

```python
from src.database_migration import migrate_to_evidence_governance_v2, rollback_migration

# Migration
result = migrate_to_evidence_governance_v2("instance/seva_cases.sqlite3", create_backup=True)
# Result: {"success": True, "migration_id": "20261031_01_evidence_governance_v2", "backup_path": "..."}

# Safe Rollback (if required)
rollback_migration(result["backup_path"], "instance/seva_cases.sqlite3")
```

#### Safety Guarantees:
- **Automatic Backup:** Atomic copy created before executing any DDL.
- **Transaction Safety:** Enclosed in `BEGIN TRANSACTION` / `COMMIT`. If any statement fails, rolls back cleanly.
- **Non-Destructive:** Uses `ALTER TABLE ADD COLUMN` and `CREATE TABLE IF NOT EXISTS`.
- **Backward-Compatible:** Historical tests asserting `SELECT MAX(version) FROM schema_version == 1` continue to pass without regression.

---

### 10. User Interface Enhancements (Tab 07 Operator Desk)

Tab 07 in `app.py` has been updated with genuine, database-connected controls:

1. **Authentication Header Bar:**
   - Displays authenticated operator username, role, and expiration.
   - Provides first-time setup form when 0 operators exist.
   - Provides login/logout forms when operators exist.
2. **Subtab `07A // HUMAN REVIEW DESK`:**
   - Attributes reviews to the authenticated operator.
3. **Subtab `07B // EVIDENCE GOVERNANCE & PROVENANCE`:**
   - **Metrics Ribbon:** Counts for Total, Submitted, Awaiting Review, Under Review, Corroborated, Disputed, Withdrawn.
   - **Queue & Filters:** Filter by Evidence Origin and Lifecycle Status.
   - **Evidence Inspector:** Displays full metadata, classification breakdown, and corroboration rationale.
   - **Training Eligibility Inspector:** Visual checklist of all 8 eligibility criteria with explanatory notes.
   - **State Transition Form:** Only permits valid next transitions; enforces corroboration rationale.
   - **Campaign Cluster Explorer:** Displays campaign details and highlights conflicts.
   - **Withdrawal Action:** Fast one-click evidence withdrawal with reason input.
   - **Append-Only Audit Trail Viewer:** Displays full history of who changed what, when, and why.

---

### 11. Automated Test Results

A dedicated test suite was implemented in `tests/test_phase6_8_2_evidence_governance.py`.

#### Test Run Summary:
```
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\prati\seva-cyber-sandbox
configfile: pytest.ini
testpaths: tests
plugins: anyio-4.15.1
collected 734 items

tests/test_apk_structural_parser.py ................                     [  2%]
tests/test_case_manager.py ..........                                    [  3%]
tests/test_case_repository.py ..................                         [  5%]
tests/test_custom_model.py .................                             [  8%]
tests/test_dataset_deconfounding.py ................                     [ 10%]
tests/test_dataset_preprocessing.py ................                     [ 12%]
tests/test_dataset_provenance.py ................                        [ 14%]
tests/test_hybrid_decision_engine.py ................                    [ 17%]
tests/test_independent_apk_validation.py .....                           [ 17%]
tests/test_integration.py ....                                           [ 18%]
tests/test_phase5_2_registry_hardening.py .............                  [ 20%]
tests/test_phase5_review_registry.py .....................               [ 22%]
tests/test_phase6_1_feedback_curation.py ............................    [ 26%]
tests/test_phase6_2_pattern_discovery.py .......................         [ 29%]
tests/test_phase6_3_continuous_training.py ........................      [ 33%]
tests/test_phase6_4_2_dataset_v3.py ....................                 [ 35%]
tests/test_phase6_4_3_controlled_training.py .....................       [ 38%]
tests/test_phase6_4_4_qualification.py .........................         [ 42%]
tests/test_phase6_4_6_dataset_v4.py ...........................          [ 45%]
tests/test_phase6_4_7_1_audit.py .......................                 [ 48%]
tests/test_phase6_4_7_controlled_training.py ......................      [ 51%]
tests/test_phase6_4_8_qualification.py ........................          [ 55%]
tests/test_phase6_4_candidate_evaluation.py ........................     [ 58%]
tests/test_phase6_5_2_test_governance.py ................                [ 60%]
tests/test_phase6_5_shadow_promotion.py .........................        [ 64%]
tests/test_phase6_6_human_feedback.py .................................. [ 68%]
................                                                         [ 70%]
tests/test_phase6_7_end_to_end.py ..............................         [ 74%]
tests/test_phase6_8_0_product_conversion.py ............................ [ 78%]
.................                                                        [ 81%]
tests/test_phase6_8_2_evidence_governance.py ........................... [ 84%]
.......                                                                  [ 85%]
tests/test_phishing_evaluation.py ..............                         [ 87%]
tests/test_privacy_gate.py ....................                          [ 90%]
tests/test_sandbox.py ........................                           [ 93%]
tests/test_scheme_verifier.py ..........                                 [ 94%]
tests/test_threat_intelligence.py ................                       [ 97%]
tests/test_url_analyzer.py ...........                                   [ 98%]
tests/test_whatsapp_integration.py ..........                            [100%]

============================ 734 passed in 38.88s =============================
```

**Results:**
- Phase 6.8.2 New Tests: **34 / 34 passing** (100%).
- Full Repository Suite: **734 / 734 passing** (100%).
- Regressions Detected: **0**.

---

### 12. Remaining Limitations

1. **Hardware Memory Residuals:** While Python immediately drops raw text and does not write it to disk or SQLite, Python's runtime memory management (garbage collector and string interning) does not guarantee cryptographic memory wiping on host RAM.
2. **Local Identity Boundary:** Operator authentication is enforced locally within SQLite. In a multi-user network environment, an external identity provider (LDAP, SAML, OAuth2) or hardware tokens would be required for non-repudiation.
3. **Automated Campaign Disambiguation:** Campaign clustering currently relies on exact APK SHA-256 and normalized domain matching. Advanced fuzzy text clustering (e.g. MinHash LSH or Jaccard text similarity) remains an offline analytical capability.

---

### 13. Production Configuration Verification

| Governance Control | Expected Value | Verified Value | Compliance Status |
|---|---|---|---|
| Active Model Name | `custom-mlp-v4.0.0-seed42` | `custom-mlp-v4.0.0-seed42` | **VERIFIED PASS** |
| Operating Mode | `shadow` | `shadow` | **VERIFIED PASS** |
| Production Authoritative | `false` | `false` | **VERIFIED PASS** |
| Last Known Good Version | `custom-mlp-v1.1.0-preproc` | `custom-mlp-v1.1.0-preproc` | **VERIFIED PASS** |
| Model Delta Impact | `0.00` | `0.00` | **VERIFIED PASS** |
| Production Rule Primacy | Deterministic Rules | Deterministic Rules | **VERIFIED PASS** |
| Model Retraining / Updates | Strictly Blocked | Strictly Blocked | **VERIFIED PASS** |
| Budget & Cloud Boundaries | ₹0.00 / 100% Local | ₹0.00 / 100% Local | **VERIFIED PASS** |

---

### 14. Phase Conclusion

Phase 6.8.2 has achieved all objectives without modifying existing model weights, reopening qualification datasets, altering production threat scoring, or introducing external network dependencies. Seva Cyber Sandbox now possesses a reliable evidence collection, provenance, and verification architecture ready for future controlled learning.
