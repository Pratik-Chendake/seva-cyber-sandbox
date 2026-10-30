# SEVA CYBER SANDBOX — PHASE 6.6
# Human-in-the-Loop Learning, Model Disagreement Analysis and Threat Pattern Review Report

**Repository:** `C:\Users\prati\seva-cyber-sandbox`  
**Execution Date:** 2026-10-30  
**Phase:** 6.6 (Master Implementation)  
**Operating Mode:** `shadow`  
**Active Shadow Model:** `custom-mlp-v4.0.0-seed42` (Lifecycle: `approved_for_shadow`, `is_production_authoritative: false`)  
**Rollback Target (LKG):** `custom-mlp-v1.1.0-preproc`  
**Evaluation Digest (Locked Test Partition):** `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda`  
**Status:** PASS  

---

## 1. Initial Architecture Audit

Prior to implementing Phase 6.6, an architectural audit was conducted across the live system components:
1. **Authoritative Decision Engine ([`src/hybrid_decision_engine.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/hybrid_decision_engine.py)):**
   - The production risk scoring is strictly ruled by deterministic rules (`deterministic_rules`) and allowlists.
   - Operating mode is strictly set to `shadow`.
   - The experimental neural network operates purely as a parallel diagnostic probe (`experimental_model`).
   - Production risk score difference is guaranteed to be exactly `0.00` across all message categories.
2. **Model Registry & Governance ([`models/model_registry.json`](file:///C:/Users/prati/seva-cyber-sandbox/models/model_registry.json), [`models/active_model_config.json`](file:///C:/Users/prati/seva-cyber-sandbox/models/active_model_config.json)):**
   - Active model: `custom-mlp-v4.0.0-seed42`, registered with lifecycle state `approved_for_shadow`.
   - Last known good (LKG) rollback target: `custom-mlp-v1.1.0-preproc`.
   - Production authoritative flag: `false`.
3. **Database Layer ([`src/case_repository.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/case_repository.py)):**
   - Implemented SQLite tables for `threat_cases`, `case_indicators`, `threat_intel_leads`, `human_reviews`, `review_audit_log`, and `training_feature_records`.
   - Deduplication and privacy gating were in place for Phase 6.1.1 (`curate_training_features`, `export_curated_training_features`), requiring affirmative user consent and a dedicated HMAC secret (`SEVA_FEEDBACK_HMAC_KEY`).
4. **Pattern Discovery ([`src/pattern_discovery.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/pattern_discovery.py)):**
   - Pattern catalogues (`models/pattern_catalog/`) held candidate feature-association hypotheses generated from synthetic or curated datasets.
   - Catalogue review allowed human state transitions (`draft`, `approved_by_human`, `rejected`, `needs_more_evidence`), writing append-only audit entries to `pattern_review_audit.jsonl`.
5. **Gaps Identified for Phase 6.6:**
   - No structured detection or persistence of discrepancies between deterministic rules and the shadow neural model.
   - No dedicated review queue for disagreements.
   - No automated bridge allowing completed disagreement reviews to enter the Phase 6.1.1 curation pipeline.
   - Streamlit review desk lacked dedicated UI panels for model disagreement review and candidate fraud pattern governance.

---

## 2. Disagreement-Detection Architecture

The disagreement-detection subsystem is implemented in [`src/disagreement_engine.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/disagreement_engine.py) via `DisagreementEngine`.

### Architecture & Data Flow

```
+-----------------------------------------------------------------------------------+
|                              CITIZEN INPUT MESSAGE                                |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        HYBRID DECISION ENGINE (Shadow Mode)                       |
|  1. Deterministic Rule Engine ------> Authoritative Production Risk Score (100%)    |
|  2. Shadow Neural MLP (v4-seed42) --> Diagnostic Shadow Prediction (Score Delta=0) |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        DISAGREEMENT ENGINE (Diagnostic Probe)                     |
|  - Compares Canonical Rule Outcome vs Neural Prediction                           |
|  - Maps to: 'agreement', 6 pairwise disagreements, or 'non_comparable'             |
|  - Extracts coarse script, language, length, and confidence buckets               |
|  - Generates pseudorandom non-derived Event ID (EVT-XXXXXXXXXXXX)                |
+-----------------------------------------+-----------------------------------------+
                                          |
              +---------------------------+---------------------------+
              |                                                       |
        Consent = False                                         Consent = True
              |                                                       |
              v                                                       v
+---------------------------+                           +---------------------------+
| Persist Event Metadata    |                           | Local Privacy Gate        |
| - Coarse Buckets Only     |                           |   sanitize_for_local_     |
| - Zero Feature Vectors    |                           |   training()              |
| - feature_record_id: None |                           +-------------+-------------+
+---------------------------+                                         |
                                                        Norm Text & HMAC Deduplication
                                                        (SEVA_FEEDBACK_HMAC_KEY)
                                                                      |
                                                                      v
                                                        1024-d Char N-Gram Hasher
                                                        (CharacterNGramHasher)
                                                                      |
                                                                      v
                                                        Persist Feature Record
                                                        Link feature_record_id to Event
```

### Safety Guarantees
- **Strict Rule Primacy:** Disagreement detection executes strictly after deterministic risk scoring. It never modifies the final score, badge color, or citizen advisory text.
- **Score Invariance:** Production risk score difference is guaranteed to be `0.00`.
- **Non-Message-Derived Event IDs:** Every disagreement event receives a purely pseudorandom identifier (e.g. `EVT-4A8E012B9D3C`) generated via `uuid.uuid4()`. No MD5, SHA-1, or SHA-256 hashes of the message text are used as identifiers.

---

## 3. Decision Mapping and Non-Comparable Handling

To prevent artificial or misleading disagreement counts, the disagreement engine enforces a strict classification ontology across canonical threat classes: `{'phishing', 'legitimate', 'protective_advisory'}`.

### Pairwise Disagreement Mapping Matrix

| Rule Outcome (`rule_decision`) | Model Prediction (`model_prediction`) | Classified Event Type (`event_type`) | Review Priority |
| :--- | :--- | :--- | :--- |
| `phishing` | `phishing` | `agreement` | Normal (No review required) |
| `legitimate` | `legitimate` | `agreement` | Normal (No review required) |
| `protective_advisory` | `protective_advisory` | `agreement` | Normal (No review required) |
| `phishing` | `legitimate` | `rule_phishing_model_legitimate` | High (Potential Model False Negative) |
| `phishing` | `protective_advisory` | `rule_phishing_model_advisory` | High (Boundary Ambiguity) |
| `legitimate` | `phishing` | `rule_legitimate_model_phishing` | Critical (Potential Model False Positive) |
| `legitimate` | `protective_advisory` | `rule_legitimate_model_advisory` | Medium (Advisory Over-trigger) |
| `protective_advisory` | `phishing` | `rule_advisory_model_phishing` | High (Advisory Misclassified as Scam) |
| `protective_advisory` | `legitimate` | `rule_advisory_model_legitimate` | Medium (Advisory Under-trigger) |

### Non-Comparable Guardrails
The system classifies an evaluation as `non_comparable` rather than fabricating an artificial disagreement when:
1. **Operating Mode is Rules-Only:** Shadow inference was explicitly disabled (`operating_mode == "rules_only"` or `is_enabled == False`).
2. **Model Unavailable or Inference Error:** The neural model failed to load, was corrupt, had NaN/infinite weights, or timed out (`model_available == False` or `predicted_label is None`).
3. **Ambiguous or Unclassified Rule Output:** Deterministic rules returned empty, null, or unclassified labels (`rule_label in (None, 'empty', 'unknown', 'unclassified')`).

Every `non_comparable` event explicitly records human-readable diagnostic reasons in `metadata_json` (e.g., `"Operating mode is rules_only; neural model inference was disabled"`).

---

## 4. Consent and Derived-Feature Storage

The Seva Cyber Sandbox privacy architecture strictly prohibits retaining raw message text, raw URLs, or citizen personal identifiable information (PII) in operational databases.

### Privacy Gating & Feature Derivation Lifecycle
1. **Explicit Affirmative Consent Gate:**
   - If affirmative user consent is not given (`consent_given == False`), feature extraction is completely bypassed.
   - The event metadata is stored with `feature_record_id = NULL`.
2. **Local Sanitization Boundary:**
   - When consent is given (`consent_given == True`), text is processed through [`src.privacy_gate.sanitize_for_local_training`](file:///C:/Users/prati\seva-cyber-sandbox\src\privacy_gate.py).
   - Citizen phone numbers, Aadhaar numbers, PAN cards, bank account numbers, OTPs, and high-entropy secret tokens are sanitized and redacted.
   - If sanitization fails or flags suspicious high-entropy material, the gate **fails closed**: feature derivation aborts, no feature vector is persisted, and `feature_record_id` remains `NULL`.
3. **Canonical Normalization & N-Gram Feature Extraction:**
   - The sanitized string is normalized using [`preprocess_for_neural_model`](file:///C:/Users/prati/seva-cyber-sandbox/src/custom_model.py) (Unicode NFC, zero-width character stripping, Devanagari digit mapping).
   - An abstract, fixed-dimension numerical feature vector (1024 floats) is derived via [`CharacterNGramHasher(num_features=1024, min_n=3, max_n=5)`](file:///C:/Users/prati/seva-cyber-sandbox/src/custom_model.py).
   - Character n-gram hashing is mathematically non-invertible; raw words and message syntax cannot be reconstructed from feature indices.
4. **Keyed Deduplication Fingerprint:**
   - An HMAC-SHA256 fingerprint is calculated using the dedicated `SEVA_FEEDBACK_HMAC_KEY` (minimum 16 characters).
   - Threat intelligence keys (`SEVA_THREAT_INTEL_KEY` or `SEVA_HMAC_SECRET`) cannot substitute for the feedback key; missing or unconfigured keys fail closed.
5. **Immediate In-Memory Text Disposal:**
   - Both raw input text and intermediate sanitized strings are immediately deleted from Python runtime memory.

---

## 5. Database Schema Changes

Three new relational tables and supporting indexes were added to the SQLite database schema in [`src/case_repository.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/case_repository.py) inside `_init_tables()`:

### Table 1: `model_disagreement_events`
Stores diagnostic disagreement events without retaining raw text, URLs, or PII.

```sql
CREATE TABLE IF NOT EXISTS model_disagreement_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    rule_decision TEXT NOT NULL,
    model_prediction TEXT,
    model_version TEXT,
    rule_engine_version TEXT,
    model_confidence REAL,
    model_confidence_bucket TEXT,
    rule_score INTEGER,
    rule_score_bucket TEXT,
    language_category TEXT DEFAULT 'unknown',
    script_category TEXT DEFAULT 'unknown',
    message_length_bucket TEXT DEFAULT 'short (<100)',
    review_state TEXT NOT NULL DEFAULT 'pending',
    created_at_utc TEXT NOT NULL,
    consent_given INTEGER NOT NULL DEFAULT 0,
    feature_record_id TEXT,
    case_id TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_disagreement_review_state ON model_disagreement_events(review_state);
CREATE INDEX IF NOT EXISTS idx_disagreement_created_at ON model_disagreement_events(created_at_utc DESC);
CREATE INDEX IF NOT EXISTS idx_disagreement_event_type ON model_disagreement_events(event_type);
```

### Table 2: `disagreement_reviews`
Stores operator adjudications for disagreement events.

```sql
CREATE TABLE IF NOT EXISTS disagreement_reviews (
    review_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    review_state TEXT NOT NULL DEFAULT 'completed',
    outcome_label TEXT NOT NULL,
    reviewer_assessment TEXT NOT NULL,
    confidence_rating TEXT NOT NULL DEFAULT 'medium',
    reviewer_label TEXT NOT NULL DEFAULT 'local_operator_unauthenticated',
    notes TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    is_superseded INTEGER NOT NULL DEFAULT 0,
    superseded_by TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (event_id) REFERENCES model_disagreement_events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_disagree_rev_event ON disagreement_reviews(event_id);
CREATE INDEX IF NOT EXISTS idx_disagree_rev_state ON disagreement_reviews(review_state);
```

### Table 3: `disagreement_review_audit`
Append-only tamper-evident audit log of review lifecycle transitions.

```sql
CREATE TABLE IF NOT EXISTS disagreement_review_audit (
    audit_id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'local_operator_unauthenticated',
    timestamp_utc TEXT NOT NULL,
    reason TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_disagree_audit_rev ON disagreement_review_audit(review_id);
CREATE INDEX IF NOT EXISTS idx_disagree_audit_evt ON disagreement_review_audit(event_id);
CREATE INDEX IF NOT EXISTS idx_disagree_audit_ts ON disagreement_review_audit(timestamp_utc DESC);
```

---

## 6. Human-Review Workflow

The human-in-the-loop review workflow allows operators to adjudicate discrepancies between deterministic rules and neural models under strict safety rules.

```
+--------------------+
| Disagreement Event |  (review_state: 'pending')
+---------+----------+
          |
          v
+--------------------+
| Operator Triage    |
+----+---------------+
     |
     +---> Insufficient Evidence -> Outcome: 'insufficient_evidence' (Excluded from training)
     |
     +---> Adjudicated Decision   -> Outcome: 'phishing' | 'legitimate' | 'protective_advisory'
                                      Assessment: 'rules_correct' | 'model_correct' |
                                                  'both_investigate' | 'neither_sufficient'
                                      Confidence: 'high' | 'medium' | 'low'
                                      (review_state: 'completed')
                                      Audit Event: action: 'created'
     |
     +---> Subsequent Rescission -> supersede_existing = True
                                      Prior Review marked 'superseded' (is_superseded = 1)
                                      New Review recorded
                                      Audit Event: action: 'superseded' & action: 'created'
```

### Two Review Operating Modes
1. **Immediate Review:** Conducted while the message is in memory during interactive simulation. The operator has access to in-memory diagnostic signals. When the review is submitted, only structural metadata and consented feature vectors are persisted.
2. **Delayed Review:** Conducted asynchronously from the review desk. Because raw message text was never saved, the delayed review desk presents:
   - Coarse length bucket (`short (<100)`, `medium (100-300)`, `long (>300)`).
   - Detected script category and vernacular language category.
   - Rule engine findings count and extracted URLs count (no URL strings).
   - Original deterministic rule decision and score.
   - Shadow neural model prediction and confidence bucket.
   - If the available coarse observations are insufficient to make a determination, the operator selects `insufficient_evidence`. The interface explicitly indicates that original message text was safely discarded at ingestion time.

---

## 7. Reviewer Attribution Limitations

In accordance with sandbox governance, operator authentication is local and unauthenticated:
- **Recorded Attribution:** Every review and audit record explicitly stamps `reviewer_label: "local_operator_unauthenticated"`.
- **Epistemic Boundary:** Operator adjudications represent subjective local operator feedback hypotheses, **NOT** certified ground truth, cryptographically signed assertions, or infallible external ground truth.
- **Label Provenance:** Curated training exports mark `review_provenance: "local_operator_unauthenticated"` and `provenance_category: "local_curated_feedback"`.

---

## 8. Streamlit Dashboard Changes

[`app.py`](file:///C:/Users/prati/seva-cyber-sandbox/app.py) Tab 7 was extended additively with four organized subtabs:
1. `07A // HUMAN REVIEW DESK`: Existing threat case triage and indicator feedback desk.
2. `07B // MODEL REGISTRY & ROLLBACK`: Shadow model status, candidate registration table, rollback controls, and telemetry audit log.
3. `07C // FRAUD PATTERN DISCOVERY`: Discovered candidate feature associations, lift/support metrics, statistical uncertainty, and candidate pattern review controls (Approve / Reject / Request Evidence).
4. `07D // MODEL DISAGREEMENT REVIEW`: Dedicated desk for model-rule discrepancies:
   - **Summary Metric Cards:** Total Disagreements, Pending Queue, Completed Reviews, Insufficient Evidence Cases, Model False Negative Count, Model False Positive Count.
   - **Filterable Event Queue:** Filter by review state (`all`, `pending`, `completed`, `insufficient_evidence`, `superseded`), event type, or model version.
   - **Delayed Review Structural Inspector:** Displays coarse script/language category, rule findings count, URL count, and clear notice regarding raw text non-retention.
   - **Review Submission Form:** Outcome label, reviewer comparative assessment, confidence rating, rationale notes, and supersede toggle.
   - **Feedback Analytics & Reports:** Disagreement telemetry report, pairwise breakdown table, operator accuracy breakdown, and one-click JSON/Markdown download buttons.

---

## 9. Training-Corpus Integration

Phase 6.6 connects approved human-reviewed feedback to the existing Phase 6.1.1 curation pipeline (`curate_training_features` and `export_curated_training_features` in [`src/case_repository.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/case_repository.py)).

### Nine Mandatory Eligibility Criteria
A disagreement event enters future training exports **only** when all nine conditions are satisfied simultaneously:
1. **Affirmative Consent:** Explicit user consent exists (`consent_given == 1`).
2. **Valid Derived Features:** A 1024-dimensional feature vector exists and passes numerical finiteness checks.
3. **Completed Review:** A non-superseded review exists with `review_state == 'completed'`.
4. **Valid Canonical Label:** Outcome label belongs to `{'phishing', 'legitimate', 'protective_advisory'}`.
5. **High/Medium Confidence:** Low confidence reviews (`confidence == 'low'`) and `insufficient_evidence` outcomes are strictly excluded.
6. **Non-Superseded:** Superseded reviews (`is_superseded == 1`) are excluded.
7. **Unrevoked Consent:** `eligibility_state != 'consent_revoked'`.
8. **Deduplication:** Examples sharing identical HMAC-SHA256 deduplication fingerprints are deduplicated; only the earliest highest-confidence representative is exported.
9. **Provenance Tagging:** Output records explicitly retain `review_provenance: "local_operator_unauthenticated"`.

### Export Privacy Guarantees
The exported training dataset ([`export_curated_training_features`](file:///C:/Users/prati/seva-cyber-sandbox/src/case_repository.py)) strips:
- Citizen `case_id` and `event_id` (replaced with anonymous `example_id`).
- Internal HMAC deduplication fingerprints.
- Raw message text, sanitized text, and tokens.
- Reviewer rationale notes.
- Direct citizen personal identifiers.

---

## 10. Pattern Catalogue Review Integration

The review desk integrates candidate fraud patterns discovered in Phase 6.2 ([`src/pattern_discovery.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/pattern_discovery.py)).

### Pattern Review Safeguards
1. **No Automatic Approval:** Discovered candidate patterns always initialize in `draft` state. They can never become approved without human intervention.
2. **Audit Logging:** Every state transition (`approved_by_human`, `rejected`, `needs_more_evidence`) appends an audit event to `pattern_review_audit.jsonl` with actor attribution and rationale.
3. **Anti-Reactivation Guardrail:** Patterns marked `rejected` are permanently locked from silent reactivation to `approved_by_human`. Attempting silent reactivation raises `PatternReviewError`.
4. **Scoring Invariance:** An approved pattern is a human-reviewed hypothesis in the catalogue; it **never** automatically modifies deterministic detection rules or alters risk scores.
5. **Strict Provenance Separation:** Synthetic corpus patterns (`synthetic_corpus_v4`) and human-reviewed feedback patterns (`local_curated_feedback`) retain distinct provenance metadata and cannot be conflated.

---

## 11. Feedback Analytics

The feedback analytics module ([`src/feedback_analytics.py`](file:///C:/Users/prati/seva-cyber-sandbox/src/feedback_analytics.py)) compiles aggregate diagnostic statistics from local review tables without accessing message text or PII.

### Generated Metrics
- **Concordance Rates:** Overall agreement rate, disagreement rate, and non-comparable volume.
- **Pairwise Distribution:** Counts across all 6 canonical disagreement pairs.
- **Review Queue Health:** Pending, Completed, Insufficient Evidence, and Superseded counts.
- **Operator Assessment Distribution:** Percentage where rules appeared correct vs where neural model appeared correct.
- **Language & Script Stratification:** Devanagari, Latin (English), Latin (Vernacular Romanized Marathi), and Mixed Marathi-English distributions.
- **Model Version Comparison:** Concordance tracked per neural model version (`custom-mlp-v4.0.0-seed42`, `custom-mlp-v1.1.0-preproc`).

### Attribution Notice
All analytics outputs are explicitly titled and disclaimed as `local_operator_feedback_statistics`. The reports emphasize that metrics represent local unauthenticated operational feedback rather than formal statistical model accuracy.

---

## 12. Consent Revocation Behavior

When a citizen revokes consent via `revoke_training_consent(case_id)`:
1. `model_disagreement_events.consent_given` is atomically set to `0`.
2. `training_feature_records.eligibility_state` is set to `'consent_revoked'` and `consent_given` is set to `0`.
3. `metadata_json` records the revocation timestamp and reason (`user_revoked`).
4. Subsequent calls to `curate_training_features()` and `export_curated_training_features()` immediately exclude the record with reason `"consent_revoked"`.
5. Underlying event audit logs and disagreement history are preserved for operational accountability without retaining reusable training features.

---

## 13. Privacy and Security Boundaries

Phase 6.6 maintains strict isolation boundaries:
1. **Network Boundary:** 100% offline, local-only CPU execution. Zero outbound socket connections or cloud telemetry.
2. **Process Boundary:** Streamlit web application bound strictly to `127.0.0.1:8501`.
3. **Zero Raw Text Retention:** Zero raw message strings, sanitized texts, or raw URLs exist in `model_disagreement_events`, `disagreement_reviews`, or `disagreement_review_audit`.
4. **Secret Key Segregation:**
   - Dedicated feedback secret: `SEVA_FEEDBACK_HMAC_KEY` (minimum 16 characters).
   - Threat intelligence secret (`SEVA_THREAT_INTEL_KEY` / `SEVA_HMAC_SECRET`) cannot substitute. Missing key fails closed.
5. **Database Transaction Isolation:** All review submissions, superseding operations, and consent revocations execute within SQLite atomic transactions.

---

## 14. Production Scoring Invariance

Production risk scoring invariance was empirically verified across rules-only and shadow modes:
- **Authoritative Source:** Deterministic rule engine (`deterministic_rules`).
- **Production Score Difference:** Exactly `0.00` across all test messages.
- **Decision Invariance:** Review adjudications and pattern approvals do not modify active scoring weights, risk levels, badge colors, or citizen advice.

---

## 15. Rollback and Shadow-Mode Compatibility

The rollback mechanism implemented in Phase 6.5 remains fully operational alongside Phase 6.6:
- **Active Model:** `custom-mlp-v4.0.0-seed42` (Operating mode: `shadow`, `is_production_authoritative: false`).
- **Rollback Target:** `custom-mlp-v1.1.0-preproc` (verified present, SHA-256 intact, lifecycle: `last_known_good`).
- **Rollback Execution:** Verified via [`RollbackController`](file:///C:/Users/prati/seva-cyber-sandbox/src/rollback_controller.py) in test fixtures. Atomically restores prior configuration with full audit logging in `models/model_registry.json`.

---

## 16. Test Results

### Phase 6.6 Dedicated Test Suite
The comprehensive test suite [`tests/test_phase6_6_human_feedback.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_6_human_feedback.py) was executed:

```
tests/test_phase6_6_human_feedback.py::test_01_rules_and_model_agreement PASSED
tests/test_phase6_6_human_feedback.py::test_02_rules_phishing_model_legitimate PASSED
tests/test_phase6_6_human_feedback.py::test_03_rules_phishing_model_advisory PASSED
tests/test_phase6_6_human_feedback.py::test_04_rules_legitimate_model_phishing PASSED
tests/test_phase6_6_human_feedback.py::test_05_rules_legitimate_model_advisory PASSED
tests/test_phase6_6_human_feedback.py::test_06_rules_advisory_model_phishing PASSED
tests/test_phase6_6_human_feedback.py::test_07_rules_advisory_model_legitimate PASSED
tests/test_phase6_6_human_feedback.py::test_08_non_comparable_outputs PASSED
tests/test_phase6_6_human_feedback.py::test_09_missing_model_output PASSED
tests/test_phase6_6_human_feedback.py::test_10_corrupt_model_output PASSED
tests/test_phase6_6_human_feedback.py::test_11_rules_only_mode PASSED
tests/test_phase6_6_human_feedback.py::test_12_consent_disabled_means_no_message_derived_persistence PASSED
tests/test_phase6_6_human_feedback.py::test_13_consent_enabled_allows_valid_feature_capture PASSED
tests/test_phase6_6_human_feedback.py::test_14_no_raw_text_stored PASSED
tests/test_phase6_6_human_feedback.py::test_15_no_raw_url_stored PASSED
tests/test_phase6_6_human_feedback.py::test_16_no_pii_stored PASSED
tests/test_phase6_6_human_feedback.py::test_17_sanitization_failure_prevents_storage PASSED
tests/test_phase6_6_human_feedback.py::test_18_missing_hmac_secret_fails_closed PASSED
tests/test_phase6_6_human_feedback.py::test_19_threat_intel_secret_cannot_substitute_for_feedback_secret PASSED
tests/test_phase6_6_human_feedback.py::test_20_consent_revocation_excludes_future_training_exports PASSED
tests/test_phase6_6_human_feedback.py::test_21_pending_review_creation PASSED
tests/test_phase6_6_human_feedback.py::test_22_valid_review_completion PASSED
tests/test_phase6_6_human_feedback.py::test_23_invalid_review_labels_rejected PASSED
tests/test_phase6_6_human_feedback.py::test_24_duplicate_review_submission_rejected PASSED
tests/test_phase6_6_human_feedback.py::test_25_superseding_completed_reviews_creates_audit_entries PASSED
tests/test_phase6_6_human_feedback.py::test_26_insufficient_evidence_remains_excluded PASSED
tests/test_phase6_6_human_feedback.py::test_27_unauthenticated_provenance_preserved PASSED
tests/test_phase6_6_human_feedback.py::test_28_delayed_review_clearly_indicates_missing_raw_message_evidence PASSED
tests/test_phase6_6_human_feedback.py::test_29_review_decisions_do_not_alter_production_scores PASSED
tests/test_phase6_6_human_feedback.py::test_30_draft_pattern_cannot_be_automatically_approved PASSED
tests/test_phase6_6_human_feedback.py::test_31_human_approval_is_audited PASSED
tests/test_phase6_6_human_feedback.py::test_32_rejected_pattern_cannot_silently_reactivate PASSED
tests/test_phase6_6_human_feedback.py::test_33_pattern_approval_does_not_change_production_rules PASSED
tests/test_phase6_6_human_feedback.py::test_34_synthetic_and_human_reviewed_provenance_remain_separate PASSED
tests/test_phase6_6_human_feedback.py::test_35_only_eligible_reviewed_records_enter_future_training_exports PASSED
tests/test_phase6_6_human_feedback.py::test_36_pending_and_low_confidence_records_are_excluded PASSED
tests/test_phase6_6_human_feedback.py::test_37_superseded_reviews_are_excluded PASSED
tests/test_phase6_6_human_feedback.py::test_38_duplicate_feature_examples_are_not_counted_twice PASSED
tests/test_phase6_6_human_feedback.py::test_39_revoked_consent_is_excluded PASSED
tests/test_phase6_6_human_feedback.py::test_40_case_ids_and_hmac_fingerprints_are_absent_from_exports PASSED
tests/test_phase6_6_human_feedback.py::test_41_shadow_inference_does_not_alter_production_scoring PASSED
tests/test_phase6_6_human_feedback.py::test_42_disagreement_detection_failures_do_not_disrupt_normal_analysis PASSED
tests/test_phase6_6_human_feedback.py::test_43_existing_apk_analyzer_works PASSED
tests/test_phase6_6_human_feedback.py::test_44_existing_multilingual_phishing_detector_works PASSED
tests/test_phase6_6_human_feedback.py::test_45_existing_url_analyzer_works PASSED
tests/test_phase6_6_human_feedback.py::test_46_maharashtra_scheme_verifier_remains_functional PASSED
tests/test_phase6_6_human_feedback.py::test_47_existing_case_management_remains_functional PASSED
tests/test_phase6_6_human_feedback.py::test_48_audio_alerts_remain_functional PASSED
tests/test_phase6_6_human_feedback.py::test_49_existing_review_desk_remains_functional PASSED
tests/test_phase6_6_human_feedback.py::test_50_existing_shadow_rollback_remains_functional PASSED

============================= 50 passed in 1.30s ==============================
```

### Full Regression Suite Results
The complete regression test suite (`pytest -q`) was run across the entire codebase:

```
625 passed in 32.70s
Passed: 625
Failed: 0
Skipped: 0
Regression Delta: +50 tests passed (100% pass rate, zero regressions)
```

---

## 17. Dataset and Model Integrity

Every model artifact, checkpoint, synthetic corpus, and locked test partition was cryptographically audited:

| Component | Path | Expected Digest / Value | Observed Digest / Value | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Candidate Weights** | `models/candidates/candidate_v4_seed42/model_weights.npz` | `3affa8908153924e...` | `3affa8908153924e1ab6c66f1f9597b61de0e45a8ba1740e9bc472045888348f` | MATCH |
| **Candidate Metadata** | `models/candidates/candidate_v4_seed42/model_metadata.json` | `8bf388271453b805...` | `8bf388271453b805c148b17232972f6adbe1a4689370893159454b7fe61cafa3` | MATCH |
| **Baseline Weights** | `models/experimental_custom_v1/model_weights.npz` | `d4b6c2b1cc035996...` | `d4b6c2b1cc0359966100623fe18d1f728caeeaef9bcad561bfa00f89485bef20` | MATCH |
| **Baseline Metadata** | `models/experimental_custom_v1/model_metadata.json` | `23cdb9df5004abc3...` | `23cdb9df5004abc3a16b5ebe0df6c773e52b1d36248695e37164cb9d9991bea8` | MATCH |
| **Locked Test Partition** | `data/phishing_eval_dataset.json` | `9b9c02d438cfca8b...` | `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` | MATCH |
| **Active Shadow Model** | `models/active_model_config.json` | `custom-mlp-v4.0.0-seed42` | `custom-mlp-v4.0.0-seed42` | MATCH |
| **Operating Mode** | `models/active_model_config.json` | `shadow` | `shadow` | MATCH |
| **Production Authority** | `models/active_model_config.json` | `false` | `false` | MATCH |
| **Rollback Target** | `models/active_model_config.json` | `custom-mlp-v1.1.0-preproc` | `custom-mlp-v1.1.0-preproc` | MATCH |

---

## 18. Git Status Summary

Working tree inspection confirms all changes are purely additive and maintain strict preservation of existing functionality:

- **Source Modules Added / Extended:**
  - `src/disagreement_engine.py` (New)
  - `src/feedback_analytics.py` (New)
  - `src/case_repository.py` (Extended: disagreement tables, review methods, curation bridge)
  - `src/case_manager.py` (Extended: disagreement store wrappers)
  - `app.py` (Extended: Tab 7 subtabs 07C and 07D)
- **Tests Added:**
  - `tests/test_phase6_6_human_feedback.py` (New: 50 tests)
- **Documentation Added:**
  - `docs/PHASE_6_6_HUMAN_IN_THE_LOOP_REPORT.md` (New: this report)
- **Preserved Artifacts:** All prior phase candidate weights, baseline checkpoints, datasets, manifests, and qualification ledgers remain untouched.

---

## 19. Remaining Limitations

1. **Unauthenticated Operator Attribution:** Reviewer identity remains `local_operator_unauthenticated`. There is currently no multi-party consensus, cryptographic analyst signing, or role-based access control.
2. **Delayed Review Information Loss:** Because original message bodies and raw URLs are safely discarded to protect citizen privacy, delayed reviews rely solely on coarse metadata, structural counts, and 1024-d character n-gram vectors.
3. **Local-Only Feedback Scope:** Feedback records reflect individual sandbox deployments. No cross-deployment federated threat sharing exists.
4. **No Direct Production Promotion:** Disagreement reviews curate features for offline candidate training only; they do not dynamically reweight or retrain the active shadow model in real time.

---

## 20. Recommended Phase 6.7 Work

1. **Multi-Operator Consensus & Inter-Annotator Agreement:** Implement multi-analyst review protocols (Fleiss' or Cohen's Kappa) to validate candidate threat indicators before training curation.
2. **Targeted Active Learning Curation:** Query disagreement clusters with high statistical uncertainty to prioritize operator review queue ordering.
3. **Automated Continuous Pre-Training Qualification Gate:** Construct an automated harness for testing newly curated candidate models against regression baselines without human intervention.
4. **Rule Hypothesis Synthesizer:** Provide offline tooling that assists analysts in drafting deterministic regex rules from approved pattern hypotheses in `models/pattern_catalog/`.

---

## 21. Final Verdict

### **VERDICT: PASS**

The Phase 6.6 Human-in-the-Loop Learning, Model Disagreement Analysis and Threat Pattern Review system has been fully implemented, rigorously verified, and benchmarked. All 50 required tests pass, and all 625 full regression tests pass with zero errors. Deterministic production risk scoring remains 100% authoritative with score difference exactly 0.00. Citizen privacy guarantees, consent gating, and model registry integrity remain strictly preserved.

Execution is hereby **STOPPED** at Phase 6.6. No Phase 6.7 tasks, model retraining, or production promotions have been initiated.
