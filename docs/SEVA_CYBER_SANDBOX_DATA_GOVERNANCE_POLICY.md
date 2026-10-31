# SEVA CYBER SANDBOX — DATA GOVERNANCE POLICY
**Policy Document:** DGP-2026-V1  
**Effective Date:** 2026-10-31  
**Authority:** Cybersecurity Architecture and Data Ethics Board  
**Target Scope:** Real-World Evidence Lifecycle, Dataset Construction, Model Retraining  
**System Baseline:** v7.0.0  

---

## 1. PURPOSE AND PRINCIPLES

This Data Governance Policy defines the operational, cryptographic, and ethical mandates governing the collection, curation, partitioning, and consumption of cybersecurity evidence within Seva Cyber Sandbox.

### Foundational Principles:
1. **Verifiable Truth over Volume:** The system shall never prioritize training dataset size at the cost of evidence veracity.
2. **The Real-World Evidence Invariant:** Machine learning models intended for production deployment shall never be trained on synthetic or fabricated evidence. If real-world evidence is insufficient, retraining must be blocked.
3. **Citizen Sovereignty:** Citizens retain the right to withdraw their submitted artifacts at any point prior to final anonymized candidate training.
4. **Air-Gapped Confidentiality:** All evidence collection, curation, and model evaluation must take place strictly on local, non-networked infrastructure.

---

## 2. EVIDENCE PROVENANCE AND INTAKE CONTROL

### 2.1 Provenance Categorization
Every ingested artifact must be assigned an immutable provenance origin from the approved enumerated set:
- `user_reported`: Genuine fraud evidence submitted directly by citizens.
- `analyst_submitted`: Suspect material gathered by forensic investigators in the field.
- `internal_case`: Evidence linked to existing ongoing incident investigations.
- `public_source_reference`: Official advisories or threat bulletins issued by CERT-In or Maharashtra Cyber.
- `synthetic_test_data`: Synthetically generated data used **strictly** in isolated testing environments; strictly prohibited from entering production databases.
- `system_generated`: Automated telemetry or system logs.

### 2.2 Cryptographic Intake Seal
- Upon submission, the engine computes the SHA-256 cryptographic digest of the raw artifact.
- The resulting digest `artifact_sha256`, intake timestamp `submitted_at`, and submitter identity `submitted_by` are permanently bound to the case record.

---

## 3. EVIDENCE VERIFICATION STANDARDS & LIFECYCLE

### 3.1 Verification Tiers
Evidence is categorized into four verification tiers:
1. **Tier 0 — `unverified`:** Newly submitted artifacts. Ineligible for dataset construction or training.
2. **Tier 1 — `triaged`:** Reviewed by an analyst for basic relevance and non-spam status. Ineligible for candidate training.
3. **Tier 2 — `analyst_confirmed`:** Confirmed by a qualified forensic analyst via technical analysis (e.g., domain registration records, malicious APK signatures).
4. **Tier 3 — `multi_source_corroborated`:** Confirmed by two or more independent analysts or corroborated by official government advisories (GRs).

### 3.2 Two-Person Corroboration Rule
- **Mandate:** To prevent self-confirmation bias and internal data poisoning, an analyst cannot corroborate an evidence item they submitted (`submitted_by != reviewed_by`).
- **Emergency Exception:** In validated single-operator configurations where a second analyst is unavailable, the system permits self-corroboration provided that:
  1. The audit trail permanently records `self_reviewed: true`.
  2. The evidence item is capped at Tier 2 (`analyst_confirmed`) and cannot attain Tier 3 status without external review.

---

## 4. CAMPAIGN CLUSTERING & ATOMIC PARTITIONING

### 4.1 Threat Campaign Identification
- Evidence items are clustered into threat campaigns based on structural text templates, URL domain roots, and APK certificate serials.
- Each cluster is assigned a unique `campaign_id`.

### 4.2 Prohibition of Row-Level Random Splitting
- Standard random row-level splitting (e.g., standard `train_test_split`) is **strictly prohibited**. Row-level splitting allows identical or near-duplicate phishing templates from the same campaign to appear in both training and test sets, causing severe evaluation data leakage and overfitting.
- **Atomic Campaign Partitioning Mandate:** All samples belonging to a shared `campaign_id` must be assigned as an indivisible atom to a single partition:
  - `train`: Used for candidate model weight optimization.
  - `dev`: Used for hyperparameter tuning and early stopping.
  - `sealed_eval`: Sealed partition used solely for independent model qualification.
  - `excluded`: Staged or corrupted samples withheld from all splits.

---

## 5. CITIZEN PRIVACY, CONSENT, AND WITHDRAWAL

### 5.1 Automated PII Sanitization
Prior to entering dataset staging pools, all evidence must undergo automated PII redaction:
- Indian mobile phone numbers are masked.
- Indian Aadhaar numbers (12 digits starting with digits 2–9) are stripped.
- Passwords, OTP codes, and payment credentials are sanitized.

### 5.2 Consent Withdrawal Protocol
1. Citizens may request evidence withdrawal at any time.
2. Upon receiving a withdrawal request, the lead analyst executes `withdraw_evidence(evidence_id, reason)`.
3. The system executes immediate cascading actions:
   - Sets evidence status to `withdrawn`.
   - Purges raw text, attachments, and URLs from active views.
   - Immediately invalidates all uncompiled dataset staging pools containing the item.
   - Records the withdrawal action in `evidence_audit_log`.

---

## 6. TRAINING READINESS GATING & BLOCKED RETRAINING

### 6.1 Gating Prerequisites
The `TrainingReadinessGate` prevents candidate retraining until the following five conditions are met simultaneously:
1. **Total Corroborated Evidence:** $\ge 30$ samples.
2. **Class Parity:** $\ge 10$ confirmed `phishing` and $\ge 10$ confirmed `legitimate` samples.
3. **Campaign Diversity:** $\ge 5$ distinct, non-overlapping campaign clusters.
4. **Multilingual Representation:** $\ge 2$ supported Indian languages represented.
5. **Campaign Consistency:** Zero label contradictions across any campaign cluster.

### 6.2 Retraining Blockade Policy
- If any prerequisite is unsatisfied, the gate returns:
  `gate_decision = BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE`
- **Strict Compliance:** Under a blocked gate decision, candidate training functions (`RealWorldCandidateTrainer`) must throw `TrainingBlockedError` and immediately abort execution. Fabricating data to bypass the gate is a critical policy violation.

---

## 7. AUDITING AND POLICY ENFORCEMENT

- All transitions, approvals, rejections, withdrawals, and dataset partitionings are recorded in an append-only SQLite audit table (`evidence_audit_log`).
- System administrators shall review audit logs on a monthly schedule to ensure compliance with this policy.
