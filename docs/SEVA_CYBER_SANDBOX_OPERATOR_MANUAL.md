# SEVA CYBER SANDBOX — OPERATOR AND INVESTIGATOR MANUAL
**Document Version:** 1.0.0  
**Effective Date:** 2026-10-31  
**Target Audience:** Cybersecurity Analysts, Forensic Investigators, System Operators  
**System Version:** Seva Cyber Sandbox v7.0.0  

---

## 1. SYSTEM OVERVIEW & GETTING STARTED

Seva Cyber Sandbox is an air-gapped, fully local cybersecurity investigation and evidence governance platform tailored for analyzing phishing messages, malicious URLs, and suspicious Android APKs targeting Indian citizens (specifically tailored to Maharashtra Government Schemes).

### 1.1 Core Operational Principles
- **Air-Gapped Localhost Binding:** The application binds strictly to `127.0.0.1`. It never initiates outbound internet connections, telemetry requests, or cloud API calls.
- **Authoritative Determinism:** All risk classifications, threat indicators, and citizen advisories are issued exclusively by the deterministic rule engine and official Maharashtra Government Resolutions (GRs).
- **Shadow Artificial Intelligence:** The onboard custom neural network (`custom-mlp-v4.0.0-seed42`) operates purely in shadow mode. Its predictions are logged for performance monitoring but have zero authority over production verdicts.
- **Strict Evidence Integrity:** The system enforces strict provenance tracking and a Two-Person verification rule before any evidence can be considered for candidate model retraining.

### 1.2 System Requirements & Startup
- **Operating System:** Windows 10/11 x64, Linux x86_64, or macOS.
- **Python Runtime:** Python 3.10+ (64-bit required for memory-hard Scrypt).
- **Dependencies:** Standard library, `streamlit`, `numpy`, `hashlib`, `sqlite3`.
- **Launching the Platform:**
  Open a terminal inside the project root directory and execute:
  ```powershell
  streamlit run app.py --server.address 127.0.0.1 --server.port 8501
  ```
  Access the web interface at `http://127.0.0.1:8501`.

---

## 2. CITIZEN EVIDENCE SUBMISSION & INTAKE

Seva Cyber Sandbox provides three direct intake channels for real-world evidence:

### 2.1 Suspicious Message Analysis
1. Navigate to **"Submit Evidence" $\rightarrow$ "Message Text"**.
2. Paste the raw message received by the citizen (SMS, WhatsApp, Telegram, email body).
3. Specify language if known (Marathi, Hindi, English, or auto-detect).
4. Click **"Analyze Message"**.
   - The engine automatically computes SHA-256 fingerprints.
   - PII (Aadhaar numbers, phone numbers, credentials) is identified and staged for privacy-compliant redaction.
   - Deterministic rules detect urgency markers, banking fraud triggers, and counterfeit government subsidy claims.

### 2.2 Suspicious URL Investigation
1. Navigate to **"Submit Evidence" $\rightarrow$ "URL Investigation"**.
2. Enter the full suspect URL (e.g., `http://ladki-bahin-yojana-apply.cc/login`).
3. Click **"Analyze URL"**.
   - The engine performs lexical and structural decomposition: domain entropy, brand impersonation, deceptive TLDs (`.top`, `.cc`, `.xyz`), IP-literal hosts, credential traps, and homograph lookups.

### 2.3 Android APK Static Sandbox
1. Navigate to **"Submit Evidence" $\rightarrow$ "APK File Upload"**.
2. Upload the suspicious `.apk` package (maximum 50 MB local upload limit).
3. Click **"Run Static APK Analysis"**.
   - Binary AndroidManifest.xml (AXML) parser inspects requested permissions without executing the APK.
   - Flags dangerous permission clusters (e.g., `RECEIVE_SMS` + `SEND_SMS` + `READ_CONTACTS` + `BIND_ACCESSIBILITY_SERVICE`).
   - Analyzes certificate fingerprints and obfuscation flags.

---

## 3. TECHNICAL ANALYSIS & TRIAGE

When an analysis is completed, the system generates a unified cybersecurity report:

1. **Deterministic Risk Assessment:**
   - Classification: `SUSPICIOUS_PHISHING`, `SUSPICIOUS_MALWARE`, or `LEGITIMATE_VERIFIED`.
   - Threat Level: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `BENIGN`.
2. **Maharashtra GR Matching:**
   - Correlates claims against official Government Resolutions (e.g., *Majhi Ladki Bahin Yojana*, *Namo Shetkari Mahasanman Nidhi*, *MSEDCL Bill Updates*).
   - Flags discrepancies in official portal domains (`.gov.in`, `.nic.in`, `mahadiscom.in`).
3. **Evidence Fingerprint:**
   - Every intake generates a cryptographic `artifact_sha256` and an intake timestamp stored in `instance/seva_cases.sqlite3`.

---

## 4. OPERATOR AUTHENTICATION & SECURITY

Access to evidence governance, case adjudication, and dataset configuration requires analyst authentication.

### 4.1 Authentication Protocols
- **Algorithm:** Memory-hard `scrypt` ($N=131072, r=8, p=1, \text{maxmem}=256\text{ MiB}$).
- **Role Hierarchy:**
  - `admin`: Full administrative control, operator creation, system audits.
  - `analyst`: Evidence review, triage, corroboration, dataset construction.
  - `submitter`: Read-only submission and personal case tracking.
- **Brute-Force Lockout:** Five consecutive failed authentication attempts automatically lock the target account. Lockouts require administrative reset.

### 4.2 Logging In
1. Navigate to **"Analyst Portal"** in the sidebar.
2. Enter Operator Username and Password.
3. Upon authentication, an active session token is minted with rolling expiration.

---

## 5. EVIDENCE GOVERNANCE & INVESTIGATION WORKFLOW

Seva Cyber Sandbox enforces a strict 8-stage evidence lifecycle state machine:
```
[submitted] ---> [awaiting_review] ---> [under_review] ---> [corroborated] ---> [dataset_candidate]
      |                 |                    |                    |
      v                 v                    v                    v
  [rejected]        [rejected]           [rejected]           [withdrawn]
```

### 5.1 Step-by-Step Investigation Workflow
1. **Intake & Triage (`submitted` $\rightarrow$ `awaiting_review`):**
   - The intake analyst verifies that the artifact is genuine cybersecurity evidence and not accidental spam or corrupted bytes.
2. **Reviewer Assignment (`awaiting_review` $\rightarrow$ `under_review`):**
   - The lead investigator or triage analyst calls `assign_reviewer(evidence_id, reviewer_username)`.
   - The evidence is locked to that reviewer to prevent collision.
3. **Corroboration & The Two-Person Rule (`under_review` $\rightarrow$ `corroborated`):**
   - **Crucial Rule:** An investigator cannot corroborate evidence they originally submitted (`submitted_by != reviewed_by`).
   - If operating in an emergency single-operator mode, the system permits self-review only by appending an explicit `self_reviewed: true` warning flag into the append-only audit trail.
   - The reviewer records:
     - `reviewer_classification`: Ground truth determined by human inspection (`phishing`, `legitimate`, or `inconclusive`).
     - `corroboration_notes`: Forensic observations (e.g., "Verified fake payment gateway harvesting UPI PINs").
     - `verification_level`: Elevated to `analyst_confirmed` or `multi_source_corroborated`.
4. **Rejection & Withdrawal:**
   - **Rejection:** If evidence is invalid, false positive, or corrupted, transition to `rejected` with documented reason.
   - **Withdrawal:** If a citizen revokes consent, invoke `withdraw_evidence(evidence_id, reason)`. The system immediately purges PII, removes candidate flags, and marks the record `withdrawn`.

---

## 6. CAMPAIGN CLUSTERING & THREAT TRACKING

Attackers frequently distribute variations of the same phishing template across thousands of SMS/WhatsApp recipients.

1. **Campaign Grouping:**
   - The system clusters incoming evidence by structural hashes, URL root domains, and SMS sender headers.
2. **Cluster Consistency:**
   - An entire campaign cluster must share a uniform consensus classification. Conflicting human labels within the same cluster raise a security alert and block dataset readiness.
3. **Campaign Isolation:**
   - When training datasets are formed, campaigns are split **atomically**. An entire campaign belongs either to `train`, `dev`, or `sealed_eval`—never split across them.

---

## 7. DATASET READINESS & RETRAINING GATES

Before any candidate model training can occur, the `TrainingReadinessGate` evaluates 5 strict criteria:

### 7.1 Readiness Thresholds
1. **Corroborated Evidence Count:** Minimum 30 verified samples.
2. **Class Balance:** Minimum 10 verified `phishing` and 10 verified `legitimate` samples.
3. **Campaign Diversity:** Minimum 5 independent campaign clusters.
4. **Multilingual Representation:** Minimum 2 supported languages (Marathi, English, or Hindi).
5. **Campaign Consistency:** 100% agreement within each campaign cluster.

### 7.2 Gate Status Interpretation
- **`BLOCKED_INSUFFICIENT_EVIDENCE`:** The operational database does not yet meet minimum verified thresholds. Retraining is disabled.
- **`APPROVED_FOR_CANDIDATE_TRAINING`:** All 5 criteria are satisfied. A cryptographically signed `manifest.json` is generated with SHA-256 hashes of all splits.

---

## 8. CANDIDATE RETRAINING & EVALUATION

### 8.1 Training Protocol
- Training is invoked via `RealWorldCandidateTrainer`.
- **Initialization:** Models are trained strictly from pure random initialization (using seeds 42 and 999). Pretrained weights are strictly forbidden.
- **Location:** Candidate weights and metadata are saved to `models/candidates/<candidate_version>/`.
- **Zero-Promotion Invariant:** Training a candidate model **never** activates it. The active model remains `custom-mlp-v4.0.0-seed42` in shadow mode.

### 8.2 Evaluation Protocol
- Evaluated by `RealWorldModelEvaluator` against the sealed evaluation split.
- Performance metrics evaluated: Accuracy, Precision, Recall, Macro F1, Weighted F1, False Positive Rate (FPR), False Negative Rate (FNR), and 3x3 Confusion Matrix.
- Promotion to production requires an explicit qualification audit and manual administrative approval.

---

## 9. INCIDENT RESPONSE & TROUBLESHOOTING

| Incident / Symptom | Probable Cause | Corrective Action |
|:---|:---|:---|
| **Operator account locked** | 5 consecutive failed login attempts | Administrator must execute account unlock script or update `failed_attempts = 0` in `operator_accounts`. |
| **Retraining fails with `TrainingBlockedError`** | Insufficient corroborated real evidence | Normal behavior under the Real-World Evidence Blocker Rule. Check readiness deficit dashboard. |
| **Model disagreement spike** | New threat campaign emerging | Review disagreement taxonomy in `instance/shadow_inference.sqlite3`. Create new deterministic rules. |
| **Citizen requests data deletion** | Consent withdrawal | Execute `withdraw_evidence(evidence_id, "User requested")` to purge PII and unstage from training. |
