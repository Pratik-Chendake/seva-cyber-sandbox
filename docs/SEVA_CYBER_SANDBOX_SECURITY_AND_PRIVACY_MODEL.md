# SEVA CYBER SANDBOX — SECURITY AND PRIVACY MODEL
**Document Version:** 1.0.0  
**Effective Date:** 2026-10-31  
**Security Classification:** Comprehensive Threat Model & Defense Specification  
**System Baseline:** v7.0.0  

---

## 1. THREAT MODEL & SECURITY OBJECTIVES

Seva Cyber Sandbox processes sensitive evidence regarding cyber fraud, financial scams, and phishing campaigns targeting vulnerable citizens. To defend both citizen privacy and system integrity, the platform operates under an adversarial threat model addressing six primary attack vectors.

### Threat Matrix:
| Threat ID | Threat Vector | Attacker Motivation | Countermeasure in Seva Cyber Sandbox |
|:---:|:---|:---|:---|
| **T-01** | **Training Data Poisoning** | Adversary submits crafted messages or corrupts labels to trick the AI into whitelisting malicious campaigns. | Four-tier verification gate, Two-Person Rule, campaign consistency auditing, strict training readiness gating. |
| **T-02** | **Rogue Operator Tampering** | Compromised internal analyst attempts to manipulate evidence status or flip classifications. | Append-only audit trails, Two-Person Rule (`submitted_by != reviewed_by`), role-based access control. |
| **T-03** | **Evaluation Data Leakage** | Retrained models memorize test sets, yielding falsely inflated qualification metrics. | Campaign-level atomic partitioning; all samples of a campaign reside strictly in one partition (`train`, `dev`, or `sealed_eval`). |
| **T-04** | **Data Exfiltration / Snooping** | Malicious third parties or cloud providers harvest citizen fraud data. | Strict air-gap architecture: 100% local CPU execution, binding to `127.0.0.1`, zero cloud APIs or outbound sockets. |
| **T-05** | **Credential Compromise** | Attackers attempt offline or online dictionary attacks against analyst accounts. | OWASP Scrypt ($N=131072, r=8, p=1$, 256 MiB memory ceiling), 5-strike progressive lockout policy. |
| **T-06** | **Denial of Service (ReDoS)** | Attacker submits pathological text strings or malformed APKs to freeze analysis threads. | Fail-closed input length ceiling (>50,000 chars), zero-execution binary AXML parsing with bounds checking. |

---

## 2. ANTI-POISONING & EVIDENCE TRUST ARCHITECTURE

### 2.1 The Real-World Evidence Blocker Invariant
The system adheres to an uncompromising rule: **no machine learning model shall be trained on unverified or fabricated data**.
- To prevent synthetic artifacts from distorting real-world threat models, the operational database (`instance/seva_cases.sqlite3`) strictly rejects synthetic evidence seeding.
- When real-world evidence volume is insufficient, the system fails closed by halting model training (`BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE`) rather than falling back on unvetted synthetic filler.

### 2.2 Four-Tier Evidence Verification Gating
Evidence must ascend through four strict verification tiers before qualification:
1. `unverified`: Raw citizen intake. Excluded from all training.
2. `triaged`: Validated by an intake analyst as non-spam cybersecurity data. Excluded from training.
3. `analyst_confirmed`: Human analyst has inspected technical indicators and verified ground truth.
4. `multi_source_corroborated`: Verified by multiple independent sources or corroborated against official Maharashtra Government advisories.

### 2.3 The Two-Person Rule & Integrity Audits
- To prevent insider threats or accidental bias, an analyst cannot corroborate evidence they originally submitted (`submitted_by != reviewed_by`).
- In emergency single-operator deployments where a second analyst is unavailable, the system logs an explicit `self_reviewed: true` flag in the immutable audit trail, automatically downgrading the evidence verification weight.

### 2.4 Campaign Cluster Homogeneity Auditing
- Incoming evidence is clustered by structural fingerprints and domain roots.
- The `TrainingReadinessGate` scans every campaign cluster. If any cluster contains conflicting human classifications (e.g., three analysts marked it `phishing` but one marked it `legitimate`), the entire dataset is flagged with `CAMPAIGN_LABEL_CONFLICT` and retraining is blocked until the conflict is resolved.

---

## 3. CITIZEN PRIVACY & DATA PROTECTION MODEL

### 3.1 Principle of Data Minimization
Citizen evidence is sanitized at intake. The platform retains only the technical indicators required for forensic analysis (URLs, APK signatures, phishing syntax, linguistic markers) and strips identifying citizen attributes.

### 3.2 Automated PII Redaction
Text submissions are processed through the `PrivacyGate`:
- **Indian Mobile Numbers:** Stripped or masked (`+91-XXXXXXXXXX`).
- **Indian Aadhaar Numbers:** 12-digit UID numbers starting with digits 2–9 are detected and redacted.
- **Financial & Identity Secrets:** Passwords, OTP tokens, and bank account numbers are sanitized.

### 3.3 Boundary Protection (ReDoS)
- Regular expression processing of unstructured text introduces potential ReDoS vulnerabilities.
- Texts exceeding 50,000 characters trigger fail-closed boundary enforcement: sanitization is aborted, the input is marked as potentially malicious, and processing halts safely without CPU exhaustion.

### 3.4 Evidence Withdrawal & Right-to-be-Forgotten
Citizens have the right to withdraw their submitted evidence at any time:
1. When `withdraw_evidence(evidence_id)` is invoked, the case status immediately transitions to `withdrawn`.
2. Staged candidate training records are purged immediately.
3. All original message text and associated forensic notes are sanitized from the operational store.
4. The immutable audit log records the withdrawal timestamp and authorization token.

### 3.5 Anonymized Telemetry
Telemetry logged to `instance/shadow_inference.sqlite3` stores only cryptographic SHA-256 digests of inputs, model confidence scores, and latency metrics. Zero citizen plaintext or PII is recorded in telemetry stores.

---

## 4. CRYPTOGRAPHIC STANDARDS & AUTHENTICATION HARDENING

### 4.1 Memory-Hard Password Hashing
Operator accounts in `instance/seva_cases.sqlite3` are protected using `scrypt`:
- **Parameters:**
  $$\text{Algorithm: scrypt}, \quad N = 131,072 \; (2^{17}), \quad r = 8, \quad p = 1, \quad \text{maxmem} = 256\text{ MiB}$$
- **Hardware Defense:** Requiring 256 MiB of high-bandwidth RAM per hash verification renders GPU, ASIC, and FPGA brute-force cracking economically and computationally impractical.
- **Windows MSVC Compatibility:** Parameter sizes are safeguarded against 32-bit signed long truncation via explicit 64-bit unsigned bounds checks.

### 4.2 Progressive Brute-Force Lockout
- Accounts track `failed_attempts`.
- Upon the 5th consecutive invalid password attempt, the account transitions to `is_locked = 1`.
- Subsequent login attempts are immediately rejected with `AccountLockedError` prior to executing any cryptographic hash derivation, mitigating CPU exhaustion attacks.

---

## 5. LOCAL EXECUTION & BOUNDARY INTEGRITY

- **Strict Air-Gap Guarantee:** Seva Cyber Sandbox contains zero telemetry reporting, zero third-party tracking scripts, zero external stylesheet CDNs, and zero cloud API hooks.
- **Socket Isolation:** The Streamlit dashboard and underlying services bind exclusively to `127.0.0.1`. Binding to `0.0.0.0` is prevented by configuration checks.
- **Shadow Model Score Isolation:** The neural model (`custom-mlp-v4.0.0-seed42`) has zero authority over production scores. Its contribution to the production decision delta is mathematically verified as:
  $$\Delta = |\text{Score}_{\text{production}} - \text{Score}_{\text{deterministic}}| = 0.00$$
- Any failure, crash, or unexpected output from the neural shadow model fails open, ensuring uninterrupted availability of the deterministic security engine.
