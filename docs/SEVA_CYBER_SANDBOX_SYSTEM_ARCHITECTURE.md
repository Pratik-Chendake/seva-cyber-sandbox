# SEVA CYBER SANDBOX — SYSTEM ARCHITECTURE SPECIFICATION
**Document Version:** 1.0.0  
**Effective Date:** 2026-10-31  
**System Architecture Baseline:** v7.0.0  
**Security Classification:** Highly Secure Local Architecture  

---

## 1. HIGH-LEVEL ARCHITECTURAL BLUEPRINT

Seva Cyber Sandbox is architected as a modular, air-gapped cybersecurity analysis platform operating entirely on local workstation hardware. The architecture bifurcates production decision-making from artificial intelligence experimentation through an authoritative deterministic pipeline paired with an isolated neural shadow pipeline.

```mermaid
flowchart TD
    subgraph INTAKE ["1. Intake & Feature Extraction Layer"]
        A1[Citizen Input: Message / URL / APK] --> B1[Input Validation & SHA-256 Fingerprinting]
        B1 --> B2[Privacy Gate & PII Redaction]
        B2 --> C1[Text Feature Extraction & Tokenization]
        B2 --> C2[URL Lexical Decomposition Engine]
        B2 --> C3[Binary AXML Static APK Parser]
    end

    subgraph PRODUCTION ["2. Authoritative Production Decision Pipeline"]
        C1 & C2 & C3 --> D1[Deterministic Rule Engine]
        C1 --> D2[Maharashtra GR Knowledge Base]
        D1 & D2 --> E1[Production Decision Synthesizer]
        E1 --> F1["Final Production Verdict (Authoritative: True)"]
    end

    subgraph SHADOW ["3. Neural Shadow Execution Pipeline"]
        C1 --> G1["Active Shadow Model (custom-mlp-v4.0.0-seed42)"]
        G1 --> G2[Shadow Inference Logger]
        G2 --> G3["Disagreement Engine (Score Delta == 0.00)"]
        G3 --> G4[(instance/shadow_inference.sqlite3)]
    end

    subgraph GOVERNANCE ["4. Evidence Governance & Anti-Poisoning Subsystem"]
        F1 --> H1[(instance/seva_cases.sqlite3)]
        H1 --> H2[Campaign Clustering Engine]
        H2 --> H3[Analyst Portal: Two-Person Review]
        H3 --> H4[Dataset Readiness Analyzer]
        H4 --> H5[Training Readiness Gate]
        H5 -->|Approved| H6[Atomic Campaign Partitioning]
        H5 -->|Blocked| H7["Retraining Halted (Insufficient Real Evidence)"]
    end
```

---

## 2. INTAKE AND FEATURE EXTRACTION LAYER

### 2.1 Cryptographic Intake & PII Sanitization
- **SHA-256 Digesting:** Every intake artifact (raw text string, URL target, or binary APK) is hashed immediately upon receipt. This cryptographic digest serves as the primary forensic identifier across all database tables and audit trails.
- **Privacy Sanitization Gate:** Text strings undergo regex-based PII identification before entering forensic staging:
  - Indian Mobile Numbers (`(\+91|0)?[6-9]\d{9}`).
  - Indian Aadhaar Numbers (`\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b`).
  - Passwords, OTPs, and API credentials.
- **ReDoS Boundary Protection:** Any input exceeding 50,000 characters is rejected by fail-closed boundary enforcement to eliminate regular expression denial-of-service vulnerabilities.

### 2.2 Multilingual Text Tokenizer
- Multilingual tokenization supporting English, Marathi (Devanagari script), and Hindi.
- Extraction of threat indicators: urgency keywords, fake authority claims, deceptive payment prompts, and banking terminology.

### 2.3 Binary AXML Static APK Analyzer
- **Zero-Execution Static Sandbox:** Suspicious APK archives are decompressed into memory without executing bytecodes or Dalvik executables.
- **Direct AXML Manifest Parser:** A custom binary parser unpacks the compiled `AndroidManifest.xml` string table and XML nodes directly in Python.
- Extracts package name, declared activities, services, intent filters, and permission arrays.
- Flags dangerous privilege combinations: SMS interception (`RECEIVE_SMS`), background dialing (`CALL_PHONE`), accessibility abuse (`BIND_ACCESSIBILITY_SERVICE`), and overlay injection (`SYSTEM_ALERT_WINDOW`).

### 2.4 URL Lexical Decomposition Engine
- Structural breakdown of URL components (scheme, FQDN, path, query, fragment).
- Shannon entropy analysis across domain labels to detect algorithmically generated domains (DGA).
- Brand impersonation detection checking against official portals (`maharashtra.gov.in`, `mahadiscom.in`, `ladkibahin.maharashtra.gov.in`).
- Detection of high-risk top-level domains (`.top`, `.xyz`, `.cc`, `.tk`) and embedded credentials (`http://user:pass@host`).

---

## 3. DETERMINISTIC PRODUCTION ENGINE

The deterministic engine is the sole authoritative decision-maker in Seva Cyber Sandbox.

### 3.1 Rule Hierarchy & Weights
The engine evaluates an ordered cascade of weighted heuristic rules:
1. **Rule Set R1 — Identity & Impersonation:** Counterfeit government seals, fake minister signatures, unverified WhatsApp header claims.
2. **Rule Set R2 — Financial Trap Markers:** Unofficial payment gateways, third-party UPI QR codes, demands for registration fees for free government schemes.
3. **Rule Set R3 — APK Risk Aggregators:** Dangerous permission triplets, non-standard application signing certificates.
4. **Rule Set R4 — Legitimate Whitelist Confirmations:** Officially registered Maharashtra Government domains (`.gov.in`, `.nic.in`), verified helpline numbers (e.g., 181, 112).

### 3.2 Maharashtra Government Resolution (GR) Verifier
- Integrates a structured local database of legitimate Maharashtra state schemes:
  - *Majhi Ladki Bahin Yojana* (Women & Child Development).
  - *Namo Shetkari Mahasanman Nidhi* (Agriculture Department).
  - *MSEDCL Power Subsidy & Light Bill Updates* (Energy Department).
- Cross-references incoming claims against official GR numbers, application deadlines, and authentic portal URLs. Claims referencing nonexistent GRs or expired subsidy windows are automatically escalated to high-threat classifications.

---

## 4. NEURAL SHADOW SUBSYSTEM

### 4.1 Custom Neural Architecture (MLP)
The custom neural network is implemented entirely in NumPy without external machine learning frameworks:
- **Topology:** 3-Layer Multilayer Perceptron (MLP).
  - Input Layer: 1024 dimensions (TF-IDF unigram/bigram feature projections).
  - Hidden Layer 1: 64 units, Rectified Linear Unit (ReLU) activation.
  - Hidden Layer 2: 32 units, Rectified Linear Unit (ReLU) activation.
  - Output Layer: 3 units, Softmax activation (`phishing`, `legitimate`, `suspicious`).
- **Initialization:** Strictly randomized weights (seed 42 for production shadow, seed 999 for candidate baselines) using He/Kaiming normal initialization.

### 4.2 Shadow Isolation Invariant
- The model runs in an isolated wrapper. Any exception, division by zero, or numerical instability inside the neural forward pass fails open, leaving the deterministic production decision completely unimpacted.
- Output probabilities are recorded in `instance/shadow_inference.sqlite3` along with input hashes and timestamped execution latencies.
- **Score Delta Guarantee:** The active model configuration enforces `is_production_authoritative: false`. The difference between the deterministic risk score and the final published risk score is identically $0.00$.

---

## 5. EVIDENCE GOVERNANCE & ANTI-POISONING SUBSYSTEM

```mermaid
stateDiagram-v2
    [*] --> submitted
    submitted --> awaiting_review : Intake Validation
    submitted --> rejected : Invalid Artifact
    awaiting_review --> under_review : Reviewer Assigned
    awaiting_review --> rejected : Triage Rejection
    under_review --> corroborated : Two-Person Corroboration
    under_review --> rejected : Analyst Invalidation
    corroborated --> dataset_candidate : Gate Approved
    corroborated --> withdrawn : Citizen Withdrawal
    dataset_candidate --> partitioned : Atomic Split
    dataset_candidate --> withdrawn : Consent Revoked
    partitioned --> trained_into_candidate : Candidate Retrained
    trained_into_candidate --> [*]
    rejected --> [*]
    withdrawn --> [*]
```

### 5.1 Evidence Lifecycle State Machine
Evidence progresses through an append-only state transition model. Each state change requires authenticated operator credentials and appends an immutable record into `evidence_audit_log`.

### 5.2 Anti-Poisoning Controls
1. **Two-Person Verification Rule:** Prevents a single rogue or compromised operator from injecting biased or poisoned labels into the training pipeline.
2. **Campaign-Level Atomic Partitioning:** Phishing campaigns are discovered via structural clustering. Splitting is executed at the campaign level, ensuring that an entire threat cluster resides strictly in `train`, `dev`, or `sealed_eval`, completely preventing evaluation data leakage.
3. **Training Readiness Gate:** Prohibits automatic or unverified retraining. Retraining is strictly halted unless multi-source corroborated evidence meets predefined threshold minimums.

---

## 6. OPERATOR AUTHENTICATION & ACCESS CONTROL

### 6.1 Cryptographic Storage Specification
- **Algorithm:** Scrypt (OWASP Password Storage Standard).
- **Parameters:**
  - Cost Parameter ($N$): $131072$ ($2^{17}$)
  - Block Size ($r$): $8$
  - Parallelization ($p$): $1$
  - Memory Ceiling (`maxmem`): $268,435,456$ bytes ($256\text{ MiB}$)
- Stored hash format: `$scrypt$ln=17,r=8,p=1$<salt_hex>$<hash_hex>`.

### 6.2 Access Governance
- Role-based capabilities (`admin`, `analyst`, `submitter`).
- Five-strike lockout policy locking compromised accounts on the 5th sequential authentication failure.

---

## 7. PERSISTENCE & DATA STORAGE ARCHITECTURE

### 7.1 Database Architecture
- **`instance/seva_cases.sqlite3` (Operational Database):**
  - Schema Version: v3.
  - Contains production cases, user evidence provenance, audit trails, campaign cluster mappings, and operator authentication tables.
  - Holds zero synthetic or fabricated cases.
- **`instance/shadow_inference.sqlite3` (Telemetry Database):**
  - Stores shadow model inference timings, output logits, and model-rule disagreement records.

### 7.2 Model Checkpoint Hierarchy
- **Active Shadow Model:** `models/custom-mlp-v4.0.0-seed42/`
- **Last-Known-Good Rollback Target:** `models/custom-mlp-v1.1.0-preproc/`
- **Candidate Retraining Sandbox:** `models/candidates/<candidate_version>/`
- Active model configuration is maintained in `models/active_model_config.json`.
