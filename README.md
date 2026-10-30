# Seva Cyber Sandbox (Maha-Suraksha)

**A Defensive Malicious APK, Vernacular Phishing & Government Scheme Detector for WhatsApp**  
**Hackathon:** Seva First Innovation Challenge 2026 (Maharashtra Zone)  
**Sub-Theme:** Responsible AI, Cyber Resilience and Digital Trust  
**Target Beneficiaries:** Citizens in Maharashtra, Maha e-Seva Kendra operators, Setu Suvidha Kendra staff, and NSS cyber volunteers.

---

## 1. Project Overview

Every day across Maharashtra, smartphone users receive urgent WhatsApp messages in Marathi threatening electricity disconnection at 9:30 PM, promising welfare payouts (such as *Majhi Ladki Bahin* or *Namo Shetkari* installments), or alerting them to unpaid e-Challans, accompanied by a raw Android `.apk` dropper file or a shortened `.xyz` link.

**Seva Cyber Sandbox** is a 100% offline-capable, privacy-preserving defensive desktop prototype. It inspects suspicious messages, Android APK packages, web links, and government welfare claims statically in memory — warning citizens of threat indicators in plain Marathi and English before financial loss or credential theft occurs.

---

## 2. Core Architecture & Modules

The project is structured into modular, independent engines with consistent data models:

```
                               +-------------------------------------------------+
                               |           Streamlit UI (app.py)                 |
                               |    6 Dedicated citizen facilitation tabs        |
                               +-----------------------+-------------------------+
                                                       |
        +-------------------+--------------------------+-------------------------+-------------------+
        |                   |                          |                         |                   |
        v                   v                          v                         v                   v
+---------------+   +---------------+          +---------------+         +---------------+   +---------------+
|   Vernacular  |   |   Static APK  |          | Safe URL &    |         |  Maharashtra  |   |  Threat Case  |
|    Phishing   |   |    Analyzer   |          | Domain Engine |         | Scheme Engine |   |   Dashboard   |
|   Detector    |   |               |          |               |         |               |   |  & Evidence   |
+---------------+   +---------------+          +---------------+         +---------------+   +---------------+
| src/phishing_ |   | src/apk_      |          | src/url_      |         | src/scheme_   |   | src/case_     |
| detector.py   |   | analyzer.py   |          | analyzer.py   |         | verifier.py   |   | manager.py    |
+-------+-------+   +-------+-------+          +-------+-------+         +-------+-------+   +-------+-------+
        |                   |                          |                         |                   |
        |                   |                          |                         |                   v
        |                   |                          |                         |           +---------------+
        |                   |                          |                         |           | Secure SQLite |
        |                   |                          |                         |           |  Repository   |
        |                   |                          |                         |           | src/case_     |
        |                   |                          |                         |           | repository.py |
        |                   |                          |                         |           +-------+-------+
        |                   |                          |                         |                   |
        |                   |                          |                         |                   v
        |                   |                          |                         |           [instance/      |
        |                   |                          |                         |            seva_cases.db] |
        +-------------------+--------------------------+-------------------------+-------------------+
                                                       |
                                                       v
                                       +-------------------------------+
                                       |      Heuristic Risk Scorer    |
                                       |      & Audio Alert Engine     |
                                       | src/risk_scorer.py            |
                                       | src/audio_alert.py            |
                                       +-------------------------------+
```

### Module Breakdown:
1. **Vernacular Phishing Detector (`src/phishing_detector.py`)**:
   - Normalizes Devanagari numerals (`०-९` $\rightarrow$ `0-9`) and removes zero-width obfuscation characters (`\u200B`, `\u200C`, `\u200D`).
   - Scans for 7 threat categories (OTP requests, APK lures, disconnection urgency, fake KYC, phishing links, task scams, utility impersonation).
   - Contains a **Context Safeguard** ensuring legitimate electricity bill notices and bank security advisories are not falsely flagged.
2. **Safe Static APK Analyzer (`src/apk_analyzer.py`)**:
   - Inspects `.apk` archives in memory without installing, emulating, or executing bytecode.
   - Enforces strict ZIP bomb safety limits (15 MB compressed, 10 MB uncompressed member ceiling).
   - Extracts binary AXML string pools, DEX headers, SHA-256 fingerprints, and matches against an 11-permission sensitive watch catalog.
3. **Safe Suspicious URL & Domain Analyzer (`src/url_analyzer.py`)**:
   - 100% offline static URL inspection without making network requests or resolving DNS.
   - Detects brand lookalikes / typosquatting (`msedcl-bill-update.xyz`), Punycode / IDN homoglyphs (`xn--...`), URL shorteners (`bit.ly`), raw IP hosts, non-standard ports, and direct APK download targets.
   - Enforces internal network and SSRF guards (flags RFC 1918 private IPs and loopback addresses).
4. **Maharashtra Government Scheme Verifier (`src/scheme_verifier.py`)**:
   - Evaluates citizen welfare claims against verified Government Resolutions (GRs) in `data/official_sources.json`.
   - Categorizes claims into 4 factual verdicts: `SUPPORTED BY OFFICIAL SOURCE`, `CONFLICTING EVIDENCE FOUND`, `NOT ENOUGH EVIDENCE`, or `SOURCE UNAVAILABLE`.
   - Separates scheme validation from registration links: a genuine scheme name never validates an accompanying fake WhatsApp link.
5. **Threat Case Dashboard & Evidence Export (`src/case_manager.py`, `src/case_repository.py`)**:
   - Session-isolated incident case management backed by an ACID-compliant SQLite storage layer (`instance/seva_cases.sqlite3`).
   - WAL (Write-Ahead Logging) mode and thread-safe connection pooling for multi-reader/writer concurrency.
   - Built-in privacy safeguards: URL auth credential stripping, Aadhaar and phone number masking, and keyed HMAC sender anonymization.
   - Idempotent deduplication keys (`dedup_key = wamid:...`) and automated 30-day retention pruning.
   - Generates formal, exportable reports labeled: *"Cybersecurity Analysis Summary — Not an Official Forensic Certification"*.
6. **Heuristic Risk Scorer & Audio Alert (`src/risk_scorer.py`, `src/audio_alert.py`)**:
   - Translates observations into a transparent 0–100 heuristic severity index with capability family caps (SMS capped at 40).
   - Synthesizes 100% offline PCM WAV caution chimes (660/520 Hz) in memory and supports optional local Windows SAPI5 offline speech.
7. **Educational Machine-Learning Baseline (`src/ml_classifier.py`)**:
   - Educational TF-IDF + Logistic Regression pipeline trained on `data/sample_messages.json` with stratified train/test split.
8. **Phishing Evaluation & Dataset Quality Harness (`src/dataset_validator.py`, `evaluation/evaluate_phishing.py`)**:
   - Schema validation enforcing 11 fields, strict taxonomy (`phishing`, `legitimate`, `protective_advisory`, `ambiguous_needs_review`), and provenance categories (`public_benchmark`, `human_reviewed_curated`, `synthetic_test_case`, `unreviewed_flagged`).
   - Group-aware, leak-free train/test splitting partitioned strictly by `campaign_id`.
   - Comprehensive statistical reporting: confusion matrix, precision, recall, specificity, F1, FPR, FNR, language/script breakdowns, and separate advisory negation evaluations.
   - Transparent small-sample warning disclosures; separates Live Analysis, ML Training, Holdout Evaluation, and Synthetic Demos.

---

## 3. Quick Start (Windows PowerShell)

### Prerequisites:
- Python 3.10+ (tested on Python 3.14 on Windows 10/11 x64).
- Windows PowerShell.

### Step 1: Clone and Set Up Virtual Environment
```powershell
# Navigate to the workspace
cd C:\Users\prati\seva-cyber-sandbox

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell blocks script activation, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 2: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Generate Safe Sample Fixtures
```powershell
python create_sample_apks.py
```

### Step 4: Run the Automated Test Suite (122 Tests)
```powershell
pytest -v
```
*Executes all 122 automated unit, regression, concurrency, persistence, and evaluation quality tests covering binary AXML manifest element parsing, archive decompression safety, multilingual phishing heuristics, offline URL analysis, scheme verification, secure SQLite persistence with WAL mode, dataset schema validation, group-aware split integrity, and audio alerts.*

### Step 5: Run the Phishing Evaluation Benchmark (Reproducible Metrics)
```powershell
python evaluation/evaluate_phishing.py
```
*Validates the 39-record evaluation corpus against the documented schema, performs group-aware leak-free partitioning, evaluates both the rule-based engine and ML baseline, computes confusion matrices and granular breakdowns, and exports `evaluation/reports/evaluation_summary.json`.*

### Step 6: Launch the Streamlit Web Application
```powershell
streamlit run app.py
```
*Starts the local web server. Open your browser at `http://localhost:8501` to use the interactive dashboard.*

---

## 4. Beginner's Guide: Understanding the Windows Commands

For new developers on Windows, here is what each command actually does:

| Command | What It Does (Plain English) |
| :--- | :--- |
| `cd C:\Users\prati\seva-cyber-sandbox` | Changes your terminal's current working folder to the project directory. |
| `python -m venv venv` | Creates an isolated Python virtual environment folder named `venv` so project dependencies do not conflict with system-wide software. |
| `.\venv\Scripts\Activate.ps1` | Activates the virtual environment in your current PowerShell session (you will see `(venv)` appear at the beginning of your command prompt). |
| `pip install -r requirements.txt` | Reads the list of required libraries (like `streamlit`, `scikit-learn`, `requests`, `pytest`) and downloads them safely into your `venv`. |
| `python create_sample_apks.py` | Generates safe, non-executable test files inside the `sample_apks/` directory so you can test high, moderate, and low risk scenarios without needing real malware. |
| `pytest -v` | Runs the full automated verification test suite and prints a detailed green `PASSED` line for every security, parser, and edge-case test. |
| `streamlit run app.py` | Starts the local web application and provides a local URL (`http://localhost:8501`) to interact with the tabs in your web browser. |

---

## 5. Scope & Honest Limitations Disclosure

To maintain full transparency with academic evaluators, engineering auditors, and hackathon juries:

1. **Static Analysis vs. Runtime Execution:**
   - The APK analyzer inspects declared Android manifest permissions (`AndroidManifest.xml`), file structures, and string pools.
   - It **never** installs, executes, or runs Dalvik bytecode (`classes.dex`). It cannot detect malicious behaviors that only execute at runtime or through encrypted secondary payloads downloaded from external servers.
2. **Heuristic Severity Index vs. Calibrated Probability:**
   - The 0–100 risk score is an ordinal severity index based on weighted threat indicators and capability caps. It is **not** a mathematical or Bayesian probability of maliciousness.
3. **Educational ML Baseline Limitations:**
   - The ML baseline in `src/ml_classifier.py` is trained on a 20-sample prototype corpus in `data/sample_messages.json`.
   - It evaluates 5-fold cross-validation to demonstrate ML concepts. **It is NOT production-ready** and should never be used as a standalone automated blocking mechanism.
4. **Vernacular Dialect Coverage:**
   - The phishing engine checks documented social-engineering templates in Marathi, Romanized Marathi, and English commonly used across Maharashtra. It does not understand every local dialect, colloquial slang, or novel rephrasing.
5. **No Network Crawling of Citizen Links:**
   - Extracted suspicious URLs are analyzed 100% offline using structural heuristics (punycode, lookalike keywords, IP hosts, non-standard ports). The sandbox never opens external URLs submitted by users.
6. **Not an Official Forensic Certification:**
   - Exported reports are cybersecurity decision-support summaries for citizen facilitation, not Section 65B certified legal forensic evidence.

---

## 6. Secure SQLite Persistence & Operational Maintenance

Seva Cyber Sandbox provides an ACID-compliant, privacy-first SQLite persistence layer (`src/case_repository.py`) designed for robust offline execution, local citizen facilitation counters, and multi-threaded messaging integrations.

### Architecture & Concurrency
- **Storage Engine:** Standard library `sqlite3` with Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and `PRAGMA synchronous = NORMAL`.
- **Concurrency:** Allows concurrent readers and writers between the Streamlit user interface and background WhatsApp webhook workers without encountering `database is locked` errors, supported by `PRAGMA busy_timeout = 5000`.
- **Session Boundary Isolation:** Cases are segregated by `session_id`. Individual browser sessions cannot access or leak cases belonging to other browser tabs or webhook archives.

### Database Schema Overview
The database uses normalized schemas initialized automatically upon first startup:
- `threat_cases`: Primary case ledger storing derived indicators, scores, risk badges, SHA-256 fingerprints, serialized JSON evidence, and expiration timestamps.
- `schema_version`: Version tracking table ensuring idempotent upgrades without data loss.
- **Indexes:** Indexed on `session_id`, `created_at DESC`, `analysis_type`, `risk_score`, `dedup_key`, and `expires_at` for sub-millisecond query performance.

### Configuration & Environment Variables
| Environment Variable | Default Value | Purpose |
| :--- | :--- | :--- |
| `SEVA_CASE_DB_PATH` | `<project_root>/instance/seva_cases.sqlite3` | Custom filesystem path for SQLite database file. |
| `SEVA_HMAC_SECRET` | *(Built-in Dev Fallback Secret)* | Secret salt key for HMAC-SHA256 sender phone anonymization. |

### Privacy Safeguards
1. **Zero Raw Payload Retention:** Original uploaded APK binary bytes and raw citizen messages are never stored in the database.
2. **URL Credential Stripping:** Removes inline basic authentication (`user:pass@`) and sensitive query parameters (`token=`, `otp=`, `auth=`, `secret=`, `password=`).
3. **Citizen Identifier Masking:** Masks 10-digit phone numbers (`+91-98XXXX3210`) and 12-digit Aadhaar numbers (`XXXX-XXXX-1234`) in stored evidence strings.
4. **Keyed HMAC Anonymization:** Hashes WhatsApp sender phone numbers with HMAC-SHA256 to prevent rainbow-table and dictionary reverse-lookups.

### Database Administration (Windows PowerShell)

#### 1. Safe Database Backup (Hot Backup via Online Backup API)
```powershell
.\venv\Scripts\python.exe -c "import sqlite3; src = sqlite3.connect('instance/seva_cases.sqlite3'); dst = sqlite3.connect('instance/seva_cases_backup.sqlite3'); src.backup(dst); dst.close(); src.close(); print('Hot backup completed.')"
```

#### 2. Restoring from Backup
```powershell
Copy-Item -Path "instance\seva_cases_backup.sqlite3" -Destination "instance\seva_cases.sqlite3" -Force
```

#### 3. Triggering Retention Pruning (Removing Expired Cases)
```powershell
.\venv\Scripts\python.exe -c "from src.case_repository import get_default_case_repository; n = get_default_case_repository().prune_expired_cases(); print(f'Pruned {n} expired cases.')"
```

#### 4. Checking Database Integrity
```powershell
.\venv\Scripts\python.exe -c "import sqlite3; conn = sqlite3.connect('instance/seva_cases.sqlite3'); cur = conn.cursor(); print(cur.execute('PRAGMA integrity_check;').fetchall())"
```

---

## 7. Feature Status: Implemented vs. Simulated

To maintain full transparency with academic evaluators and hackathon juries:

| Capability | Status | Implementation Details |
| :--- | :---: | :--- |
| **Static APK Permission Analysis** | **Implemented** | Safe memory-only ZIP/AXML inspection; extracts declared permissions, SHA-256, and package metadata. |
| **Vernacular Phishing Detection** | **Implemented** | Rule engine covering Marathi (Devanagari), Romanized Marathi, Mixed, and English text lures. |
| **Context Safeguard & Negation** | **Implemented** | Suppresses false alarms on legitimate utility notices and bank security advisories. |
| **Safe Offline URL Analyzer** | **Implemented** | Heuristic lookalike, Punycode, IP, shortener, and TLD inspection with zero network calls. |
| **Govt Scheme Resolution Verification** | **Implemented** | Curated registry (`data/official_sources.json`) backed by official GR numbers and allowlisted domains. |
| **Threat Case Dashboard & Export** | **Implemented** | Persistent SQLite storage (`instance/seva_cases.sqlite3`) with WAL mode, CSV/JSON export, and session isolation. |
| **Offline Browser WAV Tone Chime** | **Implemented** | Mathematical PCM WAV tone synthesis directly in RAM. |
| **Windows SAPI5 Offline TTS** | **Implemented** | Isolated child process with timeout (speaks English; reports Marathi voice presence). |
| **Phishing Evaluation & Quality Harness** | **Implemented** | Strict schema validation, group-aware leak-free train/test split, and reproducible metrics (`evaluation/evaluate_phishing.py`). |
| **Live WhatsApp Bot Integration** | **Simulated / Webhook-Ready** | Validated Meta Cloud API webhook handler (`src/whatsapp_webhook.py`) and UI simulation. |
| **Dynamic APK Sandboxing** | **Omitted by Design** | The tool does not execute or emulate APK bytecode; inspection is strictly static and isolated. |
| **External Law Enforcement Reporting** | **Advisory Only** | Never auto-submits records to MahaCyber or 1930. Provides verified reporting links for citizen self-action. |

---

## 8. Privacy & Security Boundaries

1. **Local-First Processing:** All analysis workflows run locally without sending telemetry or citizen data to external cloud services.
2. **Zero Raw Payload Retention:** Original uploaded APK files and raw message strings are discarded immediately after structural feature extraction.
3. **Session-Scoped Case Access:** Dashboard views query cases filtered by active `session_id`, keeping browser desk counter sessions partitioned.
4. **Automated Expiration:** Derived case records default to a 30-day retention window and can be pruned automatically.
5. **Zero-Network URL Safety:** Arbitrary citizen URLs are never resolved, fetched, or crawled over the internet.
6. **Not a Forensic Certificate:** Exported reports are explicitly labeled *"Cybersecurity Analysis Summary — Not an Official Forensic Certification"*.

---

## 9. Official Cyber Helplines in Maharashtra

- **National Cyber Financial Fraud Helpline:** Dial **1930** immediately to freeze fraudulent banking transactions.
- **National Cyber Crime Reporting Portal:** File an official FIR / complaint at [https://cybercrime.gov.in](https://cybercrime.gov.in).
- **Government of Maharashtra Official Portal:** [https://maharashtra.gov.in](https://maharashtra.gov.in).
- **MahaVitaran (MSEDCL) Official Website:** [https://www.mahadiscom.in](https://www.mahadiscom.in).
