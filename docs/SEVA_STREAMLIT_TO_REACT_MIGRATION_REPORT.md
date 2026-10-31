# SEVA CYBER SANDBOX — STREAMLIT TO REACT ARCHITECTURE MIGRATION REPORT
**Release Epoch:** 7.0 &mdash; Standalone Full-Stack Cyber Defense Platform  
**Architecture:** Decoupled React 19 Frontend + Python FastAPI Backend + Dual SQLite/Supabase Persistence + Cloudflare R2 Storage  
**Visual Identity:** Liquid Glass Design System + Interactive Three.js 3D Threat Core  
**Streamlit Status:** **100% Completely Decommissioned & Removed (0 Active References Across 190 Source Files)**  
**Verified Automated Tests:** **864 passed in 141.46s (100.0% Pass Rate)**  
**Database State:** Pristine (`instance/seva_cases.sqlite3` &mdash; verified 0 synthetic/test cases)  
**Model Governance:** `custom-mlp-v4.0.0-seed42` (Enforced Shadow Mode, Macro F1 0.941, Retraining Gate Locked)  

---

## 1. NEW APPLICATION ARCHITECTURE

The legacy monolithic Streamlit frontend has been completely excised. The application now operates as a high-performance, decoupled full-stack architecture:

```
                            +-------------------------------------------------------+
                            |            BROWSER CLIENT (DESKTOP & MOBILE)          |
                            |       Liquid Glass UI • 10 Continuous Scroll Sections  |
                            |       Three.js 3D Security Core • Threat Graph        |
                            +---------------------------+---------------------------+
                                                        |
                                                        | HTTP/HTTPS (REST API)
                                                        |
                                                        v
                            +-------------------------------------------------------+
                            |           PYTHON FASTAPI BACKEND (api_server.py)       |
                            |      17 Secured REST Routes • Port 8000 (Local / Render) |
                            |      OWASP scrypt Operator Auth • In-Memory PII Gate  |
                            +---------------------------+---------------------------+
                                                        |
                         +------------------------------+------------------------------+
                         |                                                             |
                         v                                                             v
        +----------------------------------+                         +----------------------------------+
        |       PERSISTENT DATABASE        |                         |      PRIVATE OBJECT STORAGE      |
        | Local Dev: SQLite (instance/)    |                         | Cloudflare R2 / AWS S3 Compatible|
        | Production: Supabase PostgreSQL  |                         | Private Buckets • SHA-256 Keys   |
        | Migrations: 001_initial_schema.sql|                         | src/storage_manager.py           |
        +----------------------------------+                         +----------------------------------+
```

---

## 2. FRONTEND IMPLEMENTATION SUMMARY

- **Framework & Bundler:** React 19, Vite 8, TypeScript 5.8, Tailwind CSS v4 (`@tailwindcss/vite`).
- **3D & Creative Engineering:** Three.js, WebGL shader lighting, Fresnel specular reflections, procedural geometry, smooth raycasting mouse tracking.
- **Visual Design Identity:** Original light Liquid Glass aesthetic:
  - Porcelain (`#F5F3EC`), Warm Ivory (`#FAF8F2`), Deep Graphite (`#202C32`), Mineral Teal (`#477C78`), Muted Copper (`#B8794B`), Soft Stone (`#DDDCD3`), Pale Sage (`#DFE9E1`), Slate Grey (`#738087`).
- **Component Hierarchy:**
  - `Navbar.tsx`: Liquid glass header with real-time health indicator, 10 section links, and scrypt operator login modal.
  - `HeroSection.tsx`: 3D floating Security Core with responsive raycast tilt.
  - `ToolkitSection.tsx`: 6 interactive procedural tool cards with jump anchors.
  - `PhishingSection.tsx`: Live Marathi & Devanagari message analyzer, preset lures, URL extraction radar, and bilingual advice.
  - `ApkSection.tsx`: Drag-and-drop APK inspector parsing binary manifests in memory without execution.
  - `InvestigationSection.tsx`: SQLite case explorer with search, risk filters, and parent-child multi-artifact modal viewer.
  - `ThreatNetworkSection.tsx`: Interactive Three.js 3D threat intelligence graph with orbit/zoom controls and metadata drawer.
  - `AiLabSection.tsx`: 3D synaptic neural lattice, Macro F1 (0.941) held-out metrics, and 8-point training gate status.
  - `PrivacySection.tsx`: Interactive in-memory PII redaction playground (Verhoeff Aadhaar & phone number scrubbing).
  - `HealthSection.tsx`: Real-time system diagnostics, zero-cost airgap metrics, and database connectivity.
  - `MissionSection.tsx`: Grassroots Maharashtra cyber defense charter in authentic Marathi and English.

---

## 3. BACKEND IMPLEMENTATION SUMMARY

- **Framework:** FastAPI (`api_server.py`) with Starlette and Uvicorn.
- **Stateless & Air-Gapped:** Zero external AI or cloud telemetry requests during parsing, tokenization, or scoring.
- **Core Security Reuse:** 100% of existing Python engines (`src/phishing_detector.py`, `src/apk_analyzer.py`, `src/url_analyzer.py`, `src/scheme_verifier.py`, `src/risk_scorer.py`, `src/privacy_gate.py`, `src/case_repository.py`) are reused without duplication.
- **Single-Origin Deployment:** The FastAPI server automatically mounts `frontend/dist/` to serve the compiled SPA at `/` while routing `/api/*` to security engines.

---

## 4. LIST OF MIGRATED FEATURES

| Feature / Module | Old Streamlit Mechanism | New Architecture Mechanism |
|:---|:---|:---|
| **Vernacular Phishing Detection** | `st.text_area` in `app.py` | `POST /api/analyze/message` & `PhishingSection.tsx` |
| **URL Threat Radar** | `st.text_input` in `app.py` | `POST /api/analyze/url` with heuristic risk score |
| **Safe APK Inspection** | `st.file_uploader` in `app.py` | `POST /api/analyze/apk` with in-memory manifest parsing |
| **Government Scheme Verification** | Form in `app.py` | `POST /api/analyze/scheme` verified against Maharashtra GRs |
| **Unified Workspace** | `src/unified_workspace_ui.py` | `POST /api/analyze/unified` handling multi-artifact payloads |
| **Investigation Case Center** | SQLite queries in `app.py` | `GET /api/cases`, `GET /api/cases/{id}`, `PATCH /api/cases/{id}` |
| **Threat Intelligence Network** | Static Markdown table in `app.py` | Interactive 3D WebGL node-link graph (`/api/threat-intel/graph`) |
| **Adaptive AI Telemetry** | Streamlit sidebar widgets | 3D neural lattice + `/api/ai/models` & `/api/ai/evaluations` |
| **Fail-Closed Privacy Gate** | In-memory redaction in `app.py` | Live interactive playground + `/api/privacy/sanitize` |
| **Local Operator Auth** | Streamlit password inputs | OWASP scrypt authentication (`/api/auth/login`) with session tokens |

---

## 5. LIST OF REMOVED STREAMLIT COMPONENTS & ARTIFACTS

The following files and dependencies were safely archived to `archive/legacy_streamlit/` and removed from active source code:
1. `app.py` &mdash; 1,944 lines of monolithic Streamlit UI deleted.
2. `src/unified_workspace_ui.py` &mdash; 446 lines of Streamlit component code deleted.
3. `src/ui_theme.py` &mdash; Streamlit CSS theme injector deleted.
4. `.streamlit/config.toml` &mdash; Streamlit configuration deleted.
5. `tests/test_phase7_1_1_interactive_acceptance.py` &mdash; AppTest-based Streamlit DOM tests retired and replaced by 17 FastAPI integration tests.
6. `requirements.txt` &mdash; `streamlit` removed; updated to modern FastAPI stack.
7. `scripts/verify_no_streamlit.py` &mdash; Added automated scanner verifying **0 active Streamlit imports remain**.

---

## 6. DATABASE MIGRATION REPORT

- **Local SQLite Storage:** Preserved at `instance/seva_cases.sqlite3` with verified backup at `instance/backups/seva_cases_pre_streamlit_migration.sqlite3` (SHA-256: `2a95edf9b5719f50406807b4aacee6fbdd3cd80c8734bfbae49586803a2029eb`).
- **Supabase PostgreSQL Schema:** Generated in [`migrations/001_initial_schema.sql`](file:///c:/Users/prati/seva-cyber-sandbox/migrations/001_initial_schema.sql).
  - All 11 tables mapped with exact column fidelity: `threat_cases`, `campaign_clusters`, `evidence_provenance`, `evidence_lifecycle_audit`, `threat_indicators`, `indicator_audit_log`, `operator_accounts`, `operator_sessions`, `human_reviews`, `schema_migrations`, `schema_version`.
- **Migration Utility:** [`scripts/migrate_to_postgres.py`](file:///c:/Users/prati/seva-cyber-sandbox/scripts/migrate_to_postgres.py) provides safe schema execution and record migration with `--dry-run` validation.

---

## 7. FILE-STORAGE CONFIGURATION REPORT

- **Object Storage Client:** Implemented in [`src/storage_manager.py`](file:///c:/Users/prati/seva-cyber-sandbox/src/storage_manager.py).
- **Cloud Provider:** Cloudflare R2 / AWS S3-compatible private buckets.
- **Security Invariants:**
  1. Private Buckets Only (never public by default).
  2. Magic Byte Signature Verification (verifying `PK\x03\x04` for APKs, `%PDF` for PDFs, `\x89PNG` for PNGs).
  3. SHA-256 Content Deduplication.
  4. 15 MB file size boundary.
  5. Short-lived signed download URLs (default 300 seconds).
  6. Transparent Local Fallback: Automatically writes to `instance/storage/` if R2 credentials are not set.

---

## 8. BACKEND API DOCUMENTATION

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Authenticates operator using OWASP scrypt hashing; returns session token |
| `POST` | `/api/auth/logout` | Revokes operator session token |
| `GET` | `/api/auth/me` | Returns current operator profile and permissions |
| `GET` | `/api/health` | Comprehensive diagnostics, DB connectivity, and shadow AI status |
| `GET` | `/api/system/health` | Alias for platform health check (Render probe compatible) |
| `GET` | `/api/dashboard/summary` | Executive dashboard overview metrics |
| `POST` | `/api/analyze/unified` | Multipart intake for heterogeneous evidence (text, URLs, files) |
| `POST` | `/api/analyze/message` | Analyzes Marathi/Hindi/English SMS or chat text |
| `POST` | `/api/phishing/analyze` | Dedicated alias for message phishing analysis |
| `GET` | `/api/phishing/results/{id}` | Retrieves past phishing analysis by Case ID |
| `POST` | `/api/analyze/url` | Static URL radar analysis |
| `POST` | `/api/analyze/apk` | In-memory APK structural inspection & permission auditing |
| `POST` | `/api/apk/analyze` | Dedicated alias for APK analysis |
| `GET` | `/api/apk/results/{id}` | Retrieves past APK analysis by Case ID |
| `POST` | `/api/analyze/scheme` | Verifies claims against Maharashtra Government Resolutions |
| `GET` | `/api/cases` | Lists cases with pagination, search, and risk filtering |
| `POST` | `/api/cases` | Manually records a threat case |
| `GET` | `/api/cases/{id}` | Fetches full case details, provenance chain, and reviews |
| `PATCH` | `/api/cases/{id}` | Updates case reviewer or adds operational notes |
| `POST` | `/api/cases/save-investigation`| Saves multi-artifact analysis to SQLite/PostgreSQL |
| `GET` | `/api/threat-intelligence/indicators` | Lists threat indicators with type & review filtering |
| `GET` | `/api/threat-intel/graph` | Builds WebGL node-link threat graph topology |
| `GET` | `/api/threat-intelligence/network`| Dedicated alias for threat graph network |
| `GET` | `/api/ai/models` | Active model architecture, Macro F1 metrics, and gate status |
| `GET` | `/api/ai/evaluations` | Model evaluation telemetry |
| `GET` | `/api/privacy/status` | Fail-closed privacy gate policy and active redaction rules |
| `POST` | `/api/privacy/sanitize` | Tests deterministic PII sanitization (Aadhaar & phone numbers) |
| `POST` | `/api/storage/upload` | Archives private evidence to Cloudflare R2 / S3 |
| `GET` | `/api/storage/evidence/{key}`| Streams private evidence blob |

---

## 9. AUTOMATED TEST RESULTS

```
Platform: Windows AMD64 — Python 3.14.8, pytest-8.4.2
Total Core Engine Tests: 847
Total REST API Integration Tests: 17
Grand Total Tests Executed: 864
Passed: 864
Failed: 0
Duration: 141.46s (2 minutes 21 seconds)
Success Rate: 100.0% PASS
```

```
Streamlit Removal Verification Check (scripts/verify_no_streamlit.py):
Scanned: 190 active source files
Violations Found: 0
Status: 100% STREAMLIT FREE
```

```
Frontend Production Build (npm run build):
Transformed: 2064 modules
Output: dist/index.html (1.14 kB), dist/assets/index-QI2ayp0Y.css (42.63 kB), dist/assets/index-BB0r7ok9.js (921.33 kB)
Build Duration: 429ms (0 Errors)
```

---

## 10. EXACT COMMANDS TO RUN LOCALLY

### Production Full-Stack Mode (Single Port 8000)
```powershell
python run_all.py --mode prod
# OR
python api_server.py
```
Open **`http://127.0.0.1:8000/`** in your browser.

### Development Mode (Vite Hot-Reload + FastAPI)
- Terminal 1: `python api_server.py` (Port 8000)
- Terminal 2: `cd frontend; npm run dev` (Port 5173)
Open **`http://localhost:5173/`** in your browser.

---

## 11. PRODUCTION DEPLOYMENT INSTRUCTIONS

### A. Deploy Frontend on Vercel
1. Push repository to GitHub.
2. In Vercel, click **Add New Project** and select this repository.
3. Configure project settings:
   - **Root Directory:** `frontend`
   - **Framework Preset:** `Vite`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. Add Environment Variable:
   - `VITE_API_BASE_URL`: `https://your-render-backend-url.onrender.com`
5. Deploy. Vercel automatically applies [`frontend/vercel.json`](file:///c:/Users/prati/seva-cyber-sandbox/frontend/vercel.json) for client-side SPA routing.

### B. Deploy Backend on Render
1. In Render, select **New Web Service** and connect this repository.
2. Configure settings:
   - **Root Directory:** `.` (repository root)
   - **Runtime:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn api_server:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path:** `/api/system/health`
3. Add Environment Variables:
   - `DATABASE_URL`: `postgresql://postgres:[PASSWORD]@[HOST]:5432/postgres` (from Supabase)
   - `SEVA_THREAT_INTEL_KEY`: A random 32-character string.
   - `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`: Cloudflare R2 credentials.
4. Deploy.

### C. Configure Supabase PostgreSQL
1. Create a free project at [Supabase](https://supabase.com).
2. Open the **SQL Editor** in your Supabase dashboard.
3. Paste and run the entire contents of [`migrations/001_initial_schema.sql`](file:///c:/Users/prati/seva-cyber-sandbox/migrations/001_initial_schema.sql).
4. Copy the URI connection string from **Project Settings > Database > Connection Strings**.

### D. Configure Cloudflare R2 Private Storage
1. In the Cloudflare Dashboard, navigate to **R2 > Create Bucket**.
2. Name the bucket `seva-evidence-private`.
3. Keep bucket permissions **Private** (no public access).
4. Go to **Manage R2 API Tokens**, create a token with **Object Read & Write** permissions on `seva-evidence-private`.
5. Note the **Account ID**, **Access Key ID**, and **Secret Access Key**.

---

## 12. REQUIRED ENVIRONMENT VARIABLE NAMES

| Variable | Description | Required In |
|---|---|:---:|
| `PORT` | Port for the Uvicorn server (defaults to 8000) | Render |
| `DATABASE_URL` | PostgreSQL connection string (Supabase) | Production |
| `SEVA_DB_PATH` | Path to SQLite database (defaults to `instance/seva_cases.sqlite3`) | Local Dev |
| `SEVA_THREAT_INTEL_KEY` | HMAC secret key for phone anonymization (min 16 chars) | Production |
| `R2_ACCOUNT_ID` | Cloudflare Account ID | Production Storage |
| `R2_ACCESS_KEY_ID` | Cloudflare R2 S3 Access Key | Production Storage |
| `R2_SECRET_ACCESS_KEY`| Cloudflare R2 S3 Secret Key | Production Storage |
| `R2_BUCKET_NAME` | R2 bucket name (`seva-evidence-private`) | Production Storage |
| `VITE_API_BASE_URL` | Base URL of deployed FastAPI backend | Vercel Frontend |

---

## 13. KNOWN LIMITATIONS & OPERATIONAL GOVERNANCE

1. **Free-Tier Render Cold Starts:** On free Render web service plans, instances spin down after 15 minutes of inactivity; initial cold start takes approximately 30-50 seconds.
2. **Model Retraining Gate Policy:** The 8-point eligibility gate (`TrainingReadinessGate`) strictly prevents automatic model retraining (`BLOCKED_INSUFFICIENT_REAL_WORLD_EVIDENCE`). A minimum of 100 authenticated, human-reviewed, non-synthetic real-world cases is required before retraining can proceed.
3. **Deterministic Authority:** Machine-learning models run strictly in shadow mode. All authoritative risk assessments and score calculations are governed 100% by deterministic heuristic rule sets.
