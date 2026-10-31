# Seva Cyber Sandbox (Maha-Suraksha)

**An Air-Gapped Cyber Defense, Malicious APK, and Vernacular Phishing Detection Platform**  
**Frontend Architecture:** React 19 + Vite 8 + TypeScript + Three.js + Tailwind CSS v4  
**Backend Architecture:** Python FastAPI REST API + Standalone Core Security Services  
**Database:** Dual Support (SQLite Local Dev + Supabase PostgreSQL Production)  
**Private Evidence Storage:** Cloudflare R2 / S3-Compatible Object Storage  
**Visual Identity:** Liquid Glass Aesthetic & 3D Threat Core  

---

## 1. Project Overview

Across Maharashtra, smartphone users frequently receive deceptive WhatsApp messages and SMS in Marathi threatening immediate electricity disconnection, fraudulent registration links for *Majhi Ladki Bahin* or *PM Kisan* welfare benefits, or notifications accompanied by rogue Android `.apk` dropper files.

**Seva Cyber Sandbox** is a sovereign, 100% offline-capable, privacy-preserving cybersecurity application. It statically inspects suspicious messages, Android APK packages, web URLs, and government scheme claims in local memory — warning citizens of threat indicators in plain Marathi and English before financial compromise occurs.

---

## 2. Decoupled System Architecture

```
                    +-------------------------------------------------------------+
                    |                 REACT 19 + THREE.JS FRONTEND                |
                    |           Liquid Glass UI • 10 Continuous Sections          |
                    |          WebGL 3D Security Core • Threat Graph Explorer     |
                    +------------------------------+------------------------------+
                                                   |
                                                   | HTTP / REST (JSON)
                                                   v
                    +-------------------------------------------------------------+
                    |                 FASTAPI REST BACKEND (Port 8000)            |
                    |               api_server.py (17 Secure Endpoints)           |
                    |           OWASP scrypt Auth • Fail-Closed Privacy Gate      |
                    +------------------------------+------------------------------+
                                                   |
         +--------------------+--------------------+--------------------+--------------------+
         |                    |                    |                    |                    |
         v                    v                    v                    v                    v
+-----------------+  +-----------------+  +-----------------+  +-----------------+  +-----------------+
|   Vernacular    |  |   Static APK    |  |  Safe URL Radar |  |   Maharashtra   |  |   Unified Multi |
|    Phishing     |  |    Analyzer     |  |  & Domain Check |  |  Scheme Engine  |  |  Evidence Store |
| src/phishing_   |  | src/apk_        |  | src/url_        |  | src/scheme_     |  | src/unified_    |
| detector.py     |  | analyzer.py     |  | analyzer.py     |  | verifier.py     |  | analyzer.py     |
+--------+--------+  +--------+--------+  +--------+--------+  +--------+--------+  +--------+--------+
         |                    |                    |                    |                    |
         +--------------------+--------------------+--------------------+--------------------+
                                                   |
                        +--------------------------+--------------------------+
                        |                                                     |
                        v                                                     v
        +-------------------------------+                     +-------------------------------+
        |     DATABASE PERSISTENCE      |                     |     PRIVATE OBJECT STORAGE    |
        |  Local: SQLite (instance/)    |                     |  Cloudflare R2 / S3 Storage   |
        |  Prod: Supabase PostgreSQL    |                     |  src/storage_manager.py       |
        |  src/case_repository.py       |                     |  Signed URLs • SHA-256 Hashes |
        +-------------------------------+                     +-------------------------------+
```

---

## 3. Quick Start & Local Execution

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Node.js 18+ & npm

### Installation
```powershell
# 1. Install backend dependencies
pip install -r requirements.txt

# 2. Install frontend dependencies
cd frontend
npm install
npm run build
cd ..
```

### Running the Application

#### Option A: Full-Stack Production Mode (Recommended)
Launches the FastAPI server which automatically serves both the API endpoints and the precompiled Liquid Glass 3D React UI at a single origin:
```powershell
python run_all.py --mode prod
# OR directly:
python api_server.py
```
Open **`http://127.0.0.1:8000/`** in your browser.

#### Option B: Development Mode (Hot-Reloading)
Runs the Vite frontend development server on port 5173 with live reload, proxying `/api` requests to FastAPI on port 8000:
- Terminal 1: `python api_server.py`
- Terminal 2: `cd frontend; npm run dev`
Open **`http://localhost:5173/`** in your browser.

---

## 4. Production Deployment Guide

### A. Frontend Hosting — Vercel
1. Connect this GitHub repository to [Vercel](https://vercel.com).
2. Set **Root Directory** to `frontend`.
3. Set **Framework Preset** to `Vite`.
4. Build Command: `npm run build`
5. Output Directory: `dist`
6. Add Environment Variable:
   - `VITE_API_BASE_URL`: URL of your deployed Render backend (e.g. `https://seva-api.onrender.com`)

### B. Backend Hosting — Render
1. Create a new **Web Service** on [Render](https://render.com).
2. Connect your GitHub repository (using `render.yaml` or manual configuration).
3. Set **Build Command**: `pip install -r requirements.txt`
4. Set **Start Command**: `uvicorn api_server:app --host 0.0.0.0 --port $PORT`
5. Configure Health Check Path: `/api/system/health`
6. Add Environment Variables:
   - `DATABASE_URL`: Your Supabase connection string.
   - `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`: Cloudflare R2 credentials.
   - `SEVA_THREAT_INTEL_KEY`: A cryptographically secure secret (minimum 16 chars).

### C. Database — Supabase PostgreSQL
1. Create a project in [Supabase](https://supabase.com).
2. Run the migration script in the SQL editor:
   ```sql
   -- Copy and run migrations/001_initial_schema.sql
   ```
3. Set `DATABASE_URL` in your Render backend settings.

### D. Private Storage — Cloudflare R2
1. Create a private bucket in [Cloudflare R2](https://dash.cloudflare.com) named `seva-evidence-private`.
2. Generate an R2 API token with read/write permissions.
3. Configure `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and `R2_BUCKET_NAME` on the backend.

---

## 5. Security Invariants & Testing

- **Automated Pytests:** Run `python -m pytest -q` to execute the full test suite.
- **Streamlit Decommissioning Verification:** Run `python scripts/verify_no_streamlit.py` to confirm zero Streamlit imports exist across active source files.
- **Airgap Guarantee:** Zero external network calls are made during message parsing, APK unpacking, or AI inference.
- **Fail-Closed Privacy Gate:** In-memory PII sanitization removes Aadhaar and Indian phone numbers before persistent storage.
- **Model Governance:** Neural network (`custom-mlp-v4.0.0-seed42`) executes purely in shadow mode; deterministic rule engines remain production-authoritative.
