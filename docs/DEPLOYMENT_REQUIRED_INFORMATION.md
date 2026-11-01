# SEVA CYBER SANDBOX — DEPLOYMENT CONFIGURATION & REQUIRED INFORMATION

This document catalogs every piece of information, dashboard identifier, environment variable, and cryptographic secret needed to deploy Seva Cyber Sandbox to production.

---

## Category A: Information Available from Repository (Confirmed Local Values)

These values have been discovered and verified directly from the codebase. No user action is required to determine them.

| Parameter | Confirmed Value | Source File |
| :--- | :--- | :--- |
| **Repository Root** | `C:\Users\prati\seva-cyber-sandbox` | Workspace Root |
| **Frontend Directory** | `frontend/` | [frontend/](file:///c:/Users/prati/seva-cyber-sandbox/frontend) |
| **Frontend Build Command** | `npm run build` (`tsc -b && vite build`) | [frontend/package.json](file:///c:/Users/prati/seva-cyber-sandbox/frontend/package.json) |
| **Frontend Output Directory** | `dist` (resolved to `frontend/dist`) | [frontend/vite.config.ts](file:///c:/Users/prati/seva-cyber-sandbox/frontend/vite.config.ts) |
| **Frontend Node Version** | Node.js 18.x or 20.x | React 19 / Vite 8 compatibility |
| **Backend Entry Point** | `api_server.py` | [api_server.py](file:///c:/Users/prati/seva-cyber-sandbox/api_server.py) |
| **FastAPI App Instance** | `app` | `api_server:app` |
| **Backend Python Version** | Python 3.11+ (recommended: `3.11.9`) | [render.yaml](file:///c:/Users/prati/seva-cyber-sandbox/render.yaml) |
| **Backend Dependency File** | `requirements.txt` | [requirements.txt](file:///c:/Users/prati/seva-cyber-sandbox/requirements.txt) |
| **Backend Build Command** | `pip install -r requirements.txt` | [render.yaml](file:///c:/Users/prati/seva-cyber-sandbox/render.yaml) |
| **Backend Start Command** | `uvicorn api_server:app --host 0.0.0.0 --port $PORT` | [render.yaml](file:///c:/Users/prati/seva-cyber-sandbox/render.yaml) |
| **Backend Health Route** | `/api/system/health` (also `/api/health`) | [api_server.py](file:///c:/Users/prati/seva-cyber-sandbox/api_server.py#L374) |
| **Default Local SQLite Path**| `instance/seva_cases.sqlite3` | [src/database_adapter.py](file:///c:/Users/prati/seva-cyber-sandbox/src/database_adapter.py#L30) |
| **SQL Schema Migration** | `migrations/001_initial_schema.sql` | [migrations/001_initial_schema.sql](file:///c:/Users/prati/seva-cyber-sandbox/migrations/001_initial_schema.sql) |
| **Data Migration Script** | `scripts/migrate_to_postgres.py` | [scripts/migrate_to_postgres.py](file:///c:/Users/prati/seva-cyber-sandbox/scripts/migrate_to_postgres.py) |
| **Default Storage Bucket** | `seva-evidence-private` | [src/storage_manager.py](file:///c:/Users/prati/seva-cyber-sandbox/src/storage_manager.py#L63) |

---

## Category B: Information User Must Obtain from Hosting Dashboards

The user must retrieve the following external values from the respective third-party hosting dashboards after creating projects.

### 1. GitHub Repository URL
* **Service:** GitHub ([github.com](https://github.com))
* **Where to Find:** Navigate to your repository &rarr; click green **Code** button &rarr; copy the HTTPS URL (e.g., `https://github.com/your-username/seva-cyber-sandbox.git`).
* **Classification:** Public
* **Where Configured:** Render and Vercel project creation flows.
* **Required:** YES

---

### 2. Render Backend Public URL
* **Service:** Render ([dashboard.render.com](https://dashboard.render.com))
* **Where to Find:** In the Render dashboard, click your newly created Web Service (`seva-cyber-sandbox-api`). The URL appears right under the service title (e.g., `https://seva-cyber-sandbox-api.onrender.com`).
* **Classification:** Public
* **Where Configured:**
  1. Configured in Vercel as `VITE_API_URL` (or in `vercel.json` rewrites).
  2. Used locally in `scripts/migrate_to_postgres.py` if verifying connectivity.
* **Required:** YES

---

### 3. Vercel Frontend Public URL
* **Service:** Vercel ([vercel.com/dashboard](https://vercel.com/dashboard))
* **Where to Find:** In the Vercel dashboard, click your deployed project &rarr; **Domains** or **Deployment URL** (e.g., `https://seva-cyber-sandbox.vercel.app`).
* **Classification:** Public
* **Where Configured:** Render environment variable `CORS_ALLOWED_ORIGINS`.
* **Required:** YES

---

### 4. Supabase PostgreSQL Connection URI (`DATABASE_URL`)
* **Service:** Supabase ([supabase.com/dashboard](https://supabase.com/dashboard))
* **Where to Find:**
  1. Open your Supabase project dashboard.
  2. Click **Project Settings** (gear icon in the left sidebar) &rarr; **Database**.
  3. Scroll to **Connection string** &rarr; select **URI** tab &rarr; select **Mode: Session** (port 5432) or **Transaction** (port 6543).
  4. Copy URI format: `postgresql://postgres.[ref]:[YOUR-PASSWORD]@aws-0-[region].pooler.supabase.com:5432/postgres?sslmode=require`.
  5. Replace `[YOUR-PASSWORD]` with the database password chosen during project creation.
* **Classification:** **HIGH-SECURITY SECRET**
* **Where Configured:** Configured in Render Web Service Environment Variables. Never commit to Git.
* **Required:** YES (for persistent cloud production)

---

### 5. Cloudflare R2 Object Storage Credentials
* **Service:** Cloudflare ([dash.cloudflare.com](https://dash.cloudflare.com))
* **Where to Find:**
  1. In Cloudflare sidebar, click **R2** &rarr; **Manage R2 API Tokens**.
  2. Click **Create API Token** &rarr; Name: `seva-evidence-token` &rarr; Permissions: **Admin Read & Write** &rarr; TTL: Forever &rarr; Click **Create API Token**.
  3. Save the generated credentials immediately:
     - **Account ID:** Found on the main R2 Overview page in the right-hand panel.
     - **Access Key ID:** Displayed on token creation success screen.
     - **Secret Access Key:** Displayed on token creation success screen.
     - **Bucket Name:** The name of the bucket you create (e.g., `seva-evidence-private`).
* **Classification:** **HIGH-SECURITY SECRET**
* **Where Configured:** Render Web Service Environment Variables.
* **Required:** OPTIONAL (If omitted, backend automatically stores evidence in the container's private local directory).

---

## Category C: Secrets to Configure Privately

Configure these variables privately in the **Render Dashboard &rarr; Environment &rarr; Environment Variables**.

| Environment Variable | Purpose | Required? | Recommended Secure Generation Method | Where to Configure |
| :--- | :--- | :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection string | **REQUIRED** for persistent production | Provided by Supabase during database setup | Render Dashboard |
| `SEVA_ENV` | Sets execution environment to cloud production | **REQUIRED** (`production`) | Set to literal value: `production` | Render Dashboard |
| `SEVA_STRICT_DB_STARTUP` | Enforces fail-closed database connectivity check on server start | **REQUIRED** (`true`) | Set to literal value: `true` | Render Dashboard |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowlist of origins permitted to call the API | **REQUIRED** | Set to your Vercel URL, e.g.: `https://seva-cyber-sandbox.vercel.app` | Render Dashboard |
| `SEVA_THREAT_INTEL_KEY` | HMAC secret for anonymizing phone number intelligence | **REQUIRED** | Run in PowerShell: `[Convert]::ToHexString((1..32 \| ForEach-Object { Get-Random -Maximum 256 }))` | Render Dashboard |
| `SEVA_FEEDBACK_HMAC_KEY`| Isolated HMAC key for user feedback curation | **REQUIRED** | Run in PowerShell: `[Convert]::ToHexString((1..32 \| ForEach-Object { Get-Random -Maximum 256 }))` | Render Dashboard |
| `SEVA_JWT_SECRET` | Secret key for signing operator authentication session tokens | **REQUIRED** | Run in PowerShell: `[Convert]::ToHexString((1..32 \| ForEach-Object { Get-Random -Maximum 256 }))` | Render Dashboard |
| `SEVA_FIRST_ADMIN_TOKEN`| One-time token unlocking initial administrator registration | OPTIONAL (Recommended) | Run in PowerShell: `[Convert]::ToHexString((1..16 \| ForEach-Object { Get-Random -Maximum 256 }))` | Render Dashboard |
| `R2_ACCOUNT_ID` | Cloudflare account identifier | OPTIONAL | Copied from Cloudflare R2 dashboard | Render Dashboard |
| `R2_ACCESS_KEY_ID` | S3-compatible Access Key ID | OPTIONAL | Copied from Cloudflare R2 token generation | Render Dashboard |
| `R2_SECRET_ACCESS_KEY` | S3-compatible Secret Access Key | OPTIONAL | Copied from Cloudflare R2 token generation | Render Dashboard |
| `R2_BUCKET_NAME` | Name of private R2 bucket | OPTIONAL (`seva-evidence-private`) | Set to your bucket name | Render Dashboard |

> [!CAUTION]
> Never commit `.env` or paste real credentials into public chat, Git commits, or pull requests. All values must be configured directly in the hosting dashboard's encrypted secret manager.

---

## Category D: User Decisions Required

| Decision | Recommended Default | Beginner Explanation |
| :--- | :--- | :--- |
| **1. Primary Hosting Architecture** | **Option B: Vercel (Frontend) + Render (Backend) + Supabase (DB)** | Provides instant loading of the Liquid Glass 3D UI via Vercel Edge CDN, permanent persistence of threat cases on Supabase for ₹0, and dedicated Python API execution on Render. |
| **2. Storage Backend for Uploaded Evidence** | **Cloudflare R2** (if you have Cloudflare account), or **Local Fallback** | Cloudflare R2 provides 10 GB free cloud storage with zero bandwidth charges. If you don't wish to set up Cloudflare right now, leave R2 variables blank; the backend safely defaults to local disk. |
| **3. Initial Admin Credentials** | Username: e.g. `superadmin` / Strong Password (12+ chars, mixed case, symbols) | The very first account registered becomes the Sandbox Administrator with full privileges to view threat graphs and indicators. |
