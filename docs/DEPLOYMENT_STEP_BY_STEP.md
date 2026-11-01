# SEVA CYBER SANDBOX — COMPLETE STEP-BY-STEP DEPLOYMENT GUIDE

**Target Architecture:** Vercel (React Frontend) + Render (FastAPI Backend) + Supabase (PostgreSQL) + Cloudflare R2 (Private Storage)  
**Budget:** **₹0 / $0 USD (100% Free-Tier Compatible)**  
**Estimated Time:** 35–45 minutes  

---

### Step 1: Pre-Deployment Backup & Local Database Verification
* **Where:** Local Workstation &rarr; PowerShell Terminal.
* **Exact Command:**
  ```powershell
  python scripts/verify_db_integrity.py
  ```
* **What Success Looks Like:**
  ```
  Active DB SHA-256 : 2a95edf9b5719f50406807b4aacee6fbdd3cd80c8734bfbae49586803a2029eb
  Backup DB SHA-256 : 2a95edf9b5719f50406807b4aacee6fbdd3cd80c8734bfbae49586803a2029eb
  [+] SHA-256 Verification: IDENTICAL (Pristine)
  [+] Schema Verification: All 79 objects (tables, indexes, triggers) 100% MATCH
  ```
* **What to Do If It Fails:** Restore `instance/seva_cases.sqlite3` from `instance/backups/seva_cases_pre_migration_backup.sqlite3`.
* **Cost:** Free.
* **Security Warning:** Do not delete or overwrite the backup file.

---

### Step 2: Confirm Commit & Working Tree Status
* **Where:** PowerShell Terminal.
* **Exact Command:**
  ```powershell
  git status
  ```
* **What Success Looks Like:** Working directory clean, on branch `main`.
* **What to Do If It Fails:** If you have uncommitted deployment-hardening changes, commit them:
  ```powershell
  git add migrations/ scripts/ src/ api_server.py .env.example
  git commit -m "chore(deploy): prepare production schema and pool configurations"
  ```
* **Cost:** Free.

---

### Step 3: Create or Verify GitHub Repository
* **Where:** Browser &rarr; [github.com/new](https://github.com/new).
* **Menu/Settings:**
  1. Repository Name: `seva-cyber-sandbox`.
  2. Visibility: **Private** (recommended for security audits) or **Public**.
  3. Leave "Initialize this repository with a README" unchecked.
  4. Click **Create repository**.
* **Exact Command in Terminal:**
  ```powershell
  git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/seva-cyber-sandbox.git
  git branch -M main
  git push -u origin main
  ```
* **What Success Looks Like:** `git push` prints `Branch 'main' set up to track remote branch 'main' from 'origin'`.
* **Cost:** Free.
* **Security Warning:** Ensure `.gitignore` ignores `instance/`, `*.sqlite3`, and `.env` so no private logs or keys are pushed.

---

### Step 4: Create Hosting Accounts
* **Where:** Browser.
* **Actions:**
  1. **Supabase:** Sign up at [supabase.com](https://supabase.com) using GitHub. (Free Tier: 500 MB DB, no card required).
  2. **Render:** Sign up at [render.com](https://render.com) using GitHub. (Free Tier: 750 free instance hours/month, no card required).
  3. **Vercel:** Sign up at [vercel.com](https://vercel.com) using GitHub. (Hobby Free Tier: Unlimited static deployments, no card required).
  4. **Cloudflare (Optional):** Sign up at [cloudflare.com](https://cloudflare.com) if using R2 private storage.
* **Cost:** Free.

---

### Step 5: Provision Supabase PostgreSQL Database
* **Where:** Supabase Dashboard &rarr; [supabase.com/dashboard](https://supabase.com/dashboard).
* **Menu/Settings:**
  1. Click **New project**.
  2. Organization: Select your default organization.
  3. Name: `seva-cyber-sandbox`.
  4. Database Password: Generate a strong password (at least 16 characters). **Save this password safely in your password manager!**
  5. Region: Select the region closest to your users (e.g., `South Asia (Mumbai)`).
  6. Pricing Plan: **Free Plan** ($0/month).
  7. Click **Create new project** and wait 60 seconds for provisioning.
* **Retrieve Connection URI:**
  1. In left sidebar, click **Project Settings** (gear icon) &rarr; **Database**.
  2. Scroll down to **Connection string** &rarr; select **URI** tab &rarr; select **Mode: Session** (port 5432).
  3. Format: `postgresql://postgres.[ref]:[PASSWORD]@aws-0-[region].pooler.supabase.com:5432/postgres?sslmode=require`.
  4. Replace `[PASSWORD]` with your actual password.
* **What Success Looks Like:** Connection string copied to clipboard.
* **Cost:** Free.

---

### Step 6: Run Idempotent Schema Migration Against Supabase
* **Where:** PowerShell Terminal.
* **Exact Command:**
  ```powershell
  python scripts/migrate_to_postgres.py --url "YOUR_SUPABASE_POSTGRESQL_URI"
  ```
* **What Success Looks Like:**
  ```
  [*] Target SQLite Source (Strict Read-Only): ...\instance\seva_cases.sqlite3
  [*] Applying Supabase PostgreSQL schema DDL (16 tables)...
  [+] Supabase PostgreSQL schema initialized successfully.
  [*] Replicating records across all 16 tables from SQLite to PostgreSQL...
  [*] Table 'schema_version' verified (1 records in source).
  [+] Data replication completed across all 16 tables.
  [+] Migration completed successfully!
  ```
* **What to Do If It Fails:** If connection times out, verify your password does not contain unencoded special characters or test port 6543 (Transaction pooler).
* **Cost:** Free.

---

### Step 7: Provision Cloudflare R2 Storage Bucket (Optional)
* **Where:** Cloudflare Dashboard &rarr; [dash.cloudflare.com](https://dash.cloudflare.com).
* **Menu/Settings:**
  1. In left menu, click **R2** &rarr; **Create bucket**.
  2. Bucket name: `seva-evidence-private`.
  3. Location: Automatic.
  4. Click **Create bucket**.
  5. Click **Manage R2 API Tokens** &rarr; **Create API Token**.
  6. Permissions: **Admin Read & Write**.
  7. Save: `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`.
* **Cost:** Free (10 GB/month included, zero egress fees).
* **Note:** If you skip this step, leave R2 variables blank in Render; the backend safely uses local storage.

---

### Step 8: Deploy Backend API on Render
* **Where:** Render Dashboard &rarr; [dashboard.render.com](https://dashboard.render.com).
* **Menu/Settings:**
  1. Click **New +** &rarr; **Web Service**.
  2. Select **Build and deploy from a Git repository** &rarr; click **Next**.
  3. Connect your GitHub account and select `seva-cyber-sandbox`.
  4. Configure settings:
     - **Name:** `seva-cyber-sandbox-api`
     - **Region:** Singapore or Frankfurt (closest to your users).
     - **Branch:** `main`
     - **Root Directory:** *(leave blank — runs from repo root)*
     - **Runtime:** `Python 3`
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `uvicorn api_server:app --host 0.0.0.0 --port $PORT`
     - **Instance Type:** `Free` (512 MB RAM, 0.1 CPU).
  5. Do not click Create yet — scroll down to **Environment Variables** in Step 9.
* **Cost:** Free.

---

### Step 9: Configure Backend Environment Variables on Render
* **Where:** Render Web Service creation form &rarr; **Environment Variables** section.
* **Variables to Add:**

| Key | Value to Enter |
| :--- | :--- |
| `PYTHON_VERSION` | `3.11.9` |
| `DATABASE_URL` | *Your Supabase PostgreSQL URI from Step 5* |
| `SEVA_ENV` | `production` |
| `SEVA_STRICT_DB_STARTUP` | `true` |
| `SEVA_THREAT_INTEL_KEY` | *(Generate a random 32-character hex key)* |
| `SEVA_FEEDBACK_HMAC_KEY` | *(Generate a random 32-character hex key)* |
| `SEVA_JWT_SECRET` | *(Generate a random 32-character hex key)* |
| `SEVA_FIRST_ADMIN_TOKEN` | *(Choose a secret provisioning token, e.g. `SetupAdmin2026!Key`)* |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` *(We will append your Vercel URL in Step 13)* |
| `R2_ACCOUNT_ID` | *(Optional: Your Cloudflare Account ID)* |
| `R2_ACCESS_KEY_ID` | *(Optional: Your R2 Access Key)* |
| `R2_SECRET_ACCESS_KEY` | *(Optional: Your R2 Secret Key)* |
| `R2_BUCKET_NAME` | `seva-evidence-private` |

* **Action:** Click **Create Web Service**.
* **What Success Looks Like:** Render deploys your code. Deployment log ends with:
  ```
  INFO:     Application startup complete.
  INFO:     Uvicorn running on http://0.0.0.0:10000 (Press CTRL+C to quit)
  ==> Your service is live 🎉 at https://seva-cyber-sandbox-api.onrender.com
  ```
* **Cost:** Free.

---

### Step 10: Verify Backend Startup & Health
* **Where:** Browser or Terminal.
* **Exact URL:** `https://<YOUR-RENDER-SERVICE-NAME>.onrender.com/api/system/health`
* **What Success Looks Like:** Returns HTTP 200 with JSON:
  ```json
  {
    "status": "operational",
    "database": {
      "connected": true,
      "type": "postgresql",
      "path": "postgresql://postgres:****@aws-0-....pooler.supabase.com:5432/postgres",
      "cases_count": 0
    },
    "platform": {
      "version": "7.2.0",
      "name": "Seva Cyber Sandbox"
    }
  }
  ```
* **What to Do If It Fails:** Check Render logs. If `Production database startup failure` appears, verify your `DATABASE_URL` credentials in Render environment variables.
* **Cost:** Free.

---

### Step 11: Deploy Frontend on Vercel
* **Where:** Vercel Dashboard &rarr; [vercel.com/new](https://vercel.com/new).
* **Menu/Settings:**
  1. Click **Import** next to your `seva-cyber-sandbox` repository.
  2. Configure Project:
     - **Project Name:** `seva-cyber-sandbox`
     - **Framework Preset:** `Vite`
     - **Root Directory:** Click **Edit** &rarr; select `frontend` &rarr; click **Continue**.
     - **Build Command:** `npm run build` (automatic)
     - **Output Directory:** `dist` (automatic)
  3. Expand **Environment Variables**:
     - Key: `VITE_API_URL`
     - Value: `https://<YOUR-RENDER-SERVICE-NAME>.onrender.com` *(Your Render URL from Step 10, without trailing slash)*
  4. Click **Deploy**.
* **What Success Looks Like:** Build completes in ~40 seconds. Confetti animation displays: `Congratulations! Your project is deployed.`
* **Copy Your Production URL:** Note your Vercel URL (e.g., `https://seva-cyber-sandbox.vercel.app`).
* **Cost:** Free.

---

### Step 12: Configure Vercel API Proxy (Eliminates CORS & Relative Path Issues)
* **Where:** Local Workstation &rarr; `frontend/vercel.json`.
* **Action:** To ensure zero CORS headaches and seamless `/api` proxying directly from Vercel's edge to Render, verify `frontend/vercel.json` includes the `/api/(.*)` rewrite destination pointing to your Render backend:
  ```json
  {
    "version": 2,
    "framework": "vite",
    "rewrites": [
      {
        "source": "/api/(.*)",
        "destination": "https://<YOUR-RENDER-SERVICE-NAME>.onrender.com/api/$1"
      },
      {
        "source": "/(.*)",
        "destination": "/index.html"
      }
    ]
  }
  ```
* **Commit & Push:**
  ```powershell
  git add frontend/vercel.json
  git commit -m "chore(deploy): add Vercel API proxy rewrite to Render backend"
  git push origin main
  ```
* **What Success Looks Like:** Vercel automatically detects the push and redeploys in 30 seconds.
* **Cost:** Free.

---

### Step 13: Align CORS on Render Backend
* **Where:** Render Dashboard &rarr; Web Service `seva-cyber-sandbox-api` &rarr; **Environment**.
* **Edit Variable:**
  - Key: `CORS_ALLOWED_ORIGINS`
  - Value: `https://seva-cyber-sandbox.vercel.app,http://localhost:5173` *(Include both your production Vercel URL and local dev origin)*
* **Action:** Click **Save Changes**. Render automatically redeploys in ~30 seconds.
* **What Success Looks Like:** Render log shows `Application startup complete`.
* **Cost:** Free.

---

### Step 14: Secure Initial Administrator Account Provisioning
* **Where:** PowerShell Terminal (or Browser Swagger UI at `https://<YOUR-RENDER-URL>.onrender.com/docs`).
* **Exact Command:**
  ```powershell
  curl -X POST "https://<YOUR-RENDER-URL>.onrender.com/api/auth/setup-admin" `
    -H "Content-Type: application/json" `
    -H "X-Setup-Token: YOUR_SEVA_FIRST_ADMIN_TOKEN" `
    -d '{"username": "admin_seva", "password": "SuperSecurePassword2026!#"}'
  ```
* **What Success Looks Like:**
  ```json
  {
    "status": "success",
    "message": "Initial administrator account 'admin_seva' provisioned successfully.",
    "role": "admin"
  }
  ```
* **Security Verification:** Run the exact same command a second time. It must return **HTTP 403 Forbidden**: `"Initial administrator setup is locked because operator accounts already exist."`
* **Cost:** Free.

---

### Step 15: Test Authentication & Session Management
* **Where:** Open `https://<YOUR-VERCEL-URL>.vercel.app` in your browser.
* **Action:**
  1. Click **Operator Login** in the navigation bar.
  2. Enter username `admin_seva` and your password.
  3. Click **Sign In**.
* **What Success Looks Like:** The status badge changes to `Active Operator: admin_seva (Role: admin)`.
* **Cost:** Free.

---

### Step 16: Test Phishing Intelligence Workspace
* **Where:** Navigate to Phishing Intelligence section on the live website.
* **Action:**
  1. Click preset: **MSEDCL Bill Disconnection**.
  2. Click **ANALYZE SUBMITTED EVIDENCE**.
* **What Success Looks Like:**
  - Analysis completes in <2 seconds.
  - Overall Verdict displays: `CRITICAL / HIGH RISK`.
  - Dialect analysis highlights Marathi urgency markers (`तात्काळ`, `खंडित`).
  - Extracted URL `http://bit.ly/mseb-update` flagged as suspicious shortened domain.
  - **No 502 Bad Gateway error appears.**
* **Cost:** Free.

---

### Step 17: Test Target URL Analysis
* **Where:** Phishing Intelligence &rarr; Target URL field.
* **Action:**
  1. Input: `http://pm-kisan-portal-free-subsidy.xyz/apply`.
  2. Click **ANALYZE SUBMITTED EVIDENCE**.
* **What Success Looks Like:** Risk score 90+, badge color `#EF4444`, flagged for non-governmental TLD targeting vernacular users.
* **Cost:** Free.

---

### Step 18: Test Maharashtra Scheme Verification Engine
* **Where:** Scroll to Government Scheme Verifier section.
* **Action:**
  1. Input claim text: `मुख्यमंत्री माझी लाडकी बहीण योजना अंतर्गत दरमहा ३००० रुपये मिळवण्यासाठी खालील फॉर्म भरा`.
  2. Click **Verify Scheme**.
* **What Success Looks Like:** Engine identifies authoritative source: `https://ladkibahin.maharashtra.gov.in/`, flags the unofficial claim amount, and outputs official helpline `181`.
* **Cost:** Free.

---

### Step 19: Test APK Structural Static Analyzer
* **Where:** Scroll to APK Inspection section.
* **Action:**
  1. Drag and drop a test APK fixture from `sample_apks/` (e.g. `sample_apks/MSEDCL_Light_Bill_Update_Test.apk`).
  2. Click **Analyze Android Application**.
* **What Success Looks Like:** Displays parsed package name, declared dangerous permissions (`RECEIVE_SMS`, `REQUEST_INSTALL_PACKAGES`), embedded URLs, and static risk score.
* **Cost:** Free.

---

### Step 20: Test Threat Case Creation & Retrieval
* **Where:** Phishing Intelligence Workspace.
* **Action:**
  1. With an active analysis result, click **Save Investigation Case**.
  2. Open Investigation Dashboard.
* **What Success Looks Like:** The case appears in the table with its ID `CASE-...`, risk score, and timestamp. Clicking the case loads full evidence details from Supabase PostgreSQL.
* **Cost:** Free.

---

### Step 21: Test Private Evidence Storage & Authorized Download
* **Where:** Investigation Dashboard &rarr; Case Details.
* **Action:**
  1. Click **Download Evidence Artifact**.
  2. Open in private/incognito window without login.
* **What Success Looks Like:**
  - Authenticated admin download streams the file correctly with `Cache-Control: private`.
  - Unauthenticated request returns HTTP 401/403.
* **Cost:** Free.

---

### Step 22: Test Access Control (RBAC) & Unauthorized Access Rejection
* **Where:** PowerShell Terminal.
* **Exact Command:**
  ```powershell
  curl -i "https://<YOUR-RENDER-URL>.onrender.com/api/cases"
  ```
* **What Success Looks Like:** Returns HTTP 200 for public case telemetry (or HTTP 401 when testing private evidence routes `/api/storage/evidence/...` without `Authorization: Bearer <token>`).
* **Cost:** Free.

---

### Step 23: Verify Security Headers & HTTPS Enforcement
* **Where:** PowerShell Terminal.
* **Exact Command:**
  ```powershell
  curl -I "https://<YOUR-VERCEL-URL>.vercel.app"
  ```
* **What Success Looks Like:** Response headers contain:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy`
* **Cost:** Free.

---

### Step 24: Verify Cold-Start & Data Persistence Across Restarts
* **Where:** Render Dashboard &rarr; Web Service &rarr; **Manual Deploy** &rarr; **Restart Service**.
* **Action:**
  1. Wait for restart to complete.
  2. Reopen `https://<YOUR-VERCEL-URL>.vercel.app`.
  3. Log in with your admin credentials created in Step 14.
  4. Check the Investigation Dashboard.
* **What Success Looks Like:**
  - Admin login succeeds immediately (credentials survived restart in Supabase).
  - All previously saved cases, threat indicators, and audit logs are 100% intact.
* **Cost:** Free.

---

### Step 25: Final Production Review
* **Where:** Render Dashboard &rarr; **Logs** & Vercel Dashboard &rarr; **Logs**.
* **Review:**
  - Confirm zero unhandled Python exceptions.
  - Confirm zero 502 Bad Gateway responses.
  - Confirm all Three.js 3D lattice animations render smoothly in the browser.
* **Congratulations!** Your Seva Cyber Sandbox is live, persistent, and production-secure!
