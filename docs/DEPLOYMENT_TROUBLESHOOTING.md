# SEVA CYBER SANDBOX — DEPLOYMENT TROUBLESHOOTING RUNBOOK

This runbook catalogs the most common errors encountered during cloud deployment and local development of the Seva Cyber Sandbox, along with exact diagnostic commands and verified remedies.

---

## 1. HTTP 502 Bad Gateway / Backend Unreachable

### Scenario A: Local Development Server Displays 502
* **Symptom:** In the Phishing Intelligence Workspace on `http://localhost:5173`, clicking "ANALYZE SUBMITTED EVIDENCE" displays a red alert: `Local API server is unreachable (HTTP 502 Bad Gateway)`.
* **Root Cause:** The Vite frontend development server is running, but the FastAPI backend (`python api_server.py`) is not running on port 8000.
* **Diagnosis:**
  ```powershell
  # Check if port 8000 is listening
  Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
  ```
  If empty, no process is listening on port 8000.
* **Fix:**
  Start both servers together using the unified launcher:
  ```powershell
  python run_all.py --mode dev
  ```
  Or start the backend in a separate terminal:
  ```powershell
  .\start_backend.ps1
  ```

---

### Scenario B: Production Vercel Frontend Displays 502 or Failed to Fetch
* **Symptom:** The live Vercel website displays network errors or 502 when analyzing messages.
* **Root Cause 1 — Render Cold Start:** Render's free tier spins down (sleeps) after 15 minutes of inactivity. When a request arrives, Render takes 50–90 seconds to wake up the container.
* **Diagnosis:**
  Open `https://<YOUR-RENDER-URL>.onrender.com/api/system/health` in a browser.
  - If it takes ~60 seconds to respond, Render was sleeping.
  - Once the health check returns `status: operational`, try the frontend again.
* **Remedy:** Add a free cron pinger (e.g., [cron-job.org](https://cron-job.org) or GitHub Actions) that pings `https://<YOUR-RENDER-URL>.onrender.com/api/system/health` every 14 minutes.
* **Root Cause 2 — Missing Proxy Rewrite:**
  In `frontend/src/services/api.ts`, `API_BASE` is `/api`. If Vercel is not proxying `/api/(.*)` to Render, Vercel returns `index.html` (404/200 HTML) instead of contacting Render.
* **Fix:** Ensure [frontend/vercel.json](file:///c:/Users/prati/seva-cyber-sandbox/frontend/vercel.json) contains:
  ```json
  {
    "rewrites": [
      {
        "source": "/api/(.*)",
        "destination": "https://<YOUR-RENDER-URL>.onrender.com/api/$1"
      },
      {
        "source": "/(.*)",
        "destination": "/index.html"
      }
    ]
  }
  ```

---

## 2. CORS Errors (`Access-Control-Allow-Origin` Missing)

* **Symptom:** Browser developer console displays:
  > `Access to fetch at 'https://seva-api.onrender.com/api/analyze/unified' from origin 'https://seva.vercel.app' has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present on the requested resource.`
* **Root Cause:** The production Vercel domain is not listed in Render's `CORS_ALLOWED_ORIGINS` environment variable.
* **Fix:**
  1. Open **Render Dashboard** &rarr; Web Service &rarr; **Environment**.
  2. Locate `CORS_ALLOWED_ORIGINS`.
  3. Add your exact Vercel production origin (no trailing slash):
     ```
     https://seva-cyber-sandbox.vercel.app,http://localhost:5173
     ```
  4. Save changes. Render will automatically redeploy.

---

## 3. Production Database Startup Failure (`RuntimeError`)

* **Symptom:** Render deployment fails with log output:
  > `RuntimeError: Production database startup failure: Unable to establish connection to configured database ('postgresql://postgres:****@...'). Refusing to start in unverified database state: ...`
* **Root Causes:**
  1. **Incorrect Database Password:** Special characters (like `@`, `#`, `/`) in the password must be URL-encoded (e.g. `@` &rarr; `%40`).
  2. **Supabase Project Paused:** Supabase free-tier projects pause after 7 days of zero database queries.
  3. **Pooler Port Mismatch:** In Supabase, port 5432 is Session Pooler, while port 6543 is Transaction Pooler.
* **Diagnosis:**
  Test direct connectivity from your local workstation:
  ```powershell
  python -c "import psycopg2; conn = psycopg2.connect('YOUR_SUPABASE_URI'); print('Connected!')"
  ```
* **Fix:**
  - If paused, open the **Supabase Dashboard** and click **Restore Project** (takes ~90 seconds).
  - Update `DATABASE_URL` in the Render dashboard with the verified URI.

---

## 4. Initial Administrator Setup Rejected (403 Forbidden)

* **Symptom:** Submitting `/api/auth/setup-admin` returns:
  > `HTTP 403 Forbidden: Initial administrator setup is locked because operator accounts already exist.`
* **Root Cause:** By design, the setup endpoint only permits creating an administrator when the database contains **zero** operator accounts (`SELECT COUNT(*) FROM operator_accounts == 0`).
* **Fix:**
  - If you previously set up an account, log in using `/api/auth/login` using your previously created credentials.
  - If credentials were lost, log in to the Supabase dashboard &rarr; **Table Editor** &rarr; `operator_accounts` &rarr; delete the lost operator row to unlock the setup endpoint once more.

---

## 5. Cloudflare R2 Storage Errors (403 / SignatureDoesNotMatch)

* **Symptom:** Uploading an APK or evidence document returns HTTP 500 or falls back to local storage with log message: `SignatureDoesNotMatch` or `Access Denied`.
* **Root Causes:**
  - Clock skew between the server and Cloudflare.
  - API Token permissions were set to "Read-Only" instead of "Admin Read & Write".
  - Bucket name in `R2_BUCKET_NAME` does not match the bucket created in Cloudflare.
* **Fix:**
  - In Cloudflare R2 dashboard, create a new API Token with **Admin Read & Write** permissions.
  - Verify `R2_ACCOUNT_ID` is the 32-character hex ID from the R2 Overview page.
  - If issues persist, simply remove the `R2_*` variables from Render; the backend gracefully falls back to local container storage without crashing.

---

## 6. HTTP 429 Too Many Requests (Rate Limiting)

* **Symptom:** Rapid API requests return `HTTP 429 Too Many Requests`.
* **Root Cause:** [src/rate_limiter.py](file:///c:/Users/prati/seva-cyber-sandbox/src/rate_limiter.py) defends against automated brute-force attacks:
  - `/api/auth/login`: 15 requests / minute
  - `/api/analyze/message`: 30 requests / minute
  - `/api/analyze/apk`: 10 requests / minute
  - General endpoints: 120 requests / minute
* **Fix:** Wait 60 seconds for the rate-limiting sliding window to reset. In development, rate limits can be adjusted in [src/rate_limiter.py](file:///c:/Users/prati/seva-cyber-sandbox/src/rate_limiter.py).

---

## 7. APK Parser Timeout or Memory Exhaustion

* **Symptom:** Uploading very large APK files (>25 MB) causes Render container to run out of memory or timeout.
* **Root Cause:** Render Free Tier provides 512 MB of RAM. Decompressing huge APK archives in memory can exceed this limit.
* **Safety Feature:** [src/apk_structural_parser.py](file:///c:/Users/prati/seva-cyber-sandbox/src/apk_structural_parser.py) enforces:
  - `MAX_FILE_SIZE = 35 * 1024 * 1024` (35 MB limit).
  - Streamed extraction of only `AndroidManifest.xml` and metadata files (never decompressing entire `.dex` or asset trees in memory).
* **Fix:** Keep uploaded APK samples under 25 MB for optimal performance on the free tier.
