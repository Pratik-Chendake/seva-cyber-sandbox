# SEVA CYBER SANDBOX — ENVIRONMENT VARIABLES SPECIFICATION & AUDIT

**Version:** 7.2.0  
**Scope:** Complete project environment variable mapping across local development, Render backend, Vercel frontend, Supabase PostgreSQL, and Cloudflare R2.  

---

## 1. Master Environment Variables Reference Table

| Variable | Purpose | Required or Optional | Where to Obtain It | Used By |
| :--- | :--- | :--- | :--- | :--- |
| `SEVA_ENV` | Specifies environment mode (`development` vs `production`) | **Required** (Defaults to `development`) | Local configuration or Render dashboard | `api_server.py`, `database_adapter.py` |
| `SEVA_STRICT_DB_STARTUP` | Enforces fail-closed database connectivity check on server start | **Required in Prod** (set `true` in production; `false` in dev) | Configured in dashboard / `.env` | `api_server.py` (`verify_startup_database`) |
| `HOST` | Local network binding address (e.g. `127.0.0.1` or `0.0.0.0`) | Optional (Defaults to `127.0.0.1`) | Local `.env` (Render sets automatically) | `api_server.py` |
| `PORT` | HTTP port for FastAPI backend | Optional (Defaults to `8000`) | Local `.env` (Render provides `$PORT`) | `api_server.py`, `render.yaml`, `Dockerfile` |
| `DISABLE_RATE_LIMITING` | Disables in-memory rate limiting when set to `1` | Optional (Defaults to `0`) | Local `.env` during automated load tests | `src/rate_limiter.py` |
| `DATABASE_URL` | Primary PostgreSQL connection URI (Supabase Direct Connection) | **Required for Cloud Prod** (Optional locally: defaults to SQLite) | Supabase Dashboard &rarr; Project Settings &rarr; Database &rarr; Connection string URI | `src/database_adapter.py`, `scripts/migrate_to_postgres.py` |
| `SEVA_DATABASE_URL` | Fallback alias for PostgreSQL connection URI | Optional | Secondary alias | `src/database_adapter.py` |
| `SEVA_CASE_DB_PATH` | Path override for SQLite database file | Optional (Defaults to `instance/seva_cases.sqlite3`) | Local workstation `.env` | `src/case_repository.py`, `src/database_adapter.py` |
| `SEVA_DB_PATH` | Secondary path alias for SQLite database | Optional | Local workstation `.env` | `src/database_adapter.py`, `scripts/create_operator.py` |
| `SEVA_THREAT_INTEL_KEY` | HMAC secret for anonymizing phone number IOCs (min 16 chars) | **Required** (Auto-generated in `.env`) | Generated cryptographically (`secrets.token_hex(32)`) | `src/case_repository.py` (`get_threat_intel_hmac_secret`) |
| `SEVA_HMAC_SECRET` | Fallback alias for threat intelligence HMAC secret | Optional | Secondary alias | `src/case_repository.py` |
| `SEVA_FEEDBACK_HMAC_KEY` | Isolated HMAC secret for feedback feature deduplication (min 16 chars) | **Required** (Auto-generated in `.env`) | Generated cryptographically (`secrets.token_hex(32)`) | `src/case_repository.py` (`get_feedback_hmac_secret`) |
| `SEVA_JWT_SECRET` | Secret key for signing operator authentication session tokens | **Required** (Auto-generated in `.env`) | Generated cryptographically (`secrets.token_hex(32)`) | `src/operator_auth.py`, `api_server.py` |
| `SEVA_INITIAL_ADMIN_TOKEN` | One-time bootstrap token unlocking initial admin registration | **Required in Prod** (Optional on localhost) | User-chosen strong passphrase | `api_server.py` (`/api/auth/setup-admin`) |
| `SEVA_FIRST_ADMIN_TOKEN` | Alias for initial admin setup token | Optional | User-chosen strong passphrase | `api_server.py` (`/api/auth/setup-admin`) |
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of allowed frontend origins | **Required in Prod** (Defaults to localhost) | Set to your Vercel URL in Render dashboard | `api_server.py` (CORSMiddleware) |
| `R2_ACCOUNT_ID` | Cloudflare account identifier for private evidence vault | Optional (Defaults to local storage) | Cloudflare Dashboard &rarr; R2 Overview | `src/storage_manager.py` |
| `R2_ACCESS_KEY_ID` | S3-compatible Access Key ID for Cloudflare R2 | Optional (Defaults to local storage) | Cloudflare Dashboard &rarr; R2 &rarr; Manage API Tokens | `src/storage_manager.py` |
| `R2_SECRET_ACCESS_KEY` | S3-compatible Secret Access Key for Cloudflare R2 | Optional (Defaults to local storage) | Cloudflare Dashboard &rarr; R2 &rarr; Manage API Tokens | `src/storage_manager.py` |
| `R2_BUCKET_NAME` | Name of private evidence R2 bucket | Optional (Defaults to `seva-evidence-private`) | Cloudflare Dashboard &rarr; R2 Buckets | `src/storage_manager.py` |
| `R2_ENDPOINT_URL` | Custom endpoint URL override for S3-compatible storage | Optional | Cloudflare R2 custom domain | `src/storage_manager.py` |
| `WHATSAPP_MODE` | WhatsApp platform operational mode (`simulation` or `live`) | Optional (Defaults to `simulation`) | Local `.env` or Render dashboard | `src/whatsapp_handler.py` |
| `WHATSAPP_VERIFY_TOKEN` | Webhook verification handshake token | Optional (Defaults to safe preset) | User-chosen secret entered in Meta Console | `src/whatsapp_handler.py` |
| `WHATSAPP_APP_SECRET` | Meta App Secret for X-Hub-Signature HMAC validation | Optional (Required only for live Meta webhooks) | Meta for Developers &rarr; App Settings &rarr; Basic | `src/whatsapp_handler.py` |
| `WHATSAPP_ACCESS_TOKEN` | Meta Graph API permanent system user token | Optional (Required only for live Meta messages) | Meta Business Manager &rarr; System Users | `src/whatsapp_handler.py` |
| `WHATSAPP_PHONE_NUMBER_ID` | Meta WhatsApp Business Phone Number ID | Optional (Required only for live Meta messages) | Meta for Developers &rarr; WhatsApp &rarr; API Setup | `src/whatsapp_handler.py` |
| `WHATSAPP_API_VERSION` | Meta Graph API version | Optional (Defaults to `v21.0`) | Meta for Developers documentation | `src/whatsapp_handler.py` |
| `WHATSAPP_SENDER_SALT` | Cryptographic salt for anonymizing sender phone numbers | Optional (Defaults to safe random salt) | Generated cryptographically (`secrets.token_hex(16)`) | `src/whatsapp_handler.py` |
| `VITE_API_URL` | Public backend base URL exposed to frontend browser | Optional in Dev; **Required on Vercel** | Render Web Service URL (e.g. `https://seva.onrender.com`) | `frontend/src/services/api.ts` |

---

## 2. Security Classification: Public vs Secret Values

### 🔴 Private Secrets (NEVER Expose Publicly, Commit to Git, or Put in Frontend Files)
These values must remain strictly on the backend (in `.env` locally, or in Render's encrypted Environment Variables dashboard):
* `DATABASE_URL` / `SEVA_DATABASE_URL` (Contains database password)
* `SEVA_THREAT_INTEL_KEY` / `SEVA_HMAC_SECRET` (Cryptographic key)
* `SEVA_FEEDBACK_HMAC_KEY` (Cryptographic key)
* `SEVA_JWT_SECRET` (Session signing key)
* `SEVA_INITIAL_ADMIN_TOKEN` / `SEVA_FIRST_ADMIN_TOKEN` (Admin creation token)
* `R2_SECRET_ACCESS_KEY` (Cloud storage private key)
* `WHATSAPP_APP_SECRET` / `WHATSAPP_ACCESS_TOKEN` (Meta API tokens)

### 🟢 Safe Configuration (Safe to Share & Commit in Documentation)
* `SEVA_ENV="development"` or `"production"`
* `SEVA_STRICT_DB_STARTUP="false"` or `"true"`
* `HOST="127.0.0.1"`
* `PORT=8000`
* `R2_BUCKET_NAME="seva-evidence-private"`
* `WHATSAPP_MODE="simulation"`
* `WHATSAPP_API_VERSION="v21.0"`
* `VITE_API_URL` (Public URL of the backend API, e.g., `https://seva-cyber-sandbox-api.onrender.com`)
* `CORS_ALLOWED_ORIGINS` (Public domains allowed to call the API)

---

## 3. How to Configure the Local `.env` File

1. The root `.env` file has been created directly in `C:\Users\prati\seva-cyber-sandbox\.env`.
2. All required internal cryptographic keys (`SEVA_THREAT_INTEL_KEY`, `SEVA_FEEDBACK_HMAC_KEY`, `SEVA_JWT_SECRET`, `WHATSAPP_SENDER_SALT`) have been generated using Python's cryptographically secure `secrets` module (256-bit entropy).
3. If using local SQLite for development, leave `DATABASE_URL` blank; the application automatically falls back to `instance/seva_cases.sqlite3`.
4. If testing Supabase locally:
   Paste your Supabase Shared Pooler (Session Mode) Connection string into `DATABASE_URL`:
   ```bash
   DATABASE_URL="postgresql://postgres.vqbqvrlyinieakosgalm:<URL_ENCODED_PASSWORD>@aws-0-eu-central-2.pooler.supabase.com:5432/postgres?sslmode=require"
   ```
   *(Ensure special characters in the password are URL-encoded, e.g. `@` &rarr; `%40`)*.

---

## 4. How to Configure Render Environment Variables

When deploying the backend to Render ([dashboard.render.com](https://dashboard.render.com)):
1. Open your Web Service &rarr; **Environment** tab.
2. Add the following variables:
   * `DATABASE_URL`: Your Supabase Shared Pooler (Session Mode) Connection URI (`postgresql://postgres.vqbqvrlyinieakosgalm:<URL_ENCODED_PASSWORD>@aws-0-eu-central-2.pooler.supabase.com:5432/postgres?sslmode=require`).
   * `SEVA_ENV`: `production`
   * `SEVA_STRICT_DB_STARTUP`: `true`
   * `SEVA_INITIAL_ADMIN_TOKEN`: A secret passphrase for first administrator creation.
   * `SEVA_THREAT_INTEL_KEY`: Copy the generated key from your local `.env`.
   * `SEVA_FEEDBACK_HMAC_KEY`: Copy the generated key from your local `.env`.
   * `SEVA_JWT_SECRET`: Copy the generated key from your local `.env`.
   * `CORS_ALLOWED_ORIGINS`: Your Vercel frontend URL (e.g. `https://seva-cyber-sandbox.vercel.app,http://localhost:5173`).
   * `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`: *(Optional, if using Cloudflare R2)*.

---

## 5. How to Configure Vercel Frontend Variables

When deploying the frontend to Vercel ([vercel.com](https://vercel.com)):
1. Open your Project &rarr; **Settings** &rarr; **Environment Variables**.
2. Add:
   * **Key:** `VITE_API_URL`
   * **Value:** Your Render backend URL (e.g. `https://seva-cyber-sandbox-api.onrender.com`) without trailing slash.
3. **CRITICAL SECURITY RULE:** Never add any database, HMAC, or secret keys to Vercel. Vite variables prefixed with `VITE_` are compiled directly into public client-side JavaScript bundle files!
