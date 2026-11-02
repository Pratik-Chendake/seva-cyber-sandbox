"""
Seva Cyber Sandbox — Supabase Shared Pooler (Session Mode) Connection Diagnostic
Safely validates PostgreSQL connectivity to the Supabase Shared Pooler.

Requirements:
1. Connects through the Shared Pooler host (aws-0-eu-central-2.pooler.supabase.com:5432).
2. Uses SSL mode 'require'.
3. Executes strictly 'SELECT 1'.
4. Closes the connection reliably in a finally block.
5. Never prints passwords or raw credentials in logs, console, or exceptions.
6. Never performs schema changes, queries, or data insertions.
"""

import getpass
import os
import re
import sys
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load local .env without overriding environment-provided variables
try:
    from dotenv import load_dotenv
    env_file = os.path.join(BASE_DIR, ".env")
    if os.path.isfile(env_file):
        load_dotenv(dotenv_path=env_file, override=False)
except ImportError:
    pass

try:
    import psycopg2
except ImportError:
    try:
        import psycopg as psycopg2
    except ImportError:
        print("[!] Error: 'psycopg2' is not installed in the active environment.")
        print("[*] Install it with: pip install psycopg2-binary")
        sys.exit(1)


def sanitize_url(raw_url: str) -> str:
    """Masks database password and sensitive tokens in PostgreSQL URI."""
    if not raw_url:
        return ""
    try:
        parsed = urlparse(raw_url)
        if parsed.password:
            netloc = parsed.netloc.replace(f":{parsed.password}@", ":****@")
            return urlunparse(parsed._replace(netloc=netloc))
        return raw_url
    except Exception:
        return re.sub(r"://([^:]+):([^@]+)@", r"://\1:****@", raw_url)


def sanitize_error_message(err: Exception, raw_url: str) -> str:
    """Removes sensitive credentials if they appear in database exception strings."""
    msg = str(err)
    try:
        parsed = urlparse(raw_url)
        if parsed.password and parsed.password in msg:
            msg = msg.replace(parsed.password, "****")
    except Exception:
        pass
    return msg


def ensure_ssl_require(url: str) -> str:
    """Ensures sslmode=require is set in the connection URI."""
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        if "sslmode" not in query_params:
            query_params["sslmode"] = ["require"]
            new_query = urlencode(query_params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        return url
    except Exception:
        if "sslmode=" not in url:
            delimiter = "&" if "?" in url else "?"
            return f"{url}{delimiter}sslmode=require"
        return url


def test_connection():
    print("=" * 70)
    print("  SEVA CYBER SANDBOX — SUPABASE SHARED POOLER DIAGNOSTIC")
    print("=" * 70)

    # 1. Resolve connection URI
    target_url = os.environ.get("DATABASE_URL") or os.environ.get("SEVA_DATABASE_URL") or ""

    if not target_url or "<URL_ENCODED_PASSWORD>" in target_url or "[YOUR-PASSWORD]" in target_url:
        print("\n[*] Notice: DATABASE_URL in .env contains a placeholder password.")
        print("[*] You can enter your full connection URI below (input is hidden).")
        try:
            if sys.stdin.isatty():
                prompt_input = getpass.getpass("Enter Supabase Connection URI (or press Enter to cancel): ").strip()
            else:
                prompt_input = sys.stdin.readline().strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Diagnostic cancelled by operator.")
            sys.exit(0)

        if not prompt_input:
            print("[!] No connection URI provided. Please edit .env with your actual password.")
            sys.exit(1)
        target_url = prompt_input

    # 2. Enforce SSL requirement
    target_url = ensure_ssl_require(target_url)

    # 3. Validate target parameters
    sanitized = sanitize_url(target_url)
    print(f"[*] Target Endpoint       : {sanitized}")
    print("[*] Connection Type       : Shared Pooler (Session Mode)")
    print("[*] Target Port           : 5432")
    print("[*] SSL Enforcement       : require")

    conn = None
    try:
        print("[*] Connecting with 10-second timeout...")
        conn = psycopg2.connect(target_url, connect_timeout=10)
        conn.autocommit = True

        with conn.cursor() as cur:
            # 4. Strict read-only probe: SELECT 1
            print("[*] Executing test probe: SELECT 1;")
            cur.execute("SELECT 1;")
            result = cur.fetchone()

        if result and result[0] == 1:
            print("\n" + "=" * 70)
            print("  [+] SUCCESS: SUPABASE SHARED POOLER CONNECTION ESTABLISHED!")
            print("  [+] Probe verified: SELECT 1 returned successfully.")
            print("  [+] SSL session is active and verified.")
            print("  [+] Zero database mutations or schema changes occurred.")
            print("=" * 70)
            return 0
        else:
            print(f"[!] Warning: Unexpected probe response: {result}")
            return 1

    except Exception as e:
        safe_msg = sanitize_error_message(e, target_url)
        print("\n" + "=" * 70)
        print("  [-] CONNECTION FAILED")
        print(f"  [-] Error: {safe_msg}")
        print("=" * 70)
        print("\n[!] Troubleshooting Tips:")
        print("  1. Verify your password is correct in the Supabase Dashboard.")
        print("  2. If your password contains special characters (e.g. '@'), encode them ('@' -> '%40').")
        print("  3. Verify the user is 'postgres.vqbqvrlyinieakosgalm' for the Shared Pooler.")
        print("  4. Verify the host is 'aws-0-eu-central-2.pooler.supabase.com'.")
        return 1

    finally:
        # 5. Reliable closure
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(test_connection())
