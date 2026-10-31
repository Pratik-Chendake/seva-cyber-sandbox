#!/usr/bin/env python3
"""
Seva Cyber Sandbox — Local Operator Provisioning CLI
Allows secure creation and role management of operators without exposing
public registration endpoints or relying on default credentials.

Uses standard library hashlib.scrypt (N=131072, r=8, p=1).
"""

import argparse
import getpass
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.operator_auth import (
    ALLOWED_ROLES,
    OperatorAuthService,
    OperatorAuthError,
    PasswordPolicyError,
    get_utc_now_iso,
    hash_password,
    validate_username,
)


def get_db_path() -> str:
    return (
        os.environ.get("SEVA_CASE_DB_PATH")
        or os.environ.get("SEVA_DB_PATH")
        or os.path.join(BASE_DIR, "instance", "seva_cases.sqlite3")
    )


def create_operator(
    username: str,
    password: str,
    role: str = "operator",
    force_admin: bool = False,
) -> None:
    db_path = get_db_path()
    auth_svc = OperatorAuthService(db_path=db_path)

    username = username.strip()
    validate_username(username)

    if role not in ALLOWED_ROLES:
        print(f"[!] Error: Invalid role '{role}'. Allowed roles: {sorted(list(ALLOWED_ROLES))}")
        sys.exit(1)

    with auth_svc._get_connection() as conn:
        # Check if username exists
        cur = conn.execute(
            "SELECT username FROM operator_accounts WHERE username = ?;",
            (username,),
        )
        if cur.fetchone():
            print(f"[!] Error: Operator '{username}' already exists.")
            sys.exit(1)

        # Check total operators count
        cur_cnt = conn.execute("SELECT COUNT(*) FROM operator_accounts WHERE is_active = 1;")
        active_count = cur_cnt.fetchone()[0]

        if active_count == 0 and role != "admin" and not force_admin:
            print("[*] Note: No operator accounts exist yet. Provisioning first user with 'admin' role.")
            role = "admin"

        try:
            stored_hash, salt_hex = hash_password(password, algorithm="scrypt")
        except PasswordPolicyError as ppe:
            print(f"[!] Password policy error: {ppe}")
            sys.exit(1)

        now_iso = get_utc_now_iso()
        conn.execute(
            """
            INSERT INTO operator_accounts (
                username, password_hash, salt, role, created_at_utc,
                last_login_utc, failed_login_count, locked_until_utc, is_active
            ) VALUES (?, ?, ?, ?, ?, NULL, 0, NULL, 1);
            """,
            (username, stored_hash, salt_hex, role, now_iso),
        )

    print(f"[+] Operator '{username}' created successfully!")
    print(f"    Role: {role}")
    print(f"    Database: {db_path}")
    print(f"    Algorithm: scrypt (N=131072, r=8, p=1)")
    print(f"    Created at: {now_iso}")


def main():
    parser = argparse.ArgumentParser(
        description="Provision local operators for Seva Cyber Sandbox."
    )
    parser.add_argument(
        "--username",
        "-u",
        required=True,
        help="Username (3-32 alphanumeric characters, dashes or underscores)",
    )
    parser.add_argument(
        "--role",
        "-r",
        default="operator",
        choices=sorted(list(ALLOWED_ROLES)),
        help="Account role (default: operator)",
    )
    parser.add_argument(
        "--password",
        "-p",
        default=None,
        help="Account password (omit to prompt securely via stdin)",
    )
    parser.add_argument(
        "--db-path",
        default=None,
        help="Explicit SQLite database path",
    )

    args = parser.parse_args()

    if args.db_path:
        os.environ["SEVA_CASE_DB_PATH"] = args.db_path

    password = args.password
    if not password:
        password = getpass.getpass(f"Enter password for operator '{args.username}': ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("[!] Passwords do not match.")
            sys.exit(1)

    try:
        create_operator(
            username=args.username,
            password=password,
            role=args.role,
        )
    except Exception as e:
        print(f"[!] Operation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
