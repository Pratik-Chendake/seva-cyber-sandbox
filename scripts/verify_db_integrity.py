"""
Comprehensive Database Integrity Verification Script.
Compares active instance/seva_cases.sqlite3 with instance/backups/seva_cases_pre_streamlit_migration.sqlite3.
"""

import hashlib
import sqlite3
import sys

def verify_db_integrity():
    print("=" * 70)
    print("  SEVA CYBER SANDBOX — DATABASE INTEGRITY AUDIT")
    print("=" * 70)

    act_path = "instance/seva_cases.sqlite3"
    bak_path = "instance/backups/seva_cases_pre_streamlit_migration.sqlite3"

    # 1. SHA-256 Hashes
    h_act = hashlib.sha256(open(act_path, "rb").read()).hexdigest()
    h_bak = hashlib.sha256(open(bak_path, "rb").read()).hexdigest()

    print(f"Active DB SHA-256 : {h_act}")
    print(f"Backup DB SHA-256 : {h_bak}")
    assert h_act == h_bak, "Active database hash differs from backup!"
    print("  [+] SHA-256 Verification: IDENTICAL (Pristine)")

    # 2. Table Schemas & Indexes
    conn_act = sqlite3.connect(act_path)
    conn_bak = sqlite3.connect(bak_path)

    cur_act = conn_act.cursor()
    cur_bak = conn_bak.cursor()

    cur_act.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
    schema_act = cur_act.fetchall()

    cur_bak.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
    schema_bak = cur_bak.fetchall()

    assert len(schema_act) == len(schema_bak), f"Schema count differs: {len(schema_act)} vs {len(schema_bak)}"
    for s_act, s_bak in zip(schema_act, schema_bak):
        assert s_act == s_bak, f"Schema mismatch for {s_act[1]}: act={s_act[2]} vs bak={s_bak[2]}"

    print(f"  [+] Schema Verification: All {len(schema_act)} objects (tables, indexes, triggers) 100% MATCH")

    # 3. Record Counts Per Table
    tables = [row[1] for row in schema_act if row[0] == "table"]
    print(f"\nAudit of {len(tables)} Database Tables:")
    print(f"{'Table Name':<32} {'Active':<10} {'Backup':<10} {'Status':<10}")
    print("-" * 65)

    all_matched = True
    for t in tables:
        cur_act.execute(f'SELECT COUNT(*) FROM "{t}"')
        cnt_act = cur_act.fetchone()[0]
        cur_bak.execute(f'SELECT COUNT(*) FROM "{t}"')
        cnt_bak = cur_bak.fetchone()[0]

        status = "MATCH" if cnt_act == cnt_bak else "DIFF"
        if cnt_act != cnt_bak:
            all_matched = False
        print(f"{t:<32} {cnt_act:<10} {cnt_bak:<10} {status:<10}")

    conn_act.close()
    conn_bak.close()

    assert all_matched, "Record counts mismatch between active and backup!"
    print("\n" + "=" * 70)
    print("  DATABASE INTEGRITY FULLY PRESERVED — ZERO CONTAMINATION DETECTED")
    print("=" * 70)

if __name__ == "__main__":
    verify_db_integrity()
