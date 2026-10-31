import sqlite3
import re
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLITE_DB = os.path.join(BASE_DIR, "instance", "seva_cases.sqlite3")
PG_SCHEMA_FILE = os.path.join(BASE_DIR, "migrations", "001_initial_schema.sql")

conn = sqlite3.connect(SQLITE_DB)
cur = conn.cursor()

with open(PG_SCHEMA_FILE, "r", encoding="utf-8") as f:
    pg_sql = f.read()

# Extract table definitions from PG SQL
table_blocks = re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)\s*\((.*?)\);", pg_sql, re.DOTALL | re.IGNORECASE)

print("=== COLUMN DIFFERENCES IN MATCHING TABLES ===")
for t_name, block in table_blocks:
    cur.execute(f"PRAGMA table_info({t_name});")
    sqlite_cols = {r[1] for r in cur.fetchall()}
    
    # Parse PG columns
    pg_cols = set()
    for line in block.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("--") or line.startswith("CONSTRAINT") or line.startswith("FOREIGN KEY") or line.startswith("PRIMARY KEY ("):
            continue
        col_match = re.match(r"^([a-zA-Z0-9_]+)\s+", line)
        if col_match:
            pg_cols.add(col_match.group(1))
    
    missing_in_pg = sqlite_cols - pg_cols
    extra_in_pg = pg_cols - sqlite_cols
    if missing_in_pg or extra_in_pg:
        print(f"\nTable: {t_name}")
        if missing_in_pg:
            print(f"  Missing in PG: {missing_in_pg}")
        if extra_in_pg:
            print(f"  Extra in PG: {extra_in_pg}")
    else:
        print(f"\nTable: {t_name}: EXACT COLUMN MATCH ({len(sqlite_cols)} cols)")

conn.close()
