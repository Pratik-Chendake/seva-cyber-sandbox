import sqlite3
import re
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLITE_DB = os.path.join(BASE_DIR, "instance", "seva_cases.sqlite3")
PG_SCHEMA_FILE = os.path.join(BASE_DIR, "migrations", "001_initial_schema.sql")

print("--- SQLITE SCHEMA ---")
conn = sqlite3.connect(SQLITE_DB)
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
sqlite_tables = [r[0] for r in cur.fetchall()]
sqlite_info = {}
for t in sqlite_tables:
    cur.execute(f"PRAGMA table_info({t});")
    cols = [r[1] for r in cur.fetchall()]
    sqlite_info[t] = cols
    print(f"Table: {t} ({len(cols)} columns): {cols}")

cur.execute("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name;")
sqlite_indexes = [r[0] for r in cur.fetchall()]
print(f"\nTotal SQLite indexes: {len(sqlite_indexes)}")

cur.execute("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name;")
sqlite_triggers = [r[0] for r in cur.fetchall()]
print(f"Total SQLite triggers: {len(sqlite_triggers)}: {sqlite_triggers}")
conn.close()

print("\n--- POSTGRES SCHEMA (001_initial_schema.sql) ---")
with open(PG_SCHEMA_FILE, "r", encoding="utf-8") as f:
    pg_sql = f.read()

# Find CREATE TABLE in PG schema
pg_tables = re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)", pg_sql, re.IGNORECASE)
print(f"Tables in PG schema: {len(pg_tables)}: {pg_tables}")

print("\n--- COMPARISON ---")
missing_in_pg = set(sqlite_tables) - set(pg_tables)
extra_in_pg = set(pg_tables) - set(sqlite_tables)
print(f"Missing in PG schema: {missing_in_pg}")
print(f"Extra in PG schema: {extra_in_pg}")
