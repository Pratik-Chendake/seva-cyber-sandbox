import sqlite3

def get_counts(db_file):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    counts = {}
    for t in tables:
        cur.execute(f'SELECT COUNT(*) FROM "{t}"')
        counts[t] = cur.fetchone()[0]
    conn.close()
    return counts

c_act = get_counts('instance/seva_cases.sqlite3')
c_bak = get_counts('instance/backups/seva_cases_pre_streamlit_migration.sqlite3')

print('Active counts:', c_act)
print('Backup counts:', c_bak)
diffs = {k: (c_act.get(k), c_bak.get(k)) for k in c_act if c_act.get(k) != c_bak.get(k)}
print('Diffs:', diffs)
