import sqlite3, json, os
p = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.db')
if not os.path.exists(p):
    print('MISSING_DB')
    raise SystemExit(1)
conn = sqlite3.connect(p)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
rows = cur.execute('SELECT id, username, is_admin, approved FROM users').fetchall()
print(json.dumps([dict(r) for r in rows], ensure_ascii=False))
conn.close()
