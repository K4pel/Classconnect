#!/usr/bin/env python3
"""Management helpers for ClassConnect.

Usage:
  python manage.py gen-admin-token

This will generate a one-time token, store its hash in the DB, and print the token to stdout.
"""
import secrets
import sys
import sqlite3
from werkzeug.security import generate_password_hash
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')


def ensure_meta_table(conn):
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')
    conn.commit()


def gen_admin_token():
    token = secrets.token_urlsafe(16)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_meta_table(conn)
    cur = conn.cursor()
    cur.execute('REPLACE INTO meta (key, value) VALUES (?, ?)', ('admin_token_hash', generate_password_hash(token)))
    conn.commit()
    conn.close()
    print('One-time admin token (store this somewhere safe):')
    print(token)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python manage.py gen-admin-token')
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'gen-admin-token':
        gen_admin_token()
    else:
        print('Unknown command')
