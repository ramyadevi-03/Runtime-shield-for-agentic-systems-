# debug_db.py – utility to inspect the Users table and verify JWT sub mappings
# Place this file in the project root (same folder as bridge.py) and run it with Python.

import os
import sqlite3
import sys

# Resolve the path to the SQLite DB (same logic as bridge.py)
PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(PROJECT_DIR, "damn-vulnerable-llm-agent", "transactions.db")

def list_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT userId, username, keycloak_sub FROM Users")
    rows = cur.fetchall()
    if not rows:
        print("[debug_db] No users found in the database.")
    else:
        print("[debug_db] Users table contents:")
        for userId, username, sub in rows:
            print(f"  userId={userId}, username='{username}', keycloak_sub='{sub}'")
    conn.close()

def resolve_sub(sub):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT userId FROM Users WHERE keycloak_sub = ?", (sub,))
    row = cur.fetchone()
    if row:
        print(f"[debug_db] sub '{sub}' resolves to userId={row[0]}")
    else:
        print(f"[debug_db] sub '{sub}' NOT FOUND in Users table.")
    conn.close()

if __name__ == "__main__":
    # Usage: python debug_db.py [sub_to_check]
    list_users()
    if len(sys.argv) > 1:
        resolve_sub(sys.argv[1])
