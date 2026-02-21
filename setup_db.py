"""
setup_db.py — Verify Supabase connection and check required tables.

The full schema is defined in:
  supabase/migrations/20260220000000_full_schema.sql

This script checks whether the required tables exist and prints the SQL
to run in the Supabase Dashboard if any are missing.

Run:  python setup_db.py
"""

import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

MIGRATION_FILE = os.path.join(
    os.path.dirname(__file__), "..", "supabase", "migrations", "20260220000000_full_schema.sql"
)

REQUIRED_TABLES = ["users", "apps", "logs", "summaries", "sdk_device_sessions", "app_chats"]


def _headers():
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def _probe_connection() -> bool:
    url = f"{SUPABASE_URL}/rest/v1/"
    try:
        resp = requests.get(url, headers=_headers(), timeout=10)
        return resp.status_code in (200, 404)
    except Exception as exc:
        print(f"  Connection error: {exc}")
        return False


def _table_exists(table: str) -> bool:
    url = f"{SUPABASE_URL}/rest/v1/{table}?limit=0"
    resp = requests.get(url, headers=_headers(), timeout=10)
    return resp.status_code == 200


def main():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        print("[ERROR] SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set in .env")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("  Sentry — DB Setup Checker")
    print(f"  Project: {SUPABASE_URL}")
    print(f"{'='*60}\n")

    print("1. Testing connection to Supabase...")
    if _probe_connection():
        print("   Connected\n")
    else:
        print("   Could not reach Supabase. Check SUPABASE_URL and network.\n")
        sys.exit(1)

    print("2. Checking required tables...")
    missing = []
    for name in REQUIRED_TABLES:
        exists = _table_exists(name)
        status = "exists" if exists else "MISSING"
        print(f"   [{status:^6}]  {name}")
        if not exists:
            missing.append(name)
    print()

    if not missing:
        print("All required tables exist — DB is ready.\n")
        sys.exit(0)

    print(f"{len(missing)} table(s) missing: {', '.join(missing)}\n")
    print("Run the following migration in the Supabase SQL Editor:")
    print("  https://supabase.com/dashboard/project/_/sql/new\n")

    migration_path = os.path.normpath(MIGRATION_FILE)
    if os.path.exists(migration_path):
        print(f"Migration file: {migration_path}\n")
        with open(migration_path, "r", encoding="utf-8") as f:
            sql = f.read()
        print("─" * 60)
        print(sql)
        print("─" * 60)
    else:
        print(f"Migration file not found at: {migration_path}")
        print("Check supabase/migrations/20260220000000_full_schema.sql")

    sys.exit(1)


if __name__ == "__main__":
    main()
