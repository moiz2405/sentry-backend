"""
setup_db.py — Test Supabase connection and create required tables.

Required tables:
  1. apps               — core app registry (with api_key column)
  2. sdk_device_sessions — SDK CLI onboarding device-code flow

Run:  python setup_db.py
"""

import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

# ── SQL migrations ────────────────────────────────────────────────────────────

SQL_CREATE_APPS = """
CREATE TABLE IF NOT EXISTS apps (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL,
  name        TEXT        NOT NULL,
  description TEXT,
  url         TEXT,
  api_key     TEXT        UNIQUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_apps_user_id  ON apps(user_id);
CREATE INDEX IF NOT EXISTS idx_apps_api_key  ON apps(api_key) WHERE api_key IS NOT NULL;
"""

SQL_CREATE_SDK_DEVICE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sdk_device_sessions (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  device_code TEXT        NOT NULL UNIQUE,
  user_code   TEXT        NOT NULL,
  status      TEXT        NOT NULL DEFAULT 'pending',
  app_name    TEXT        NOT NULL,
  description TEXT,
  user_id     UUID,
  app_id      UUID,
  api_key     TEXT,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sdk_device_sessions_device_code
  ON sdk_device_sessions(device_code);
CREATE INDEX IF NOT EXISTS idx_sdk_device_sessions_status_expires
  ON sdk_device_sessions(status, expires_at);
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _headers():
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }


def _run_sql(sql: str) -> tuple[bool, str]:
    """Execute raw SQL via Supabase's pg-meta query endpoint."""
    url = f"{SUPABASE_URL}/rest/v1/rpc/exec_sql"
    resp = requests.post(url, json={"sql": sql}, headers=_headers(), timeout=15)
    if resp.ok:
        return True, "ok"
    # Fallback: try pg endpoint (self-hosted / Docker Supabase)
    url2 = f"{SUPABASE_URL}/pg/query"
    resp2 = requests.post(url2, json={"query": sql}, headers=_headers(), timeout=15)
    if resp2.ok:
        return True, "ok (pg endpoint)"
    return False, f"HTTP {resp.status_code}: {resp.text[:300]}"


def _table_exists(table: str) -> bool:
    """Check if a table exists by querying it via PostgREST."""
    url = f"{SUPABASE_URL}/rest/v1/{table}?limit=0"
    resp = requests.get(url, headers=_headers(), timeout=10)
    return resp.status_code == 200


def _probe_connection() -> bool:
    """Ping the Supabase REST endpoint."""
    url = f"{SUPABASE_URL}/rest/v1/"
    try:
        resp = requests.get(url, headers=_headers(), timeout=10)
        return resp.status_code in (200, 404)  # 404 = endpoint found but no table
    except Exception as exc:
        print(f"  Connection error: {exc}")
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        print("[ERROR] SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set in .env")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("  Sentry — DB Setup")
    print(f"  Project: {SUPABASE_URL}")
    print(f"{'='*60}\n")

    # ── 1. Connection test ────────────────────────────────────────────────────
    print("1. Testing connection to Supabase...")
    if _probe_connection():
        print("   ✅ Connected\n")
    else:
        print("   ❌ Could not reach Supabase. Check SUPABASE_URL and network.\n")
        sys.exit(1)

    # ── 2. Table status ───────────────────────────────────────────────────────
    tables = {
        "apps": SQL_CREATE_APPS,
        "sdk_device_sessions": SQL_CREATE_SDK_DEVICE_SESSIONS,
    }

    print("2. Checking required tables...")
    missing = {}
    for name, sql in tables.items():
        exists = _table_exists(name)
        status = "✅ exists" if exists else "❌ missing"
        print(f"   {status}  →  {name}")
        if not exists:
            missing[name] = sql
    print()

    if not missing:
        print("3. All required tables already exist — nothing to create.\n")
    else:
        print(f"3. Creating {len(missing)} missing table(s)...")
        auto_failed = {}
        for name, sql in missing.items():
            ok, msg = _run_sql(sql)
            if ok:
                print(f"   ✅ Created  →  {name}")
            else:
                print(f"   ⚠️  Auto-create unavailable for '{name}' (PostgREST DDL restriction)")
                auto_failed[name] = sql

        if auto_failed:
            # Save combined migration to a file for easy copy-paste
            migration_path = os.path.join(os.path.dirname(__file__), "create_tables.sql")
            combined_sql = "\n\n".join(s.strip() for s in auto_failed.values())
            with open(migration_path, "w", encoding="utf-8") as f:
                f.write("-- Run this in: Supabase Dashboard → SQL Editor → New query\n\n")
                f.write(combined_sql + "\n")
            print(f"\n   📄 Migration SQL saved to: {migration_path}")
            print("\n   ─── Combined SQL to run in Supabase SQL Editor ───────────")
            print(combined_sql)
            print("   ───────────────────────────────────────────────────────────\n")
            print("   Open: https://supabase.com/dashboard/project/tqpbvosyxlevtyaaprad/sql/new")
            print("   Paste the SQL above and click Run.\n")
        print()

    # ── 3. Re-verify ─────────────────────────────────────────────────────────
    print("4. Final verification...")
    all_ok = True
    for name in tables:
        exists = _table_exists(name)
        status = "✅" if exists else "❌"
        print(f"   {status}  {name}")
        if not exists:
            all_ok = False

    print()
    if all_ok:
        print("✅ DB setup complete — all tables are ready.\n")
    else:
        print("⚠️  Some tables are still missing. Run the SQL above in the Supabase dashboard.\n")
        print("   Dashboard → SQL Editor → New query → paste & run.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
