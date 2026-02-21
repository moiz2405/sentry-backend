"""
Supabase helpers: API key resolution, user management, log storage,
summary storage, SDK device-code provisioning, and anomaly persistence.
"""
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    from supabase import create_client, Client
except ImportError:
    Client = None
    create_client = None

_supabase: Optional["Client"] = None


def _get_supabase():
    global _supabase
    if _supabase is None and create_client:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        if url and key:
            _supabase = create_client(url, key)
    return _supabase


def _utc_iso_after(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


# ============================================================
# Key generation
# ============================================================

def generate_api_key() -> str:
    return f"sk_{secrets.token_urlsafe(24)}"


def generate_device_code() -> str:
    return secrets.token_urlsafe(32)


def generate_user_code() -> str:
    raw = secrets.token_hex(4).upper()
    return f"{raw[:4]}-{raw[4:]}"


# ============================================================
# Users
# ============================================================

def upsert_user(user_id: str, email: str, name: Optional[str], image: Optional[str]) -> Optional[str]:
    """
    Upsert a user row and return the canonical user ID stored in the DB.

    Returns the canonical ID on success, None on failure.

    Strategy:
    1. Happy path — upsert on `id` (repeated logins, new users).
    2. Email conflict (stale UUID from a previous Auth.js session) — find the
       existing row by email, update name/image, and return the existing ID.
       We never change the PRIMARY KEY because apps.user_id has no ON UPDATE CASCADE.
    """
    client = _get_supabase()
    if not client:
        return None

    try:
        client.table("users").upsert(
            {
                "id": user_id,
                "email": email,
                "name": name,
                "image": image,
                "updated_at": _now_utc().isoformat(),
            },
            on_conflict="id",
        ).execute()
        return user_id
    except Exception:
        pass

    # Fallback: email already exists under a different id.
    # supabase-py's SyncFilterRequestBuilder does not support chaining .select()
    # after .update().eq() — split into two separate queries.
    try:
        client.table("users").update(
            {"name": name, "image": image, "updated_at": _now_utc().isoformat()}
        ).eq("email", email).execute()
        result = (
            client.table("users")
            .select("id")
            .eq("email", email)
            .limit(1)
            .execute()
        )
        if result.data:
            return result.data[0]["id"]
    except Exception:
        pass

    return None


# ============================================================
# Apps
# ============================================================

def resolve_api_key_to_app_id(api_key: str) -> Optional[str]:
    """
    Look up app_id from api_key in Supabase apps table.
    Returns app_id (UUID string) or None if invalid.
    """
    client = _get_supabase()
    if not client:
        return None
    try:
        result = (
            client.table("apps")
            .select("id")
            .eq("api_key", api_key)
            .limit(1)
            .execute()
        )
        if result.data and len(result.data) > 0:
            return str(result.data[0]["id"])
    except Exception:
        pass
    return None


def verify_app_ownership(app_id: str, user_id: str) -> bool:
    """Return True if the app belongs to user_id."""
    client = _get_supabase()
    if not client:
        return False
    try:
        result = (
            client.table("apps")
            .select("id")
            .eq("id", app_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        return bool(result.data)
    except Exception:
        return False


# ============================================================
# App chat (persistent conversation history per app)
# ============================================================

def get_app_chat(app_id: str) -> list:
    """Return stored chat messages for an app (list of {role, content, ts} dicts)."""
    client = _get_supabase()
    if not client:
        return []
    try:
        result = (
            client.table("app_chats")
            .select("messages")
            .eq("app_id", app_id)
            .limit(1)
            .execute()
        )
        if result.data:
            return result.data[0].get("messages") or []
    except Exception:
        pass
    return []


def save_app_chat(app_id: str, messages: list) -> bool:
    """Upsert chat messages for an app (one row per app via unique constraint)."""
    client = _get_supabase()
    if not client:
        return False
    try:
        client.table("app_chats").upsert(
            {
                "app_id": app_id,
                "messages": messages,
                "updated_at": _now_utc().isoformat(),
            },
            on_conflict="app_id",
        ).execute()
        return True
    except Exception:
        return False


def clear_app_chat(app_id: str) -> bool:
    """Delete the chat history row for an app."""
    client = _get_supabase()
    if not client:
        return False
    try:
        client.table("app_chats").delete().eq("app_id", app_id).execute()
        return True
    except Exception:
        return False


# ============================================================
# Logs
# ============================================================

def bulk_insert_logs(parsed_logs: list[dict]) -> int:
    """
    Bulk insert a list of parsed log dicts into the logs table.
    Returns the count of inserted rows.
    """
    client = _get_supabase()
    if not client or not parsed_logs:
        return 0
    try:
        result = client.table("logs").insert(parsed_logs).execute()
        return len(result.data) if result.data else 0
    except Exception:
        return 0


def get_logs_paginated(
    app_id: str,
    limit: int = 100,
    offset: int = 0,
    level: Optional[str] = None,
    service: Optional[str] = None,
) -> list[dict]:
    """Return paginated logs for an app, newest first."""
    client = _get_supabase()
    if not client:
        return []
    try:
        query = (
            client.table("logs")
            .select("id,level,message,service,raw,logged_at")
            .eq("app_id", app_id)
            .order("logged_at", desc=True)
            .limit(limit)
            .offset(offset)
        )
        if level:
            query = query.eq("level", level.upper())
        if service:
            query = query.eq("service", service)
        result = query.execute()
        return result.data or []
    except Exception:
        return []


def get_analytics(app_id: str) -> dict:
    """
    Compute basic analytics from the logs table.
    Returns totals, per-level counts, error rate, and last log time.
    """
    client = _get_supabase()
    if not client:
        return {"total": 0, "by_level": {}, "error_rate": 0.0}
    try:
        result = (
            client.table("logs")
            .select("level,logged_at")
            .eq("app_id", app_id)
            .order("logged_at", desc=True)
            .limit(10000)
            .execute()
        )
        records = result.data or []
        if not records:
            return {"total": 0, "by_level": {}, "error_rate": 0.0}

        total = len(records)
        by_level: dict[str, int] = {}
        for r in records:
            lvl = (r.get("level") or "UNKNOWN").upper()
            by_level[lvl] = by_level.get(lvl, 0) + 1

        error_count = by_level.get("ERROR", 0) + by_level.get("CRITICAL", 0)
        warning_count = by_level.get("WARNING", 0)

        return {
            "total": total,
            "by_level": by_level,
            "error_rate": round(error_count / total, 4) if total else 0.0,
            "warning_rate": round(warning_count / total, 4) if total else 0.0,
            "last_log_time": records[0]["logged_at"] if records else None,
        }
    except Exception:
        return {"total": 0, "by_level": {}, "error_rate": 0.0}


# ============================================================
# Summaries
# ============================================================

def store_summary(app_id: str, summary: dict) -> bool:
    """Upsert the latest dashboard summary for an app."""
    client = _get_supabase()
    if not client:
        return False
    try:
        client.table("summaries").upsert(
            {
                "app_id": app_id,
                "summary": summary,
                "updated_at": _now_utc().isoformat(),
            },
            on_conflict="app_id",
        ).execute()
        return True
    except Exception:
        return False


def get_summary_from_db(app_id: str) -> Optional[dict]:
    """Return the latest summary for an app (with generated_at), or None."""
    client = _get_supabase()
    if not client:
        return None
    try:
        result = (
            client.table("summaries")
            .select("summary,updated_at")
            .eq("app_id", app_id)
            .single()
            .execute()
        )
        if result.data:
            summary = result.data.get("summary") or {}
            summary["generated_at"] = result.data.get("updated_at")
            return summary
    except Exception:
        pass
    return None


# ============================================================
# SDK Device Sessions
# ============================================================

def start_device_session(
    app_name: str, description: Optional[str], ttl_seconds: int
) -> Optional[dict]:
    """
    Create a pending SDK onboarding session.
    Returns {'device_code', 'user_code', 'expires_at'} or None.
    """
    client = _get_supabase()
    if not client:
        return None

    device_code = generate_device_code()
    user_code = generate_user_code()
    expires_at = _utc_iso_after(ttl_seconds)

    payload = {
        "device_code": device_code,
        "user_code": user_code,
        "status": "pending",
        "app_name": app_name,
        "description": description or "",
        "expires_at": expires_at,
        "created_at": _now_utc().isoformat(),
    }
    try:
        result = client.table("sdk_device_sessions").insert(payload).execute()
        row = result.data[0] if result.data else None
        if not row:
            return None
        return {
            "device_code": row["device_code"],
            "user_code": row["user_code"],
            "expires_at": row["expires_at"],
        }
    except Exception:
        return None


def get_device_session(device_code: str) -> Optional[dict]:
    client = _get_supabase()
    if not client:
        return None
    try:
        result = (
            client.table("sdk_device_sessions")
            .select("*")
            .eq("device_code", device_code)
            .limit(1)
            .execute()
        )
        if result.data and len(result.data) > 0:
            return result.data[0]
    except Exception:
        pass
    return None


def mark_device_session_expired(device_code: str) -> None:
    client = _get_supabase()
    if not client:
        return
    try:
        client.table("sdk_device_sessions").update({"status": "expired"}).eq(
            "device_code", device_code
        ).execute()
    except Exception:
        pass


def complete_device_session(
    device_code: str,
    user_id: str,
    app_name_override: Optional[str] = None,
) -> Optional[dict]:
    """
    Complete onboarding: create app + api_key, store on device session.
    Returns {'app_id', 'api_key', 'app_name'} or None.
    """
    client = _get_supabase()
    if not client:
        return None

    session = get_device_session(device_code)
    if not session:
        return None
    if session.get("status") != "pending":
        return None
    expires_at = session.get("expires_at")
    if not expires_at:
        return None
    if _now_utc() >= _parse_utc(expires_at):
        mark_device_session_expired(device_code)
        return None

    app_name = (app_name_override or session.get("app_name") or "").strip() or "My App"
    description = (session.get("description") or "").strip() or None
    api_key = generate_api_key()

    try:
        app_result = (
            client.table("apps")
            .insert(
                {
                    "user_id": user_id,
                    "name": app_name,
                    "description": description,
                    "api_key": api_key,
                }
            )
            .execute()
        )
        app = app_result.data[0] if app_result.data else None
        if not app:
            return None

        client.table("sdk_device_sessions").update(
            {
                "status": "approved",
                "user_id": user_id,
                "app_id": app["id"],
                "api_key": api_key,
                "approved_at": _now_utc().isoformat(),
            }
        ).eq("device_code", device_code).execute()

        return {"app_id": str(app["id"]), "api_key": api_key, "app_name": app["name"]}
    except Exception:
        return None


# ============================================================
# Alert helpers
# ============================================================

def get_alert_recipient_emails(app_id: str) -> list[str]:
    """Resolve default alert recipient email from the app owner's users row."""
    client = _get_supabase()
    if not client:
        return []
    try:
        app_result = (
            client.table("apps").select("user_id").eq("id", app_id).single().execute()
        )
        user_id = app_result.data.get("user_id") if app_result.data else None
        if not user_id:
            return []
        users_result = (
            client.table("users").select("email").eq("id", user_id).limit(1).execute()
        )
        if users_result.data and users_result.data[0].get("email"):
            return [users_result.data[0]["email"]]
    except Exception:
        pass
    return []


# ============================================================
# Schema validation (startup probe)
# ============================================================

def _probe_table_columns(table: str, columns: list[str]) -> dict:
    client = _get_supabase()
    if not client:
        return {
            "table": table,
            "ok": False,
            "error": "supabase_not_configured",
            "columns_checked": columns,
        }
    try:
        client.table(table).select(",".join(columns)).limit(1).execute()
        return {"table": table, "ok": True, "columns_checked": columns}
    except Exception as exc:
        return {
            "table": table,
            "ok": False,
            "error": str(exc),
            "columns_checked": columns,
        }


def validate_sdk_schema() -> dict:
    """Probe required tables/columns and report status."""
    checks = {
        "users": _probe_table_columns("users", ["id", "email"]),
        "apps": _probe_table_columns("apps", ["id", "user_id", "name", "api_key"]),
        "logs": _probe_table_columns("logs", ["id", "app_id", "level", "message"]),
        "summaries": _probe_table_columns("summaries", ["app_id", "summary"]),
        "sdk_device_sessions": _probe_table_columns(
            "sdk_device_sessions",
            ["device_code", "status", "app_name", "expires_at", "user_id", "app_id", "api_key"],
        ),
        "app_chats":  _probe_table_columns("app_chats",  ["app_id", "messages"]),
        "anomalies":  _probe_table_columns("anomalies",  ["id", "app_id", "type", "severity"]),
    }

    all_ok = all(v["ok"] for v in checks.values())
    guidance: list[str] = []
    for table, result in checks.items():
        if not result["ok"]:
            guidance.append(f"Table '{table}' is missing or incomplete: {result.get('error', '')}")

    if not all_ok and not guidance:
        guidance.append(
            "Run missing migrations from supabase/migrations/ in the Supabase SQL editor. "
            "Key files: 20260220000000_full_schema.sql, 20260221000000_add_app_chats.sql, "
            "20260221200000_add_anomalies.sql"
        )

    return {
        "ok": all_ok,
        "checks": checks,
        "guidance": guidance,
    }


# ============================================================
# Anomaly persistence
# ============================================================

def get_log_timeline(app_id: str, window: str = "1h") -> dict:
    """
    Return time-bucketed log counts for the timeline chart.

    window  → bucket_minutes × n_buckets
    "1h"    → 5 min  × 12
    "6h"    → 30 min × 12
    "24h"   → 60 min × 24
    "7d"    → 360 min × 28
    """
    CONFIGS = {
        "1h":  {"total_min": 60,    "bucket_min": 5,   "n": 12},
        "6h":  {"total_min": 360,   "bucket_min": 30,  "n": 12},
        "24h": {"total_min": 1440,  "bucket_min": 60,  "n": 24},
        "7d":  {"total_min": 10080, "bucket_min": 360, "n": 28},
    }
    cfg = CONFIGS.get(window, CONFIGS["1h"])
    total_min  = cfg["total_min"]
    bucket_min = cfg["bucket_min"]
    n_buckets  = cfg["n"]

    client = _get_supabase()
    empty = {"buckets": [], "window": window, "bucket_size_minutes": bucket_min}
    if not client:
        return empty

    now   = _now_utc()
    since = (now - timedelta(minutes=total_min)).isoformat()

    try:
        result = (
            client.table("logs")
            .select("level,logged_at")
            .eq("app_id", app_id)
            .gte("logged_at", since)
            .order("logged_at", desc=False)
            .limit(10000)
            .execute()
        )
        rows = result.data or []
    except Exception:
        return empty

    # Build empty buckets (oldest first)
    def _label(dt: "datetime") -> str:
        if window in ("1h", "6h"):
            return dt.strftime("%H:%M")
        elif window == "24h":
            return dt.strftime("%H:00")
        else:
            return dt.strftime("%a %H:00")

    buckets = []
    for i in range(n_buckets):
        bucket_start = now - timedelta(minutes=(n_buckets - i) * bucket_min)
        buckets.append({
            "time":      _label(bucket_start),
            "timestamp": bucket_start.isoformat(),
            "total":     0,
            "errors":    0,
            "warnings":  0,
        })

    # Fill buckets
    for row in rows:
        try:
            ts      = datetime.fromisoformat(row["logged_at"].replace("Z", "+00:00"))
            age_min = (now - ts).total_seconds() / 60.0
            idx     = n_buckets - 1 - int(age_min / bucket_min)
            if 0 <= idx < n_buckets:
                level = (row.get("level") or "").upper()
                buckets[idx]["total"] += 1
                if level in ("ERROR", "CRITICAL"):
                    buckets[idx]["errors"] += 1
                elif level == "WARNING":
                    buckets[idx]["warnings"] += 1
        except Exception:
            pass

    return {"buckets": buckets, "window": window, "bucket_size_minutes": bucket_min}


def get_logs_since(app_id: str, minutes: int = 90, limit: int = 1000) -> list:
    """Return logs from the last N minutes, oldest first (for temporal analysis)."""
    client = _get_supabase()
    if not client:
        return []
    since = (_now_utc() - timedelta(minutes=minutes)).isoformat()
    try:
        result = (
            client.table("logs")
            .select("level,message,service,logged_at")
            .eq("app_id", app_id)
            .gte("logged_at", since)
            .order("logged_at", desc=False)
            .limit(limit)
            .execute()
        )
        return result.data or []
    except Exception:
        return []


def save_anomalies(app_id: str, anomalies: list) -> int:
    """
    Insert detected anomalies with a 15-min cooldown per type to avoid alert spam.
    Returns count inserted.
    """
    client = _get_supabase()
    if not client or not anomalies:
        return 0

    # Find types already detected in the cooldown window
    cooldown_since = (_now_utc() - timedelta(minutes=15)).isoformat()
    try:
        recent = (
            client.table("anomalies")
            .select("type")
            .eq("app_id", app_id)
            .gte("detected_at", cooldown_since)
            .execute()
        )
        recent_types = {r["type"] for r in (recent.data or [])}
    except Exception:
        recent_types = set()

    new = [a for a in anomalies if a["type"] not in recent_types]
    if not new:
        return 0

    now_iso = _now_utc().isoformat()
    rows = [
        {
            "app_id":            app_id,
            "detected_at":       now_iso,
            "type":              a["type"],
            "severity":          a["severity"],
            "title":             a["title"],
            "summary":           a["summary"],
            "services_affected": a.get("services_affected", []),
            "evidence":          a.get("evidence", {}),
        }
        for a in new
    ]
    try:
        client.table("anomalies").insert(rows).execute()
        return len(rows)
    except Exception as exc:
        import traceback
        print(f"[save_anomalies] DB insert failed for {app_id}: {exc}", flush=True)
        traceback.print_exc()
        return 0


def get_anomalies(app_id: str, limit: int = 50) -> list:
    """Return recent anomalies for an app, newest first."""
    client = _get_supabase()
    if not client:
        return []
    try:
        result = (
            client.table("anomalies")
            .select("id,detected_at,type,severity,title,summary,services_affected,evidence")
            .eq("app_id", app_id)
            .order("detected_at", desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []
    except Exception:
        return []
