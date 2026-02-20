"""API key resolution and SDK device-code provisioning via Supabase."""
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


def generate_api_key() -> str:
    return f"sk_{secrets.token_urlsafe(24)}"


def generate_device_code() -> str:
    return secrets.token_urlsafe(32)


def generate_user_code() -> str:
    raw = secrets.token_hex(4).upper()
    return f"{raw[:4]}-{raw[4:]}"


def resolve_api_key_to_app_id(api_key: str) -> Optional[str]:
    """
    Look up app_id from api_key in Supabase apps table.
    Returns app_id (UUID string) or None if invalid.
    """
    client = _get_supabase()
    if not client:
        return None
    try:
        result = client.table("apps").select("id").eq("api_key", api_key).limit(1).execute()
        if result.data and len(result.data) > 0:
            return str(result.data[0]["id"])
    except Exception:
        pass
    return None


def start_device_session(app_name: str, description: str | None, ttl_seconds: int) -> Optional[dict]:
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
        result = client.table("sdk_device_sessions").insert(payload).select(
            "device_code,user_code,expires_at"
        ).single().execute()
        return result.data if result.data else None
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
    app_name_override: str | None = None,
) -> Optional[dict]:
    """
    Complete onboarding by creating app + api key and storing it on the device session.
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
            .select("id,name")
            .single()
            .execute()
        )
        app = app_result.data
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


def get_alert_recipient_emails(app_id: str) -> list[str]:
    """
    Resolve default alert recipients from the app owner.
    Attempts users.email, then profiles.email.
    """
    client = _get_supabase()
    if not client:
        return []
    user_id = None
    try:
        app_result = client.table("apps").select("user_id").eq("id", app_id).single().execute()
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

    try:
        if not user_id:
            return []
        profiles_result = (
            client.table("profiles").select("email").eq("id", user_id).limit(1).execute()
        )
        if profiles_result.data and profiles_result.data[0].get("email"):
            return [profiles_result.data[0]["email"]]
    except Exception:
        pass
    return []


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
    """
    Probe required tables/columns and detect default email source for alerts.
    """
    checks = {
        "apps_required": _probe_table_columns("apps", ["id", "user_id", "name", "api_key"]),
        "sdk_device_sessions_required": _probe_table_columns(
            "sdk_device_sessions",
            ["device_code", "status", "app_name", "expires_at", "user_id", "app_id", "api_key"],
        ),
        "users_email_optional": _probe_table_columns("users", ["id", "email"]),
        "profiles_email_optional": _probe_table_columns("profiles", ["id", "email"]),
    }

    users_ok = bool(checks["users_email_optional"]["ok"])
    profiles_ok = bool(checks["profiles_email_optional"]["ok"])
    if users_ok:
        email_source = "users.email"
    elif profiles_ok:
        email_source = "profiles.email"
    else:
        email_source = None

    required_ok = bool(checks["apps_required"]["ok"] and checks["sdk_device_sessions_required"]["ok"])
    overall_ok = bool(required_ok and email_source is not None)

    guidance: list[str] = []
    if not checks["apps_required"]["ok"]:
        guidance.append("Run apps migration with api_key column and required fields.")
    if not checks["sdk_device_sessions_required"]["ok"]:
        guidance.append("Run sdk_device_sessions migration.")
    if email_source is None:
        guidance.append("Add email to users or profiles table for default alert recipients.")

    return {
        "ok": overall_ok,
        "required_ok": required_ok,
        "email_source": email_source,
        "checks": checks,
        "guidance": guidance,
    }
