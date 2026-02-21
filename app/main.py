import asyncio
import os
import re
import ssl
import smtplib
import json
import threading
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.models.smart_log_processor import process_and_summarize_stream
from app.core.api_key import (
    bulk_insert_logs,
    clear_app_chat,
    complete_device_session,
    generate_api_key,
    get_alert_recipient_emails,
    get_analytics,
    get_anomalies,
    get_app_chat,
    get_device_session,
    get_log_timeline,
    get_logs_paginated,
    get_logs_since,
    get_summary_from_db,
    mark_device_session_expired,
    resolve_api_key_to_app_id,
    save_anomalies,
    save_app_chat,
    start_device_session,
    store_summary,
    upsert_user,
    validate_sdk_schema,
    verify_app_ownership,
    _get_supabase,
)
from app.models.anomaly_detector import detect_anomalies

app = FastAPI(title="Sentry Log Platform API")

# ============================================================
# CORS
# ============================================================

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:3001,https://sentrylabs.live,https://www.sentrylabs.live",
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Config
# ============================================================

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_CHAT_MODEL = "gemini-2.5-flash"

RISK_ALERT_WEBHOOK_URL = os.environ.get("RISK_ALERT_WEBHOOK_URL", "").strip()
NOTIFICATION_COOLDOWN_SECONDS = int(os.environ.get("NOTIFICATION_COOLDOWN_SECONDS", "300"))

EMAIL_ALERT_FROM = os.environ.get("EMAIL_ALERT_FROM", "").strip()
EMAIL_ALERT_TO = [
    addr.strip()
    for addr in os.environ.get("EMAIL_ALERT_TO", "").split(",")
    if addr.strip()
]
SMTP_HOST     = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS  = os.environ.get("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()

SDK_VERIFICATION_BASE_URL = os.environ.get(
    "SDK_VERIFICATION_BASE_URL", "http://localhost:3000"
).rstrip("/")
SDK_DEFAULT_DSN = os.environ.get("SDK_DEFAULT_DSN", "http://localhost:8001").rstrip("/")
SDK_SCHEMA_STRICT_STARTUP = os.environ.get("SDK_SCHEMA_STRICT_STARTUP", "false").lower() in {
    "1", "true", "yes", "on",
}

# Directory for smart_log_processor output files (risk history state)
OUTPUTS_BASE_DIR = os.path.join(os.path.dirname(__file__), "outputs")
NOTIFICATION_COOLDOWN_STATE: dict = {}


# ============================================================
# Request / Response schemas
# ============================================================

class SyncUserRequest(BaseModel):
    id: str
    email: str
    name: Optional[str] = None
    image: Optional[str] = None


class CreateAppRequest(BaseModel):
    name: str
    description: Optional[str] = None
    # Optional user fields — used to auto-upsert the user row if it doesn't
    # exist yet (guards against the server-side auth callback being skipped).
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    user_image: Optional[str] = None


class UpdateAppRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None


class IngestRequest(BaseModel):
    logs: List[str]


class DeviceStartRequest(BaseModel):
    app_name: str
    description: Optional[str] = None
    ttl_seconds: int = 600


class DeviceCompleteRequest(BaseModel):
    device_code: str
    user_id: str
    app_name: Optional[str] = None
    # Optional user fields — used to upsert the user row and resolve the
    # canonical DB id before creating the app (guards stale UUID sessions).
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    user_image: Optional[str] = None


class ChatRequest(BaseModel):
    message: str


# ============================================================
# Auth dependencies
# ============================================================

def get_current_user_id(
    authorization: Optional[str] = Header(None),
) -> str:
    """
    Extract user_id from `Authorization: Bearer <user_id>` header.
    The user_id is the Google sub stored in the NextAuth session.
    """
    if authorization and authorization.startswith("Bearer "):
        user_id = authorization[7:].strip()
        if user_id:
            return user_id
    raise HTTPException(
        status_code=401,
        detail="Missing or invalid Authorization header. Expected: Bearer <user_id>",
    )


def get_api_key(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    """Extract SDK API key from X-API-Key or Authorization: Bearer header."""
    if x_api_key:
        return x_api_key
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip()
    raise HTTPException(
        status_code=401,
        detail="Missing API key. Use X-API-Key or Authorization: Bearer <key> header.",
    )


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def validate_schema_on_startup() -> None:
    report = validate_sdk_schema()
    if report.get("ok"):
        print("[startup] DB schema validation passed.")
        return

    print("[startup] DB schema validation issues:")
    for note in report.get("guidance", []):
        print(f"[startup]   - {note}")

    if SDK_SCHEMA_STRICT_STARTUP:
        raise RuntimeError(
            "DB schema validation failed and SDK_SCHEMA_STRICT_STARTUP=true."
        )


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.get("/sdk/schema/validate")
async def sdk_schema_validate():
    return validate_sdk_schema()


# ============================================================
# Users
# ============================================================

@app.post("/users/sync", status_code=200)
async def sync_user(request: SyncUserRequest):
    """
    Upsert a user row from NextAuth session data.
    Returns the canonical DB id (may differ from request.id if the email
    already existed under a different id — e.g. stale Auth.js UUID).
    """
    canonical_id = upsert_user(
        user_id=request.id,
        email=request.email,
        name=request.name,
        image=request.image,
    )
    if canonical_id is None:
        raise HTTPException(status_code=503, detail="Database not available")
    return {"status": "ok", "id": canonical_id}


# ============================================================
# Apps CRUD
# ============================================================

@app.get("/apps")
async def list_apps(user_id: str = Depends(get_current_user_id)):
    """List all apps for the authenticated user."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        result = (
            client.table("apps")
            .select("id,user_id,name,description,url,api_key,created_at,updated_at")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/apps/{app_id}")
async def get_app(app_id: str, user_id: str = Depends(get_current_user_id)):
    """Get a single app by ID (must belong to the authenticated user)."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        result = (
            client.table("apps")
            .select("id,user_id,name,description,url,api_key,created_at,updated_at")
            .eq("id", app_id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=404, detail="App not found")
        return result.data
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=404, detail="App not found")


@app.post("/apps", status_code=201)
async def create_app(
    request: CreateAppRequest,
    user_id: str = Depends(get_current_user_id),
):
    """Create a new app for the authenticated user with an auto-generated API key."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    if not request.name.strip():
        raise HTTPException(status_code=400, detail="name is required")

    # Ensure the user row exists before inserting the app (FK guard).
    # upsert_user now returns the canonical DB id — use it in case the
    # session id was a stale UUID that maps to a different DB id.
    if request.user_email:
        canonical_id = upsert_user(
            user_id=user_id,
            email=request.user_email,
            name=request.user_name,
            image=request.user_image,
        )
        if canonical_id:
            user_id = canonical_id

    api_key = generate_api_key()
    payload = {
        "user_id": user_id,
        "name": request.name.strip(),
        "description": (request.description or "").strip() or None,
        "api_key": api_key,
    }
    try:
        result = client.table("apps").insert(payload).execute()
        if not result.data:
            raise HTTPException(status_code=500, detail="Failed to create app")
        return result.data[0]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/apps/{app_id}/rotate-key", status_code=200)
async def rotate_api_key(app_id: str, user_id: str = Depends(get_current_user_id)):
    """Generate a new API key for an app, invalidating the previous one."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    new_key = generate_api_key()
    try:
        client.table("apps").update(
            {"api_key": new_key, "updated_at": datetime.now(timezone.utc).isoformat()}
        ).eq("id", app_id).execute()
        return {"api_key": new_key}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.patch("/apps/{app_id}", status_code=200)
async def update_app(
    app_id: str,
    request: UpdateAppRequest,
    user_id: str = Depends(get_current_user_id),
):
    """Update mutable fields (name, description) for an app."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")

    updates: dict = {"updated_at": datetime.now(timezone.utc).isoformat()}
    if request.name is not None:
        name = request.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="name cannot be empty")
        updates["name"] = name
    if request.description is not None:
        updates["description"] = request.description.strip() or None
    if request.url is not None:
        updates["url"] = request.url.strip() or None

    try:
        result = (
            client.table("apps")
            .update(updates)
            .eq("id", app_id)
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=500, detail="Update failed")
        return result.data[0]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/apps/{app_id}", status_code=200)
async def delete_app(app_id: str, user_id: str = Depends(get_current_user_id)):
    """Delete an app (must belong to the authenticated user)."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    try:
        client.table("apps").delete().eq("id", app_id).execute()
        return {"status": "deleted", "app_id": app_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# Logs (frontend read)
# ============================================================

@app.get("/logs/{app_id}")
async def get_logs(
    app_id: str,
    user_id: str = Depends(get_current_user_id),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    level: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
):
    """Return paginated raw logs for an app."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    logs = get_logs_paginated(app_id, limit=limit, offset=offset, level=level, service=service)
    return {"logs": logs, "count": len(logs)}


# ============================================================
# Analytics
# ============================================================

@app.get("/analytics/{app_id}")
async def get_app_analytics(
    app_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """Compute real-time analytics from the logs table."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    return get_analytics(app_id)


# ============================================================
# Anomalies
# ============================================================

@app.get("/anomalies/{app_id}")
async def get_app_anomalies(
    app_id: str,
    user_id: str = Depends(get_current_user_id),
    limit: int = Query(50, ge=1, le=200),
):
    """Return detected anomalies for an app, newest first."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    anomalies = get_anomalies(app_id, limit=limit)
    return {"anomalies": anomalies}


# ============================================================
# Log Timeline
# ============================================================

@app.get("/timeline/{app_id}")
async def get_app_timeline(
    app_id: str,
    user_id: str = Depends(get_current_user_id),
    window: str = Query("1h", regex="^(1h|6h|24h|7d)$"),
):
    """Return time-bucketed log counts for the interactive timeline chart."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    return get_log_timeline(app_id, window=window)


# ============================================================
# Summary (AI dashboard)
# ============================================================

@app.get("/summary/{app_id}")
async def get_summary(app_id: str, user_id: str = Depends(get_current_user_id)):
    """Return the latest AI-generated dashboard summary stored in the DB."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    summary = get_summary_from_db(app_id)
    return {"summary": summary}


# ============================================================
# Log Ingest (SDK push)
# ============================================================

# Regex for parsing standard log lines:
# e.g. "2024-01-01 10:00:00,123 [INFO] [ServiceName]: message"
_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}[,.]?\d*)"
    r".*?\[(?P<level>INFO|WARNING|WARN|ERROR|CRITICAL|DEBUG)\]"
    r"(?:.*?\[(?P<service>[^\]]+)\])?"
    r"[:\s]*(?P<message>.+)$",
    re.IGNORECASE,
)

# ── Service inference ─────────────────────────────────────────────────────────
# When logs have no explicit [ServiceName] tag we try to infer a functional
# domain from the message text using four strategies in priority order:
#   1. Known logger/library prefix → deterministic map
#   2. Dotted module path in the message (e.g. app.payments.service)
#   3. File path in a Python stacktrace (e.g. File "app/auth/tokens.py")
#   4. HTTP verb + URL path (e.g. POST /payment/charge)
#   5. Domain keyword dictionary

_LOGGER_MAP: dict = {
    "uvicorn":          "api",
    "django.request":   "api",
    "django.db":        "database",
    "django.security":  "auth",
    "sqlalchemy":       "database",
    "alembic":          "database",
    "psycopg2":         "database",
    "pymongo":          "database",
    "celery":           "queue",
    "kombu":            "queue",
    "stripe":           "payment",
    "boto3":            "storage",
    "botocore":         "storage",
    "paramiko":         "ssh",
    "smtplib":          "email",
    "redis":            "cache",
    "aioredis":         "cache",
}

_SERVICE_KEYWORDS: dict = {
    "database":  ["database", "db error", "postgres", "mysql", "sqlite", "mongodb",
                  "connection pool", "query failed", "migration", "sqlalchemy", "orm"],
    "auth":      ["auth", "authentication", "login", "logout", "jwt", "oauth",
                  "session expired", "invalid token", "unauthorized", "forbidden",
                  "permission denied", "sign in", "signup", "password"],
    "payment":   ["payment", "stripe", "billing", "invoice", "charge", "refund",
                  "transaction", "checkout", "subscription"],
    "api":       ["api", "endpoint", "http error", "status code", "rest",
                  "graphql", "webhook", "request failed"],
    "cache":     ["cache miss", "cache hit", "cache error", "redis", "memcache", "ttl"],
    "queue":     ["queue", "worker", "celery", "rabbitmq", "kafka", "job failed",
                  "task retry", "message broker"],
    "email":     ["smtp", "sendgrid", "mailgun", "send mail", "email failed"],
    "storage":   ["s3", "bucket", "upload failed", "object store", "blob storage"],
    "scheduler": ["cron", "scheduled task", "periodic task"],
}

_MODULE_PATH_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,})\b")
_FILE_PATH_RE   = re.compile(r'[Ff]ile ["\']([^"\']+\.py)["\']')
_URL_PATH_RE    = re.compile(r'(?:GET|POST|PUT|DELETE|PATCH)\s+/([a-zA-Z][a-zA-Z0-9_-]+)', re.I)

_GENERIC_PARTS = {"app", "apps", "src", "lib", "core", "utils", "helpers",
                  "common", "base", "models", "views", "tests", "main", "api",
                  "routes", "handlers", "middleware", "config", "settings"}


def _infer_service(message: str, raw: str) -> Optional[str]:
    """Infer a service/domain name from a log line with no explicit service tag."""
    text = raw or message
    lower = text.lower()

    # 1. Known logger prefix
    for prefix, svc in _LOGGER_MAP.items():
        if lower.startswith(prefix + ".") or lower.startswith(prefix + ":") or f" {prefix}." in lower:
            return svc

    # 2. Dotted module path — take first meaningful component after generic prefixes
    for m in _MODULE_PATH_RE.finditer(text):
        parts = [p for p in m.group(1).split(".") if p not in _GENERIC_PARTS and len(p) > 2]
        if parts:
            candidate = parts[0].rstrip("_").removesuffix("_service").removesuffix("_handler")
            if candidate and len(candidate) > 2:
                return candidate

    # 3. Python stacktrace file path — second-to-last directory component
    m = _FILE_PATH_RE.search(text)
    if m:
        segments = m.group(1).replace("\\", "/").split("/")
        for seg in reversed(segments[:-1]):
            if seg not in _GENERIC_PARTS and len(seg) > 2:
                return seg

    # 4. HTTP verb + URL path — take the first path segment
    m = _URL_PATH_RE.search(text)
    if m:
        seg = m.group(1).rstrip("s")   # /payments → payment, /users → user
        if len(seg) > 2:
            return seg

    # 5. Domain keyword matching
    for service, keywords in _SERVICE_KEYWORDS.items():
        for kw in keywords:
            if kw in lower:
                return service

    return None


def _parse_log_line(raw: str, app_id: str) -> dict:
    """Parse a raw SDK log string into a structured dict for DB insertion."""
    stripped = raw.strip()
    m = _LOG_PATTERN.match(stripped)
    if m:
        level = m.group("level").upper()
        if level == "WARN":
            level = "WARNING"
        service = m.group("service") or None
        message = (m.group("message") or "").strip()
        ts_str = m.group("timestamp").replace(",", ".")
        try:
            parsed_ts = datetime.fromisoformat(ts_str)
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
            logged_at = parsed_ts.isoformat()
        except Exception:
            logged_at = datetime.now(timezone.utc).isoformat()
    else:
        level = "INFO"
        service = None
        message = stripped
        logged_at = datetime.now(timezone.utc).isoformat()

    # Fall back to inference when no explicit [ServiceName] tag
    if service is None:
        service = _infer_service(message, stripped)

    return {
        "app_id": app_id,
        "level": level,
        "message": message[:2000],
        "service": service,
        "raw": stripped[:4000],
        "logged_at": logged_at,
    }


@app.post("/ingest")
async def ingest_logs(
    request: IngestRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Accept batched logs from the SDK.
    1. Validates API key → resolves app_id
    2. Parses and bulk-inserts logs into the logs table
    3. Runs AI processing → stores dashboard summary in DB
    4. Emits risk notifications
    """
    app_id = resolve_api_key_to_app_id(api_key)
    if not app_id:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not request.logs:
        return {"status": "accepted", "app_id": app_id, "processed": 0}

    # Parse and store raw logs in DB
    parsed = [_parse_log_line(raw, app_id) for raw in request.logs]
    inserted = bulk_insert_logs(parsed)

    # AI processing — uses per-app outputs dir to maintain risk history state
    outputs_dir = os.path.join(OUTPUTS_BASE_DIR, app_id)
    os.makedirs(outputs_dir, exist_ok=True)
    dashboard = process_and_summarize_stream(request.logs, outputs_dir)

    # Store summary in DB
    store_summary(app_id, dashboard)

    # Trigger notifications
    notifications = _trigger_risk_notifications(app_id, dashboard)

    # Run anomaly detection in background so ingest stays fast
    threading.Thread(target=_run_anomaly_detection, args=(app_id,), daemon=True).start()

    return {
        "status": "accepted",
        "app_id": app_id,
        "processed": len(request.logs),
        "inserted": inserted,
        "notifications_triggered": len(notifications),
        "dashboard_summary": dashboard,
    }


def _run_anomaly_detection(app_id: str) -> None:
    """Fetch recent logs, run all detectors, persist new anomalies. Runs in a daemon thread."""
    try:
        logs = get_logs_since(app_id, minutes=90, limit=1000)
        if logs:
            found = detect_anomalies(logs)
            if found:
                saved = save_anomalies(app_id, found)
                if saved > 0:
                    for a in found:
                        if a.get("severity") in ("high", "critical"):
                            atype = a.get("type", "").replace("_", " ").title()
                            _notify_all(
                                app_id=app_id,
                                title=a.get("title", "Anomaly detected"),
                                summary=a.get("summary", ""),
                                severity=a.get("severity", "high"),
                                services=a.get("services_affected", []),
                                extra_lines=[f"Type: {atype}"],
                            )
    except Exception:
        pass


# ============================================================
# SDK Device Login + Provisioning
# ============================================================

def _build_sdk_verification_url(device_code: str, app_name: str, user_code: str) -> str:
    callback_target = (
        f"/sdk/link?device_code={urllib.parse.quote(device_code)}"
        f"&app_name={urllib.parse.quote(app_name)}"
    )
    callback_query = urllib.parse.quote(callback_target, safe="")
    return (
        f"{SDK_VERIFICATION_BASE_URL}/auth/sign-in"
        f"?callbackUrl={callback_query}&user_code={urllib.parse.quote(user_code)}"
    )


@app.post("/sdk/device/start")
async def sdk_device_start(request: DeviceStartRequest):
    if not request.app_name.strip():
        raise HTTPException(status_code=400, detail="app_name is required")
    ttl = max(120, min(request.ttl_seconds, 1800))
    session = start_device_session(
        app_name=request.app_name.strip(),
        description=request.description,
        ttl_seconds=ttl,
    )
    if not session:
        raise HTTPException(status_code=500, detail="Could not create device session")

    verification_uri_complete = _build_sdk_verification_url(
        device_code=session["device_code"],
        app_name=request.app_name.strip(),
        user_code=session["user_code"],
    )
    return {
        "device_code": session["device_code"],
        "user_code": session["user_code"],
        "verification_uri": f"{SDK_VERIFICATION_BASE_URL}/auth/sign-in",
        "verification_uri_complete": verification_uri_complete,
        "expires_in": ttl,
        "interval": 3,
    }


@app.get("/sdk/device/poll")
async def sdk_device_poll(device_code: str):
    session = get_device_session(device_code)
    if not session:
        raise HTTPException(status_code=404, detail="unknown_device_code")

    expires_at = session.get("expires_at")
    if not expires_at:
        raise HTTPException(status_code=500, detail="invalid_session")
    if datetime.now(timezone.utc) >= datetime.fromisoformat(
        expires_at.replace("Z", "+00:00")
    ):
        mark_device_session_expired(device_code)
        raise HTTPException(status_code=400, detail="expired_token")

    status = session.get("status", "pending")
    if status == "approved":
        return {
            "status": "approved",
            "app_id": session.get("app_id"),
            "app_name": session.get("app_name"),
            "api_key": session.get("api_key"),
            "dsn": SDK_DEFAULT_DSN,
        }
    if status == "expired":
        raise HTTPException(status_code=400, detail="expired_token")
    return {"status": "pending"}


@app.post("/sdk/device/complete")
async def sdk_device_complete(request: DeviceCompleteRequest):
    if not request.device_code.strip() or not request.user_id.strip():
        raise HTTPException(status_code=400, detail="device_code and user_id are required")

    # If the client supplied user profile info, upsert the user row and use the
    # canonical DB id. This handles sessions where user.id is a stale/temp UUID
    # that doesn't match the primary key in the users table.
    user_id = request.user_id.strip()
    if request.user_email:
        canonical = upsert_user(
            user_id=user_id,
            email=request.user_email,
            name=request.user_name or "",
            image=request.user_image or "",
        )
        if canonical:
            user_id = canonical

    result = complete_device_session(
        device_code=request.device_code.strip(),
        user_id=user_id,
        app_name_override=request.app_name,
    )
    if not result:
        raise HTTPException(status_code=400, detail="Unable to complete device session")
    return {"status": "approved", **result}


# ============================================================
# Notifications — unified multi-channel system
# Channels: Telegram · Discord · Email · Generic Webhook
# Each channel fires only if the relevant env vars are set.
# ============================================================

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Severity → (emoji, Discord embed color int)
_SEV_META = {
    "critical": ("🔴", 0xED4245),
    "high":     ("🟠", 0xFFA500),
    "medium":   ("🟡", 0xFEE75C),
    "low":      ("🔵", 0x5865F2),
}


# ── Telegram ──────────────────────────────────────────────────────────────────

def _send_telegram(text: str) -> tuple[bool, str]:
    """Send a plain Markdown message to a Telegram chat via Bot API."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "not_configured"
    try:
        body = json.dumps({
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       text,
            "parse_mode": "Markdown",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
        return True, "sent"
    except Exception as exc:
        return False, f"failed:{type(exc).__name__}"


# ── Discord ───────────────────────────────────────────────────────────────────

def _send_discord(title: str, description: str, color: int, fields: list) -> tuple[bool, str]:
    """Send a rich embed to a Discord channel via webhook."""
    if not DISCORD_WEBHOOK_URL:
        return False, "not_configured"
    try:
        body = json.dumps({
            "username": "Sentry Monitor",
            "embeds": [{
                "title":       title,
                "description": description,
                "color":       color,
                "fields":      fields,
                "footer":      {"text": "Sentry Monitor"},
                "timestamp":   _utc_now_iso(),
            }],
        }).encode("utf-8")
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
        return True, "sent"
    except Exception as exc:
        return False, f"failed:{type(exc).__name__}"


# ── Generic webhook (unchanged) ───────────────────────────────────────────────

def _post_webhook(payload: dict) -> tuple[bool, str]:
    if not RISK_ALERT_WEBHOOK_URL:
        return False, "not_configured"
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            RISK_ALERT_WEBHOOK_URL,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
        return True, "sent"
    except Exception as exc:
        return False, f"failed:{type(exc).__name__}"


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_email(app_id: str, subject: str, body_lines: list) -> tuple[bool, str]:
    recipients = EMAIL_ALERT_TO or get_alert_recipient_emails(app_id)
    if not recipients:
        return False, "not_configured:missing_recipient"
    if not EMAIL_ALERT_FROM or not SMTP_HOST:
        return False, "not_configured:missing_smtp"

    msg = EmailMessage()
    msg["From"]    = EMAIL_ALERT_FROM
    msg["To"]      = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content("\n".join(body_lines))

    try:
        if SMTP_USE_TLS:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls(context=ctx)
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        return True, "sent"
    except Exception as exc:
        return False, f"failed:{type(exc).__name__}"


# ── Unified dispatcher ────────────────────────────────────────────────────────

def _notify_all(
    app_id:   str,
    title:    str,
    summary:  str,
    severity: str,
    services: list,
    extra_lines: Optional[list] = None,
    webhook_payload: Optional[dict] = None,
) -> dict:
    """
    Fire every configured notification channel.
    Returns a dict with per-channel results.
    """
    sev_lower = severity.lower()
    emoji, color = _SEV_META.get(sev_lower, ("⚪", 0x99AAB5))
    sev_upper = severity.upper()
    services_str = ", ".join(services) if services else "unknown"
    extra = extra_lines or []

    # ── Telegram ──────────────────────────────────────────────
    tg_text = "\n".join([
        f"{emoji} *[{sev_upper}] {title}*",
        "",
        summary,
        "",
        f"*Services:* {services_str}",
        f"*App:* `{app_id}`",
        *([" "] + extra if extra else []),
        "",
        "_Open your Sentry dashboard for details._",
    ])
    tg_ok, tg_status = _send_telegram(tg_text)

    # ── Discord ───────────────────────────────────────────────
    dc_fields = [
        {"name": "Severity",  "value": sev_upper,    "inline": True},
        {"name": "Services",  "value": services_str, "inline": True},
        {"name": "App ID",    "value": f"`{app_id}`", "inline": False},
    ]
    for line in extra:
        if ": " in line:
            k, v = line.split(": ", 1)
            dc_fields.append({"name": k.strip(), "value": v.strip(), "inline": True})
    dc_ok, dc_status = _send_discord(
        title=f"{emoji} {title}",
        description=summary,
        color=color,
        fields=dc_fields,
    )

    # ── Email ─────────────────────────────────────────────────
    email_body = [
        title,
        "=" * len(title),
        "",
        f"Severity:          {sev_upper}",
        f"Affected services: {services_str}",
        f"App ID:            {app_id}",
        "",
        "Summary:",
        f"  {summary}",
        *([" "] + extra if extra else []),
        "",
        "Open your Sentry dashboard → Anomalies tab for full details.",
    ]
    email_ok, email_status = _send_email(
        app_id=app_id,
        subject=f"[Sentry] [{sev_upper}] {title}",
        body_lines=email_body,
    )

    # ── Generic webhook ───────────────────────────────────────
    if webhook_payload:
        wh_ok, wh_status = _post_webhook(webhook_payload)
    else:
        wh_ok, wh_status = False, "skipped"

    return {
        "telegram": {"sent": tg_ok, "status": tg_status},
        "discord":  {"sent": dc_ok, "status": dc_status},
        "email":    {"sent": email_ok, "status": email_status},
        "webhook":  {"sent": wh_ok,  "status": wh_status},
    }


# ── Risk notification trigger ─────────────────────────────────────────────────

def _trigger_risk_notifications(app_id: str, dashboard: dict) -> list[dict]:
    """Emit alerts for at-risk services, with in-memory cooldown."""
    at_risk_services = dashboard.get("at_risk_services", [])
    if not at_risk_services:
        return []

    now_epoch = datetime.now(timezone.utc).timestamp()
    triggered = []

    for service in at_risk_services:
        app_state    = NOTIFICATION_COOLDOWN_STATE.setdefault(app_id, {})
        last_sent_ts = float(app_state.get(service, {}).get("last_sent_ts", 0))
        if (now_epoch - last_sent_ts) < NOTIFICATION_COOLDOWN_SECONDS:
            continue

        score       = dashboard.get("service_risk_scores",      {}).get(service, 0)
        level       = dashboard.get("service_risk_levels",      {}).get(service, "low")
        confidence  = dashboard.get("service_risk_confidence",  {}).get(service, 0)
        trend       = dashboard.get("service_risk_trend",       {}).get(service, "stable")
        eta_minutes = dashboard.get("service_failure_eta_minutes", {}).get(service)
        reasons     = dashboard.get("service_risk_reasons",     {}).get(service, [])
        recs        = dashboard.get("service_recommendations",  {}).get(service, [])

        extra_lines = [
            f"Risk score: {score}",
            f"Confidence: {confidence}",
            f"Trend: {trend}",
        ]
        if eta_minutes:
            extra_lines.append(f"ETA (min): {eta_minutes}")
        if reasons:
            extra_lines += [f"Reason: {r}" for r in reasons[:3]]
        if recs:
            extra_lines += [f"Fix: {r}" for r in recs[:2]]

        webhook_payload = {
            "event":       "service_failure_risk",
            "timestamp":   _utc_now_iso(),
            "app_id":      app_id,
            "service":     service,
            "score":       score,
            "level":       level,
            "confidence":  confidence,
            "trend":       trend,
            "eta_minutes": eta_minutes,
            "reasons":     reasons,
        }

        delivery = _notify_all(
            app_id=app_id,
            title=f"Service at risk: {service} ({level})",
            summary=f"Service *{service}* is at **{level}** failure risk (score {score}, trend: {trend}).",
            severity=level,
            services=[service],
            extra_lines=extra_lines,
            webhook_payload=webhook_payload,
        )

        triggered.append({**webhook_payload, "delivery": delivery})
        app_state[service] = {"last_sent_ts": now_epoch, "last_score": score, "last_level": level}

    return triggered


# ============================================================
# Log Chat (Ask your logs — persistent, DB-backed)
# ============================================================

def _build_log_context(logs: list) -> str:
    """Compress recent logs into a structured context string for the LLM."""
    if not logs:
        return "No logs available yet."
    by_service: dict = {}
    for log in logs:
        svc = log.get("service") or "app"
        by_service.setdefault(svc, []).append(log)
    lines = []
    for svc in sorted(by_service):
        svc_logs = by_service[svc]
        counts: dict = {}
        for lg in svc_logs:
            lvl = lg.get("level", "INFO")
            counts[lvl] = counts.get(lvl, 0) + 1
        count_str = "  ".join(f"{k}:{v}" for k, v in counts.items())
        lines.append(f"\n=== SERVICE: {svc} ({count_str}) ===")
        prioritized = sorted(
            svc_logs,
            key=lambda l: (0 if l.get("level") in ("CRITICAL", "ERROR", "WARNING") else 1, l.get("logged_at", "")),
        )
        for lg in prioritized[:25]:
            ts = (lg.get("logged_at") or "")[:19]
            lvl = lg.get("level", "INFO")
            msg = (lg.get("message") or "")[:250]
            lines.append(f"  {ts} [{lvl}] {msg}")
    return "\n".join(lines)


@app.get("/chat/{app_id}")
async def get_chat_history(
    app_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """Return the stored chat history for an app."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    messages = get_app_chat(app_id)
    return {"messages": messages}


@app.delete("/chat/{app_id}")
async def delete_chat_history(
    app_id: str,
    user_id: str = Depends(get_current_user_id),
):
    """Clear the chat history for an app."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    clear_app_chat(app_id)
    return {"status": "cleared"}


@app.post("/chat/{app_id}")
async def chat_with_logs(
    app_id: str,
    request: ChatRequest,
    user_id: str = Depends(get_current_user_id),
):
    """Send a message and stream the reply token-by-token (text/plain SSE chunks)."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    if not GEMINI_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Chat is not configured — add GEMINI_API_KEY to your backend environment.",
        )

    stored = get_app_chat(app_id)
    logs = get_logs_paginated(app_id, limit=300, offset=0)
    context = _build_log_context(logs)

    # Include recent anomalies so the AI already knows what was auto-detected
    recent_anomalies = get_anomalies(app_id, limit=10)
    anomaly_context = ""
    if recent_anomalies:
        lines = []
        for a in recent_anomalies:
            lines.append(
                f"[{a['severity'].upper()}] {a['type']} — {a['title']}: {a['summary']}"
            )
        anomaly_context = (
            f"\nAUTO-DETECTED ANOMALIES (last 24 h, newest first):\n"
            + "\n".join(lines)
            + "\n"
        )

    system_prompt = (
        "You are an expert log analysis assistant embedded in a production monitoring platform.\n"
        "Always format your responses in Markdown:\n"
        "- Use **bold** for service names, timestamps, and key terms.\n"
        "- Use `inline code` for log levels and error messages.\n"
        "- Use ## for section headers (Root Cause, Symptoms, Recommendations).\n"
        "- Use bullet lists for multiple points.\n"
        "- Keep responses focused and actionable — developers are in the middle of incidents.\n\n"
        f"RECENT LOGS ({len(logs)} entries, grouped by service):\n"
        f"{context}\n"
        f"{anomaly_context}\n"
        "When answering:\n"
        "1. Cite specific log lines with their timestamps.\n"
        "2. Identify cascading failures — which service triggered what.\n"
        "3. Give the root cause, not just symptoms.\n"
        "4. Suggest concrete fixes (code-level where possible).\n"
        "5. Reference auto-detected anomalies if they are relevant.\n"
        "6. If logs are insufficient, say so and suggest what to add."
    )

    contents = []
    for msg in stored:
        role = "model" if msg.get("role") == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": msg.get("content", "")}]})
    contents.append({"role": "user", "parts": [{"text": request.message}]})

    payload = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1500},
    }

    gemini_url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_CHAT_MODEL}:streamGenerateContent?alt=sse&key={GEMINI_API_KEY}"
    )
    body_bytes = json.dumps(payload).encode("utf-8")

    # Use a thread + asyncio.Queue so the blocking urllib stream doesn't stall the event loop
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    full_answer: list = []

    def _producer():
        try:
            req = urllib.request.Request(
                gemini_url,
                data=body_bytes,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").rstrip()
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    try:
                        chunk_json = json.loads(data_str)
                        text = chunk_json["candidates"][0]["content"]["parts"][0]["text"]
                        if text:
                            full_answer.append(text)
                            loop.call_soon_threadsafe(queue.put_nowait, text)
                    except (KeyError, json.JSONDecodeError):
                        pass
        except Exception as exc:
            loop.call_soon_threadsafe(queue.put_nowait, f"\n\n[Error: {exc!r}]")
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

    threading.Thread(target=_producer, daemon=True).start()

    async def _stream():
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk

        # Persist full conversation after streaming completes
        answer = "".join(full_answer)
        now = _utc_now_iso()
        updated = stored + [
            {"role": "user", "content": request.message, "ts": now},
            {"role": "assistant", "content": answer, "ts": now},
        ]
        if len(updated) > 100:
            updated = updated[-100:]
        save_app_chat(app_id, updated)

    return StreamingResponse(
        _stream(),
        media_type="text/plain; charset=utf-8",
        headers={
            "X-Accel-Buffering": "no",       # disable nginx proxy buffering
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
        },
    )
