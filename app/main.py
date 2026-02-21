import os
import re
import ssl
import smtplib
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.models.smart_log_processor import process_and_summarize_stream
from app.core.api_key import (
    bulk_insert_logs,
    clear_app_chat,
    complete_device_session,
    generate_api_key,
    get_alert_recipient_emails,
    get_analytics,
    get_app_chat,
    get_device_session,
    get_logs_paginated,
    get_summary_from_db,
    mark_device_session_expired,
    resolve_api_key_to_app_id,
    save_app_chat,
    start_device_session,
    store_summary,
    upsert_user,
    validate_sdk_schema,
    verify_app_ownership,
    _get_supabase,
)

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
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}

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
            .select("id,user_id,name,description,api_key,created_at,updated_at")
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
            .select("id,user_id,name,description,api_key,created_at,updated_at")
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
            # Make timezone-aware if naive
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

    return {
        "status": "accepted",
        "app_id": app_id,
        "processed": len(request.logs),
        "inserted": inserted,
        "notifications_triggered": len(notifications),
        "dashboard_summary": dashboard,
    }


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
# Risk notifications (in-memory cooldown + webhook/email)
# ============================================================

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _post_webhook(payload: dict) -> tuple[bool, str]:
    if not RISK_ALERT_WEBHOOK_URL:
        return False, "webhook_not_configured"
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


def _send_email_alert(app_id: str, payload: dict) -> tuple[bool, str]:
    recipients = EMAIL_ALERT_TO or get_alert_recipient_emails(app_id)
    if not recipients:
        return False, "email_not_configured:missing_recipient"
    if not EMAIL_ALERT_FROM or not SMTP_HOST:
        return False, "email_not_configured:missing_smtp"

    msg = EmailMessage()
    msg["From"] = EMAIL_ALERT_FROM
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = (
        f"[Sentry Risk Alert] {payload.get('service', 'service')} "
        f"{payload.get('level', 'risk')} risk"
    )

    reasons = payload.get("reasons", [])
    recommendations = payload.get("recommendations", [])
    lines = [
        "Service failure risk alert",
        "",
        f"App ID:      {payload.get('app_id')}",
        f"Service:     {payload.get('service')}",
        f"Risk score:  {payload.get('score')}",
        f"Risk level:  {payload.get('level')}",
        f"Confidence:  {payload.get('confidence')}",
        f"Trend:       {payload.get('trend')}",
        f"ETA (min):   {payload.get('eta_minutes')}",
        "",
        "Reasons:",
        *([f"  - {r}" for r in reasons] if reasons else ["  - N/A"]),
        "",
        "Recommendations:",
        *([f"  - {r}" for r in recommendations] if recommendations else ["  - N/A"]),
    ]
    msg.set_content("\n".join(lines))

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


def _trigger_risk_notifications(app_id: str, dashboard: dict) -> list[dict]:
    """Emit alert events for at-risk services, with in-memory cooldown."""
    at_risk_services = dashboard.get("at_risk_services", [])
    if not at_risk_services:
        return []

    now_epoch = datetime.now(timezone.utc).timestamp()
    triggered = []

    for service in at_risk_services:
        app_state = NOTIFICATION_COOLDOWN_STATE.setdefault(app_id, {})
        last_sent_ts = float(app_state.get(service, {}).get("last_sent_ts", 0))
        if (now_epoch - last_sent_ts) < NOTIFICATION_COOLDOWN_SECONDS:
            continue

        score = dashboard.get("service_risk_scores", {}).get(service, 0)
        level = dashboard.get("service_risk_levels", {}).get(service, "low")
        confidence = dashboard.get("service_risk_confidence", {}).get(service, 0)
        trend = dashboard.get("service_risk_trend", {}).get(service, "stable")
        eta_minutes = dashboard.get("service_failure_eta_minutes", {}).get(service)

        payload = {
            "event": "service_failure_risk",
            "timestamp": _utc_now_iso(),
            "app_id": app_id,
            "service": service,
            "score": score,
            "level": level,
            "confidence": confidence,
            "trend": trend,
            "eta_minutes": eta_minutes,
            "message": f"Service '{service}' is likely to fail soon.",
            "reasons": dashboard.get("service_risk_reasons", {}).get(service, []),
            "recommendations": dashboard.get("service_recommendations", {}).get(service, []),
        }

        webhook_sent, webhook_status = _post_webhook(payload)
        email_sent, email_status = _send_email_alert(app_id, payload)

        payload["delivery"] = {
            "webhook": {"sent": webhook_sent, "status": webhook_status},
            "email": {"sent": email_sent, "status": email_status},
        }

        triggered.append(payload)
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
    """Send a message. History is loaded from / saved to DB — no client-side state needed."""
    if not verify_app_ownership(app_id, user_id):
        raise HTTPException(status_code=404, detail="App not found")
    if not GEMINI_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Chat is not configured — add GEMINI_API_KEY to your backend environment.",
        )

    # Load persisted history from DB
    stored = get_app_chat(app_id)

    logs = get_logs_paginated(app_id, limit=300, offset=0)
    context = _build_log_context(logs)

    system_prompt = (
        "You are an expert log analysis assistant embedded in a production monitoring platform.\n"
        "Always format your responses in Markdown:\n"
        "- Use **bold** for service names, timestamps, and key terms.\n"
        "- Use `inline code` for log levels and error messages.\n"
        "- Use ## for section headers (Root Cause, Symptoms, Recommendations).\n"
        "- Use bullet lists for multiple points.\n"
        "- Keep responses focused and actionable — developers are in the middle of incidents.\n\n"
        f"RECENT LOGS ({len(logs)} entries, grouped by service):\n"
        f"{context}\n\n"
        "When answering:\n"
        "1. Cite specific log lines with their timestamps.\n"
        "2. Identify cascading failures — which service triggered what.\n"
        "3. Give the root cause, not just symptoms.\n"
        "4. Suggest concrete fixes (code-level where possible).\n"
        "5. If logs are insufficient, say so and suggest what to add."
    )

    # Build Gemini history from stored messages (role: user → user, assistant → model)
    gemini_history = []
    for msg in stored:
        role = "model" if msg.get("role") == "assistant" else "user"
        gemini_history.append({"role": role, "parts": [{"text": msg.get("content", "")}]})

    try:
        from google import genai
        from google.genai import types as genai_types
        client = genai.Client(api_key=GEMINI_API_KEY)
        chat = client.chats.create(
            model=GEMINI_CHAT_MODEL,
            config=genai_types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2,
                max_output_tokens=1500,
            ),
            history=gemini_history,
        )
        response = chat.send_message(request.message)
        answer = response.text
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Chat failed: {exc!r}")

    # Persist updated history
    now = _utc_now_iso()
    updated = stored + [
        {"role": "user", "content": request.message, "ts": now},
        {"role": "assistant", "content": answer, "ts": now},
    ]
    # Cap at 100 messages (50 exchanges) to avoid unbounded growth
    if len(updated) > 100:
        updated = updated[-100:]
    save_app_chat(app_id, updated)

    return {"answer": answer, "logs_analyzed": len(logs)}
