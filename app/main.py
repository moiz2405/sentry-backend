from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
import ssl
import smtplib
import urllib.request
import urllib.parse
from email.message import EmailMessage
from datetime import datetime, timezone
from typing import List, Optional

from app.models.smart_log_processor import process_and_summarize_stream
from app.core.api_key import (
    complete_device_session,
    generate_api_key,
    get_alert_recipient_emails,
    get_device_session,
    mark_device_session_expired,
    resolve_api_key_to_app_id,
    start_device_session,
    validate_sdk_schema,
    _get_supabase,
)

app = FastAPI(title="Smart Log Processor API")

# CORS — allow frontend origins
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:3000,https://sentrylabs.live",
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

RISK_ALERT_WEBHOOK_URL = os.environ.get("RISK_ALERT_WEBHOOK_URL", "").strip()
NOTIFICATION_COOLDOWN_SECONDS = int(os.environ.get("NOTIFICATION_COOLDOWN_SECONDS", "300"))
NOTIFICATION_STATE_FILE = "notification_state.json"
NOTIFICATION_EVENTS_FILE = "notification_events.json"

EMAIL_ALERT_FROM = os.environ.get("EMAIL_ALERT_FROM", "").strip()
EMAIL_ALERT_TO = [addr.strip() for addr in os.environ.get("EMAIL_ALERT_TO", "").split(",") if addr.strip()]
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
SDK_VERIFICATION_BASE_URL = os.environ.get(
    "SDK_VERIFICATION_BASE_URL", "http://localhost:3000"
).rstrip("/")
SDK_DEFAULT_DSN = os.environ.get("SDK_DEFAULT_DSN", "http://localhost:9000").rstrip("/")
SDK_SCHEMA_STRICT_STARTUP = os.environ.get("SDK_SCHEMA_STRICT_STARTUP", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}


# =========================================
# Schemas
# =========================================

class IngestRequest(BaseModel):
    logs: List[str]


class CreateAppRequest(BaseModel):
    user_id: str
    name: str
    description: Optional[str] = None


class DeviceStartRequest(BaseModel):
    app_name: str
    description: Optional[str] = None
    ttl_seconds: int = 600


class DeviceCompleteRequest(BaseModel):
    device_code: str
    user_id: str
    app_name: Optional[str] = None


# =========================================
# Health
# =========================================

@app.get("/health")
async def health_check():
    return {"status": "ok"}


# =========================================
# App CRUD
# =========================================

@app.get("/apps")
async def list_apps(user_id: str = Query(...)):
    """List all apps for a user."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        result = (
            client.table("apps")
            .select("id,user_id,name,description,api_key,created_at")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
        )
        return result.data or []
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/apps/{app_id}")
async def get_app(app_id: str):
    """Get a single app by ID."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        result = (
            client.table("apps")
            .select("id,user_id,name,description,api_key,created_at")
            .eq("id", app_id)
            .single()
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=404, detail="App not found")
        return result.data
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=404, detail="App not found")


@app.post("/apps")
async def create_app(request: CreateAppRequest):
    """Create a new app with an auto-generated API key."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    if not request.name.strip():
        raise HTTPException(status_code=400, detail="name is required")

    api_key = generate_api_key()
    payload = {
        "user_id": request.user_id,
        "name": request.name.strip(),
        "description": (request.description or "").strip() or None,
        "api_key": api_key,
    }
    try:
        result = (
            client.table("apps")
            .insert(payload)
            .select("id,user_id,name,description,api_key,created_at")
            .single()
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=500, detail="Failed to create app")
        return result.data
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/apps/{app_id}")
async def delete_app(app_id: str):
    """Delete an app by ID."""
    client = _get_supabase()
    if not client:
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        result = (
            client.table("apps")
            .delete()
            .eq("id", app_id)
            .execute()
        )
        return {"status": "deleted", "app_id": app_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.on_event("startup")
async def validate_schema_on_startup() -> None:
    """
    Validate DB schema at startup.
    In strict mode, fail startup if schema is not ready.
    """
    report = validate_sdk_schema()
    if report.get("ok"):
        print("[startup] SDK schema validation passed.")
        return

    print("[startup] SDK schema validation failed.")
    for note in report.get("guidance", []):
        print(f"[startup] - {note}")

    if SDK_SCHEMA_STRICT_STARTUP:
        raise RuntimeError(
            "SDK schema validation failed and SDK_SCHEMA_STRICT_STARTUP=true. "
            "Fix schema issues before starting the backend."
        )


# =========================================
# Helpers
# =========================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, payload) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def post_webhook(payload: dict) -> tuple[bool, str]:
    if not RISK_ALERT_WEBHOOK_URL:
        return False, "webhook_not_configured"
    try:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            RISK_ALERT_WEBHOOK_URL,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5):
            pass
        return True, "sent"
    except Exception as exc:
        return False, f"failed:{type(exc).__name__}"


def resolve_email_recipients(app_id: str) -> list[str]:
    if EMAIL_ALERT_TO:
        return EMAIL_ALERT_TO
    return get_alert_recipient_emails(app_id)


def send_email_alert(app_id: str, payload: dict) -> tuple[bool, str]:
    recipients = resolve_email_recipients(app_id)
    if not recipients:
        return False, "email_not_configured:missing_recipient"
    if not EMAIL_ALERT_FROM:
        return False, "email_not_configured:missing_sender"
    if not SMTP_HOST:
        return False, "email_not_configured:missing_smtp_host"

    message = EmailMessage()
    message["From"] = EMAIL_ALERT_FROM
    message["To"] = ", ".join(recipients)
    message["Subject"] = (
        f"[Sentry Risk Alert] {payload.get('service', 'service')} "
        f"{payload.get('level', 'risk')} risk"
    )

    reasons = payload.get("reasons", [])
    recommendations = payload.get("recommendations", [])

    lines = [
        "Service failure risk alert",
        "",
        f"App ID: {payload.get('app_id')}",
        f"Service: {payload.get('service')}",
        f"Risk score: {payload.get('score')}",
        f"Risk level: {payload.get('level')}",
        f"Confidence: {payload.get('confidence')}",
        f"Trend: {payload.get('trend')}",
        f"ETA (minutes): {payload.get('eta_minutes')}",
        f"Message: {payload.get('message')}",
        "",
        "Reasons:",
    ]

    if reasons:
        lines.extend([f"- {reason}" for reason in reasons])
    else:
        lines.append("- N/A")

    lines.append("")
    lines.append("Recommended actions:")
    if recommendations:
        lines.extend([f"- {recommendation}" for recommendation in recommendations])
    else:
        lines.append("- N/A")

    message.set_content("\n".join(lines))

    try:
        if SMTP_USE_TLS:
            context = ssl.create_default_context()
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls(context=context)
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(message)
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(message)
        return True, "sent"
    except Exception as exc:
        return False, f"failed:{type(exc).__name__}"


def trigger_risk_notifications(app_id: str, outputs_dir: str, dashboard: dict) -> list[dict]:
    """Emit alert events when a service is predicted to fail, with cooldown dedupe."""
    at_risk_services = dashboard.get("at_risk_services", [])
    if not at_risk_services:
        return []

    state_path = os.path.join(outputs_dir, NOTIFICATION_STATE_FILE)
    events_path = os.path.join(outputs_dir, NOTIFICATION_EVENTS_FILE)

    state = load_json(state_path, {})
    events = load_json(events_path, [])

    now_epoch = datetime.now(timezone.utc).timestamp()
    triggered = []

    for service in at_risk_services:
        service_state = state.get(service, {})
        last_sent_ts = float(service_state.get("last_sent_ts", 0))
        if (now_epoch - last_sent_ts) < NOTIFICATION_COOLDOWN_SECONDS:
            continue

        score = dashboard.get("service_risk_scores", {}).get(service, 0)
        level = dashboard.get("service_risk_levels", {}).get(service, "low")
        confidence = dashboard.get("service_risk_confidence", {}).get(service, 0)
        trend = dashboard.get("service_risk_trend", {}).get(service, "stable")
        eta_minutes = dashboard.get("service_failure_eta_minutes", {}).get(service)

        payload = {
            "event": "service_failure_risk",
            "timestamp": utc_now_iso(),
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

        webhook_sent, webhook_status = post_webhook(payload)
        email_sent, email_status = send_email_alert(app_id, payload)

        payload["delivery"] = {
            "webhook": {"sent": webhook_sent, "status": webhook_status},
            "email": {"sent": email_sent, "status": email_status},
        }
        payload["delivery_sent"] = webhook_sent or email_sent

        triggered.append(payload)
        events.append(payload)
        state[service] = {
            "last_sent_ts": now_epoch,
            "last_score": score,
            "last_level": level,
        }

    if triggered:
        save_json(state_path, state)
        save_json(events_path, events[-500:])

    return triggered


def get_api_key(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    """Extract API key from Authorization Bearer or X-API-Key header."""
    if x_api_key:
        return x_api_key
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip()
    raise HTTPException(
        status_code=401,
        detail="Missing API key. Use Authorization: Bearer <key> or X-API-Key header.",
    )


# =========================================
# SDK Device Login + Provisioning
# =========================================
def build_sdk_verification_url(device_code: str, app_name: str, user_code: str) -> str:
    callback_target = f"/sdk/link?device_code={urllib.parse.quote(device_code)}&app_name={urllib.parse.quote(app_name)}"
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

    verification_uri_complete = build_sdk_verification_url(
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
    if datetime.now(timezone.utc) >= datetime.fromisoformat(expires_at.replace("Z", "+00:00")):
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

    result = complete_device_session(
        device_code=request.device_code.strip(),
        user_id=request.user_id.strip(),
        app_name_override=request.app_name,
    )
    if not result:
        raise HTTPException(status_code=400, detail="Unable to complete device session")
    return {"status": "approved", **result}


@app.get("/sdk/schema/validate")
async def sdk_schema_validate():
    """
    Validate required DB schema for SDK onboarding/alerts and report email-source mapping.
    """
    return validate_sdk_schema()


# =========================================
# Log Ingest (SDK push)
# =========================================
@app.post("/ingest")
async def ingest_logs(
    request: IngestRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Accept batched logs from SDK. Validates API key, resolves to app_id,
    processes logs, stores dashboard summary, and emits risk alerts.
    """
    app_id = resolve_api_key_to_app_id(api_key)
    if not app_id:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not request.logs:
        return {"status": "accepted", "app_id": app_id, "processed": 0}

    outputs_dir = os.path.join(os.path.dirname(__file__), "outputs", app_id)
    os.makedirs(outputs_dir, exist_ok=True)

    dashboard = process_and_summarize_stream(request.logs, outputs_dir)
    notifications = trigger_risk_notifications(app_id, outputs_dir, dashboard)

    return {
        "status": "accepted",
        "app_id": app_id,
        "processed": len(request.logs),
        "notifications_triggered": len(notifications),
        "dashboard_summary": dashboard,
    }


# =========================================
# Summary (for frontend polling)
# =========================================
@app.get("/summary/{app_id}")
async def get_summary(app_id: str):
    """Return latest dashboard summary for an app. Used by frontend polling."""
    summary_path = os.path.join(
        os.path.dirname(__file__), "outputs", app_id, "dashboard_summary.json"
    )
    if not os.path.exists(summary_path):
        return {"summary": None}
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            summary = json.load(f)
        return {"summary": summary}
    except Exception:
        return {"summary": None}


@app.get("/notifications/{app_id}")
async def get_notifications(app_id: str):
    """Return recent generated risk notifications for an app."""
    events_path = os.path.join(
        os.path.dirname(__file__), "outputs", app_id, NOTIFICATION_EVENTS_FILE
    )
    events = load_json(events_path, [])
    return {"notifications": events[-100:]}
