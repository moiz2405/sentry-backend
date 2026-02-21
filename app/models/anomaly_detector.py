"""
Statistical anomaly detection on log streams.

Four detectors, all pure-Python (no ML deps):
  1. error_spike         — error rate in last 15 min vs baseline
  2. volume_surge        — log count surge via 5-min bucket comparison
  3. new_error_pattern   — error fingerprint not seen in prior 24 h
  4. cascade_failure     — multiple services start erroring within 2 min of each other
"""

import re
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Optional


# ── Helpers ──────────────────────────────────────────────────────────────────

_UUID_RE  = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_IP_RE    = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_NUM_RE   = re.compile(r"\b\d{4,}\b")
_PATH_RE  = re.compile(r"(?<![a-z])/[^\s,;\"']+")

_ERROR_LEVELS = {"ERROR", "CRITICAL"}


def _normalize(msg: str) -> str:
    msg = _UUID_RE.sub("<id>", msg)
    msg = _IP_RE.sub("<ip>", msg)
    msg = _NUM_RE.sub("<n>", msg)
    msg = _PATH_RE.sub("<path>", msg)
    return msg.lower().strip()


def _fingerprint(msg: str) -> str:
    return hashlib.md5(_normalize(msg).encode()).hexdigest()[:10]


def _parse_ts(value: str, fallback: datetime) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return fallback


def _services(logs: list) -> List[str]:
    seen, out = set(), []
    for l in logs:
        s = l.get("service") or "unknown"
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# ── Public API ────────────────────────────────────────────────────────────────

def detect_anomalies(logs: List[dict], now: Optional[datetime] = None) -> List[dict]:
    """
    Run all detectors against a list of log dicts.

    Each log must have: level (str), message (str), service (str|None),
                        logged_at (ISO timestamp str).

    Returns a list of anomaly dicts ready for DB insertion
    (excluding app_id / detected_at which are added by the caller).
    """
    if not logs:
        return []

    if now is None:
        now = datetime.now(timezone.utc)

    # Stamp each log with a parsed datetime
    for log in logs:
        log["_ts"] = _parse_ts(log.get("logged_at", ""), now)

    t_15m = now - timedelta(minutes=15)
    t_1h  = now - timedelta(hours=1)

    recent     = [l for l in logs if l["_ts"] >= t_15m]
    last_hour  = [l for l in logs if l["_ts"] >= t_1h]
    historical = [l for l in logs if l["_ts"] < t_15m]

    results: List[dict] = []
    results += _error_spike(recent, historical)
    results += _volume_surge(last_hour, now)
    results += _new_error_pattern(recent, historical)
    results += _cascade_failure(recent)
    return results


# ── Detector 1: Error rate spike ──────────────────────────────────────────────

def _error_spike(recent: list, historical: list) -> list:
    if not recent:
        return []

    recent_errors = [l for l in recent if l.get("level", "").upper() in _ERROR_LEVELS]
    recent_rate   = len(recent_errors) / len(recent)

    if historical:
        hist_errors   = [l for l in historical if l.get("level", "").upper() in _ERROR_LEVELS]
        baseline_rate = len(hist_errors) / len(historical)
    else:
        baseline_rate = 0.0

    # Must be 2× baseline (or 15% floor) AND at least 3 errors
    threshold = max(baseline_rate * 2.0, 0.15)
    if recent_rate < threshold or len(recent_errors) < 3:
        return []

    services = _services(recent_errors)
    severity = "critical" if recent_rate > 0.5 else "high"
    return [{
        "type":              "error_spike",
        "severity":          severity,
        "title":             f"Error rate spike: {recent_rate:.0%} in last 15 min",
        "summary":           (
            f"Error rate jumped to **{recent_rate:.0%}** (baseline {baseline_rate:.0%}). "
            f"{len(recent_errors)} errors across {len(services)} service(s): "
            f"{', '.join(services[:4])}."
        ),
        "services_affected": services,
        "evidence": {
            "recent_error_rate":  round(recent_rate, 4),
            "baseline_error_rate": round(baseline_rate, 4),
            "recent_error_count": len(recent_errors),
            "sample_errors":      [l.get("message", "")[:200] for l in recent_errors[:3]],
        },
    }]


# ── Detector 2: Volume surge ──────────────────────────────────────────────────

def _volume_surge(logs_1h: list, now: datetime) -> list:
    if len(logs_1h) < 10:
        return []

    # 12 × 5-min buckets; bucket[0] = most recent 5 min
    buckets = [0] * 12
    for log in logs_1h:
        age_min = (now - log["_ts"]).total_seconds() / 60.0
        idx = min(int(age_min / 5), 11)
        buckets[idx] += 1

    latest = buckets[0]
    older_nonzero = [b for b in buckets[1:] if b > 0]

    if not older_nonzero or latest < 5:
        return []

    mean  = sum(older_nonzero) / len(older_nonzero)
    ratio = latest / mean if mean else 0.0

    if ratio < 3.0:
        return []

    # Services active in the surge window
    surge_logs = [l for l in logs_1h if (now - l["_ts"]).total_seconds() < 300]
    services   = _services(surge_logs)
    severity   = "high" if ratio >= 5.0 else "medium"

    return [{
        "type":              "volume_surge",
        "severity":          severity,
        "title":             f"Log volume surge: {ratio:.1f}× normal in last 5 min",
        "summary":           (
            f"Log volume spiked to **{latest}** entries in the last 5 min "
            f"({ratio:.1f}× the normal ~{mean:.0f}/window). "
            f"Active services: {', '.join(services[:4])}."
        ),
        "services_affected": services,
        "evidence": {
            "recent_volume":  latest,
            "baseline_avg":   round(mean, 1),
            "surge_ratio":    round(ratio, 2),
            "bucket_counts":  buckets,
        },
    }]


# ── Detector 3: New error fingerprint ────────────────────────────────────────

def _new_error_pattern(recent: list, historical: list) -> list:
    recent_errors = [l for l in recent if l.get("level", "").upper() in _ERROR_LEVELS]
    if not recent_errors:
        return []

    hist_fps = {
        _fingerprint(l.get("message", ""))
        for l in historical
        if l.get("level", "").upper() in _ERROR_LEVELS
    }

    new, seen_fps = [], set()
    for log in recent_errors:
        fp = _fingerprint(log.get("message", ""))
        if fp not in hist_fps and fp not in seen_fps:
            seen_fps.add(fp)
            new.append(log)

    if not new:
        return []

    services = _services(new)
    return [{
        "type":              "new_error_pattern",
        "severity":          "high" if len(new) >= 2 else "medium",
        "title":             f"{len(new)} new error pattern{'s' if len(new) > 1 else ''} detected",
        "summary":           (
            f"Encountered **{len(new)}** previously unseen error pattern(s) in the last 15 min. "
            f"Services: {', '.join(services[:4])}."
        ),
        "services_affected": services,
        "evidence": {
            "new_pattern_count": len(new),
            "examples": [
                {"service": l.get("service"), "message": l.get("message", "")[:200]}
                for l in new[:4]
            ],
        },
    }]


# ── Detector 4: Cascade failure ───────────────────────────────────────────────

def _cascade_failure(recent: list) -> list:
    # First time each service appeared with an error in the recent window
    first_error: dict[str, datetime] = {}
    for log in sorted(recent, key=lambda l: l["_ts"]):
        if log.get("level", "").upper() in _ERROR_LEVELS:
            svc = log.get("service") or "unknown"
            if svc not in first_error:
                first_error[svc] = log["_ts"]

    if len(first_error) < 2:
        return []

    times = sorted(first_error.values())
    span  = (times[-1] - times[0]).total_seconds()

    if span > 120:   # must spread within 2 min
        return []

    ordered  = sorted(first_error.items(), key=lambda x: x[1])
    root_svc = ordered[0][0]
    services = [svc for svc, _ in ordered]

    return [{
        "type":              "cascade_failure",
        "severity":          "critical" if len(services) >= 3 else "high",
        "title":             f"Cascade failure across {len(services)} services",
        "summary":           (
            f"Errors propagated across **{len(services)} services** within {span:.0f}s. "
            f"Likely origin: **{root_svc}**. "
            f"Affected: {', '.join(services)}."
        ),
        "services_affected": services,
        "evidence": {
            "service_failure_order": {svc: ts.isoformat() for svc, ts in ordered},
            "total_span_seconds":    round(span, 1),
            "root_service":          root_svc,
        },
    }]
