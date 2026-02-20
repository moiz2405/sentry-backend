import os
import re
import json
import random
from datetime import datetime, timezone
from collections import defaultdict, Counter
from typing import List

# =====================================================================
# Regex patterns & keyword sets
# =====================================================================
SERVICE_REGEX = re.compile(r"\[(.*?)\]")
RISK_HISTORY_FILE = "risk_history.json"

ERROR_TYPE_KEYWORDS = {
    "Database Error": ["database", "sql", "connection failed", "SQLException"],
    "Network Error": ["timeout", "connection refused", "unavailable", "503", "502"],
    "Payment Error": ["chargeback", "suspended", "payment", "merchant"],
    "Business Logic Error": ["conflict", "optimistic locking"],
    "Communication Error": ["smtp", "mail", "messaging"],
    "Unknown": []
}

ERROR_TYPE_RECOMMENDATIONS = {
    "Database Error": "Check DB connectivity, connection pool saturation, and slow queries.",
    "Network Error": "Inspect upstream latency, retry backoff, and circuit-breaker behavior.",
    "Payment Error": "Validate payment provider status and failed transaction reasons.",
    "Business Logic Error": "Review recent deployments and conflicting state transitions.",
    "Communication Error": "Verify SMTP/queue provider credentials and delivery latency.",
    "Unknown": "Capture structured error metadata and add a rule for this pattern.",
    "None": "No immediate remediation needed."
}

# =====================================================================
# Utility Functions
# =====================================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_risk_history(output_dir: str) -> dict:
    history_path = os.path.join(output_dir, RISK_HISTORY_FILE)
    if not os.path.exists(history_path):
        return {}
    try:
        with open(history_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def save_risk_history(output_dir: str, history: dict) -> None:
    history_path = os.path.join(output_dir, RISK_HISTORY_FILE)
    with open(history_path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


def append_risk_history(history: dict, service: str, score: float) -> list:
    records = history.get(service, [])
    records.append({"timestamp": utc_now_iso(), "score": score})
    history[service] = records[-120:]
    return history[service]


def extract_service(line: str, known_services: List[str]) -> str:
    """Extracts the second bracketed value as the service name, if available."""
    matches = SERVICE_REGEX.findall(line)
    if len(matches) >= 2:
        return matches[1]
    if known_services:
        return random.choice(known_services)
    return random.choice([
        "auth-service", "api-gateway", "user-service",
        "payment-service", "notification-service", "inventory-service"
    ])


def extract_severity(line: str) -> str:
    """Classify log severity using contextual keyword detection."""
    line_lower = line.lower()

    if any(word in line_lower for word in ["success", "connected successfully", "completed", "started", "running"]):
        return "Low"

    if any(word in line_lower for word in [
        "fatal", "critical", "emergency", "crash", "panic",
        "exception", "error 5", "failed", "503", "500", "unavailable"
    ]):
        return "High"

    if any(word in line_lower for word in ["warn", "retry", "timeout", "delay", "degraded", "slow"]):
        return "Medium"

    if any(word in line_lower for word in ["info", "debug", "connected", "success", "started", "completed"]):
        return "Low"

    return "Low"


def extract_error_type(line: str) -> str:
    """Detects the general error type based on known keywords."""
    line_lower = line.lower()

    if any(word in line_lower for word in ["success", "completed", "connected", "running"]):
        return "None"

    for etype, keywords in ERROR_TYPE_KEYWORDS.items():
        if etype == "Unknown":
            continue
        if any(k in line_lower for k in keywords):
            return etype
    return "Unknown"


def count_errors_per_n_logs(entries, n=10):
    """Compute weighted error count over rolling batches."""
    severity_weights = {"High": 1.0, "Medium": 0.3, "Low": 0.0}
    batches = [entries[i:i+n] for i in range(0, len(entries), n)]
    return [sum(severity_weights.get(e["severity_level"], 0) for e in batch) for batch in batches]


def avg_errors_per_full_batches(errors_per_n, total_logs, n=10):
    """Compute average errors across full batches."""
    full_batches = total_logs // n
    if full_batches == 0:
        return 0
    return sum(errors_per_n[:full_batches]) / full_batches


def determine_service_health(entries):
    """Evaluates health based on severity ratios."""
    severity_counts = Counter(e["severity_level"] for e in entries)
    total_logs = len(entries)
    if total_logs == 0:
        return "healthy"

    high_ratio = severity_counts["High"] / total_logs
    medium_ratio = severity_counts["Medium"] / total_logs

    if high_ratio > 0.05:
        return "unhealthy"
    if medium_ratio > 0.1:
        return "warning"
    return "healthy"


def calculate_service_risk(entries):
    """Return a risk summary for service failure prediction."""
    total_logs = len(entries)
    if total_logs == 0:
        return {
            "score": 0.0,
            "level": "low",
            "likely_to_fail": False,
            "reasons": ["No logs received for this service yet."],
            "recommendations": []
        }

    severity_counts = Counter(e["severity_level"] for e in entries)
    high_count = severity_counts["High"]
    medium_count = severity_counts["Medium"]
    low_count = severity_counts["Low"]

    recent_window = entries[-20:] if len(entries) > 20 else entries
    recent_high = sum(1 for e in recent_window if e["severity_level"] == "High")
    recent_medium = sum(1 for e in recent_window if e["severity_level"] == "Medium")
    recent_high_ratio = recent_high / len(recent_window)

    incident_keywords = (
        "fatal", "panic", "crash", "outofmemory", "oom", "connection refused",
        "timeout", "503", "500", "unavailable", "failed", "exception"
    )
    incident_hits = 0
    for entry in recent_window:
        line = entry.get("line", "").lower()
        if any(keyword in line for keyword in incident_keywords):
            incident_hits += 1

    weighted_intensity = ((high_count * 1.0) + (medium_count * 0.5)) / total_logs
    recency_intensity = ((recent_high * 1.0) + (recent_medium * 0.4)) / len(recent_window)
    incident_ratio = incident_hits / len(recent_window)

    score = (
        (weighted_intensity * 55.0)
        + (recency_intensity * 30.0)
        + (incident_ratio * 15.0)
    )
    score = round(min(100.0, max(0.0, score)), 2)

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    reasons = []
    if high_count > 0:
        reasons.append(f"{high_count} high-severity logs detected.")
    if recent_high_ratio >= 0.25:
        reasons.append("High-severity log ratio is elevated in recent traffic.")
    if incident_hits >= 3:
        reasons.append("Repeated crash/timeout-style incident patterns observed.")
    if not reasons:
        reasons.append("No strong failure indicators currently detected.")

    error_type_counts = Counter(e["error_type"] for e in entries if e["error_type"] != "None")
    recommendations = []
    for error_type, _ in error_type_counts.most_common(3):
        recommendation = ERROR_TYPE_RECOMMENDATIONS.get(error_type)
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
    if not recommendations and low_count > 0:
        recommendations.append("Continue monitoring; current log pattern is stable.")

    return {
        "score": score,
        "level": level,
        "likely_to_fail": score >= 70.0,
        "reasons": reasons,
        "recommendations": recommendations
    }


def compute_failure_forecast(history_records: list, current_score: float, risk_level: str) -> dict:
    """Estimate near-term failure likelihood based on score trend + confidence."""
    scores = [float(item.get("score", 0.0)) for item in history_records if isinstance(item, dict)]

    if not scores:
        return {
            "trend": "insufficient_data",
            "confidence": 0.0,
            "likely_to_fail": current_score >= 70.0,
            "eta_minutes": 120 if current_score >= 70.0 else None,
        }

    recent = scores[-3:]
    previous = scores[-6:-3] if len(scores) >= 6 else scores[:-len(recent)]

    if previous:
        previous_avg = sum(previous) / len(previous)
        recent_avg = sum(recent) / len(recent)
        delta = recent_avg - previous_avg
    else:
        delta = recent[-1] - recent[0] if len(recent) >= 2 else 0.0

    if delta > 7.0:
        trend = "increasing"
    elif delta < -7.0:
        trend = "decreasing"
    else:
        trend = "stable"

    data_factor = min(1.0, len(scores) / 12.0)
    magnitude_factor = min(1.0, abs(delta) / 25.0)
    signal_factor = min(1.0, current_score / 100.0)

    confidence = 0.35 + (0.35 * data_factor) + (0.20 * magnitude_factor) + (0.10 * signal_factor)
    confidence = round(min(0.99, max(0.0, confidence)), 2)

    likely_to_fail = (
        current_score >= 80.0
        or (current_score >= 70.0 and trend != "decreasing")
        or (current_score >= 65.0 and trend == "increasing")
    )

    eta_minutes = None
    if likely_to_fail:
        if current_score >= 90.0 or risk_level == "critical":
            eta_minutes = 15
        elif current_score >= 80.0:
            eta_minutes = 30
        elif trend == "increasing":
            eta_minutes = 60
        else:
            eta_minutes = 120

    return {
        "trend": trend,
        "confidence": confidence,
        "likely_to_fail": likely_to_fail,
        "eta_minutes": eta_minutes,
    }


# =====================================================================
# Core Function: Stream Processing
# =====================================================================

def process_and_summarize_stream(log_iterable, output_dir: str):
    """
    Processes logs from a stream and generates summaries + dashboard.
    """
    os.makedirs(output_dir, exist_ok=True)

    processed = {}
    grouped = defaultdict(list)
    summaries = {}
    error_timeline = defaultdict(list)
    risk_history = load_risk_history(output_dir)

    lines = [line.strip() for line in log_iterable if line.strip()]
    known_services = list({SERVICE_REGEX.search(line).group(1)
                           for line in lines if SERVICE_REGEX.search(line)})

    for idx, line in enumerate(lines, 1):
        service = extract_service(line, known_services)
        severity = extract_severity(line)
        error_type = extract_error_type(line)

        timestamp_match = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:,\d+)?", line)
        timestamp = timestamp_match.group(0) if timestamp_match else "UNKNOWN"

        entry = {
            "timestamp": timestamp,
            "service": service,
            "error_type": error_type,
            "severity_level": severity,
            "line": line,
            "line_number": idx
        }

        processed[str(idx)] = entry
        grouped[service].append(entry)
        error_timeline[service].append({
            "timestamp": timestamp,
            "error_type": error_type,
            "severity": severity,
            "line": line
        })

    errors_per_10 = count_errors_per_n_logs(list(processed.values()), 10)
    avg_errors = avg_errors_per_full_batches(errors_per_10, len(processed), 10)

    dashboard = {
        "services": list(grouped.keys()),
        "total_services": len(grouped),
        "service_health": {},
        "severity_distribution": {},
        "most_common_errors": {},
        "recent_errors": {},
        "first_error_timestamp": {},
        "latest_error_timestamp": {},
        "error_types": {},
        "errors_per_10_logs": errors_per_10,
        "avg_errors_per_10_logs": avg_errors,
        "service_risk_scores": {},
        "service_risk_levels": {},
        "service_risk_confidence": {},
        "service_risk_trend": {},
        "service_failure_eta_minutes": {},
        "service_failure_prediction": {},
        "service_failure_forecast": {},
        "service_risk_reasons": {},
        "service_recommendations": {},
        "at_risk_services": []
    }

    for service, entries in grouped.items():
        severity_counts = Counter(e["severity_level"] for e in entries)
        error_type_counts = Counter(e["error_type"] for e in entries)

        health = determine_service_health(entries)

        dashboard["service_health"][service] = health
        dashboard["severity_distribution"][service] = dict(severity_counts)
        dashboard["most_common_errors"][service] = (
            error_type_counts.most_common(1)[0][0] if error_type_counts else "Other"
        )
        dashboard["recent_errors"][service] = entries[-5:]

        timestamps = [e["timestamp"] for e in entries if e["timestamp"] != "UNKNOWN"]
        dashboard["first_error_timestamp"][service] = min(timestamps) if timestamps else "UNKNOWN"
        dashboard["latest_error_timestamp"][service] = max(timestamps) if timestamps else "UNKNOWN"
        dashboard["error_types"][service] = list({e["error_type"] for e in entries})

        risk = calculate_service_risk(entries)
        service_history = append_risk_history(risk_history, service, risk["score"])
        forecast = compute_failure_forecast(service_history, risk["score"], risk["level"])

        if forecast["trend"] == "increasing":
            risk["reasons"].append("Risk trend is increasing across recent windows.")
            risk["recommendations"].append("Scale this service or reduce load before saturation.")

        dashboard["service_risk_scores"][service] = risk["score"]
        dashboard["service_risk_levels"][service] = risk["level"]
        dashboard["service_risk_confidence"][service] = forecast["confidence"]
        dashboard["service_risk_trend"][service] = forecast["trend"]
        dashboard["service_failure_eta_minutes"][service] = forecast["eta_minutes"]
        dashboard["service_failure_prediction"][service] = forecast["likely_to_fail"]
        dashboard["service_failure_forecast"][service] = forecast
        dashboard["service_risk_reasons"][service] = risk["reasons"]
        dashboard["service_recommendations"][service] = risk["recommendations"]

        if forecast["likely_to_fail"]:
            dashboard["at_risk_services"].append(service)

    save_risk_history(output_dir, risk_history)

    with open(os.path.join(output_dir, "processed_logs.json"), "w", encoding="utf-8") as f:
        json.dump(processed, f, indent=2)
    with open(os.path.join(output_dir, "grouped_logs.json"), "w", encoding="utf-8") as f:
        json.dump({"grouped": grouped, "summaries": summaries}, f, indent=2)
    with open(os.path.join(output_dir, "dashboard_summary.json"), "w", encoding="utf-8") as f:
        json.dump(dashboard, f, indent=2)

    return dashboard


# =====================================================================
# CLI Entry Point
# =====================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m app.models.smart_log_processor <outputdir>")
        sys.exit(1)
    outputdir = sys.argv[1]
    process_and_summarize_stream(sys.stdin, outputdir)
