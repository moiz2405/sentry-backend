import re
import json
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Common anomaly patterns
ANOMALY_KEYWORDS = [
    "exception", "failed", "error", "refused", "timeout", "unavailable", "denied",
    "panic", "stacktrace", "crash", "fatal", "killed"
]

def is_anomalous(log_line: str) -> bool:
    log_level_match = re.search(r"\b(INFO|DEBUG|TRACE)\b", log_line, re.IGNORECASE)
    if log_level_match:
        return False  # Skip non-error logs
    for keyword in ANOMALY_KEYWORDS:
        if keyword in log_line.lower():
            return True
    return False

def extract_timestamp(log_line: str) -> str:
    """Extract timestamp from log line using regex pattern."""
    timestamp_match = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:,\d+)?", log_line)
    return timestamp_match.group(0) if timestamp_match else "UNKNOWN"

def extract_compact_error(log_line: str) -> str:
    # Try to extract the service and a summary
    match = re.search(r"\[(.*?)\].*?(Exception|Failed|Error|Refused|Timeout|Killed|Unavailable|Crash|Panic)", log_line, re.IGNORECASE)
    if match:
        service = match.group(1)
        issue = re.search(r"(Exception.*|Failed.*|Error.*|Refused.*|Timeout.*|Killed.*|Unavailable.*|Crash.*|Panic.*)", log_line, re.IGNORECASE)
        if issue:
            return f"{issue.group(0).strip()} in {service}"
    return f"Anomaly detected: {log_line.replace('\t', ' ').strip()}"

def extract_anomaly_metadata(log_line: str, line_number: int, source_file: str = None) -> dict:
    """Extract comprehensive metadata for an anomalous log line."""
    # Normalize source_file to just the filename if it's a full path
    normalized_source_file = os.path.basename(source_file) if source_file else None
    
    return {
        "timestamp": extract_timestamp(log_line),
        "compact_error": extract_compact_error(log_line),
        "line": log_line.strip(),
        "line_number": line_number,
        "source_file": normalized_source_file
    }

def process_logs(input_path: str, output_path: str, source_file: str = None) -> dict:
    """
    Processes logs from input_path, extracts anomalies without duplicates,
    and writes them to output_path. Also returns the extracted anomalies as a dictionary.
    Now includes enhanced metadata with timestamps, line numbers, and source file info.
    """
    result = {}
    seen_compact_errors = set()
    count = 1
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Use source_file parameter or extract from input_path
    if source_file is None:
        source_file = input_path

    with open(input_path, "r") as infile:
        for line_number, line in enumerate(infile, 1):
            if is_anomalous(line):
                metadata = extract_anomaly_metadata(line, line_number, source_file)
                compact_error = metadata["compact_error"]
                
                # Check for duplicates based on compact_error
                if compact_error not in seen_compact_errors:
                    seen_compact_errors.add(compact_error)
                    result[str(count)] = metadata
                    count += 1

    with open(output_path, "w") as outfile:
        json.dump(result, outfile, indent=2)

    logging.info(f"Extracted {count - 1} unique anomalies to {output_path}")
    return result

if __name__ == "__main__":
    input_file = "app/logs/exLogs.log"
    output_file = "app/outputs/compact_anomalies.json"
    process_logs(input_file, output_file)
