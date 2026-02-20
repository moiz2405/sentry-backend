import json
from collections import defaultdict, Counter
from datetime import datetime

def group_logs(input_file="app/outputs/classified_logs.json",
               output_file="app/outputs/grouped_logs.json"):
    grouped = defaultdict(list)
    summaries = {}

    # read logs from JSON file
    with open(input_file, "r") as f:
        logs = json.load(f)

    # Group logs by service
    for log in logs:
        grouped[log["service"]].append(log)

    # Build summary + compacted logs for each service
    final_grouped = {}
    for service, entries in grouped.items():
        total_errors = len(entries)
        severity_counts = Counter(e["severity_level"] for e in entries)
        error_type_counts = Counter(e["error_type"] for e in entries)

        # most common error type
        most_common_error_type, _ = error_type_counts.most_common(1)[0]

        # extract timestamps and convert to datetime
        timestamps = [
            datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S,%f")
            for e in entries
        ]
        first_error = min(timestamps).strftime("%Y-%m-%d %H:%M:%S,%f")
        latest_error = max(timestamps).strftime("%Y-%m-%d %H:%M:%S,%f")

        # Deduplicate logs by error_type + error_sub_type + error_desc
        compacted = {}
        for e in entries:
            key = (e["error_type"], e["error_sub_type"], e["error_desc"], e["severity_level"])
            if key not in compacted:
                compacted[key] = {
                    "error_type": e["error_type"],
                    "error_sub_type": e["error_sub_type"],
                    "error_desc": e["error_desc"],
                    "severity_level": e["severity_level"],
                    "count": 0,
                    "timestamps": []
                }
            compacted[key]["count"] += 1
            compacted[key]["timestamps"].append(e["timestamp"])

        final_grouped[service] = list(compacted.values())

        summaries[service] = {
            "total_errors": total_errors,
            "severity_distribution": dict(severity_counts),
            "most_common_error_type": most_common_error_type,
            "first_error_timestamp": first_error,
            "latest_error_timestamp": latest_error,
        }

    # final structured output
    output = {
        "grouped": final_grouped,
        "summaries": summaries
    }

    # save result to output file
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"✅ Grouped logs written to {output_file}")

    return output
