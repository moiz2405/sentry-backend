import os
from app.models.logsPreprocessor import process_logs
from app.models.logsClassifier_rule_based import classify_logs_rule_based
from app.models.groupLogs import group_logs
from app.dashboard_summary import dashboard_summary

def process_log_file(logfilename: str, logs_dir: str = "app/logs", output_base: str = "app/outputs"):
    """
    Processes a log file and stores outputs in /outputs/{logfilename}/
    Args:
        logfilename: Name of the log file (e.g., 'dockerLogs.log')
        logs_dir: Directory containing log files
        output_base: Base output directory
    """
    input_path = os.path.join(logs_dir, logfilename)
    output_dir = os.path.join(output_base, logfilename)
    os.makedirs(output_dir, exist_ok=True)
    pre_output = os.path.join(output_dir, "processed_logs.json")
    classified_output = os.path.join(output_dir, "classified_logs.json")
    grouped_output = os.path.join(output_dir, "grouped_logs.json")

    # Step 1: Preprocess logs
    process_logs(input_path, pre_output)
    # Step 2: Classify logs (rule-based)
    classify_logs_rule_based(pre_output, classified_output)
    # Step 3: Group logs
    group_logs(classified_output, grouped_output)
    print(f"✅ Outputs for {logfilename} stored in {output_dir}")

    # Step 4: Dashboard summary
    summary = dashboard_summary(logfilename, output_base)
    dashboard_path = os.path.join(output_dir, "dashboard_summary.json")
    with open(dashboard_path, "w") as f:
        import json
        json.dump(summary, f, indent=2)
    print(f"\n--- Dashboard Summary saved to {dashboard_path} ---")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m app.models.log_processing_service <logfilename>")
        sys.exit(1)
    logfilename = sys.argv[1]
    process_log_file(logfilename)