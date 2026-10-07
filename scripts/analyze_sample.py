"""CLI tool to analyze any log file using the SentinelGraph AI pipeline."""
import argparse
import sys
from pathlib import Path
from sentinelgraph.pipeline import SentinelPipeline
from sentinelgraph.reporting.exporters import ReportExporter


def main():
    parser = argparse.ArgumentParser(description="SentinelGraph AI Log Analysis CLI")
    parser.add_argument("file_path", help="Path to CSV or JSON log file")
    parser.add_argument("--extended-window", action="store_true", help="Enable multi-day extended correlation window")
    parser.add_argument("--export-html", help="Path to export self-contained HTML forensic report")
    parser.add_argument("--enable-ml", action="store_true", help="Enable supplementary ML anomaly scoring")

    args = parser.parse_args()
    file_path = Path(args.file_path)
    if not file_path.exists():
        print(f"Error: File '{args.file_path}' does not exist.")
        sys.exit(1)

    print(f"Analyzing {file_path.name}...")
    result = SentinelPipeline.analyze_file(
        file_path=file_path,
        use_extended_window=args.extended_window,
        enable_ml=args.enable_ml
    )

    print(f"\n--- Analysis Summary [{result.run_id}] ---")
    print(f"Total Valid Events:  {result.valid_event_count}")
    print(f"Invalid Rows:        {len(result.invalid_records)}")
    print(f"Signals Discovered:  {len(result.signals_detected)}")
    print(f"Incidents Detected:  {len(result.incidents)}")
    print(f"Execution Time:      {result.execution_time_seconds}s\n")

    for inc in result.incidents:
        print(f"[{inc.severity}] {inc.incident_id}: {inc.title}")
        print(f"  Risk: {inc.risk_score}/100 | Confidence: {int(inc.confidence * 100)}%")
        print(f"  Attack Type: {inc.attack_type}")
        print(f"  Actors: {', '.join(inc.affected_users)} on {', '.join(inc.affected_devices)}")
        confirmed = [s.stage_name for s in inc.attack_stages if s.status == "confirmed"]
        print(f"  Confirmed Stages: {', '.join(confirmed)}")
        print(f"  Story: {inc.attack_story.what_happened if inc.attack_story else ''}\n")

        if args.export_html:
            out = Path(args.export_html)
            ReportExporter.export_html(inc, out)
            print(f"Forensic HTML report exported to {out}")


if __name__ == "__main__":
    main()
