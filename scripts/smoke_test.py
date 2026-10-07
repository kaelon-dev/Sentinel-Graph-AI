"""End-to-end smoke test validating the complete SentinelGraph AI pipeline."""
from pathlib import Path
from sentinelgraph.pipeline import SentinelPipeline
from sentinelgraph.reporting.exporters import ReportExporter


def run_smoke_test() -> None:
    """Execute end-to-end smoke test on the primary attack dataset."""
    sample_path = Path("data/generated/data_exfiltration_attack_logs.csv")
    if not sample_path.exists():
        raise FileNotFoundError(f"Primary attack dataset not found at {sample_path}")

    print("=" * 80)
    print("SENTINELGRAPH AI -- END-TO-END SMOKE TEST")
    print("=" * 80)

    # 1. Ingest, Baseline, Detect, Correlate, Reconstruct
    result = SentinelPipeline.analyze_file(
        file_path=sample_path,
        run_id="SMOKE-TEST-001"
    )

    print(f"Run ID:                 {result.run_id}")
    print(f"File:                   {result.source_metadata.file_name} ({result.source_metadata.size} bytes)")
    print(f"SHA-256:                {result.source_metadata.sha256[:16]}...")
    print(f"Valid Events Ingested:  {result.valid_event_count}")
    print(f"Invalid Rows Handled:   {len(result.invalid_records)}")
    print(f"Duplicate Events:       {result.duplicate_count}")
    print(f"Signals Detected:       {len(result.signals_detected)}")
    print(f"Incidents Reconstructed:{len(result.incidents)}")
    print(f"Execution Time:         {result.execution_time_seconds}s")

    assert len(result.incidents) >= 1, "Expected at least one incident"
    primary_inc = result.incidents[0]

    print("-" * 80)
    print("PRIMARY INCIDENT VERIFICATION:")
    print(f"Incident ID:            {primary_inc.incident_id}")
    print(f"Title:                  {primary_inc.title}")
    print(f"Severity:               {primary_inc.severity}")
    print(f"Risk Score:             {primary_inc.risk_score} / 100")
    print(f"Confidence:             {int(primary_inc.confidence * 100)}%")
    print(f"Attack Fingerprint:     {primary_inc.attack_fingerprint[:24]}...")
    print(f"Users Involved:         {', '.join(primary_inc.affected_users)}")
    print(f"Devices Involved:       {', '.join(primary_inc.affected_devices)}")
    print(f"Removable USB:          {', '.join(primary_inc.affected_usb_devices)}")
    print(f"Sensitive Files:        {', '.join(primary_inc.affected_files)}")

    # Check attack stages
    confirmed_stages = [s.stage_name for s in primary_inc.attack_stages if s.status == "confirmed"]
    print(f"Confirmed Stages:       {', '.join(confirmed_stages)}")
    assert "Initial Access" in confirmed_stages, "Initial Access stage must be confirmed"
    assert "Collection" in confirmed_stages, "Collection stage must be confirmed"
    assert "Exfiltration" in confirmed_stages, "Exfiltration stage must be confirmed"

    # Check evidence items
    print(f"Evidence Ledger Items:  {len(primary_inc.evidence_items)}")
    for item in primary_inc.evidence_items:
        print(f"  * [{item.evidence_id}] {item.event_id} ({item.timestamp.strftime('%H:%M:%S UTC')}): {item.explanation[:60]}...")

    # Check counterfactuals
    print(f"Counterfactual Scenarios:{len(primary_inc.counterfactuals)}")
    for cf in primary_inc.counterfactuals[:3]:
        print(f"  * Without {cf.removed_event_id}: Risk drops from {cf.original_risk} to {cf.counterfactual_risk} (-{cf.risk_delta} pts) -> {cf.counterfactual_severity}")

    # Export sample reports
    out_dir = Path("outputs/sample_reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    ReportExporter.export_json(primary_inc, out_dir / "sample_incident.json")
    ReportExporter.export_evidence_csv(primary_inc, out_dir / "sample_evidence.csv")
    ReportExporter.export_html(primary_inc, out_dir / "sample_incident_report.html")
    ReportExporter.export_markdown(primary_inc, out_dir / "sample_incident_report.md")

    print("-" * 80)
    print(f"Reports successfully generated in {out_dir}:")
    print("  * sample_incident.json")
    print("  * sample_evidence.csv")
    print("  * sample_incident_report.html")
    print("  * sample_incident_report.md")
    print("=" * 80)
    print("SMOKE TEST STATUS: [PASS] SUCCESS")
    print("=" * 80)


if __name__ == "__main__":
    run_smoke_test()
