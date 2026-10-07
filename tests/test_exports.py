"""Tests for report exporters (JSON, CSV, HTML, Markdown)."""
from datetime import datetime, timezone
from pathlib import Path
from sentinelgraph.models import Incident, AttackStage, EvidenceItem, AttackStory
from sentinelgraph.reporting.exporters import ReportExporter


def get_mock_incident():
    t0 = datetime(2026, 10, 12, 9, 15, 0, tzinfo=timezone.utc)
    return Incident(
        incident_id="INC-TEST-001",
        title="Test Data Exfiltration",
        severity="CRITICAL",
        risk_score=91.0,
        confidence=0.94,
        attack_type="Potential Data Exfiltration",
        start_time=t0,
        end_time=t0,
        affected_users=["U102"],
        affected_devices=["DEV-17"],
        affected_files=["/finance/payroll.xlsx"],
        affected_usb_devices=["USB-8891"],
        attack_stages=[
            AttackStage(
                stage_id="STG-01",
                stage_name="Initial Access",
                status="confirmed",
                confidence=0.9,
                summary="Initial access confirmed",
                explanation="Verified",
                evidence_event_ids=["EVT-01"]
            )
        ],
        evidence_items=[
            EvidenceItem(
                evidence_id="EVD-01",
                event_id="EVT-01",
                timestamp=t0,
                event_type="login_success",
                user_id="U102",
                fingerprint="abc123sha256",
                explanation="Unusual login"
            )
        ],
        attack_fingerprint="fp123456",
        attack_story=AttackStory(
            story_id="STORY-TEST",
            headline="Headline Test",
            what_happened="What happened narrative",
            why_it_matters="Why it matters narrative",
            confidence=0.94,
            risk_score=91.0
        )
    )


def test_exports(tmp_path: Path):
    inc = get_mock_incident()

    # JSON
    json_path = tmp_path / "inc.json"
    json_str = ReportExporter.export_json(inc, json_path)
    assert json_path.exists()
    assert "INC-TEST-001" in json_str

    # CSV
    csv_path = tmp_path / "evd.csv"
    csv_str = ReportExporter.export_evidence_csv(inc, csv_path)
    assert csv_path.exists()
    assert "EVD-01" in csv_str

    # Markdown
    md_path = tmp_path / "rep.md"
    md_str = ReportExporter.export_markdown(inc, md_path)
    assert md_path.exists()
    assert "# SentinelGraph AI" in md_str

    # HTML
    html_path = tmp_path / "rep.html"
    html_str = ReportExporter.export_html(inc, html_path)
    assert html_path.exists()
    assert "<!DOCTYPE html>" in html_str
    assert "CRITICAL" in html_str
