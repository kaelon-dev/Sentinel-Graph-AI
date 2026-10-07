"""Report generation and multi-format exporters (JSON, CSV, HTML, Markdown)."""
import csv
import io
import json
from pathlib import Path
from typing import Optional, Union
from sentinelgraph.models import Incident, AnalysisResult


class ReportExporter:
    """Exports incidents and analysis runs to JSON, CSV, HTML, and Markdown formats."""

    @classmethod
    def export_json(cls, data: Union[Incident, AnalysisResult], output_path: Optional[Union[str, Path]] = None) -> str:
        """Export incident or analysis result to formatted JSON."""
        json_str = data.model_dump_json(indent=2)
        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")
        return json_str

    @classmethod
    def export_evidence_csv(cls, incident: Incident, output_path: Optional[Union[str, Path]] = None) -> str:
        """Export incident evidence ledger to CSV."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Evidence_ID", "Event_ID", "Timestamp_UTC", "Event_Type",
            "User_ID", "Device_ID", "IP_Address", "File_Path",
            "File_Sensitivity", "USB_ID", "Destination_IP", "Strength",
            "Explanation", "Fingerprint"
        ])

        for evd in incident.evidence_items:
            writer.writerow([
                evd.evidence_id,
                evd.event_id,
                evd.timestamp.isoformat(),
                evd.event_type,
                evd.user_id or "",
                evd.device_id or "",
                evd.ip_address or "",
                evd.file_path or "",
                evd.file_sensitivity or "",
                evd.usb_id or "",
                evd.destination_ip or "",
                evd.strength,
                evd.explanation,
                evd.fingerprint
            ])

        csv_str = output.getvalue()
        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(csv_str, encoding="utf-8")
        return csv_str

    @classmethod
    def export_markdown(cls, incident: Incident, output_path: Optional[Union[str, Path]] = None) -> str:
        """Generate structured Markdown incident report."""
        decomp = incident.confidence_decomposition
        decomp_str = decomp.explanation if decomp else f"Overall: {int(incident.confidence * 100)}%"

        md = f"""# SentinelGraph AI — Forensic Incident Report

**Incident ID:** `{incident.incident_id}`  
**Title:** {incident.title}  
**Classification:** {incident.attack_type}  
**Severity:** **{incident.severity}** (Risk Score: {incident.risk_score} / 100)  
**Confidence:** {int(incident.confidence * 100)}% ({decomp_str})  
**Attack Fingerprint:** `{incident.attack_fingerprint}`  
**Window:** {incident.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')} to {incident.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}

---

## 1. Executive Summary & Attack Story
{incident.attack_story.what_happened if incident.attack_story else 'Attack reconstruction completed.'}

**Why it matters:**  
{incident.attack_story.why_it_matters if incident.attack_story else 'Significant risk of data exfiltration.'}

---

## 2. Attack Chain Stages (MITRE-aligned)

| Stage | Status | Confidence | Summary | Evidence Events |
|---|---|---|---|---|
"""
        for s in incident.attack_stages:
            evts_str = ", ".join(s.evidence_event_ids) or "None"
            md += f"| {s.stage_name} | `{s.status}` | {int(s.confidence*100)}% | {s.summary} | {evts_str} |\n"

        md += "\n---\n\n## 3. Evidence Ledger\n\n"
        for evd in incident.evidence_items:
            md += f"- **{evd.evidence_id}** (`{evd.event_id}` at {evd.timestamp.strftime('%H:%M:%S UTC')}): {evd.explanation}\n"
            md += f"  - *Entities:* User: `{evd.user_id}`, Device: `{evd.device_id}`, Target: `{evd.file_path or evd.destination_ip or evd.usb_id}`\n"
            md += f"  - *Fingerprint:* `{evd.fingerprint[:16]}...`\n"

        md += "\n---\n\n## 4. Score Breakdown & Severity Gating\n\n"
        for sc in incident.score_breakdown:
            md += f"- `{sc.rule_or_factor}`: **+{sc.capped_points} pts** ({sc.reason})\n"

        md += "\n---\n\n## 5. Counterfactual Analysis (What Changed the Decision?)\n\n"
        md += "| Removed Evidence | Original Risk | Counterfactual Risk | Risk Delta | Counterfactual Severity |\n|---|---|---|---|---|\n"
        for cf in incident.counterfactuals:
            md += f"| `{cf.removed_event_id}` ({cf.event_description[:30]}) | {cf.original_risk} | {cf.counterfactual_risk} | **-{cf.risk_delta}** | `{cf.counterfactual_severity}` |\n"

        md += "\n---\n\n## 6. Recommended Analyst Response Actions\n\n"
        for act in incident.recommended_actions:
            md += f"1. [ ] {act}\n"

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(md, encoding="utf-8")
        return md

    @classmethod
    def export_html(cls, incident: Incident, output_path: Optional[Union[str, Path]] = None) -> str:
        """Generate self-contained, SOC dark-mode HTML forensic report."""
        sev_color = {
            "CRITICAL": "#EF4444",
            "HIGH": "#F97316",
            "MEDIUM": "#F59E0B",
            "LOW": "#38BDF8",
            "INFO": "#22C55E"
        }.get(incident.severity, "#38BDF8")

        decomp = incident.confidence_decomposition
        decomp_text = decomp.explanation if decomp else f"Overall: {int(incident.confidence*100)}%"

        stages_rows = ""
        for s in incident.attack_stages:
            status_badge_color = "#22C55E" if s.status == "confirmed" else ("#F59E0B" if s.status == "suspected" else "#64748B")
            evts = ", ".join(s.evidence_event_ids) or "None"
            stages_rows += f"""
            <tr>
                <td><strong>{s.stage_name}</strong></td>
                <td><span style="background: {status_badge_color}; color: #000; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{s.status.upper()}</span></td>
                <td>{int(s.confidence * 100)}%</td>
                <td>{s.summary}</td>
                <td><code>{evts}</code></td>
            </tr>
            """

        evidence_cards = ""
        for evd in incident.evidence_items:
            evidence_cards += f"""
            <div style="background: #1E293B; border-left: 4px solid {sev_color}; padding: 12px; margin-bottom: 8px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; font-size: 13px; color: #94A3B8;">
                    <strong>{evd.evidence_id} ({evd.event_id})</strong>
                    <span>{evd.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                </div>
                <div style="margin: 6px 0; color: #F8FAFC;">{evd.explanation}</div>
                <div style="font-size: 11px; color: #38BDF8; font-family: monospace;">
                    User: {evd.user_id or 'N/A'} | Device: {evd.device_id or 'N/A'} | Target: {evd.file_path or evd.usb_id or evd.destination_ip or 'N/A'} | SHA256: {evd.fingerprint[:24]}...
                </div>
            </div>
            """

        counterfactual_rows = ""
        for cf in incident.counterfactuals:
            counterfactual_rows += f"""
            <tr>
                <td><code>{cf.removed_event_id}</code></td>
                <td>{cf.event_description}</td>
                <td>{cf.original_risk}</td>
                <td>{cf.counterfactual_risk}</td>
                <td style="color: #EF4444; font-weight: bold;">-{cf.risk_delta}</td>
                <td><span style="background: #334155; padding: 2px 6px; border-radius: 3px;">{cf.counterfactual_severity}</span></td>
            </tr>
            """

        actions_list = "".join(f"<li style='margin-bottom: 6px;'>{a}</li>" for a in incident.recommended_actions)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SentinelGraph AI Forensic Report — {incident.incident_id}</title>
    <style>
        body {{
            background-color: #0B1020;
            color: #E2E8F0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: #111827;
            border: 1px solid #1F2937;
            padding: 24px;
            border-radius: 8px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            padding: 6px 14px;
            border-radius: 6px;
            font-weight: 800;
            font-size: 14px;
            color: #FFF;
            background: {sev_color};
            text-transform: uppercase;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1F2937;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        h2 {{
            color: #38BDF8;
            margin-top: 0;
            border-bottom: 1px solid #1F2937;
            padding-bottom: 8px;
            font-size: 18px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid #1E293B;
            font-size: 13px;
        }}
        th {{
            color: #94A3B8;
            background: #0F172A;
        }}
        code {{
            background: #1E293B;
            padding: 2px 5px;
            border-radius: 4px;
            color: #38BDF8;
            font-size: 12px;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <div style="font-size: 12px; color: #38BDF8; text-transform: uppercase; letter-spacing: 1px;">SentinelGraph AI Threat Intelligence</div>
            <h1 style="margin: 4px 0; font-size: 24px;">{incident.incident_id}: {incident.title}</h1>
            <div style="color: #94A3B8; font-size: 13px;">{incident.attack_type} | Window: {incident.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')} - {incident.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </div>
        <div style="text-align: right;">
            <div class="badge">{incident.severity} (Score: {incident.risk_score}/100)</div>
            <div style="margin-top: 6px; font-size: 12px; color: #94A3B8;">Confidence: {int(incident.confidence*100)}%</div>
        </div>
    </div>

    <div class="card">
        <h2>Executive Attack Narrative</h2>
        <p style="font-size: 14px; line-height: 1.6; color: #F1F5F9;">{incident.attack_story.what_happened if incident.attack_story else ''}</p>
        <p style="font-size: 13px; color: #CBD5E1;"><em>Why it matters:</em> {incident.attack_story.why_it_matters if incident.attack_story else ''}</p>
        <div style="font-size: 12px; color: #94A3B8; margin-top: 10px;"><strong>Confidence Decomposition:</strong> {decomp_text}</div>
    </div>

    <div class="card">
        <h2>MITRE Attack Stages & Verification</h2>
        <table>
            <thead>
                <tr><th>Stage</th><th>Status</th><th>Confidence</th><th>Summary</th><th>Evidence</th></tr>
            </thead>
            <tbody>{stages_rows}</tbody>
        </table>
    </div>

    <div class="card">
        <h2>Evidence Ledger</h2>
        {evidence_cards}
    </div>

    <div class="card">
        <h2>Deterministic Counterfactual Impact</h2>
        <table>
            <thead>
                <tr><th>Removed Event</th><th>Description</th><th>Original Risk</th><th>New Risk</th><th>Impact</th><th>New Severity</th></tr>
            </thead>
            <tbody>{counterfactual_rows}</tbody>
        </table>
    </div>

    <div class="card">
        <h2>Recommended Analyst Response Actions (Safe / Defensive)</h2>
        <ul style="color: #F1F5F9; font-size: 14px; padding-left: 20px;">
            {actions_list}
        </ul>
    </div>
</div>
</body>
</html>
"""
        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(html, encoding="utf-8")
        return html
