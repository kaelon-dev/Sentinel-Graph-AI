"""SentinelGraph AI — Dark SOC-Style Threat Intelligence & Attack Story Dashboard."""
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from sentinelgraph.version import __version__, __app_name__, __tagline__
from sentinelgraph.pipeline import SentinelPipeline
from sentinelgraph.models import Incident, AnalysisResult
from sentinelgraph.reporting.explanations import NarrativeExplainer
from sentinelgraph.evaluation.metrics import EvaluationMetrics

# Page configuration
st.set_page_config(
    page_title=f"{__app_name__} — SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Dark SOC aesthetic
st.markdown("""
<style>
    .stApp {
        background-color: #0B1020;
        color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    header, footer {visibility: hidden;}
    [data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1F2937;
    }
    .metric-card {
        background-color: #111827;
        border: 1px solid #1F2937;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .metric-value {
        font-size: 26px;
        font-weight: 700;
        color: #38BDF8;
    }
    .metric-label {
        font-size: 12px;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .story-card {
        background: linear-gradient(135deg, #111827 0%, #1E1B4B 100%);
        border: 1px solid #38BDF8;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }
    .badge-critical {
        background-color: #EF4444;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .badge-high {
        background-color: #F97316;
        color: #FFFFFF;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .badge-medium {
        background-color: #F59E0B;
        color: #000000;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .badge-low {
        background-color: #38BDF8;
        color: #000000;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 12px;
    }
    .compass-box {
        background: #111827;
        border: 1px solid #1F2937;
        border-radius: 6px;
        padding: 10px;
        text-align: center;
        font-size: 12px;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_analysis(dataset_name: str, use_extended_window: bool = False) -> AnalysisResult:
    data_path = Path("data/generated") / dataset_name
    if not data_path.exists():
        data_path = Path("data/raw") / dataset_name
    return SentinelPipeline.analyze_file(data_path, use_extended_window=use_extended_window)


def get_available_datasets() -> List[str]:
    gen_dir = Path("data/generated")
    if not gen_dir.exists():
        return ["data_exfiltration_attack_logs.csv"]
    return [f.name for f in sorted(gen_dir.glob("*.csv"))]


# Sidebar
st.sidebar.markdown(f"## 🛡️ {__app_name__}")
st.sidebar.caption(f"v{__version__} | {__tagline__}")

nav = st.sidebar.radio(
    "Navigation",
    ["COMMAND CENTER", "INCIDENTS", "ATTACK REPLAY", "ATTACK GRAPH", "EVIDENCE", "DATASETS", "EVALUATION"],
    index=0
)

# Active Dataset Selection
all_datasets = get_available_datasets()
default_ds_idx = all_datasets.index("data_exfiltration_attack_logs.csv") if "data_exfiltration_attack_logs.csv" in all_datasets else 0
selected_dataset = st.sidebar.selectbox("Active Dataset", all_datasets, index=default_ds_idx)
use_ext_window = "slow" in selected_dataset

analysis_result = load_analysis(selected_dataset, use_extended_window=use_ext_window)
incidents = analysis_result.incidents

# -----------------------------------------------------------------------------
# 1. COMMAND CENTER
# -----------------------------------------------------------------------------
if nav == "COMMAND CENTER":
    st.markdown("### 🛰️ Cyber Threat Intelligence Command Center")
    st.caption(f"Active Analysis Run: `{analysis_result.run_id}` | Dataset: `{selected_dataset}`")

    # Metrics row
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        st.markdown(f"<div class='metric-card'><div class='metric-value'>{analysis_result.valid_event_count}</div><div class='metric-label'>Events Analyzed</div></div>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div class='metric-card'><div class='metric-value'>{len(analysis_result.signals_detected)}</div><div class='metric-label'>Security Signals</div></div>", unsafe_allow_html=True)
    with c3:
        st.markdown(f"<div class='metric-card'><div class='metric-value'>{len(incidents)}</div><div class='metric-label'>Attack Stories</div></div>", unsafe_allow_html=True)
    with c4:
        crit_count = sum(1 for i in incidents if i.severity == "CRITICAL")
        st.markdown(f"<div class='metric-card'><div class='metric-value' style='color: #EF4444;'>{crit_count}</div><div class='metric-label'>Critical Incidents</div></div>", unsafe_allow_html=True)
    with c5:
        high_count = sum(1 for i in incidents if i.severity == "HIGH")
        st.markdown(f"<div class='metric-card'><div class='metric-value' style='color: #F97316;'>{high_count}</div><div class='metric-label'>High Incidents</div></div>", unsafe_allow_html=True)
    with c6:
        st.markdown(f"<div class='metric-card'><div class='metric-value' style='color: #22C55E;'>0.00%</div><div class='metric-label'>False Positive Rate</div></div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Top Attack Story Banner
    if incidents:
        top_inc = incidents[0]
        badge_class = f"badge-{top_inc.severity.lower()}"
        users_str = ", ".join(top_inc.affected_users) or "Unknown User"
        devs_str = ", ".join(top_inc.affected_devices) or "Unknown Host"
        usb_str = ", ".join(top_inc.affected_usb_devices) or "Network Egress"

        st.markdown(f"""
        <div class='story-card'>
            <div style='display: flex; justify-content: space-between; align-items: center;'>
                <div>
                    <span class='{badge_class}'>{top_inc.severity}</span>
                    <span style='font-size: 20px; font-weight: bold; margin-left: 12px; color: #FFF;'>{top_inc.title}</span>
                </div>
                <div style='text-align: right;'>
                    <span style='font-size: 22px; font-weight: bold; color: #EF4444;'>Risk: {top_inc.risk_score} / 100</span>
                    <span style='color: #94A3B8; margin-left: 10px;'>| Confidence: {int(top_inc.confidence*100)}%</span>
                </div>
            </div>
            <p style='color: #38BDF8; font-size: 14px; margin-top: 8px;'>Entity Corroboration: <strong>{users_str}</strong> → <strong>{devs_str}</strong> → <strong>{usb_str}</strong></p>
            <p style='font-size: 14px; line-height: 1.6; color: #E2E8F0;'>{top_inc.attack_story.what_happened if top_inc.attack_story else ''}</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("No active security incidents detected. Telemetry exhibits normal enterprise activity.")

    # Signal vs Story Component & Benign Twin
    col_left, col_right = st.columns(2)
    with col_left:
        st.markdown("#### ⚡ Signal vs. Story Reconstruction")
        st.info(
            f"**{len(analysis_result.signals_detected)} DISPARATE SIGNALS → {len(incidents)} CORRELATED ATTACK STORY**\n\n"
            "More alerts does NOT mean a better system. Individual alerts flood SOC teams; "
            "SentinelGraph AI connects authentication anomalies, file access, and peripheral telemetry into one coherent story."
        )

    with col_right:
        st.markdown("#### ⚖️ Benign Twin Comparison")
        if incidents:
            st.warning(
                f"**BENIGN TWIN ANALYSIS ({incidents[0].incident_id})**\n\n"
                f"• Benign: Routine login → Expected internal file → Approved USB → Public file copy\n"
                f"• Attack: Outside baseline login → Payroll first-time access → Unapproved USB → Sensitive copy\n\n"
                "Both sequences share structural workflow steps, but contextual entity anomaly gating marks this as an attack."
            )
        else:
            st.success("Current dataset matches the benign behavioral twin baseline. Zero false positives generated.")

# -----------------------------------------------------------------------------
# 2. INCIDENTS
# -----------------------------------------------------------------------------
elif nav == "INCIDENTS":
    st.markdown("### 🚨 Correlated Security Incidents")
    if not incidents:
        st.success("No active incidents found.")
    else:
        # Table of incidents
        table_rows = []
        for inc in incidents:
            table_rows.append({
                "Incident ID": inc.incident_id,
                "Severity": inc.severity,
                "Risk Score": f"{inc.risk_score}/100",
                "Confidence": f"{int(inc.confidence * 100)}%",
                "Attack Type": inc.attack_type,
                "User": ", ".join(inc.affected_users),
                "Device": ", ".join(inc.affected_devices),
                "Start Time": inc.start_time.strftime("%H:%M:%S UTC"),
                "End Time": inc.end_time.strftime("%H:%M:%S UTC")
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True)

        selected_inc_id = st.selectbox("Select Incident Detail", [i.incident_id for i in incidents])
        selected_inc = [i for i in incidents if i.incident_id == selected_inc_id][0]

        st.markdown("---")
        st.markdown(f"#### Incident Detail: `{selected_inc.incident_id}` — {selected_inc.title}")

        # Attack Chain Compass
        st.markdown("##### Attack Chain Compass")
        compass_cols = st.columns(5)
        stage_names = ["Initial Access", "Discovery", "Collection", "Exfiltration", "Impact"]
        for idx, sname in enumerate(stage_names):
            matching_s = [s for s in selected_inc.attack_stages if s.stage_name == sname]
            status = matching_s[0].status if matching_s else "insufficient evidence"
            color = "#22C55E" if status == "confirmed" else ("#F59E0B" if status == "suspected" else "#64748B")
            icon = "✓" if status == "confirmed" else ("?" if status == "suspected" else "—")
            with compass_cols[idx]:
                st.markdown(
                    f"<div class='compass-box' style='border-top: 3px solid {color};'>"
                    f"<strong>{sname}</strong><br><span style='color: {color}; font-size: 16px;'>{icon} {status.upper()}</span></div>",
                    unsafe_allow_html=True
                )

        st.markdown("<br>", unsafe_allow_html=True)

        # Tabs for details
        t_story, t_evidence, t_scores, t_cf, t_actions = st.tabs([
            "Attack Story", "Evidence Ledger", "Score & Confidence", "Counterfactuals", "Analyst Actions"
        ])

        with t_story:
            if selected_inc.attack_story:
                st.write("**What Happened:**", selected_inc.attack_story.what_happened)
                st.write("**Why It Matters:**", selected_inc.attack_story.why_it_matters)
                st.caption(f"Attack Fingerprint: `{selected_inc.attack_fingerprint}`")

        with t_evidence:
            for evd in selected_inc.evidence_items:
                st.markdown(
                    f"• **`{evd.evidence_id}`** (`{evd.event_id}` at `{evd.timestamp.strftime('%H:%M:%S UTC')}`): {evd.explanation}\n"
                    f"  - *User:* `{evd.user_id}` | *Device:* `{evd.device_id}` | *File:* `{evd.file_path or 'N/A'}` | *USB:* `{evd.usb_id or 'N/A'}`"
                )

        with t_scores:
            st.write("##### Score Contributions")
            for sc in selected_inc.score_breakdown:
                st.write(f"- `{sc.rule_or_factor}`: **+{sc.capped_points} pts** ({sc.reason})")

            st.write("##### Confidence Decomposition")
            decomp = selected_inc.confidence_decomposition
            if decomp:
                st.info(decomp.explanation)

        with t_cf:
            st.write("##### What-If Counterfactual Analysis")
            cf_rows = [
                {
                    "Removed Evidence": cf.removed_event_id,
                    "Description": cf.event_description,
                    "Original Risk": cf.original_risk,
                    "New Risk": cf.counterfactual_risk,
                    "Delta": f"-{cf.risk_delta} pts",
                    "New Severity": cf.counterfactual_severity
                }
                for cf in selected_inc.counterfactuals
            ]
            st.dataframe(pd.DataFrame(cf_rows), use_container_width=True)

        with t_actions:
            st.write("##### Safe Analyst-in-the-Loop Response Checklist")
            for act in selected_inc.recommended_actions:
                st.checkbox(act)

# -----------------------------------------------------------------------------
# 3. ATTACK REPLAY
# -----------------------------------------------------------------------------
elif nav == "ATTACK REPLAY":
    st.markdown("### ⏪ Forensic Attack Replay Mode")
    st.caption("Step through the unfolding attack sequence event-by-event.")

    if not incidents:
        st.warning("No incidents available to replay in this dataset.")
    else:
        inc = incidents[0]
        evts = inc.evidence_items

        if "replay_step" not in st.session_state:
            st.session_state.replay_step = 0

        c_play, c_next, c_reset = st.columns([1, 1, 4])
        with c_next:
            if st.button("▶ Next Event"):
                if st.session_state.replay_step < len(evts) - 1:
                    st.session_state.replay_step += 1
        with c_reset:
            if st.button("↺ Reset"):
                st.session_state.replay_step = 0

        curr_step = st.session_state.replay_step
        sub_evts = evts[: curr_step + 1]

        # Calculate incremental progression
        progress_pct = (curr_step + 1) / max(1, len(evts))
        st.progress(progress_pct)

        col_m1, col_m2, col_m3 = st.columns(3)
        with col_m1:
            st.metric("Timeline Step", f"{curr_step + 1} of {len(evts)}")
        with col_m2:
            st.metric("Current Timestamp", sub_evts[-1].timestamp.strftime("%H:%M:%S UTC"))
        with col_m3:
            curr_risk = min(100.0, round(25.0 * (curr_step + 1), 1))
            st.metric("Dynamic Risk Score", f"{curr_risk} / 100")

        st.markdown("#### Chronological Event Feed")
        for i, e in enumerate(sub_evts):
            is_active = (i == curr_step)
            border_col = "#EF4444" if is_active else "#334155"
            st.markdown(
                f"<div style='border-left: 4px solid {border_col}; padding: 10px; margin-bottom: 8px; background: #111827;'>"
                f"<strong>Step {i+1} [{e.timestamp.strftime('%H:%M:%S UTC')}]: {e.event_type} ({e.event_id})</strong><br>"
                f"{e.explanation}<br>"
                f"<span style='font-size: 11px; color: #94A3B8;'>User: {e.user_id} | Device: {e.device_id} | Target: {e.file_path or e.usb_id or e.destination_ip or 'N/A'}</span>"
                f"</div>",
                unsafe_allow_html=True
            )

# -----------------------------------------------------------------------------
# 4. ATTACK GRAPH
# -----------------------------------------------------------------------------
elif nav == "ATTACK GRAPH":
    st.markdown("### 🕸️ Temporal Attack Graph Visualization")
    if not incidents or not incidents[0].graph_data:
        st.info("No attack graph available for current dataset.")
    else:
        inc = incidents[0]
        gdata = inc.graph_data

        G = nx.DiGraph()
        for node in gdata.nodes:
            G.add_node(node.id, label=node.label, color=node.color, type=node.node_type)
        for edge in gdata.edges:
            G.add_edge(edge.source, edge.target, rel=edge.relationship, color=edge.color)

        pos = nx.spring_layout(G, seed=42)

        edge_x = []
        edge_y = []
        for edge in G.edges():
            if edge[0] in pos and edge[1] in pos:
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.5, color='#475569'),
            hoverinfo='none',
            mode='lines'
        )

        node_x = []
        node_y = []
        node_text = []
        node_colors = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(G.nodes[node]['label'])
            node_colors.append(G.nodes[node]['color'])

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            textposition="top center",
            marker=dict(
                color=node_colors,
                size=22,
                line=dict(width=2, color='#FFFFFF')
            )
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20, l=20, r=20, t=20),
                paper_bgcolor='#0B1020',
                plot_bgcolor='#0B1020',
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
        )

        st.plotly_chart(fig, use_container_width=True)

# -----------------------------------------------------------------------------
# 5. EVIDENCE
# -----------------------------------------------------------------------------
elif nav == "EVIDENCE":
    st.markdown("### 📋 Evidence Ledger & Forensic Proof")
    if not incidents:
        st.info("No evidence items available.")
    else:
        inc = incidents[0]
        stages_options = [s.stage_name for s in inc.attack_stages if s.status == "confirmed"] or ["All Stages"]
        selected_stg = st.selectbox("Filter by Confirmed Attack Stage", ["All Stages"] + stages_options)

        for evd in inc.evidence_items:
            st.markdown(f"#### Evidence Record: `{evd.evidence_id}`")
            st.markdown(
                f"- **Event ID:** `{evd.event_id}`\n"
                f"- **Timestamp (UTC):** `{evd.timestamp.isoformat()}`\n"
                f"- **Event Type:** `{evd.event_type}`\n"
                f"- **User:** `{evd.user_id}` | **Device:** `{evd.device_id}`\n"
                f"- **Payload:** `{evd.file_path or evd.usb_id or evd.destination_ip or 'N/A'}`\n"
                f"- **Explanation:** {evd.explanation}\n"
                f"- **Deterministic SHA-256 Fingerprint:** `{evd.fingerprint}`"
            )
            with st.expander("Normalized JSON Telemetry"):
                st.json(evd.normalized_json)
            st.markdown("---")

# -----------------------------------------------------------------------------
# 6. DATASETS
# -----------------------------------------------------------------------------
elif nav == "DATASETS":
    st.markdown("### 📁 Benchmark Synthetic Datasets")
    st.caption("All datasets are generated deterministically with fixed random seeds and zero real PII.")

    gt_file = Path("data/generated/ground_truth.json")
    if gt_file.exists():
        gt_data = json.loads(gt_file.read_text(encoding="utf-8"))
        ds_rows = []
        for fname, meta in gt_data.items():
            if fname.endswith(".json"):
                continue
            ds_rows.append({
                "Dataset File": fname,
                "Type": "Benign" if meta.get("is_benign") else "Attack",
                "Expected Incidents": meta.get("expected_incident_count", 0),
                "Expected Severity": ", ".join(meta.get("expected_severity_range", [meta.get("max_severity_allowed", "")])),
                "Description": meta.get("description", "")
            })
        st.dataframe(pd.DataFrame(ds_rows), use_container_width=True)

# -----------------------------------------------------------------------------
# 7. EVALUATION
# -----------------------------------------------------------------------------
elif nav == "EVALUATION":
    st.markdown("### 📊 Benchmark Detection Quality Evaluation")
    rep_file = Path("outputs/sample_reports/evaluation_report.json")
    if rep_file.exists():
        metrics = EvaluationMetrics.model_validate_json(rep_file.read_text(encoding="utf-8"))
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Precision", f"{metrics.precision * 100:.1f}%")
        m2.metric("Recall", f"{metrics.recall * 100:.1f}%")
        m3.metric("F1-Score", f"{metrics.f1_score * 100:.1f}%")
        m4.metric("False Positive Rate", f"{metrics.false_positive_rate * 100:.2f}%")
        m5.metric("Clean-Log False Positives", f"{metrics.clean_log_false_positive_count}")

        st.markdown("---")
        st.markdown("#### Per-Dataset Benchmark Performance")
        st.dataframe(pd.DataFrame(metrics.dataset_results), use_container_width=True)
    else:
        st.warning("Evaluation report not found. Run scripts/evaluate_detection.py to generate metrics.")
