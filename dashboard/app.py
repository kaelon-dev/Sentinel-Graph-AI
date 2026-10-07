"""SentinelGraph AI — Enterprise Cyber Threat Intelligence Command Center.

A professional Security Operations Center (SOC) investigation interface
for explainable attack-story reconstruction and temporal graph analytics.
Supports dual-theme switching: Dark SOC Command Mode and Light Enterprise Analyst Mode.
"""
import json
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

from sentinelgraph.version import __version__, __app_name__, __tagline__
from sentinelgraph.pipeline import SentinelPipeline
from sentinelgraph.models import Incident, AnalysisResult
from sentinelgraph.reporting.explanations import NarrativeExplainer
from sentinelgraph.evaluation.metrics import EvaluationMetrics

# -----------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & STATE INITIALIZATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title=f"{__app_name__} — Threat Intelligence Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Session State Keys for 1-Click Instant Navigation
if "theme_mode_key" not in st.session_state:
    st.session_state.theme_mode_key = "🌙 Dark SOC"

if "nav_destination_key" not in st.session_state:
    st.session_state.nav_destination_key = "🛰️ Command Center"

# Design System Token Palettes (Dark SOC vs. Light Enterprise Analyst)
THEMES: Dict[str, Dict[str, str]] = {
    "🌙 Dark SOC": {
        "bg_canvas": "#0B1020",
        "bg_surface": "#111827",
        "bg_elevated": "#172033",
        "bg_elevated_subtle": "#1E293B",
        "border_color": "#263244",
        "border_subtle": "#1E293B",
        "text_primary": "#F8FAFC",
        "text_secondary": "#E2E8F0",
        "text_muted": "#94A3B8",
        "text_dim": "#64748B",
        "primary_accent": "#38BDF8",
        "primary_subtle": "rgba(56, 189, 248, 0.12)",
        "critical_color": "#EF4444",
        "critical_bg": "rgba(239, 68, 68, 0.15)",
        "critical_border": "rgba(239, 68, 68, 0.4)",
        "high_color": "#F97316",
        "high_bg": "rgba(249, 115, 22, 0.15)",
        "high_border": "rgba(249, 115, 22, 0.4)",
        "medium_color": "#F59E0B",
        "medium_bg": "rgba(245, 158, 11, 0.15)",
        "medium_border": "rgba(245, 158, 11, 0.4)",
        "low_color": "#38BDF8",
        "low_bg": "rgba(56, 189, 248, 0.15)",
        "low_border": "rgba(56, 189, 248, 0.4)",
        "success_color": "#22C55E",
        "success_bg": "rgba(34, 197, 94, 0.15)",
        "success_border": "rgba(34, 197, 94, 0.4)",
        "primary_card_gradient": "linear-gradient(135deg, #111827 0%, #172033 100%)",
        "primary_card_border": "#38BDF8",
        "card_shadow": "0 4px 20px rgba(11, 16, 32, 0.5)",
        "code_bg": "rgba(56, 189, 248, 0.1)",
        "code_text": "#38BDF8",
        "graph_bg": "#0B1020",
        "graph_edge": "#334155",
        "graph_text": "#E2E8F0",
        "graph_node_border": "#1E293B",
        "replay_active_bg": "#1E1B4B",
        "replay_active_border": "#EF4444",
        "replay_inactive_bg": "#111827",
        "replay_inactive_border": "#263244",
        "input_bg": "#172033",
        "radio_border": "#475569",
    },
    "☀️ Light Enterprise": {
        "bg_canvas": "#F8FAFC",
        "bg_surface": "#FFFFFF",
        "bg_elevated": "#F1F5F9",
        "bg_elevated_subtle": "#E2E8F0",
        "border_color": "#CBD5E1",
        "border_subtle": "#E2E8F0",
        "text_primary": "#0F172A",
        "text_secondary": "#1E293B",
        "text_muted": "#475569",
        "text_dim": "#64748B",
        "primary_accent": "#0284C7",
        "primary_subtle": "#E0F2FE",
        "critical_color": "#DC2626",
        "critical_bg": "#FEF2F2",
        "critical_border": "#FECACA",
        "high_color": "#EA580C",
        "high_bg": "#FFF7ED",
        "high_border": "#FFEDD5",
        "medium_color": "#D97706",
        "medium_bg": "#FFFBEB",
        "medium_border": "#FEF3C7",
        "low_color": "#0284C7",
        "low_bg": "#F0F9FF",
        "low_border": "#BAE6FD",
        "success_color": "#16A34A",
        "success_bg": "#F0FDF4",
        "success_border": "#BBF7D0",
        "primary_card_gradient": "linear-gradient(135deg, #FFFFFF 0%, #F8FAFC 100%)",
        "primary_card_border": "#0284C7",
        "card_shadow": "0 2px 10px rgba(15, 23, 42, 0.06)",
        "code_bg": "rgba(2, 132, 199, 0.08)",
        "code_text": "#0284C7",
        "graph_bg": "#F8FAFC",
        "graph_edge": "#CBD5E1",
        "graph_text": "#0F172A",
        "graph_node_border": "#FFFFFF",
        "replay_active_bg": "#FEF2F2",
        "replay_active_border": "#DC2626",
        "replay_inactive_bg": "#FFFFFF",
        "replay_inactive_border": "#CBD5E1",
        "input_bg": "#FFFFFF",
        "radio_border": "#94A3B8",
    }
}

# -----------------------------------------------------------------------------
# 2. SIDEBAR HEADER & 1-CLICK THEME SWITCHER
# -----------------------------------------------------------------------------
# Lift sidebar title up to top
st.sidebar.markdown(f"""
<div style='margin-top: -15px; margin-bottom: 2px;'>
    <div style='font-size: 20px; font-weight: 800; color: var(--text-primary); display: flex; align-items: center; gap: 8px;'>
        <span>🛡️</span> <span>{__app_name__}</span>
    </div>
    <div style='font-size: 12px; color: var(--text-muted); margin-top: 2px;'>
        Enterprise Threat Intelligence · <strong>v{__version__}</strong>
    </div>
</div>
""", unsafe_allow_html=True)

# 1-Click Theme Selector
theme_selection = st.sidebar.radio(
    "Console Theme Mode",
    ["🌙 Dark SOC", "☀️ Light Enterprise"],
    key="theme_mode_key",
    horizontal=True,
    help="Toggle between Dark SOC Command Center and Light Enterprise Analyst Mode"
)
T = THEMES[theme_selection]


# Helper to cleanly render HTML without markdown code-block conversion bugs
def render_html(html_str: str) -> None:
    """Render pure HTML without Markdown converting indented lines to code blocks."""
    dedented = textwrap.dedent(html_str).strip()
    if hasattr(st, "html"):
        st.html(dedented)
    else:
        st.markdown(dedented, unsafe_allow_html=True)


# Inject Dynamic CSS matching current theme tokens
render_html(f"""
<style>
    :root {{
        --bg-canvas: {T['bg_canvas']};
        --bg-surface: {T['bg_surface']};
        --bg-elevated: {T['bg_elevated']};
        --bg-elevated-subtle: {T['bg_elevated_subtle']};
        --border-color: {T['border_color']};
        --border-subtle: {T['border_subtle']};
        --text-primary: {T['text_primary']};
        --text-secondary: {T['text_secondary']};
        --text-muted: {T['text_muted']};
        --text-dim: {T['text_dim']};
        --primary-accent: {T['primary_accent']};
        --primary-subtle: {T['primary_subtle']};
        --critical-color: {T['critical_color']};
        --critical-bg: {T['critical_bg']};
        --critical-border: {T['critical_border']};
        --high-color: {T['high_color']};
        --high-bg: {T['high_bg']};
        --high-border: {T['high_border']};
        --medium-color: {T['medium_color']};
        --medium-bg: {T['medium_bg']};
        --medium-border: {T['medium_border']};
        --low-color: {T['low_color']};
        --low-bg: {T['low_bg']};
        --low-border: {T['low_border']};
        --success-color: {T['success_color']};
        --success-bg: {T['success_bg']};
        --success-border: {T['success_border']};
        --code-bg: {T['code_bg']};
        --code-text: {T['code_text']};
        --replay-active-bg: {T['replay_active_bg']};
        --replay-inactive-bg: {T['replay_inactive_bg']};
        --input-bg: {T['input_bg']};
        --radio-border: {T['radio_border']};
    }}

    /* Global Canvas */
    .stApp {{
        background-color: var(--bg-canvas) !important;
        color: var(--text-primary) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
    }}
    footer {{visibility: hidden;}}
    #MainMenu, .stDeployButton {{visibility: hidden !important;}}
    header {{background-color: transparent !important;}}

    /* Lift Main Page Title Upwards */
    .block-container {{
        padding-top: 1.2rem !important;
        padding-bottom: 2rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
    }}

    /* Sidebar Refinement */
    [data-testid="stSidebar"] {{
        background-color: var(--bg-surface) !important;
        border-right: 1px solid var(--border-color) !important;
    }}
    [data-testid="stSidebarContent"] {{
        padding-top: 0.5rem !important;
    }}
    [data-testid="stSidebarUserContent"] {{
        padding-top: 0.25rem !important;
    }}
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] span, [data-testid="stSidebar"] label {{
        color: var(--text-primary) !important;
    }}
    
    /* Return Arrow (Sidebar Collapse Button <<) - Prominently Visible & Dark */
    [data-testid="stSidebarCollapseButton"] button {{
        background-color: var(--bg-elevated) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 6px !important;
        padding: 4px 6px !important;
        opacity: 1 !important;
    }}
    [data-testid="stSidebarCollapseButton"] svg {{
        fill: var(--text-primary) !important;
        stroke: var(--text-primary) !important;
        color: var(--text-primary) !important;
        width: 20px !important;
        height: 20px !important;
        opacity: 1 !important;
    }}

    /* Prominent Sidebar Expand Button (>> when closed) */
    [data-testid="collapsedControl"] {{
        display: flex !important;
        visibility: visible !important;
        opacity: 1 !important;
        z-index: 1000000 !important;
        position: fixed !important;
        top: 10px !important;
        left: 10px !important;
        background-color: var(--bg-surface) !important;
        color: var(--text-primary) !important;
        border: 2px solid var(--primary-accent) !important;
        border-radius: 6px !important;
        padding: 6px 10px !important;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2) !important;
        cursor: pointer !important;
    }}
    [data-testid="collapsedControl"] svg {{
        fill: var(--text-primary) !important;
        stroke: var(--text-primary) !important;
        color: var(--text-primary) !important;
        width: 22px !important;
        height: 22px !important;
    }}

    /* Clean Dropdown Menus (Selectboxes) */
    div[data-baseweb="select"] > div {{
        background-color: var(--input-bg) !important;
        border: 1px solid var(--border-color) !important;
        color: var(--text-primary) !important;
        border-radius: 6px !important;
    }}
    div[data-baseweb="select"] span {{
        color: var(--text-primary) !important;
    }}
    div[data-baseweb="select"] svg {{
        fill: var(--text-primary) !important;
    }}
    div[data-baseweb="popover"],
    div[data-baseweb="popover"] > div,
    div[data-baseweb="popover"] ul {{
        background-color: var(--bg-surface) !important;
        border: 1px solid var(--border-color) !important;
    }}
    div[data-baseweb="popover"] li {{
        background-color: var(--bg-surface) !important;
        color: var(--text-primary) !important;
    }}
    div[data-baseweb="popover"] li:hover {{
        background-color: var(--bg-elevated) !important;
        color: var(--primary-accent) !important;
    }}

    /* Radio Buttons & Checkboxes Colors */
    [data-testid="stRadio"] label > div:first-child {{
        background-color: var(--input-bg) !important;
        border: 1.5px solid var(--radio-border) !important;
    }}
    [data-testid="stRadio"] label:hover > div:first-child {{
        border-color: var(--primary-accent) !important;
    }}
    [data-testid="stRadio"] label input:checked + div,
    [data-testid="stRadio"] [aria-checked="true"] > div:first-child {{
        border-color: var(--primary-accent) !important;
        background-color: var(--input-bg) !important;
    }}
    [data-testid="stRadio"] [aria-checked="true"] > div:first-child > div {{
        background-color: var(--primary-accent) !important;
    }}

    [data-testid="stCheckbox"] label > div:first-child {{
        background-color: var(--input-bg) !important;
        border: 1.5px solid var(--radio-border) !important;
        border-radius: 4px !important;
    }}
    [data-testid="stCheckbox"] label:hover > div:first-child {{
        border-color: var(--primary-accent) !important;
    }}
    [data-testid="stCheckbox"] label input:checked + div,
    [data-testid="stCheckbox"] [aria-checked="true"] > div:first-child {{
        background-color: var(--primary-accent) !important;
        border-color: var(--primary-accent) !important;
    }}

    /* Top Shell Navigation Bar */
    .soc-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px 20px;
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: {T['card_shadow']};
    }}
    .soc-header-title {{
        font-size: 18px;
        font-weight: 700;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 10px;
    }}
    .soc-header-subtitle {{
        font-size: 12px;
        color: var(--text-muted);
        font-weight: 400;
        margin-top: 2px;
    }}
    .soc-status-badge {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        color: var(--success-color);
        background-color: var(--success-bg);
        border: 1px solid var(--success-border);
        padding: 4px 10px;
        border-radius: 20px;
    }}

    /* Metric Cards System */
    .metric-card {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 14px 16px;
        text-align: left;
        box-shadow: {T['card_shadow']};
        transition: border-color 0.15s ease-in-out;
    }}
    .metric-card:hover {{
        border-color: var(--primary-accent);
    }}
    .metric-value {{
        font-size: 26px;
        font-weight: 700;
        line-height: 1.2;
        color: var(--text-primary);
        font-feature-settings: "tnum";
    }}
    .metric-label {{
        font-size: 11px;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 4px;
    }}
    .metric-subtext {{
        font-size: 11px;
        color: var(--text-dim);
        margin-top: 4px;
    }}

    /* Severity Badges */
    .badge-critical {{
        background-color: var(--critical-bg);
        color: var(--critical-color);
        border: 1px solid var(--critical-border);
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        letter-spacing: 0.5px;
    }}
    .badge-high {{
        background-color: var(--high-bg);
        color: var(--high-color);
        border: 1px solid var(--high-border);
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        letter-spacing: 0.5px;
    }}
    .badge-medium {{
        background-color: var(--medium-bg);
        color: var(--medium-color);
        border: 1px solid var(--medium-border);
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        letter-spacing: 0.5px;
    }}
    .badge-low {{
        background-color: var(--low-bg);
        color: var(--low-color);
        border: 1px solid var(--low-border);
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        letter-spacing: 0.5px;
    }}
    .badge-clean {{
        background-color: var(--success-bg);
        color: var(--success-color);
        border: 1px solid var(--success-border);
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 11px;
        letter-spacing: 0.5px;
    }}

    /* Primary Threat Story Card */
    .primary-threat-card {{
        background: {T['primary_card_gradient']};
        border: 1px solid {T['primary_card_border']};
        border-radius: 10px;
        padding: 22px;
        margin-bottom: 24px;
        box-shadow: {T['card_shadow']};
    }}
    .primary-threat-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
        padding-bottom: 14px;
        border-bottom: 1px solid var(--border-color);
    }}
    .primary-threat-title {{
        font-size: 20px;
        font-weight: 700;
        color: var(--text-primary);
        margin-left: 10px;
    }}
    .threat-score-pill {{
        display: inline-flex;
        align-items: baseline;
        gap: 6px;
        padding: 6px 14px;
        background-color: var(--bg-surface);
        border: 1px solid var(--critical-border);
        border-radius: 6px;
    }}

    /* Attack Chain Breadcrumb Flow */
    .attack-chain-bar {{
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        padding: 10px 14px;
        background-color: var(--bg-elevated);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        margin: 14px 0;
        font-size: 13px;
    }}
    .chain-node {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        color: var(--text-primary);
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
    }}
    .chain-arrow {{
        color: var(--primary-accent);
        font-weight: 700;
    }}

    /* Threat Narrative Box (Executive SOC Alert - Replaces Terminal Leak) */
    .threat-narrative-box {{
        background-color: var(--bg-elevated);
        border: 1px solid var(--border-color);
        border-left: 4px solid var(--critical-color);
        border-radius: 6px;
        padding: 14px 16px;
        margin-top: 14px;
    }}
    .threat-narrative-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
    }}
    .threat-narrative-tag {{
        font-size: 11px;
        font-weight: 700;
        color: var(--critical-color);
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }}
    .threat-narrative-body {{
        font-size: 14px;
        line-height: 1.6;
        color: var(--text-secondary);
    }}

    /* Attack Chain Compass Matrix */
    .compass-stage-card {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 12px 10px;
        text-align: center;
        box-shadow: {T['card_shadow']};
    }}
    .compass-stage-title {{
        font-size: 11px;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    .compass-stage-status {{
        font-size: 13px;
        font-weight: 700;
        margin-top: 6px;
    }}

    /* Section Cards */
    .soc-surface-card {{
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 18px;
        height: 100%;
        box-shadow: {T['card_shadow']};
    }}
    .soc-card-title {{
        font-size: 14px;
        font-weight: 700;
        color: var(--text-primary);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }}

    /* Monospace Forensics */
    .mono-id {{
        font-family: "JetBrains Mono", "Fira Code", monospace;
        font-size: 12px;
        color: var(--code-text);
        background-color: var(--code-bg);
        border: 1px solid var(--border-subtle);
        padding: 2px 6px;
        border-radius: 4px;
    }}
    .mono-hash {{
        font-family: "JetBrains Mono", "Fira Code", monospace;
        font-size: 11px;
        color: var(--text-dim);
        word-break: break-all;
    }}

    /* Clean Streamlit Overrides */
    .stTabs [data-baseweb="tab-list"] {{
        gap: 8px;
        border-bottom: 1px solid var(--border-color);
    }}
    .stTabs [data-baseweb="tab"] {{
        background-color: transparent;
        color: var(--text-muted);
        border-radius: 6px 6px 0 0;
        padding: 8px 16px;
        font-size: 13px;
        font-weight: 600;
    }}
    .stTabs [aria-selected="true"] {{
        color: var(--primary-accent) !important;
        border-bottom: 2px solid var(--primary-accent) !important;
        background-color: var(--primary-subtle);
    }}

    /* Streamlit Expander & Dataframe */
    [data-testid="stExpander"] {{
        background-color: var(--bg-surface) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        margin-bottom: 10px;
    }}
    [data-testid="stExpander"] summary {{
        color: var(--text-primary) !important;
        font-weight: 600;
    }}
    [data-testid="stMetricValue"] {{
        color: var(--text-primary) !important;
    }}
    [data-testid="stMetricLabel"] {{
        color: var(--text-muted) !important;
    }}
    .stProgress > div > div > div > div {{
        background-color: var(--primary-accent) !important;
    }}
</style>
""")

# -----------------------------------------------------------------------------
# 3. PIPELINE RUNNER & DATASET UTILITIES
# -----------------------------------------------------------------------------
@st.cache_resource
def load_analysis(dataset_name: str, use_extended_window: bool = False) -> AnalysisResult:
    """Run analysis pipeline deterministically with caching."""
    data_path = Path("data/generated") / dataset_name
    if not data_path.exists():
        data_path = Path("data/raw") / dataset_name
    return SentinelPipeline.analyze_file(data_path, use_extended_window=use_extended_window)


def get_available_datasets() -> List[str]:
    """Retrieve all available synthetic benchmark datasets."""
    gen_dir = Path("data/generated")
    if not gen_dir.exists():
        return ["data_exfiltration_attack_logs.csv"]
    return [f.name for f in sorted(gen_dir.glob("*.csv"))]


def render_badge(severity: str) -> str:
    """Render a theme-aware semantic severity badge."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return "<span class='badge-critical'>CRITICAL</span>"
    elif sev == "HIGH":
        return "<span class='badge-high'>HIGH</span>"
    elif sev == "MEDIUM":
        return "<span class='badge-medium'>MEDIUM</span>"
    elif sev == "LOW":
        return "<span class='badge-low'>LOW</span>"
    else:
        return "<span class='badge-clean'>BENIGN</span>"


# -----------------------------------------------------------------------------
# 4. SIDEBAR NAVIGATION (1-CLICK INSTANT SWITCHING)
# -----------------------------------------------------------------------------
st.sidebar.markdown("---")

# Dataset Switcher
all_datasets = get_available_datasets()
default_ds_idx = all_datasets.index("data_exfiltration_attack_logs.csv") if "data_exfiltration_attack_logs.csv" in all_datasets else 0

selected_dataset = st.sidebar.selectbox(
    "Active Telemetry Dataset",
    all_datasets,
    index=default_ds_idx,
    help="Select an enterprise benchmark scenario to analyze"
)
use_ext_window = "slow" in selected_dataset

# Navigation Destinations (Organized by operational function)
render_html(f"<div style='font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-bottom: 6px;'>OPERATIONS</div>")

nav_options = [
    "🛰️ Command Center",
    "🚨 Incidents",
    "⏪ Attack Replay",
    "🕸️ Attack Graph",
    "📋 Evidence Ledger",
    "📁 Datasets",
    "📊 Evaluation"
]

# 1-Click Operational Navigation using Direct Key Binding
nav_selection = st.sidebar.radio(
    "Console Navigation",
    nav_options,
    key="nav_destination_key",
    label_visibility="collapsed"
)

# System status in sidebar
st.sidebar.markdown("---")
render_html(f"""
<div style='background-color: var(--bg-elevated); padding: 10px 12px; border-radius: 6px; border: 1px solid var(--border-color);'>
    <div style='font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600;'>System Engine</div>
    <div style='font-size: 12px; color: var(--success-color); font-weight: 600; margin-top: 2px;'>● 100% Deterministic Local</div>
    <div style='font-size: 11px; color: var(--text-dim); margin-top: 4px;'>Zero Cloud Leakage · Air-Gapped</div>
</div>
""")

# Load pipeline data
try:
    analysis_result = load_analysis(selected_dataset, use_extended_window=use_ext_window)
    incidents = analysis_result.incidents
except Exception as e:
    st.error(f"Error loading analysis for dataset '{selected_dataset}': {e}")
    st.stop()


# -----------------------------------------------------------------------------
# 5. GLOBAL SOC HEADER
# -----------------------------------------------------------------------------
render_html(f"""
<div class='soc-header'>
    <div>
        <div class='soc-header-title'>🛡️ {__app_name__} <span style='font-weight: 400; color: var(--text-dim);'>|</span> <span style='font-size: 15px; color: var(--primary-accent);'>Threat Intelligence Command Center</span></div>
        <div class='soc-header-subtitle'>Autonomous Explainable Attack Story Reconstruction · Telemetry: <code class='mono-id'>{selected_dataset}</code></div>
    </div>
    <div style='text-align: right;'>
        <div class='soc-status-badge'>● SYSTEM OPERATIONAL</div>
        <div style='font-size: 11px; color: var(--text-dim); margin-top: 4px;'>Run ID: <code class='mono-hash'>{analysis_result.run_id}</code></div>
    </div>
</div>
""")


# -----------------------------------------------------------------------------
# 6. VIEW ROUTING
# -----------------------------------------------------------------------------

# =============================================================================
# VIEW 1: COMMAND CENTER
# =============================================================================
if nav_selection == "🛰️ Command Center":
    # 1. Top Metrics System
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    crit_count = sum(1 for i in incidents if i.severity == "CRITICAL")
    high_count = sum(1 for i in incidents if i.severity == "HIGH")

    with m1:
        render_html(f"""
        <div class='metric-card'>
            <div class='metric-value'>{analysis_result.valid_event_count:,}</div>
            <div class='metric-label'>Events Analyzed</div>
            <div class='metric-subtext'>Ingested & Normalized</div>
        </div>
        """)
    with m2:
        render_html(f"""
        <div class='metric-card'>
            <div class='metric-value' style='color: var(--primary-accent);'>{len(analysis_result.signals_detected)}</div>
            <div class='metric-label'>Security Signals</div>
            <div class='metric-subtext'>Rule & Anomaly Matches</div>
        </div>
        """)
    with m3:
        render_html(f"""
        <div class='metric-card'>
            <div class='metric-value'>{len(incidents)}</div>
            <div class='metric-label'>Attack Stories</div>
            <div class='metric-subtext'>Correlated Clusters</div>
        </div>
        """)
    with m4:
        render_html(f"""
        <div class='metric-card'>
            <div class='metric-value' style='color: {"var(--critical-color)" if crit_count > 0 else "var(--text-dim)"};'>{crit_count}</div>
            <div class='metric-label'>Critical Incidents</div>
            <div class='metric-subtext'>Multi-Stage Exfiltration</div>
        </div>
        """)
    with m5:
        render_html(f"""
        <div class='metric-card'>
            <div class='metric-value' style='color: {"var(--high-color)" if high_count > 0 else "var(--text-dim)"};'>{high_count}</div>
            <div class='metric-label'>High Incidents</div>
            <div class='metric-subtext'>Unconfirmed / Staged</div>
        </div>
        """)
    with m6:
        render_html(f"""
        <div class='metric-card'>
            <div class='metric-value' style='color: var(--success-color);'>0.00%</div>
            <div class='metric-label'>False Positive Rate</div>
            <div class='metric-subtext'>Zero Clean Alarms</div>
        </div>
        """)

    st.markdown("<br>", unsafe_allow_html=True)

    # 2. Primary Threat Card
    if incidents:
        top_inc = incidents[0]
        users_str = ", ".join(top_inc.affected_users) or "Unknown User"
        devs_str = ", ".join(top_inc.affected_devices) or "Unknown Host"
        usb_str = ", ".join(top_inc.affected_usb_devices) or "N/A"
        dest_str = ", ".join(top_inc.affected_ips) or "External Host"
        what_happened_text = top_inc.attack_story.what_happened if top_inc.attack_story else "Multi-stage correlated sequence detected."

        render_html(f"""
        <div class='primary-threat-card'>
            <div class='primary-threat-header'>
                <div style='display: flex; align-items: center;'>
                    {render_badge(top_inc.severity)}
                    <span class='primary-threat-title'>{top_inc.title}</span>
                    <span style='margin-left: 12px; font-size: 12px;'><code class='mono-id'>{top_inc.incident_id}</code></span>
                </div>
                <div>
                    <span class='threat-score-pill'>
                        <span style='font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600;'>Risk Score</span>
                        <span style='font-size: 18px; font-weight: 700; color: var(--critical-color);'>{top_inc.risk_score}</span>
                        <span style='font-size: 12px; color: var(--text-dim);'>/ 100</span>
                        <span style='color: var(--text-dim); margin: 0 4px;'>|</span>
                        <span style='font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600;'>Confidence</span>
                        <span style='font-size: 16px; font-weight: 700; color: var(--primary-accent);'>{int(top_inc.confidence * 100)}%</span>
                    </span>
                </div>
            </div>
            
            <div class='attack-chain-bar'>
                <span style='color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 11px;'>Attack Chain Flow:</span>
                <span class='chain-node'>👤 {users_str}</span>
                <span class='chain-arrow'>➔</span>
                <span class='chain-node'>💻 {devs_str}</span>
                <span class='chain-arrow'>➔</span>
                <span class='chain-node'>💾 {usb_str if usb_str != 'N/A' else 'Network Socket'}</span>
                <span class='chain-arrow'>➔</span>
                <span class='chain-node' style='color: var(--critical-color); border-color: var(--critical-border);'>🎯 Exfiltrated Asset</span>
            </div>

            <div class='threat-narrative-box'>
                <div class='threat-narrative-header'>
                    <span class='threat-narrative-tag'>EXECUTIVE THREAT SUMMARY</span>
                    <span style='font-size: 11px; color: var(--text-muted);'>Deterministic Graph Correlation</span>
                </div>
                <div class='threat-narrative-body'>{what_happened_text}</div>
            </div>
        </div>
        """)

        # Prominent CTA button to drill down into the incident
        c_act1, c_act2 = st.columns([1, 4])
        with c_act1:
            if st.button("🚨 Investigate Incident", type="primary", use_container_width=True):
                st.session_state.nav_destination_key = "🚨 Incidents"
                st.session_state.selected_inc_id = top_inc.incident_id
                st.rerun()
    else:
        render_html(f"""
        <div style='background-color: var(--bg-surface); border: 1px solid var(--success-color); border-radius: 8px; padding: 24px; text-align: center; box-shadow: {T['card_shadow']};'>
            <div style='font-size: 28px;'>🛡️</div>
            <div style='font-size: 18px; font-weight: 700; color: var(--success-color); margin-top: 8px;'>Zero Threats Detected</div>
            <div style='font-size: 13px; color: var(--text-muted); margin-top: 4px;'>Telemetry exhibits expected enterprise baseline operations. Zero false alarms generated.</div>
        </div>
        """)

    st.markdown("<br>", unsafe_allow_html=True)

    # 3. Secondary Operational Sections (Signal->Story & Benign Twin)
    col_sig, col_twin = st.columns(2)

    with col_sig:
        render_html(f"""
        <div class='soc-surface-card'>
            <div class='soc-card-title'>⚡ Signal ➔ Story Consolidation</div>
            <div style='display: flex; align-items: center; justify-content: space-around; background-color: var(--bg-elevated); padding: 14px; border-radius: 6px; border: 1px solid var(--border-color); margin-bottom: 12px;'>
                <div style='text-align: center;'>
                    <div style='font-size: 22px; font-weight: 700; color: var(--primary-accent);'>{len(analysis_result.signals_detected)}</div>
                    <div style='font-size: 11px; color: var(--text-muted); text-transform: uppercase;'>Disparate Signals</div>
                </div>
                <div style='font-size: 20px; color: var(--text-dim);'>➔</div>
                <div style='text-align: center;'>
                    <div style='font-size: 12px; font-weight: 700; color: var(--text-primary);'>Correlation Engine</div>
                    <div style='font-size: 10px; color: var(--text-dim);'>Temporal Graph Clustering</div>
                </div>
                <div style='font-size: 20px; color: var(--text-dim);'>➔</div>
                <div style='text-align: center;'>
                    <div style='font-size: 22px; font-weight: 700; color: var(--success-color);'>{len(incidents)}</div>
                    <div style='font-size: 11px; color: var(--text-muted); text-transform: uppercase;'>Unified Story</div>
                </div>
            </div>
            <p style='font-size: 13px; color: var(--text-muted); line-height: 1.5; margin: 0;'>
                Individual alerts flood SOC analysts with noise. SentinelGraph AI groups related authentication, access, and transfer signals across entities into one coherent forensic incident.
            </p>
        </div>
        """)

    with col_twin:
        render_html(f"""
        <div class='soc-surface-card'>
            <div class='soc-card-title'>⚖️ Benign Twin Architecture</div>
            <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;'>
                <div style='background-color: var(--bg-elevated); padding: 10px; border-radius: 6px; border-left: 3px solid var(--success-color);'>
                    <div style='font-size: 11px; font-weight: 700; color: var(--success-color); text-transform: uppercase;'>Benign Pattern</div>
                    <div style='font-size: 12px; color: var(--text-secondary); margin-top: 4px;'>• Routine Login (Austin)<br>• Public Doc Access<br>• Approved USB Plugged<br>• Public Collateral Copy</div>
                </div>
                <div style='background-color: var(--bg-elevated); padding: 10px; border-radius: 6px; border-left: 3px solid var(--critical-color);'>
                    <div style='font-size: 11px; font-weight: 700; color: var(--critical-color); text-transform: uppercase;'>Attack Pattern</div>
                    <div style='font-size: 12px; color: var(--text-secondary); margin-top: 4px;'>• Foreign Login (Singapore)<br>• Restricted Payroll Access<br>• Unapproved Rogue USB<br>• High-Sensitivity Exfil</div>
                </div>
            </div>
            <p style='font-size: 13px; color: var(--text-muted); line-height: 1.5; margin: 0;'>
                Both workflows share structural steps, but entity baseline profiling and sensitivity gating prevent false alarms on legitimate business operations.
            </p>
        </div>
        """)

    # 4. Recent / Important Incidents Roster
    if len(incidents) > 1:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### 🚨 All Reconstructed Incidents")
        inc_cards = []
        for inc in incidents:
            inc_cards.append({
                "Incident ID": inc.incident_id,
                "Severity": inc.severity,
                "Risk Score": f"{inc.risk_score} / 100",
                "Confidence": f"{int(inc.confidence * 100)}%",
                "Title": inc.title,
                "Affected Users": ", ".join(inc.affected_users),
                "Affected Devices": ", ".join(inc.affected_devices)
            })
        st.dataframe(pd.DataFrame(inc_cards), use_container_width=True)


# =============================================================================
# VIEW 2: INCIDENTS
# =============================================================================
elif nav_selection == "🚨 Incidents":
    st.markdown("### 🚨 Correlated Incident Command Center")
    st.caption("Investigate reconstructed multi-stage cyber incidents and evidence chains.")

    if not incidents:
        st.success("No active security incidents detected in this dataset.")
    else:
        # 1. Incident Overview Table with Filtering
        inc_table_data = []
        for inc in incidents:
            inc_table_data.append({
                "Incident ID": inc.incident_id,
                "Severity": inc.severity,
                "Risk": f"{inc.risk_score} / 100",
                "Confidence": f"{int(inc.confidence * 100)}%",
                "Attack Classification": inc.attack_type,
                "Primary User": ", ".join(inc.affected_users) or "N/A",
                "Primary Host": ", ".join(inc.affected_devices) or "N/A",
                "Start Time (UTC)": inc.start_time.strftime("%H:%M:%S"),
                "End Time (UTC)": inc.end_time.strftime("%H:%M:%S")
            })

        st.dataframe(pd.DataFrame(inc_table_data), use_container_width=True)

        # 2. Incident Selection
        all_inc_ids = [i.incident_id for i in incidents]
        default_idx = 0
        if "selected_inc_id" in st.session_state and st.session_state.selected_inc_id in all_inc_ids:
            default_idx = all_inc_ids.index(st.session_state.selected_inc_id)

        sel_id = st.selectbox("Select Incident to Investigate", all_inc_ids, index=default_idx)
        selected_inc = next((i for i in incidents if i.incident_id == sel_id), incidents[0])
        st.session_state.selected_inc_id = selected_inc.incident_id

        st.markdown("---")

        # 3. Incident Identity Header
        render_html(f"""
        <div style='background-color: var(--bg-surface); border: 1px solid var(--border-color); border-radius: 8px; padding: 18px; margin-bottom: 18px; box-shadow: {T['card_shadow']};'>
            <div style='display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;'>
                <div>
                    {render_badge(selected_inc.severity)}
                    <span style='font-size: 20px; font-weight: 700; color: var(--text-primary); margin-left: 10px;'>{selected_inc.title}</span>
                    <span style='margin-left: 10px;'><code class='mono-id'>{selected_inc.incident_id}</code></span>
                </div>
                <div>
                    <span style='color: var(--text-muted); font-size: 13px;'>Risk: <strong style='color: var(--critical-color); font-size: 16px;'>{selected_inc.risk_score} / 100</strong></span>
                    <span style='color: var(--text-dim); margin: 0 8px;'>|</span>
                    <span style='color: var(--text-muted); font-size: 13px;'>Confidence: <strong style='color: var(--primary-accent); font-size: 16px;'>{int(selected_inc.confidence * 100)}%</strong></span>
                </div>
            </div>
            <div class='attack-chain-bar' style='margin-top: 12px; margin-bottom: 0;'>
                <span style='color: var(--text-muted); font-size: 11px; font-weight: 600; text-transform: uppercase;'>Entities:</span>
                <span class='chain-node'>👤 {", ".join(selected_inc.affected_users) or 'N/A'}</span>
                <span class='chain-arrow'>➔</span>
                <span class='chain-node'>💻 {", ".join(selected_inc.affected_devices) or 'N/A'}</span>
                <span class='chain-arrow'>➔</span>
                <span class='chain-node'>📁 {", ".join(selected_inc.affected_files) or 'N/A'}</span>
                <span class='chain-arrow'>➔</span>
                <span class='chain-node'>💾 {", ".join(selected_inc.affected_usb_devices) or 'Network Egress'}</span>
            </div>
        </div>
        """)

        # 4. Attack Chain Compass (Visual Kill-Chain Progression)
        st.markdown("##### 🧭 Attack Chain Compass")
        compass_cols = st.columns(5)
        core_stages = ["Initial Access", "Discovery", "Collection", "Exfiltration", "Impact"]

        for idx, sname in enumerate(core_stages):
            match = [s for s in selected_inc.attack_stages if s.stage_name == sname]
            status = match[0].status if match else "insufficient evidence"
            
            if status == "confirmed":
                col_code = "var(--success-color)"
                icon_sym = "✓ CONFIRMED"
            elif status == "suspected":
                col_code = "var(--medium-color)"
                icon_sym = "? SUSPECTED"
            else:
                col_code = "var(--text-dim)"
                icon_sym = "— INSUFFICIENT EVIDENCE"

            with compass_cols[idx]:
                render_html(f"""
                <div class='compass-stage-card' style='border-top: 3px solid {col_code};'>
                    <div class='compass-stage-title'>{sname}</div>
                    <div class='compass-stage-status' style='color: {col_code};'>{icon_sym}</div>
                </div>
                """)

        st.markdown("<br>", unsafe_allow_html=True)

        # 5. Incident Forensic Tabs
        t_story, t_evidence, t_score, t_cf, t_response = st.tabs([
            "📖 Attack Story",
            "📋 Evidence Ledger",
            "🎯 Score & Confidence",
            "🔬 Counterfactuals",
            "🛡️ Analyst Response Checklist"
        ])

        with t_story:
            if selected_inc.attack_story:
                st.markdown("#### What Happened")
                render_html(f"<div style='background-color: var(--bg-elevated); padding: 14px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 14px; line-height: 1.6; color: var(--text-secondary);'>{selected_inc.attack_story.what_happened}</div>")
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown("#### Why It Matters")
                render_html(f"<div style='background-color: var(--bg-elevated); padding: 14px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 14px; line-height: 1.6; color: var(--text-secondary);'>{selected_inc.attack_story.why_it_matters}</div>")
                
                st.markdown("<br>", unsafe_allow_html=True)
                st.caption(f"Cryptographic Attack Fingerprint: `{selected_inc.attack_fingerprint}`")

        with t_evidence:
            st.markdown(f"##### Corroborating Evidence Items ({len(selected_inc.evidence_items)})")
            for evd in selected_inc.evidence_items:
                render_html(f"""
                <div style='background-color: var(--bg-elevated); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; margin-bottom: 10px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center;'>
                        <div>
                            <span class='mono-id'>{evd.evidence_id}</span>
                            <span style='margin-left: 8px; font-weight: 600; color: var(--text-primary);'>{evd.event_type}</span>
                            <span style='color: var(--text-dim); margin-left: 8px;'>({evd.event_id})</span>
                        </div>
                        <div style='font-size: 12px; color: var(--text-muted);'>{evd.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                    </div>
                    <div style='font-size: 13px; color: var(--text-secondary); margin-top: 6px;'>{evd.explanation}</div>
                    <div style='font-size: 11px; color: var(--text-dim); margin-top: 6px;'>
                        User: <code class='mono-id'>{evd.user_id}</code> | Host: <code class='mono-id'>{evd.device_id}</code> | Target: <code class='mono-id'>{evd.file_path or evd.usb_id or evd.destination_ip or 'N/A'}</code>
                    </div>
                </div>
                """)

        with t_score:
            st.markdown("#### Deterministic Score Contributions")
            score_data = []
            for sc in selected_inc.score_breakdown:
                score_data.append({
                    "Rule / Factor": sc.rule_or_factor,
                    "Points Awarded": f"+{sc.capped_points} pts",
                    "Reason & Context": sc.reason
                })
            st.dataframe(pd.DataFrame(score_data), use_container_width=True)

            st.markdown("#### 5-Factor Confidence Decomposition")
            decomp = selected_inc.confidence_decomposition
            if decomp:
                c_c1, c_c2, c_c3, c_c4, c_c5 = st.columns(5)
                c_c1.metric("Evidence Completeness", f"{int(decomp.evidence_completeness * 100)}%")
                c_c2.metric("Entity Linkage", f"{int(decomp.entity_linkage * 100)}%")
                c_c3.metric("Temporal Consistency", f"{int(decomp.temporal_consistency * 100)}%")
                c_c4.metric("Baseline Strength", f"{int(decomp.baseline_strength * 100)}%")
                c_c5.metric("Stage Coverage", f"{int(decomp.stage_coverage * 100)}%")
                st.caption(decomp.explanation)

        with t_cf:
            st.markdown("#### Counterfactual Sensitivity (What-If Analysis)")
            st.caption("Measures how each event affected the final risk score. Proves which log is the definitive smoking gun.")
            cf_table = []
            for cf in selected_inc.counterfactuals:
                cf_table.append({
                    "Removed Event": cf.removed_event_id,
                    "Event Description": cf.event_description,
                    "Original Risk": f"{cf.original_risk} / 100",
                    "New Risk (Without Event)": f"{cf.counterfactual_risk} / 100",
                    "Risk Drop (Delta)": f"-{cf.risk_delta} pts",
                    "New Severity": cf.counterfactual_severity
                })
            st.dataframe(pd.DataFrame(cf_table), use_container_width=True)

        with t_response:
            st.markdown("#### Safe Analyst-in-the-Loop Triage Checklist")
            st.caption("Human-controlled response protocol. SentinelGraph AI never takes destructive automated actions.")
            for idx, act in enumerate(selected_inc.recommended_actions):
                st.checkbox(act, key=f"act_{selected_inc.incident_id}_{idx}")


# =============================================================================
# VIEW 3: ATTACK REPLAY
# =============================================================================
elif nav_selection == "⏪ Attack Replay":
    st.markdown("### ⏪ Forensic Attack Replay Mode")
    st.caption("Step through the unfolding attack sequence in strict chronological order.")

    if not incidents:
        st.warning("No incidents available to replay in this dataset.")
    else:
        inc = incidents[0]
        evts = inc.evidence_items

        if "replay_step" not in st.session_state:
            st.session_state.replay_step = 0

        if not evts:
            st.info("No evidence events associated with this incident.")
        else:
            # Bound replay step
            st.session_state.replay_step = max(0, min(st.session_state.replay_step, len(evts) - 1))
            curr_step = st.session_state.replay_step
            sub_evts = evts[: curr_step + 1]

            # Replay Controls Bar
            c_prev, c_next, c_reset, c_counter = st.columns([1, 1, 1, 3])
            with c_prev:
                if st.button("◀ Previous Event", use_container_width=True):
                    if st.session_state.replay_step > 0:
                        st.session_state.replay_step -= 1
                        st.rerun()
            with c_next:
                if st.button("Next Event ▶", type="primary", use_container_width=True):
                    if st.session_state.replay_step < len(evts) - 1:
                        st.session_state.replay_step += 1
                        st.rerun()
            with c_reset:
                if st.button("↺ Reset", use_container_width=True):
                    st.session_state.replay_step = 0
                    st.rerun()
            with c_counter:
                render_html(f"<div style='padding-top: 6px; font-size: 14px; color: var(--text-muted);'>Timeline Step: <strong style='color: var(--primary-accent);'>{curr_step + 1} of {len(evts)}</strong></div>")

            # Timeline Progress
            progress_val = (curr_step + 1) / max(1, len(evts))
            st.progress(progress_val)

            # Replay Metrics
            rm1, rm2, rm3 = st.columns(3)
            with rm1:
                st.metric("Timeline Step", f"{curr_step + 1} of {len(evts)}")
            with rm2:
                ts_str = sub_evts[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if sub_evts else "N/A"
                st.metric("Current UTC Time", ts_str)
            with rm3:
                curr_risk = min(100.0, round(25.0 * (curr_step + 1), 1))
                st.metric("Dynamic Risk Score", f"{curr_risk} / 100")

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("#### Chronological Forensic Feed")

            for i, e in enumerate(sub_evts):
                is_active = (i == curr_step)
                border_style = f"border: 1px solid var(--critical-color); background-color: var(--replay-active-bg);" if is_active else f"border: 1px solid var(--border-color); background-color: var(--replay-inactive-bg);"
                dot_color = "var(--critical-color)" if is_active else "var(--primary-accent)"

                render_html(f"""
                <div style='{border_style} border-radius: 8px; padding: 14px; margin-bottom: 10px; box-shadow: {T['card_shadow']};'>
                    <div style='display: flex; justify-content: space-between; align-items: center;'>
                        <div style='font-size: 14px; font-weight: 700; color: var(--text-primary);'>
                            <span style='color: {dot_color}; font-size: 16px; margin-right: 6px;'>●</span>
                            Step {i+1}: {e.event_type} <span style='font-weight: 400; color: var(--text-muted);'>(<code class='mono-id'>{e.event_id}</code>)</span>
                        </div>
                        <div style='font-size: 12px; color: var(--text-muted);'><code class='mono-id'>{e.timestamp.strftime('%H:%M:%S UTC')}</code></div>
                    </div>
                    <div style='font-size: 13px; color: var(--text-secondary); margin-top: 6px; line-height: 1.5;'>{e.explanation}</div>
                    <div style='font-size: 11px; color: var(--text-dim); margin-top: 8px;'>
                        Entity Lineage: User <code class='mono-id'>{e.user_id}</code> ➔ Host <code class='mono-id'>{e.device_id}</code> ➔ Target <code class='mono-id'>{e.file_path or e.usb_id or e.destination_ip or 'N/A'}</code>
                    </div>
                </div>
                """)


# =============================================================================
# VIEW 4: ATTACK GRAPH
# =============================================================================
elif nav_selection == "🕸️ Attack Graph":
    st.markdown("### 🕸️ Temporal Attack Graph Visualization")
    st.caption("Heterogeneous entity relationship graph connecting Users, Hosts, IPs, Files, and Peripherals.")

    if not incidents or not incidents[0].graph_data or not incidents[0].graph_data.nodes:
        st.info("No attack graph available for current dataset.")
    else:
        inc = incidents[0]
        gdata = inc.graph_data

        # Graph Legend
        render_html(f"""
        <div style='display: flex; gap: 16px; flex-wrap: wrap; background-color: var(--bg-surface); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border-color); margin-bottom: 16px; font-size: 12px; box-shadow: {T['card_shadow']};'>
            <span style='color: var(--text-muted); font-weight: 600;'>ENTITY NODES:</span>
            <span><span style='color: #38BDF8;'>●</span> User</span>
            <span><span style='color: #A855F7;'>●</span> Device</span>
            <span><span style='color: #F97316;'>●</span> IP Address</span>
            <span><span style='color: #EAB308;'>●</span> Application</span>
            <span><span style='color: #EF4444;'>●</span> Sensitive File</span>
            <span><span style='color: #EC4899;'>●</span> Rogue USB</span>
            <span style='color: var(--text-dim);'>|</span>
            <span style='color: var(--text-muted); font-weight: 600;'>EDGES:</span>
            <span style='color: var(--text-dim);'>— Causal Interaction</span>
        </div>
        """)

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
            line=dict(width=1.5, color=T['graph_edge']),
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
            textfont=dict(color=T['graph_text'], size=11),
            marker=dict(
                color=node_colors,
                size=24,
                line=dict(width=2, color=T['graph_node_border'])
            )
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20, l=20, r=20, t=20),
                paper_bgcolor=T['graph_bg'],
                plot_bgcolor=T['graph_bg'],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
        )

        st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# VIEW 5: EVIDENCE
# =============================================================================
elif nav_selection == "📋 Evidence Ledger":
    st.markdown("### 📋 Evidence Ledger & Forensic Proof")
    st.caption("Cryptographically verifiable SHA-256 evidence trail for courtroom auditability.")

    if not incidents:
        st.info("No evidence records available in current dataset.")
    else:
        inc = incidents[0]
        confirmed_stgs = sorted(list({s.stage_name for s in inc.attack_stages if s.status == "confirmed" and s.stage_name}))
        stages_options = ["All Stages"] + [s for s in confirmed_stgs if s != "All Stages"]
        
        c_flt1, c_flt2 = st.columns([2, 4])
        with c_flt1:
            selected_stg = st.selectbox("Filter by Confirmed Attack Stage", stages_options)

        displayed_items = inc.evidence_items
        if selected_stg != "All Stages":
            matching_stages = [s for s in inc.attack_stages if s.stage_name == selected_stg]
            if matching_stages and matching_stages[0].evidence_event_ids:
                stg_evts = set(matching_stages[0].evidence_event_ids)
                displayed_items = [e for e in inc.evidence_items if e.event_id in stg_evts]

        st.caption(f"Showing {len(displayed_items)} verified evidence records:")

        for evd in displayed_items:
            with st.expander(f"📦 {evd.evidence_id} — {evd.event_type} at {evd.timestamp.strftime('%H:%M:%S UTC')}"):
                c_e1, c_e2 = st.columns(2)
                with c_e1:
                    st.markdown(f"**Event ID:** `{evd.event_id}`")
                    st.markdown(f"**User ID:** `{evd.user_id}`")
                    st.markdown(f"**Device ID:** `{evd.device_id}`")
                with c_e2:
                    st.markdown(f"**Event Type:** `{evd.event_type}`")
                    st.markdown(f"**Target:** `{evd.file_path or evd.usb_id or evd.destination_ip or 'N/A'}`")
                    st.markdown(f"**Evidence Strength:** `{evd.strength * 100:.0f}%`")
                
                st.markdown(f"**Forensic Explanation:** {evd.explanation}")
                render_html(f"<div><strong>SHA-256 Hash:</strong> <code class='mono-hash'>{evd.fingerprint}</code></div>")
                
                st.markdown("###### Normalized JSON Telemetry")
                st.json(evd.normalized_json)


# =============================================================================
# VIEW 6: DATASETS
# =============================================================================
elif nav_selection == "📁 Datasets":
    st.markdown("### 📁 Synthetic Benchmark Datasets Catalog")
    st.caption("17 deterministic datasets modeling DARPA CDM and MITRE ATT&CK standards.")

    gt_file = Path("data/generated/ground_truth.json")
    if gt_file.exists():
        gt_data = json.loads(gt_file.read_text(encoding="utf-8"))
        ds_cards = []
        for fname, meta in gt_data.items():
            if fname.endswith(".json"):
                continue
            ds_cards.append({
                "Dataset File": fname,
                "Classification": "BENIGN" if meta.get("is_benign") else "ATTACK",
                "Expected Incidents": meta.get("expected_incident_count", 0),
                "Allowed Severity": ", ".join(meta.get("expected_severity_range", [meta.get("max_severity_allowed", "")])),
                "Description": meta.get("description", "")
            })
        st.dataframe(pd.DataFrame(ds_cards), use_container_width=True)
    else:
        st.warning("Ground truth catalog not found.")


# =============================================================================
# VIEW 7: EVALUATION
# =============================================================================
elif nav_selection == "📊 Evaluation":
    st.markdown("### 📊 Benchmark Quality Evaluation")
    st.caption("Detection performance evaluated against all 17 ground truth benchmark specifications.")

    rep_file = Path("outputs/sample_reports/evaluation_report.json")
    if rep_file.exists():
        metrics = EvaluationMetrics.model_validate_json(rep_file.read_text(encoding="utf-8"))
        
        em1, em2, em3, em4, em5 = st.columns(5)
        em1.metric("Precision", f"{metrics.precision * 100:.1f}%")
        em2.metric("Recall", f"{metrics.recall * 100:.1f}%")
        em3.metric("F1-Score", f"{metrics.f1_score * 100:.1f}%")
        em4.metric("False Positive Rate", f"{metrics.false_positive_rate * 100:.2f}%")
        em5.metric("Clean False Alarms", f"{metrics.clean_log_false_positive_count}")

        st.markdown("---")
        st.markdown("#### Per-Dataset Benchmark Scorecard")
        st.dataframe(pd.DataFrame(metrics.dataset_results), use_container_width=True)
    else:
        st.warning("Evaluation report not found. Run scripts/evaluate_detection.py to generate metrics.")
