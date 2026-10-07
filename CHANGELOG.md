# Changelog

All notable changes to **SentinelGraph AI** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-07

### Added
- **Core Ingestion & Provenance:**
  - Robust multi-format parsing for CSV, JSON, and JSON Lines logs.
  - Full UTC timestamp parsing and timezone normalization.
  - Deterministic event fingerprinting using SHA-256 digests.
  - Preserved malformed input logging with `InvalidEventRecord`.
  - Duplicate event identification based on event ID and content fingerprints.
- **Behavioral Profiler Engine:**
  - Entity-centric profiles tracking users and devices across countries, IPs, login hours, applications, sensitive files, and approved removable media.
  - Transparent baseline maturity tiers (`INSUFFICIENT`, `WEAK`, `MODERATE`, `STRONG`).
- **Deterministic Detection Engine:**
  - Implemented 17 deterministic rules across MITRE stages (Initial Access, Credential Access, Discovery, Collection, Exfiltration).
  - Explicit score deduplication preventing artificial inflation from co-occurring authentication attributes.
  - Optional supplementary IsolationForest anomaly detection without critical gating permissions.
- **Temporal & Entity Correlation Engine:**
  - Weighted entity affinity scoring across users, devices, sessions, files, USBs, and destinations.
  - Strict 60-minute standard correlation window and 72-hour extended window for slow-burn attacks.
  - Derived sessionization based on idle gap inactivity timeouts.
  - Multi-stage attack chain validation preventing single anomalies from escalating to high/critical.
- **Explainability & Forensic Ledger:**
  - First-class `AttackStory` generation grounded strictly in empirical event telemetry.
  - Immutable `EvidenceItem` ledger with line-item linkage to verified MITRE stages.
  - 5-dimension deterministic Confidence Decomposition.
  - Counterfactual what-if analysis computing exact risk/severity deltas upon evidence removal.
- **Interactive SOC Dashboard (Streamlit):**
  - Dark SOC aesthetic with Command Center, Incidents, Replay, Graph, Evidence, Datasets, and Evaluation views.
  - Stateful chronological Attack Replay mode with interactive step controls.
  - Attack Chain Compass visualizer with verification state indicators.
  - Interactive NetworkX/Plotly temporal attack graph.
  - Signal vs. Story transformation and Benign Twin side-by-side comparators.
- **FastAPI REST Service:**
  - Complete REST endpoints for ingestion, analysis, incident exploration, evidence inspection, graphs, attack stories, and evaluation benchmarks.
  - Non-destructive upload handling with MIME and payload size validation.
- **Evaluation & Verification Suite:**
  - 17 deterministic synthetic benchmark datasets and `ground_truth.json`.
  - Zero false positives on clean benign telemetry; 100% precision, 100% recall, 100% F1-score across evaluated datasets.
  - 30 comprehensive Pytest unit and integration tests passing in under 4 seconds.
