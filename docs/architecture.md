# SentinelGraph AI — Architectural Specification

```
Raw Telemetry Logs (CSV, JSON, JSONL)
                │
                ▼
   [ Ingestion & Provenance Engine ]
   (SHA-256 Digest, Parsing, UTC Normalization, Malformed Preservation)
                │
                ▼
   [ Behavioral Profiling Engine ]
   (Per-User & Per-Device Baselines: Geo, IP, Hours, Assets, USBs)
                │
                ▼
   [ Deterministic Detection Engine ]
   (Rules 1-17, Deduplication Caps, Supplementary Isolation Forest)
                │
                ▼
   [ Sessionization & Correlation ]
   (Derived Sessions, 60m Standard / 72h Extended Window, Entity Affinity)
                │
                ▼
   [ Attack Chain & Evidence Engine ]
   (MITRE Stage Verification, Evidence Ledger, Attack Fingerprint)
                │
                ▼
   [ Scoring, Gating & Counterfactuals ]
   (0-100 Bounded Risk, Severity Gates, What-If Sensitivity Deltas)
                │
                ▼
   [ Temporal Graph Reconstruction ]
   (NetworkX Multi-Entity Directed Graph, Visual Encodings)
                │
        ┌───────┴───────┐
        ▼               ▼
 [ FastAPI REST API ] [ Streamlit SOC Dashboard ]
```

---

## 1. Ingestion & Provenance Subsystem
- **Multi-Format Parsers:** Seamlessly processes CSV, nested JSON, and streaming JSON Lines (`.jsonl`).
- **Integrity Tracking:** Computes cryptographic SHA-256 hashes of all input files. Never executes uploaded files.
- **Strict UTC Normalization:** Parses ISO-8601, epoch timestamps, and legacy formats into timezone-aware UTC `datetime` objects.
- **Malformed Input Preservation:** Non-conforming rows are never discarded silently; they are captured as `InvalidEventRecord` objects.
- **Deterministic Fingerprinting:** Generates SHA-256 digests over core normalized event attributes to identify identical re-transmissions.

---

## 2. Behavioral Profiling Subsystem
- **Entity Baselines:** Dynamically profiles known countries, cities, source IPs, login hours, applications, sensitive files, and approved removable media per user and per host.
- **Maturity Grading:** Assigns explicit baseline confidence tiers (`INSUFFICIENT` < 5 events, `WEAK` 5-15, `MODERATE` 16-40, `STRONG` > 40).
- **Conservative Scoring:** When baseline maturity is low, confidence is mathematically discounted to suppress speculative false alarms.

---

## 3. Detection & Deduplication Engine
- **Deterministic Rule Taxonomy:** Implements 17 rules aligned with MITRE ATT&CK stages.
- **Score Deduplication:** Caps compound authentication signals (e.g. co-occurring unfamiliar country and unfamiliar IP on the same event) to prevent score inflation.
- **Supplementary ML:** Employs an offline `IsolationForest` for statistical outlier flagging, explicitly marked as supplementary and restricted from independently escalating incidents to Critical.

---

## 4. Correlation & Attack Chain Reconstruction
- **Entity Affinity:** Computes weighted affinity across User (+30), Device (+20), Session (+20), Target File (+15), USB Serial (+20), IP (+10), Application (+5), and Stage Continuity (+15).
- **Temporal Windows:** Enforces a strict 60-minute standard correlation window. Sequences separated by >60 minutes cannot merge unless an analyst explicitly enables the 72-hour extended window for multi-day low-and-slow attacks.
- **Decoy Separation:** Unrelated anomalous events from different users or hosts form independent components.

---

## 5. Evidence Ledger & Counterfactual What-If Engine
- **Unforgiving Evidence Linking:** Every confirmed stage must point to empirical `EvidenceItem` records.
- **Deterministic Counterfactuals:** Systematically removes evidence items and recalculates risk/severity deltas, revealing the exact pivot points behind classifications.
- **Confidence Decomposition:** 5-dimensional decomposition across Evidence Completeness, Entity Linkage, Temporal Consistency, Baseline Strength, and Stage Coverage.

---

## 6. Visualization & Reporting
- **Streamlit SOC Dashboard:** Modern dark-theme operations center with Command Center, Incidents, Replay, Graph, Evidence, Datasets, and Evaluation.
- **FastAPI Backend:** Complete REST API supporting headless ingestion, analysis, evidence querying, and reporting.
- **Multi-Format Reports:** Automated exports in JSON, CSV, Markdown, and self-contained dark-mode HTML.
