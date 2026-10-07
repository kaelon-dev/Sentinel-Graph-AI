# SentinelGraph AI 🛡️

> **"From Millions of Logs to One Explainable Attack Story."**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B.svg)](https://streamlit.io)
[![Tests: 30 Passed](https://img.shields.io/badge/Tests-30%20Passed-brightgreen.svg)](tests/)
[![Precision: 100%](https://img.shields.io/badge/Precision-100%25-success.svg)](outputs/sample_reports/evaluation_report.md)
[![FPR: 0.00%](https://img.shields.io/badge/FPR-0.00%25-success.svg)](outputs/sample_reports/evaluation_report.md)

---

## 1. Project Overview & Competition Challenge
**SentinelGraph AI** is an explainable, graph-powered cyber threat intelligence and attack-story reconstruction platform developed for the **HackNex Internal Qualifier (Problem HNX26PSI03: AI-Powered Cyber Threat Intelligence)**.

### The Central Problem
Modern enterprise security tools collect millions of logs across logins, computers, files, removable media, and networks. Each log individually looks benign. Together, they can reveal a coordinated, stealthy breach. Traditional SIEMs overwhelm analysts by turning 5 suspicious events into 5 isolated alerts.

**SentinelGraph AI transforms this paradigm:**
```
     Events ➔ Signals ➔ Relationships ➔ Attack Chain ➔ Evidence Ledger ➔ Attack Story
```
Instead of flooding the SOC with disconnected alerts, it connects actors, hosts, payloads, and per-event timestamps into **ONE explainable attack story** backed by verifiable forensic proof.

---

## 2. Key Product Innovations

| Innovation | Core Purpose | Differentiator |
|---|---|---|
| **First-Class Attack Story** | Grounded natural language narrative generated from verified telemetry. | Never invents facts; every statement is traceable to an event ID. |
| **Evidence Ledger** | Immutable proof backing every confirmed MITRE stage. | No confirmed attack stage exists without proof. |
| **Why This Event Belongs** | Explicit mathematical correlation score between linked events. | Exposes user match (+30), host match (+20), USB (+20), file (+15), temporal proximity (+10). |
| **Temporal Attack Graph** | Directed NetworkX graph encoding entities and temporal continuity. | Colors indicate status (red confirmed, yellow suspicious, blue/green context). |
| **Attack Fingerprint** | Deterministic SHA-256 hash derived from the stage sequence and entity structure. | Matches recurring threat patterns without speculative actor attribution. |
| **Counterfactual What-If** | Deterministic sensitivity analysis: "What if this evidence did not exist?" | Proves exactly which event drove the decision (e.g. without USB copy, risk drops from 100 to 78). |
| **Benign Twin Concept** | Side-by-side comparison of structurally similar benign vs. attack workflows. | Demonstrates why rule counting fails and contextual behavioral baselines succeed. |
| **Signal vs. Story** | Reconstructs 11 atomic signals into 1 correlated incident. | 5 alerts ≠ 5 attacks. |
| **Confidence Decomposition** | 5-dimension breakdown: Completeness, Linkage, Consistency, Baseline, Coverage. | Eliminates mysterious confidence numbers. |
| **Forensic Attack Replay** | Step-by-step playback of unfolding attack timeline in Streamlit. | Interactive hackathon centerpiece updating risk and stages live. |

---

## 3. Architecture Pipeline

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

## 4. Repository Structure

```
sentinelgraph-ai/
├── README.md                           # Master system overview and documentation
├── LICENSE                             # MIT License
├── .gitignore                          # Standard git exclusions
├── requirements.txt                    # Pinned dependency requirements
├── pyproject.toml                      # Package build configuration & pytest options
├── THIRD_PARTY_NOTICES.md              # Open-source third-party licenses
├── CHANGELOG.md                        # Version release history
│
├── data/
│   ├── raw/                            # Uploaded and raw logs directory
│   ├── generated/                      # 17 synthetic benchmark datasets + ground_truth.json
│   └── README.md                       # Synthetic dataset catalog & safety notices
│
├── docs/
│   ├── architecture.md                 # Detailed architecture specification
│   ├── data_schema.md                  # Comprehensive Pydantic schema documentation
│   ├── detection_rules.md              # Rule documentation for detectors 1 through 17
│   ├── evaluation_mapping.md           # Direct mapping to HackNex judging criteria
│   ├── demo_script.md                  # 3-5 minute live presentation script
│   ├── resources_and_attributions.md   # Open-source libraries and citations
│   ├── security_privacy_ethics.md      # Strictly defensive and offline ethical scope
│   └── troubleshooting.md              # Common troubleshooting steps
│
├── scripts/
│   ├── generate_sample_data.py         # Deterministic benchmark dataset generator
│   ├── analyze_sample.py               # CLI tool to analyze any log file
│   ├── evaluate_detection.py           # Benchmark evaluator testing all 17 datasets
│   ├── smoke_test.py                   # Automated end-to-end pipeline smoke test
│   ├── run_all_checks.py               # Master test runner orchestrating all checks
│   └── run_demo.py                     # Automated hackathon console demonstration
│
├── sentinelgraph/
│   ├── __init__.py                     # Package initialization
│   ├── config.py                       # Centralized configuration & thresholds
│   ├── models.py                       # Core Pydantic data models
│   ├── version.py                      # Version information
│   ├── pipeline.py                     # 16-step analysis orchestrator
│   ├── ingestion/                      # Parsers, normalizers, and SHA-256 integrity
│   ├── baseline/                       # Behavioral profiler for users and hosts
│   ├── detection/                      # Rules 1-17, scoring engine, Isolation Forest
│   ├── correlation/                    # Derived sessionizer & attack chain reconstructor
│   ├── graph/                          # NetworkX temporal entity graph engine
│   ├── reporting/                      # Explanations, narratives, and multi-format exporters
│   ├── storage/                        # In-memory and file-backed run repository
│   ├── evaluation/                     # Benchmark metrics formulas & evaluation
│   └── api/                            # FastAPI application and endpoints
│
├── dashboard/
│   └── app.py                          # Streamlit Dark SOC Command Center
│
├── tests/                              # Comprehensive test suite (30 passing tests)
│   ├── test_parsers.py
│   ├── test_integrity.py
│   ├── test_baseline.py
│   ├── test_detectors.py
│   ├── test_sessionization.py
│   ├── test_correlation.py
│   ├── test_scoring.py
│   ├── test_evaluation.py
│   ├── test_exports.py
│   └── test_api.py
│
└── outputs/
    ├── analysis_runs/                  # Persisted JSON analysis runs
    └── sample_reports/                 # Generated forensic reports (JSON, CSV, HTML, MD)
```

---

## 5. Quickstart & Installation

### Prerequisites
- Python 3.11+ (Tested on Python 3.14 on Windows 11)
- Git

### 1. Set Up Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
pip install -e . --no-deps
```

### 3. Generate Benchmark Datasets
```powershell
python scripts/generate_sample_data.py
```

---

## 6. Verification & Testing

### Run Pytest Test Suite
```powershell
pytest -q
```
*Output: 30 passed in ~3.1 seconds.*

### Run End-to-End Pipeline Smoke Test
```powershell
python scripts/smoke_test.py
```

### Run Benchmark Detection Quality Evaluation
```powershell
python scripts/evaluate_detection.py
```

### Run All Master Checks in One Command
```powershell
python scripts/run_all_checks.py
```

---

## 7. Running the Applications

### Launch FastAPI Backend
```powershell
uvicorn sentinelgraph.api.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger API documentation is available at `http://127.0.0.1:8000/docs`.

### Launch Streamlit SOC Dashboard
```powershell
streamlit run dashboard/app.py
```
Open `http://localhost:8501` in your browser.

---

## 8. Benchmark Evaluation Results

Evaluated across **17 deterministic benchmark datasets** mapped against `ground_truth.json`:

| Metric | Result | Target |
|---|---|---|
| **Precision** | **100.0%** | >90.0% |
| **Recall** | **100.0%** | >90.0% |
| **F1-Score** | **100.0%** | >90.0% |
| **False Positive Rate** | **0.00%** | <5.0% |
| **Clean-Log False Positives** | **0** | 0 |
| **Stage-Level Evidence Coverage** | **100.0%** | 100.0% |
| **Timeline Ordering Accuracy** | **100.0%** | 100.0% |

---

## 9. Security, Privacy, and Ethical Scope
- **Strictly Defensive:** Strictly designed for threat intelligence and security operations assistance. Contains no exploit code or offensive functionality.
- **Offline & Private:** Operates 100% locally without cloud APIs, external LLM calls, or internet access.
- **Analyst-in-the-Loop:** Never executes automated destructive actions (such as account locking or host isolation) without human approval.
- **Synthetic Data:** Uses purely synthetic data with RFC 5737 documentation IPs and zero real PII.

---

## 10. License
This project is licensed under the [MIT License](LICENSE).
