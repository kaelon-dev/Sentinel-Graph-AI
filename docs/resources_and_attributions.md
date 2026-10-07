# SentinelGraph AI — Resources and Attributions

This project was built from the ground up for the **HackNex Internal Qualifier (Problem HNX26PSI03: AI-Powered Cyber Threat Intelligence)**.

---

## 1. Core Frameworks and Libraries
- **Python (3.11+ / 3.14):** Underlying deterministic programming language.
- **Pydantic (v2.10+):** High-performance type validation and serialization for domain models (`NormalizedEvent`, `Incident`, `EvidenceItem`, `AttackStory`).
- **NetworkX (v3.4+):** Graph modeling, connected-component correlation, and relationship traversal.
- **FastAPI & Uvicorn:** Modern asynchronous REST API server for headless and microservice deployments.
- **Streamlit (v1.40+):** Security Operations Center (SOC) interactive web dashboard.
- **Plotly:** Interactive multi-entity temporal attack graph visualizer.
- **Pandas:** Tabular log processing, data reshaping, and evaluation metric formatting.
- **Scikit-learn:** Supplementary `IsolationForest` statistical outlier detection.
- **Pytest & HTTPX:** Comprehensive automated unit, integration, and API test execution.

---

## 2. Standards and Taxonomies
- **MITRE ATT&CK Framework:** Kill-chain stage taxonomy (Initial Access, Credential Access, Discovery, Collection, Exfiltration, Impact).
- **RFC 5737:** Documentation IP address reservations (`198.51.100.0/24`, `203.0.113.0/24`) used exclusively across all synthetic datasets.
- **ISO 8601 & UTC:** Timezone normalization standard ensuring temporal consistency across disparate log sources.
