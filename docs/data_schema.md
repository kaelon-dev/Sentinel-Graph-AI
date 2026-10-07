# SentinelGraph AI — Data Schema Specification

This document details the Pydantic domain models governing input ingestion, intermediate representations, and exported threat intelligence.

---

## 1. NormalizedEvent Schema
Represents the unified internal telemetry schema across all log formats.

| Field | Type | Description |
|---|---|---|
| `event_id` | `str` | Unique event identifier. |
| `timestamp` | `datetime` | UTC timezone-aware datetime of event occurrence. |
| `event_type` | `str` | Standard taxonomy (`login_success`, `login_failure`, `file_access`, `usb_connected`, `usb_file_copy`, `network_transfer`, `process_execution`, `alert`). |
| `user_id` | `Optional[str]` | Unique identifier of actor/user. |
| `user_name` | `Optional[str]` | Display name of user. |
| `device_id` | `Optional[str]` | Workstation/host identifier. |
| `device_name` | `Optional[str]` | Hostname or machine name. |
| `ip_address` | `Optional[str]` | Source IP address. |
| `country` | `Optional[str]` | Geolocation country name. |
| `city` | `Optional[str]` | Geolocation city name. |
| `application` | `Optional[str]` | Process or software binary. |
| `file_path` | `Optional[str]` | Target filesystem path. |
| `file_sensitivity` | `Optional[str]` | Normalized classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `usb_id` | `Optional[str]` | Removable storage hardware serial ID. |
| `destination_ip` | `Optional[str]` | Egress network transfer target IP. |
| `destination_domain` | `Optional[str]` | Egress network transfer target domain. |
| `bytes_transferred` | `Optional[int]` | Payload byte volume. |
| `action` | `Optional[str]` | Raw source action label. |
| `status` | `Optional[str]` | Outcome (`success`, `failed`). |
| `metadata` | `Dict[str, Any]` | Extensible contextual attributes. |
| `source_file` | `Optional[str]` | Ingested source filename. |
| `raw_event` | `Optional[dict]` | Preserved verbatim input record. |
| `event_fingerprint` | `str` | SHA-256 digest of normalized event fields. |
| `derived_session_id` | `Optional[str]` | Inactivity-derived session grouping ID. |

---

## 2. InvalidEventRecord Schema
Preserves unparseable or schema-violating rows for forensic auditability.

| Field | Type | Description |
|---|---|---|
| `source_file` | `str` | Name of file containing the invalid entry. |
| `row_number` | `int` | 1-indexed record number in source. |
| `raw_record` | `Any` | Unparsed row string or malformed dictionary. |
| `validation_error` | `str` | Exception message or parsing error. |
| `reason` | `str` | High-level diagnostic reason. |

---

## 3. EvidenceItem Schema
Structured evidence proof linking raw telemetry to attack stages.

| Field | Type | Description |
|---|---|---|
| `evidence_id` | `str` | Unique proof identifier (`EVD-EVT-XXXX`). |
| `event_id` | `str` | Underlying log event ID. |
| `timestamp` | `datetime` | Event occurrence timestamp (UTC). |
| `event_type` | `str` | Type of log event. |
| `user_id` / `device_id` | `Optional[str]` | Correlated actors and endpoints. |
| `raw_json` | `dict` | Original unparsed event record. |
| `normalized_json` | `dict` | Serialized normalized representation. |
| `fingerprint` | `str` | SHA-256 content verification hash. |
| `explanation` | `str` | Forensic explanation of why this proves the stage. |
| `strength` | `float` | Evidentiary weight (0.0 to 1.0). |

---

## 4. AttackStage Schema
Represents verified attack phases.

| Field | Type | Description |
|---|---|---|
| `stage_id` | `str` | Stage identifier (`STG-01` to `STG-06`). |
| `stage_name` | `str` | Name (`Initial Access`, `Credential Access`, `Discovery`, `Collection`, `Exfiltration`, `Impact`). |
| `status` | `str` | Verification tier (`confirmed`, `suspected`, `insufficient evidence`). |
| `confidence` | `float` | Stage-specific confidence score. |
| `evidence_event_ids` | `List[str]` | Specific log event IDs proving this stage. |
| `missing_evidence` | `List[str]` | Telemetry gaps required to upgrade unconfirmed stages. |

---

## 5. Incident Schema
Top-level correlated security story.

| Field | Type | Description |
|---|---|---|
| `incident_id` | `str` | Unique incident identifier (`INC-001`). |
| `title` | `str` | Descriptive incident headline. |
| `severity` | `str` | Bounded tier (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `risk_score` | `float` | Deterministic score from 0.0 to 100.0. |
| `confidence` | `float` | Multi-factor confidence score (0.0 to 1.0). |
| `attack_stages` | `List[AttackStage]` | Verified MITRE kill-chain progression. |
| `evidence_items` | `List[EvidenceItem]` | Line-item evidence proofs. |
| `attack_story` | `AttackStory` | Explainable, grounded natural language narrative. |
| `counterfactuals` | `List[CounterfactualResult]` | Deterministic sensitivity analysis deltas. |
| `graph_data` | `TemporalGraphData` | Multi-entity temporal attack graph. |
