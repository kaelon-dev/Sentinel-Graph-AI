# SentinelGraph AI — Synthetic Datasets & Ground Truth Specification

This directory houses the deterministic synthetic datasets used to benchmark and demonstrate SentinelGraph AI.

## Security & Privacy Notice
All datasets are **100% synthetic**, generated offline using a fixed random seed (`42`).
- **Zero Real PII:** All user identifiers (`U101`-`U106`) and device names (`DEV-11`-`DEV-25`) are synthetic placeholders.
- **Documentation-Safe IP Ranges:** All IP addresses use IANA documentation ranges (`198.51.100.0/24` and `203.0.113.0/24`, RFC 5737).
- **Defensive Scope:** No live offensive payloads or exploit code are contained herein.

---

## Dataset Catalog

| Dataset File | Events | Type | Expected Severity | Key Scenario |
|---|---|---|---|---|
| `normal_logs.csv` | 520 | Benign | 0 Incidents | Routine enterprise background activity; zero false alarms. |
| `suspicious_single_event_logs.csv` | 321 | Benign | LOW / MEDIUM | Isolated unfamiliar country login without sensitive access or exfiltration. |
| `data_exfiltration_attack_logs.csv` | 524 | Attack | CRITICAL (100) | Primary demo: Foreign login -> sensitive payroll access -> unapproved USB -> file copy. |
| `insider_data_exfiltration_logs.csv` | 513 | Attack | CRITICAL (100) | Known insider accessing secret M&A document and exfiltrating to rogue USB. |
| `slow_hidden_attack_logs.csv` | 523 | Attack | CRITICAL (100) | Multi-day low-and-slow attack detected via extended correlation window (72h). |
| `slow_burn_exfiltration_logs.csv` | 523 | Attack | CRITICAL (100) | Identical multi-day attack validating temporal proximity decay. |
| `benign_lookalike_logs.csv` | 313 | Benign | 0 Incidents | Structurally similar twin: Routine login -> normal file -> approved USB -> public copy. |
| `traveling_employee_logs.csv` | 312 | Benign | LOW / MEDIUM | Hard negative: Legitimate employee login from Germany without follow-on threat. |
| `approved_usb_public_copy_logs.csv` | 311 | Benign | 0 Incidents | Hard negative: Approved USB backing up public marketing brochure. |
| `benign_sensitive_access_logs.csv` | 326 | Benign | 0 Incidents | Hard negative: Authorized user routinely reading confidential financial spreadsheets. |
| `noisy_failed_logins_logs.csv` | 314 | Benign | LOW | Hard negative: Cluster of failed logins without subsequent entry or lateral movement. |
| `mixed_users_logs.csv` | 312 | Benign | 2 LOW Incidents | Decoy separation: Two unrelated users with weak login anomalies do NOT merge. |
| `network_exfiltration_logs.csv` | 322 | Attack | CRITICAL (100) | Critical database SQL dump egressed over network transfer to unfamiliar IP. |
| `credential_takeover_logs.csv` | 325 | Attack | HIGH (78) | Account takeover: Brute-force failures -> valid login -> executive document read. |
| `off_hours_activity_logs.csv` | 311 | Benign | 0 Incidents | Late-night document editing without attack progression. |
| `novel_behavior_logs.csv` | 311 | Benign | 0 Incidents | First-seen diagnostic tool launch without exfiltration. |
| `discovery_activity_logs.csv` | 317 | Attack | MEDIUM (58) | Rapid folder and directory enumeration detected as MITRE Discovery. |

---

## Ground Truth (`ground_truth.json`)
The file `ground_truth.json` provides machine-readable labels, expected incident counts, expected MITRE stages, and allowed severity bounds for all benchmark runs.
