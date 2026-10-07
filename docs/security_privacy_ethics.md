# SentinelGraph AI — Security, Privacy, and Ethical Scope

## 1. Strictly Defensive Cybersecurity Scope
SentinelGraph AI is designed exclusively as an **analyst-assistance and threat intelligence platform**.
The codebase contains:
- **NO offensive payloads:** No exploit generation, shellcode, reverse shells, or remote access Trojans.
- **NO automated destructive actions:** The system will **never** automatically isolate endpoints, terminate critical business processes, delete files, or revoke credentials without explicit human confirmation.
- **Analyst-in-the-loop:** All recommended actions provide safe, structured triage checklists requiring human SOC verification and compliance with organizational change management.

---

## 2. Complete Offline Operation & Privacy
- **Zero Cloud Leakage:** SentinelGraph AI runs 100% locally and offline.
- **No Third-Party AI/LLM APIs:** Attack stories, counterfactuals, and confidence calculations are derived deterministically using Python algorithms and templated forensic narratives. No proprietary security telemetry is ever sent over the internet.
- **No API Keys or Telemetry Trackers:** Works without external API keys, external database servers, or cloud dependencies.

---

## 3. Data Integrity and Synthetic Safety
- **100% Synthetic Datasets:** All generated benchmark datasets contain zero personally identifiable information (PII). All user IDs (`U101`-`U106`) and device hostnames (`DEV-11`-`DEV-25`) are simulated.
- **Documentation IPs:** All IP addresses adhere to RFC 5737 (`198.51.100.0/24` and `203.0.113.0/24`), ensuring zero risk of accidental scanning or traffic routing to real-world hosts.
- **Safe File Uploads:** Uploaded logs are treated strictly as read-only data strings and parsed row-by-row. Uploaded content is never executed or evaluated as executable script code.
