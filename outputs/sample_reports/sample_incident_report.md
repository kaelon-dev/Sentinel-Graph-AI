# SentinelGraph AI — Forensic Incident Report

**Incident ID:** `INC-001`  
**Title:** Data Exfiltration via Removable USB (USB-8891)  
**Classification:** Potential Data Exfiltration / Removable Media Theft  
**Severity:** **CRITICAL** (Risk Score: 100.0 / 100)  
**Confidence:** 98% (Evidence completeness: 100%, Entity linkage: 100%, Temporal consistency: 95%, Baseline strength: 95%, Stage coverage: 100%)  
**Attack Fingerprint:** `ce1ea53337d70dfedb1b7fd01b2adc8aac7415d40d0635370566200c741243fe`  
**Window:** 2026-10-12 09:15:00 UTC to 2026-10-12 09:34:00 UTC

---

## 1. Executive Summary & Attack Story
User U102 authenticated from IP 203.0.113.42 (Ukraine), which deviated from normal baseline activity. Subsequently, the same account accessed high-sensitivity file '/finance/payroll_2026.xlsx' (HIGH) for the first time. An unapproved USB device ('USB-8891') was attached to workstation DEV-17, and '/finance/payroll_2026.xlsx' was directly copied to the removable storage.

**Why it matters:**  
The combination of initial access anomaly, first-time sensitive asset access, and physical/network data staging presents strong indicators of unauthorized data exfiltration and potential corporate espionage.

---

## 2. Attack Chain Stages (MITRE-aligned)

| Stage | Status | Confidence | Summary | Evidence Events |
|---|---|---|---|---|
| Initial Access | `confirmed` | 92% | Authentication from unfamiliar external IP/country outside user baseline | EVT-1034 |
| Discovery | `insufficient evidence` | 10% | Insufficient evidence to classify this as a confirmed attack stage. | None |
| Collection | `confirmed` | 93% | First-time or unauthorized access to sensitive file (/finance/payroll_2026.xlsx) | EVT-1042 |
| Exfiltration | `confirmed` | 96% | Sensitive payroll/confidential file copied to unapproved USB USB-8891 | EVT-1050 |
| Impact | `insufficient evidence` | 5% | Insufficient evidence to classify this as a confirmed attack stage. | None |

---

## 3. Evidence Ledger

- **EVD-EVT-1034** (`EVT-1034` at 09:15:00 UTC): User U102 logged in from unfamiliar country 'Ukraine' (known: United States)
  - *Entities:* User: `U102`, Device: `DEV-17`, Target: `None`
  - *Fingerprint:* `2a419847a63d141e...`
- **EVD-EVT-1042** (`EVT-1042` at 09:25:00 UTC): User U102 accessed high-sensitivity file '/finance/payroll_2026.xlsx' for the first time
  - *Entities:* User: `U102`, Device: `DEV-17`, Target: `/finance/payroll_2026.xlsx`
  - *Fingerprint:* `d7ef428fce6b5b4e...`
- **EVD-EVT-1047** (`EVT-1047` at 09:31:00 UTC): Unapproved removable USB device 'USB-8891' connected to endpoint DEV-17
  - *Entities:* User: `U102`, Device: `DEV-17`, Target: `USB-8891`
  - *Fingerprint:* `e8526ce4bfff1c3d...`
- **EVD-EVT-1050** (`EVT-1050` at 09:34:00 UTC): Unapproved removable USB device 'USB-8891' connected to endpoint DEV-17
  - *Entities:* User: `U102`, Device: `DEV-17`, Target: `/finance/payroll_2026.xlsx`
  - *Fingerprint:* `7246c54c1f4467f2...`

---

## 4. Score Breakdown & Severity Gating

- `unusual_country_login`: **+25.0 pts** (User U102 logged in from unfamiliar country 'Ukraine' (known: United States))
- `new_ip_login`: **+5.0 pts** (User U102 authenticated from previously unseen IP address '203.0.113.42' [Deduplicated: co-occurs with country anomaly on same authentication])
- `sensitive_file_first_access`: **+25.0 pts** (User U102 accessed high-sensitivity file '/finance/payroll_2026.xlsx' for the first time)
- `first_seen_application`: **+5.0 pts** (Application 'excel.exe' observed for the first time for user U102)
- `unapproved_usb`: **+20.0 pts** (Unapproved removable USB device 'USB-8891' connected to endpoint DEV-17)
- `first_seen_application`: **+2.0 pts** (Application 'system' observed for the first time for user U102 [Diminishing contribution for repeated supportive signal])
- `unapproved_usb`: **+20.0 pts** (Unapproved removable USB device 'USB-8891' connected to endpoint DEV-17)
- `sensitive_file_usb_copy`: **+45.0 pts** (High-sensitivity file '/finance/payroll_2026.xlsx' (HIGH) copied to removable USB device 'USB-8891')
- `multi_stage_correlation_bonus`: **+15.0 pts** (Incident spans multiple confirmed attack stages: Collection, Exfiltration, Initial Access)

---

## 5. Counterfactual Analysis (What Changed the Decision?)

| Removed Evidence | Original Risk | Counterfactual Risk | Risk Delta | Counterfactual Severity |
|---|---|---|---|---|
| `EVT-1050` (usb_file_copy (/finance/payrol) | 100.0 | 78.0 | **-22.0** | `HIGH` |
| `EVT-1034` (login_success (203.0.113.42)) | 100.0 | 100.0 | **-0.0** | `CRITICAL` |
| `EVT-1042` (file_access (/finance/payroll_) | 100.0 | 100.0 | **-0.0** | `CRITICAL` |
| `EVT-1047` (usb_connected (USB-8891)) | 100.0 | 100.0 | **-0.0** | `CRITICAL` |

---

## 6. Recommended Analyst Response Actions

1. [ ] Verify account ownership and authentication history for U102 with data owner.
1. [ ] Review MFA and identity provider records for unusual token requests or geographic anomalies.
1. [ ] Inspect endpoint logs on DEV-17 for unauthorized process execution or staging archives.
1. [ ] Preserve forensic integrity: Export evidence ledger and memory artifacts before applying host remediation.
1. [ ] Human Approval Gate: Follow organizational incident response policy prior to session revocation or host containment.
1. [ ] Audit physical custody of removable storage serial number(s): USB-8891.
