# SentinelGraph AI — Detection Rules Specification

This document details the deterministic rules implemented in `sentinelgraph.detection.rules`, their mathematical weights, MITRE alignment, false-positive protection safeguards, and evidence criteria.

---

## Rule 1: `unusual_country_login`
- **Purpose:** Detect authentication from unfamiliar geopolitical regions.
- **Trigger:** Successful authentication where `event.country` is absent from the user's established baseline.
- **Weight:** +25 points
- **MITRE Stage:** Initial Access
- **Confidence Behavior:** 0.90 confidence with strong baseline; scales down to 0.45 if baseline is `INSUFFICIENT`.
- **False-Positive Protection:** Ignored if baseline has no recorded countries; suppressed when occurring as an isolated single anomaly (gated to MEDIUM max).
- **Evidence Requirements:** Valid `login_success` event containing country and source IP.

---

## Rule 2: `new_ip_login`
- **Purpose:** Flag logins originating from previously unobserved IP addresses.
- **Trigger:** Successful login from an IP address not in the user's known IP history.
- **Weight:** +10 points (capped to +5 if co-occurring with `unusual_country_login` on the same event).
- **MITRE Stage:** Initial Access
- **Confidence Behavior:** 0.85 confidence under mature baselines.
- **False-Positive Protection:** Score deduplication prevents double-counting authentication anomalies on the same login.
- **Evidence Requirements:** Valid `login_success` event with parsed IP address.

---

## Rule 3: `new_device_login`
- **Purpose:** Detect authentication to an endpoint never previously used by the account.
- **Trigger:** `event.device_id` not observed in user's known devices list.
- **Weight:** +15 points
- **MITRE Stage:** Initial Access
- **Confidence Behavior:** 0.80 confidence under mature baselines.
- **False-Positive Protection:** Requires mature device profile (>15 events).

---

## Rule 4: `unusual_login_hour`
- **Purpose:** Provide supportive temporal context for off-hours access.
- **Trigger:** Login timestamp hour outside user's typical login hours (+/- 1-hour buffer).
- **Weight:** +10 points
- **MITRE Stage:** Initial Access
- **Confidence Behavior:** 0.70 confidence; supportive signal only.
- **False-Positive Protection:** Diminishing returns on repeat occurrences; strictly capped from creating high severity alone.

---

## Rule 5: `sensitive_file_first_access`
- **Purpose:** Detect unauthorized or first-time access to high-value assets.
- **Trigger:** Access to file classified as `HIGH` or `CRITICAL` sensitivity with no prior user access history.
- **Weight:** +25 points
- **MITRE Stage:** Collection
- **Confidence Behavior:** 0.92 confidence.
- **False-Positive Protection:** If user has historical access to the document, the rule does not trigger.
- **Evidence Requirements:** File access telemetry containing file path and classification label.

---

## Rule 6: `unusual_sensitive_file_access`
- **Purpose:** Identify sensitive document access from anomalous devices.
- **Trigger:** Routine sensitive file accessed from an unfamiliar endpoint.
- **Weight:** +20 points
- **MITRE Stage:** Collection
- **Confidence Behavior:** 0.75 confidence.

---

## Rule 7: `unapproved_usb`
- **Purpose:** Flag unvetted physical storage media attached to corporate endpoints.
- **Trigger:** Removable media insertion where `usb_id` is absent from global and host-level approved registries.
- **Weight:** +20 points
- **MITRE Stage:** Unknown / Suspicious Activity (Supportive)
- **Confidence Behavior:** 0.90 confidence.
- **False-Positive Protection:** Corporate hardware serials (`USB-CORP-*`, `USB-SEC-OK`) are whitelisted.

---

## Rule 8: `sensitive_file_usb_copy`
- **Purpose:** Detect data exfiltration via removable media.
- **Trigger:** File copy operation writing a `HIGH` or `CRITICAL` sensitivity asset to USB media.
- **Weight:** +45 points
- **MITRE Stage:** Exfiltration (Primary Proof)
- **Confidence Behavior:** 0.95 confidence.
- **False-Positive Protection:** Low-sensitivity/public files copied to USB do not trigger this rule.
- **Evidence Requirements:** Event must contain both `file_path` with high sensitivity and target `usb_id`.

---

## Rule 9: `unusual_external_transfer`
- **Purpose:** Identify egress network exfiltration.
- **Trigger:** Network transfer of sensitive file or high-volume egress (>=5MB) to an unfamiliar external destination.
- **Weight:** +35 points
- **MITRE Stage:** Exfiltration
- **Confidence Behavior:** 0.92 confidence.
- **False-Positive Protection:** Known corporate cloud egress endpoints are whitelisted in the baseline.

---

## Rule 10: `multi_stage_correlation`
- **Purpose:** Reward corroboration across distinct attack phases.
- **Trigger:** Correlated incident spanning 2 or more confirmed MITRE attack stages.
- **Weight:** +15 points (Bonus)
- **MITRE Stage:** Correlation

---

## Rule 11: `same_user_device_correlation`
- **Purpose:** Weight entity continuity between events.
- **Trigger:** Subsequent suspicious event executed by the same user on the same host.
- **Weight:** +10 points (Bonus)

---

## Rule 12, 13, 14: `novel_behavior` (App, Device, Destination)
- **Purpose:** Flag first-seen peripheral entities.
- **Trigger:** First observation of application, host, or network destination.
- **Weight:** +5 points each (Supportive only)
- **False-Positive Protection:** Capped at low severity; cannot escalate incidents independently.

---

## Rule 15: `repeated_login_failures`
- **Purpose:** Detect brute-force or credential spraying attempts.
- **Trigger:** 3 or more `login_failure` events for the same account within 30 minutes.
- **Weight:** +15 points
- **MITRE Stage:** Credential Access
- **Confidence Behavior:** 0.85 confidence.

---

## Rule 16: `off_hours_activity`
- **Purpose:** Flag operational activity occurring during graveyard hours.
- **Trigger:** Sensitive access or peripheral operations outside usual baseline hours.
- **Weight:** +10 points (Supportive only)

---

## Rule 17: `discovery_activity`
- **Purpose:** Detect reconnaissance or directory enumeration.
- **Trigger:** Rapid access to >=5 distinct directories/files using command line utilities (`cmd.exe`, `powershell.exe`) within 15 minutes.
- **Weight:** +15 points
- **MITRE Stage:** Discovery
- **Confidence Behavior:** 0.85 confidence.
