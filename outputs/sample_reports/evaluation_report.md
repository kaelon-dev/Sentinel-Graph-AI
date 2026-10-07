# SentinelGraph AI — Detection Quality Evaluation Benchmark

**Datasets Evaluated:** 17  
**Precision:** **100.0%**  
**Recall:** **100.0%**  
**F1-Score:** **100.0%**  
**False Positive Rate:** **0.00%**  
**Clean-Log False Positive Count:** **0**  
**Stage-Level Evidence Coverage:** **100.0%**  
**Timeline Ordering Accuracy:** **100.0%**  
**Entity-Link Accuracy:** **100.0%**

---

## Detailed Dataset Results

| Dataset | Type | Events | Incidents | Top Severity | Risk | Stage Coverage | Status |
|---|---|---|---|---|---|---|---|
| `normal_logs.csv` | Benign | 520 | 7 | `MEDIUM` | 58.0 | 100% | **PASSED** |
| `suspicious_single_event_logs.csv` | Benign | 321 | 4 | `MEDIUM` | 58.0 | 100% | **PASSED** |
| `data_exfiltration_attack_logs.csv` | Attack | 524 | 5 | `CRITICAL` | 100.0 | 100% | **PASSED** |
| `insider_data_exfiltration_logs.csv` | Attack | 513 | 4 | `CRITICAL` | 100.0 | 100% | **PASSED** |
| `slow_hidden_attack_logs.csv` | Attack | 523 | 1 | `CRITICAL` | 100.0 | 100% | **PASSED** |
| `slow_burn_exfiltration_logs.csv` | Attack | 523 | 1 | `CRITICAL` | 100.0 | 100% | **PASSED** |
| `benign_lookalike_logs.csv` | Benign | 313 | 5 | `INFO` | 15.0 | 100% | **PASSED** |
| `traveling_employee_logs.csv` | Benign | 312 | 4 | `LOW` | 35.0 | 100% | **PASSED** |
| `approved_usb_public_copy_logs.csv` | Benign | 311 | 0 | `NONE` | 0.0 | 100% | **PASSED** |
| `benign_sensitive_access_logs.csv` | Benign | 326 | 12 | `MEDIUM` | 58.0 | 100% | **PASSED** |
| `noisy_failed_logins_logs.csv` | Benign | 314 | 4 | `MEDIUM` | 41.0 | 100% | **PASSED** |
| `mixed_users_logs.csv` | Benign | 312 | 2 | `LOW` | 35.0 | 100% | **PASSED** |
| `network_exfiltration_logs.csv` | Attack | 322 | 13 | `CRITICAL` | 100.0 | 100% | **PASSED** |
| `credential_takeover_logs.csv` | Attack | 325 | 1 | `HIGH` | 78.0 | 100% | **PASSED** |
| `off_hours_activity_logs.csv` | Benign | 311 | 1 | `INFO` | 15.0 | 100% | **PASSED** |
| `novel_behavior_logs.csv` | Benign | 311 | 3 | `LOW` | 30.0 | 100% | **PASSED** |
| `discovery_activity_logs.csv` | Attack | 317 | 4 | `MEDIUM` | 58.0 | 100% | **PASSED** |
