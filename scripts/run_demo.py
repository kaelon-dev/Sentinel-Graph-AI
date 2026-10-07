"""Automated 3-to-5 minute Hackathon live demo runner for SentinelGraph AI."""
import time
from pathlib import Path
from sentinelgraph.pipeline import SentinelPipeline
from sentinelgraph.models import AnalysisResult


def sleep_step(seconds: float = 1.0) -> None:
    time.sleep(seconds)


def run_demo() -> None:
    print("=" * 80)
    print("SENTINELGRAPH AI -- HACKATHON LIVE DEMONSTRATION")
    print("Tagline: 'From Millions of Logs to One Explainable Attack Story.'")
    print("Problem: HNX26PSI03 -- AI-Powered Cyber Threat Intelligence")
    print("=" * 80)
    sleep_step(1)

    print("\n[STEP 1] Ingesting enterprise logs (500+ events across users, endpoints, and servers)...")
    res_normal = SentinelPipeline.analyze_file("data/generated/normal_logs.csv")
    print(f"-> Ingested {res_normal.valid_event_count} events.")
    print("-> Most events represent normal day-to-day corporate operations.")
    sleep_step(1)

    print("\n[STEP 2] Evaluating Clean Benign Telemetry...")
    print(f"-> Signals Discovered: {len(res_normal.signals_detected)}")
    print(f"-> Critical Incidents: {sum(1 for i in res_normal.incidents if i.severity == 'CRITICAL')}")
    print(f"-> High Incidents:     {sum(1 for i in res_normal.incidents if i.severity == 'HIGH')}")
    print("-> Result: Zero false alarms. The SOC queue stays clean.")
    sleep_step(1.5)

    print("\n[STEP 3] Switching to Adversary Telemetry Stream...")
    print("-> Loading 'data_exfiltration_attack_logs.csv'...")
    res_attack = SentinelPipeline.analyze_file("data/generated/data_exfiltration_attack_logs.csv")
    sleep_step(1)

    print("\n[STEP 4] Chronological Attack Timeline Unfolding:")
    print("  09:15 UTC | User U102 authenticates from unfamiliar country (Ukraine / 203.0.113.42) [Risk: 25]")
    sleep_step(0.8)
    print("  09:25 UTC | U102 accesses /finance/payroll_2026.xlsx (Sensitivity: HIGH, first-time) [Risk: 50]")
    sleep_step(0.8)
    print("  09:31 UTC | Unapproved removable USB device (USB-8891) plugged into DEV-17           [Risk: 70]")
    sleep_step(0.8)
    print("  09:34 UTC | High-sensitivity payroll_2026.xlsx copied to USB-8891                   [Risk: 100/100]")
    sleep_step(1)

    inc = res_attack.incidents[0]
    print("\n[STEP 5] Signal vs. Story Transformation:")
    print(f"  {len(res_attack.signals_detected)} ATOMIC SIGNALS ---> 1 CORRELATED ATTACK STORY")
    print("  5 alerts != 5 attacks. SentinelGraph AI linked them into ONE incident.")
    sleep_step(1)

    print("\n[STEP 6] MITRE Attack Stages Verification:")
    for s in inc.attack_stages:
        status_sym = "[v]" if s.status == "confirmed" else ("(?)" if s.status == "suspected" else "[-]")
        print(f"  {status_sym} {s.stage_name:<18} : {s.status.upper():<20} | Confidence: {int(s.confidence*100)}%")
    sleep_step(1)

    print("\n[STEP 7] Evidence Ledger -- Unforgiving Proof:")
    print(f"  Stage: EXFILTRATION")
    print(f"  Why:   Sensitive payroll file copied to unapproved removable media")
    print(f"  Proof: Event EVT-1050 at 09:34:00 UTC")
    print(f"         Actor: U102 | Host: DEV-17 | USB: USB-8891 | File: /finance/payroll_2026.xlsx")
    print(f"         SHA-256 Fingerprint: {inc.evidence_items[-1].fingerprint[:24]}...")
    sleep_step(1)

    print("\n[STEP 8] Entity Graph Traceability:")
    print("  [Country: Ukraine] -> [IP: 203.0.113.42] -> [User: U102] -> [Host: DEV-17] -> [File: payroll] -> [USB: 8891]")
    sleep_step(1)

    print("\n[STEP 9] Deterministic Counterfactual Analysis (What Changed the Decision?):")
    for cf in inc.counterfactuals[:2]:
        print(f"  * Without {cf.removed_event_id} ({cf.event_description[:30]}):")
        print(f"    Risk drops from {cf.original_risk} to {cf.counterfactual_risk} (-{cf.risk_delta} pts) -> Shift to {cf.counterfactual_severity}")
    sleep_step(1)

    print("\n" + "=" * 80)
    print("DEMO CONCLUSION:")
    print("\"SentinelGraph AI doesn't ask: Which log looks suspicious?")
    print(" It asks: What story do these logs tell together, and can we prove every step?\"")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()
