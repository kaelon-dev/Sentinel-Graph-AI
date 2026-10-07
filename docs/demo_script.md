# SentinelGraph AI — Hackathon 3–5 Minute Live Demo Script

**Speaker Persona:** CTO & Lead Security Architect  
**Audience:** Competition Judges & Security Analysts  
**System State:** Streamlit Dashboard loaded at `http://localhost:8501` or running `python scripts/run_demo.py`.

---

## [0:00 - 0:45] Act I: The Problem — Alert Fatigue in the Modern SOC
1. **Open the Dashboard at the Command Center.**
   - *"Good morning, judges. In modern Security Operations Centers, enterprise SIEMs ingest millions of logs every day. Each log individually looks routine: a user logs in, a file is opened, a USB drive is plugged in."*
   - *"Current tools generate 5 independent alerts for 5 suspicious events. The result? Analyst fatigue and missed breaches."*
2. **Point to the Metric Row:**
   - *"Notice our system analyzing over 500 enterprise events. On our clean baseline dataset (`normal_logs.csv`), SentinelGraph AI produces exactly zero critical false alarms."*

---

## [0:45 - 1:45] Act II: The Primary Attack Unfolds
1. **Switch Active Dataset to `data_exfiltration_attack_logs.csv` and navigate to ATTACK REPLAY.**
   - *"Let's see what happens when an adversary strikes. Watch the attack replay unfolding chronologically:"*
2. **Click 'Next Event' (Step 1):**
   - *"09:15 UTC: User U102 logs in from Ukraine (IP 203.0.113.42) — completely outside the user's historical baseline. Risk rises to 25."*
3. **Click 'Next Event' (Step 2):**
   - *"09:25 UTC: 10 minutes later, U102 accesses `/finance/payroll_2026.xlsx`. It's a high-sensitivity file accessed for the very first time. Risk jumps to 50."*
4. **Click 'Next Event' (Step 3):**
   - *"09:31 UTC: An unapproved USB thumb drive (USB-8891) is attached to workstation DEV-17. Risk hits 70."*
5. **Click 'Next Event' (Step 4):**
   - *"09:34 UTC: `payroll_2026.xlsx` is copied directly to USB-8891. Risk reaches 100 / CRITICAL."*

---

## [1:45 - 2:45] Act III: Signal vs. Story & The Evidence Ledger
1. **Navigate to COMMAND CENTER & Point to the Banner:**
   - *"Here is the product differentiator: 11 atomic signals were transformed into ONE explainable attack story."*
   - *"5 alerts do not mean 5 attacks. SentinelGraph AI reconstructs the story: 'Likely Sensitive Data Exfiltration Sequence involving U102 and DEV-17'."*
2. **Navigate to EVIDENCE:**
   - *"Every conclusion points backwards to immutable evidence. Select Exfiltration: here is Event EVT-1050 with its raw JSON, normalized UTC timestamp, and deterministic SHA-256 fingerprint."*
   - *"No confirmed stage exists without proof."*

---

## [2:45 - 3:30] Act IV: Attack Graph & Counterfactual What-If
1. **Navigate to ATTACK GRAPH:**
   - *"Notice the interactive temporal attack graph: Country (Ukraine) -> IP (203.0.113.42) -> User (U102) -> Host (DEV-17) -> File (payroll) -> USB (8891). Confirmed attack evidence nodes glow red, while normal corporate context remains blue."*
2. **Navigate to INCIDENTS -> Counterfactuals:**
   - *"How do we know why the system made this decision? Our deterministic counterfactual engine answers: 'What if the USB copy never happened?'"*
   - *"Without EVT-1050, the risk drops by 22 points, shifting the incident from CRITICAL down to HIGH. Every decision is transparent and mathematical."*

---

## [3:30 - 4:00] Act V: Conclusion
- *"SentinelGraph AI doesn't ask: Which log looks suspicious?*
- *"It asks: What story do these logs tell together, and can we prove every step?"*
- *"Thank you, judges. We are ready for your questions."*
