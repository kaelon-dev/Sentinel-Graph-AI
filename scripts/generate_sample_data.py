"""Deterministic synthetic dataset generator for SentinelGraph AI."""
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

RANDOM_SEED = 42
BASE_TIME = datetime(2026, 10, 12, 8, 0, 0, tzinfo=timezone.utc)

CSV_FIELDS = [
    "event_id", "timestamp", "event_type", "user_id", "user_name",
    "device_id", "device_name", "ip_address", "country", "city",
    "application", "file_path", "file_sensitivity", "usb_id",
    "destination_ip", "destination_domain", "bytes_transferred",
    "action", "status"
]

USERS = ["U101", "U102", "U103", "U104", "U105", "U106"]
DEVICES = ["DEV-11", "DEV-12", "DEV-17", "DEV-20", "DEV-25"]
KNOWN_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.15"]
APPROVED_USBS = ["USB-CORP-001", "USB-CORP-002", "USB-SEC-OK"]
BENIGN_FILES = [
    "/reports/q3_summary.pdf",
    "/docs/handbook_v2.docx",
    "/public/press_release.txt",
    "/shared/meeting_notes.md",
    "/code/frontend/index.ts"
]


def generate_baseline_background(count: int, start_time: datetime) -> List[Dict[str, Any]]:
    """Generate high-volume normal enterprise background telemetry."""
    events = []
    curr = start_time
    for i in range(1, count + 1):
        u = random.choice(USERS)
        d = random.choice(DEVICES)
        ip = random.choice(KNOWN_IPS)
        evt_type = random.choice(["login_success", "file_access", "file_access", "process_execution"])
        curr += timedelta(seconds=random.randint(15, 60))

        row = {
            "event_id": f"BG-EVT-{i:05d}",
            "timestamp": curr.isoformat(),
            "event_type": evt_type,
            "user_id": u,
            "user_name": f"User {u}",
            "device_id": d,
            "device_name": f"Host-{d}",
            "ip_address": ip,
            "country": "United States",
            "city": "Austin",
            "application": "explorer.exe" if "file" in evt_type else "chrome.exe",
            "file_path": random.choice(BENIGN_FILES) if "file" in evt_type else "",
            "file_sensitivity": "LOW" if "file" in evt_type else "",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": random.randint(1024, 65536) if evt_type == "network_transfer" else "",
            "action": evt_type,
            "status": "success"
        }
        events.append(row)
    return events


def write_csv(filepath: Path, records: List[Dict[str, Any]]) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r.get(k, "") for k in CSV_FIELDS})


def main() -> None:
    random.seed(RANDOM_SEED)
    output_dir = Path("data/generated")
    output_dir.mkdir(parents=True, exist_ok=True)

    ground_truth = {}

    # -------------------------------------------------------------------------
    # 1. normal_logs.csv (>= 500 events, 0 HIGH, 0 CRITICAL)
    # -------------------------------------------------------------------------
    normal_events = generate_baseline_background(520, BASE_TIME)
    write_csv(output_dir / "normal_logs.csv", normal_events)
    ground_truth["normal_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 0,
        "max_severity_allowed": "MEDIUM",
        "description": "Normal enterprise activity; zero high/critical incidents expected."
    }

    # -------------------------------------------------------------------------
    # 2. suspicious_single_event_logs.csv (>= 300 events, single anomaly: new country)
    # -------------------------------------------------------------------------
    single_events = generate_baseline_background(320, BASE_TIME)
    # Inject isolated single anomaly
    single_events.insert(150, {
        "event_id": "EVT-ANOM-01",
        "timestamp": (BASE_TIME + timedelta(hours=2)).isoformat(),
        "event_type": "login_success",
        "user_id": "U102",
        "user_name": "User U102",
        "device_id": "DEV-17",
        "device_name": "Host-DEV-17",
        "ip_address": "203.0.113.88",
        "country": "Ukraine",
        "city": "Kyiv",
        "application": "chrome.exe",
        "file_path": "",
        "file_sensitivity": "",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "login_success",
        "status": "success"
    })
    write_csv(output_dir / "suspicious_single_event_logs.csv", single_events)
    ground_truth["suspicious_single_event_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 1,
        "max_severity_allowed": "MEDIUM",
        "expected_severity_range": ["LOW", "MEDIUM"],
        "description": "Isolated login anomaly; must be gated to MEDIUM or lower, never critical."
    }

    # -------------------------------------------------------------------------
    # 3. data_exfiltration_attack_logs.csv (Primary Hackathon Demo Story, >= 500 events)
    # 09:15 Login U102 (Unfamiliar IP 203.0.113.42, Ukraine)
    # 09:25 Access /finance/payroll_2026.xlsx (HIGH)
    # 09:31 USB-8891 connected to DEV-17 (unapproved)
    # 09:34 payroll_2026.xlsx copied to USB-8891
    # -------------------------------------------------------------------------
    primary_events = generate_baseline_background(520, BASE_TIME)
    attack_t0 = BASE_TIME + timedelta(hours=1, minutes=15)  # 09:15
    attack_steps = [
        {
            "event_id": "EVT-1034",
            "timestamp": attack_t0.isoformat(),
            "event_type": "login_success",
            "user_id": "U102",
            "user_name": "User U102",
            "device_id": "DEV-17",
            "device_name": "Host-DEV-17",
            "ip_address": "203.0.113.42",
            "country": "Ukraine",
            "city": "Kyiv",
            "application": "chrome.exe",
            "file_path": "",
            "file_sensitivity": "",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "login_success",
            "status": "success"
        },
        {
            "event_id": "EVT-1042",
            "timestamp": (attack_t0 + timedelta(minutes=10)).isoformat(),  # 09:25
            "event_type": "file_access",
            "user_id": "U102",
            "user_name": "User U102",
            "device_id": "DEV-17",
            "device_name": "Host-DEV-17",
            "ip_address": "203.0.113.42",
            "country": "Ukraine",
            "city": "Kyiv",
            "application": "excel.exe",
            "file_path": "/finance/payroll_2026.xlsx",
            "file_sensitivity": "HIGH",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "file_access",
            "status": "success"
        },
        {
            "event_id": "EVT-1047",
            "timestamp": (attack_t0 + timedelta(minutes=16)).isoformat(),  # 09:31
            "event_type": "usb_connected",
            "user_id": "U102",
            "user_name": "User U102",
            "device_id": "DEV-17",
            "device_name": "Host-DEV-17",
            "ip_address": "203.0.113.42",
            "country": "Ukraine",
            "city": "Kyiv",
            "application": "system",
            "file_path": "",
            "file_sensitivity": "",
            "usb_id": "USB-8891",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "usb_connected",
            "status": "success"
        },
        {
            "event_id": "EVT-1050",
            "timestamp": (attack_t0 + timedelta(minutes=19)).isoformat(),  # 09:34
            "event_type": "usb_file_copy",
            "user_id": "U102",
            "user_name": "User U102",
            "device_id": "DEV-17",
            "device_name": "Host-DEV-17",
            "ip_address": "203.0.113.42",
            "country": "Ukraine",
            "city": "Kyiv",
            "application": "explorer.exe",
            "file_path": "/finance/payroll_2026.xlsx",
            "file_sensitivity": "HIGH",
            "usb_id": "USB-8891",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": 2048500,
            "action": "usb_file_copy",
            "status": "success"
        }
    ]
    primary_events.extend(attack_steps)
    primary_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "data_exfiltration_attack_logs.csv", primary_events)
    ground_truth["data_exfiltration_attack_logs.csv"] = {
        "is_benign": False,
        "expected_incident_count": 1,
        "expected_severity_range": ["HIGH", "CRITICAL"],
        "expected_stages": ["Initial Access", "Collection", "Exfiltration"],
        "expected_attack_type": "Potential Data Exfiltration / Removable Media Theft",
        "primary_user": "U102",
        "primary_device": "DEV-17",
        "evidence_event_ids": ["EVT-1034", "EVT-1042", "EVT-1047", "EVT-1050"],
        "description": "Primary attack: Unfamiliar login -> payroll access -> unapproved USB -> file exfil."
    }

    # -------------------------------------------------------------------------
    # 4. insider_data_exfiltration_logs.csv (>= 500 events)
    # Known user inside enterprise, unusual sensitive access, unknown USB, sensitive USB copy
    # -------------------------------------------------------------------------
    insider_events = generate_baseline_background(510, BASE_TIME)
    insider_t0 = BASE_TIME + timedelta(hours=2)
    insider_steps = [
        {
            "event_id": "INS-101",
            "timestamp": insider_t0.isoformat(),
            "event_type": "file_access",
            "user_id": "U103",
            "user_name": "User U103",
            "device_id": "DEV-12",
            "device_name": "Host-DEV-12",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "acrobat.exe",
            "file_path": "/legal/merger_acquisition_secret.pdf",
            "file_sensitivity": "CRITICAL",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "file_access",
            "status": "success"
        },
        {
            "event_id": "INS-102",
            "timestamp": (insider_t0 + timedelta(minutes=5)).isoformat(),
            "event_type": "usb_connected",
            "user_id": "U103",
            "user_name": "User U103",
            "device_id": "DEV-12",
            "device_name": "Host-DEV-12",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "system",
            "file_path": "",
            "file_sensitivity": "",
            "usb_id": "USB-ROGUE-99",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "usb_connected",
            "status": "success"
        },
        {
            "event_id": "INS-103",
            "timestamp": (insider_t0 + timedelta(minutes=8)).isoformat(),
            "event_type": "usb_file_copy",
            "user_id": "U103",
            "user_name": "User U103",
            "device_id": "DEV-12",
            "device_name": "Host-DEV-12",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "explorer.exe",
            "file_path": "/legal/merger_acquisition_secret.pdf",
            "file_sensitivity": "CRITICAL",
            "usb_id": "USB-ROGUE-99",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": 5000000,
            "action": "usb_file_copy",
            "status": "success"
        }
    ]
    insider_events.extend(insider_steps)
    insider_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "insider_data_exfiltration_logs.csv", insider_events)
    ground_truth["insider_data_exfiltration_logs.csv"] = {
        "is_benign": False,
        "expected_incident_count": 1,
        "expected_severity_range": ["HIGH", "CRITICAL"],
        "expected_stages": ["Collection", "Exfiltration"],
        "expected_attack_type": "Potential Data Exfiltration / Removable Media Theft",
        "description": "Insider threat exfiltrating critical acquisition docs to rogue USB."
    }

    # -------------------------------------------------------------------------
    # 5. slow_hidden_attack_logs.csv / slow_burn_exfiltration_logs.csv (>= 500 events)
    # Spread across 3 days: Day 1 login, Day 2 sensitive access, Day 3 USB copy
    # -------------------------------------------------------------------------
    slow_events = generate_baseline_background(520, BASE_TIME)
    slow_d1 = BASE_TIME + timedelta(days=1, hours=9)
    slow_d2 = BASE_TIME + timedelta(days=2, hours=10)
    slow_d3 = BASE_TIME + timedelta(days=3, hours=11)
    slow_steps = [
        {
            "event_id": "SLOW-01",
            "timestamp": slow_d1.isoformat(),
            "event_type": "login_success",
            "user_id": "U104",
            "user_name": "User U104",
            "device_id": "DEV-20",
            "device_name": "Host-DEV-20",
            "ip_address": "203.0.113.77",
            "country": "Singapore",
            "city": "Singapore",
            "application": "chrome.exe",
            "file_path": "",
            "file_sensitivity": "",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "login_success",
            "status": "success"
        },
        {
            "event_id": "SLOW-02",
            "timestamp": slow_d2.isoformat(),
            "event_type": "file_access",
            "user_id": "U104",
            "user_name": "User U104",
            "device_id": "DEV-20",
            "device_name": "Host-DEV-20",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "code.exe",
            "file_path": "/core/algorithm_patent_source.tar.gz",
            "file_sensitivity": "HIGH",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "file_access",
            "status": "success"
        },
        {
            "event_id": "SLOW-03",
            "timestamp": slow_d3.isoformat(),
            "event_type": "usb_file_copy",
            "user_id": "U104",
            "user_name": "User U104",
            "device_id": "DEV-20",
            "device_name": "Host-DEV-20",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "explorer.exe",
            "file_path": "/core/algorithm_patent_source.tar.gz",
            "file_sensitivity": "HIGH",
            "usb_id": "USB-COVERT-71",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": 15000000,
            "action": "usb_file_copy",
            "status": "success"
        }
    ]
    slow_events.extend(slow_steps)
    slow_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "slow_hidden_attack_logs.csv", slow_events)
    write_csv(output_dir / "slow_burn_exfiltration_logs.csv", slow_events)
    ground_truth["slow_hidden_attack_logs.csv"] = {
        "is_benign": False,
        "expected_incident_count": 1,
        "requires_extended_window": True,
        "expected_severity_range": ["HIGH", "CRITICAL"],
        "description": "Multi-day slow-burn attack detected via extended correlation window."
    }
    ground_truth["slow_burn_exfiltration_logs.csv"] = ground_truth["slow_hidden_attack_logs.csv"]

    # -------------------------------------------------------------------------
    # 6. benign_lookalike_logs.csv (>= 300 events)
    # Known user, known device, approved USB, normal file copy
    # -------------------------------------------------------------------------
    lookalike_events = generate_baseline_background(310, BASE_TIME)
    t_lk = BASE_TIME + timedelta(hours=1)
    lookalike_steps = [
        {
            "event_id": "LK-01",
            "timestamp": t_lk.isoformat(),
            "event_type": "login_success",
            "user_id": "U101",
            "user_name": "User U101",
            "device_id": "DEV-11",
            "device_name": "Host-DEV-11",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "chrome.exe",
            "file_path": "",
            "file_sensitivity": "",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "login_success",
            "status": "success"
        },
        {
            "event_id": "LK-02",
            "timestamp": (t_lk + timedelta(minutes=5)).isoformat(),
            "event_type": "file_access",
            "user_id": "U101",
            "user_name": "User U101",
            "device_id": "DEV-11",
            "device_name": "Host-DEV-11",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "word.exe",
            "file_path": "/public/company_presentation.pptx",
            "file_sensitivity": "LOW",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "file_access",
            "status": "success"
        },
        {
            "event_id": "LK-03",
            "timestamp": (t_lk + timedelta(minutes=10)).isoformat(),
            "event_type": "usb_file_copy",
            "user_id": "U101",
            "user_name": "User U101",
            "device_id": "DEV-11",
            "device_name": "Host-DEV-11",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "explorer.exe",
            "file_path": "/public/company_presentation.pptx",
            "file_sensitivity": "LOW",
            "usb_id": "USB-CORP-001",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": 120000,
            "action": "usb_file_copy",
            "status": "success"
        }
    ]
    lookalike_events.extend(lookalike_steps)
    lookalike_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "benign_lookalike_logs.csv", lookalike_events)
    ground_truth["benign_lookalike_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 0,
        "max_severity_allowed": "MEDIUM",
        "description": "Benign twin sequence: Routine login -> normal file -> approved USB -> public copy."
    }

    # -------------------------------------------------------------------------
    # 7. traveling_employee_logs.csv (Hard Negative)
    # -------------------------------------------------------------------------
    travel_events = generate_baseline_background(310, BASE_TIME)
    travel_events.insert(100, {
        "event_id": "TRV-01",
        "timestamp": (BASE_TIME + timedelta(hours=2)).isoformat(),
        "event_type": "login_success",
        "user_id": "U105",
        "user_name": "User U105",
        "device_id": "DEV-25",
        "device_name": "Host-DEV-25",
        "ip_address": "203.0.113.99",
        "country": "Germany",
        "city": "Berlin",
        "application": "chrome.exe",
        "file_path": "",
        "file_sensitivity": "",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "login_success",
        "status": "success"
    })
    travel_events.insert(101, {
        "event_id": "TRV-02",
        "timestamp": (BASE_TIME + timedelta(hours=2, minutes=5)).isoformat(),
        "event_type": "file_access",
        "user_id": "U105",
        "user_name": "User U105",
        "device_id": "DEV-25",
        "device_name": "Host-DEV-25",
        "ip_address": "203.0.113.99",
        "country": "Germany",
        "city": "Berlin",
        "application": "acrobat.exe",
        "file_path": "/public/travel_policy.pdf",
        "file_sensitivity": "LOW",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "file_access",
        "status": "success"
    })
    travel_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "traveling_employee_logs.csv", travel_events)
    ground_truth["traveling_employee_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 1,
        "max_severity_allowed": "MEDIUM",
        "description": "Legitimate traveling employee; new country login without suspicious follow-on."
    }

    # -------------------------------------------------------------------------
    # 8. approved_usb_public_copy_logs.csv (Hard Negative)
    # -------------------------------------------------------------------------
    usb_pub_events = generate_baseline_background(310, BASE_TIME)
    usb_pub_events.append({
        "event_id": "USB-OK-01",
        "timestamp": (BASE_TIME + timedelta(hours=3)).isoformat(),
        "event_type": "usb_file_copy",
        "user_id": "U101",
        "user_name": "User U101",
        "device_id": "DEV-11",
        "device_name": "Host-DEV-11",
        "ip_address": "198.51.100.10",
        "country": "United States",
        "city": "Austin",
        "application": "explorer.exe",
        "file_path": "/public/marketing_brochure.pdf",
        "file_sensitivity": "LOW",
        "usb_id": "USB-CORP-001",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": 500000,
        "action": "usb_file_copy",
        "status": "success"
    })
    usb_pub_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "approved_usb_public_copy_logs.csv", usb_pub_events)
    ground_truth["approved_usb_public_copy_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 0,
        "max_severity_allowed": "MEDIUM",
        "description": "Approved USB copying low-sensitivity public collateral."
    }

    # -------------------------------------------------------------------------
    # 9. benign_sensitive_access_logs.csv (Hard Negative)
    # -------------------------------------------------------------------------
    benign_sens_events = generate_baseline_background(320, BASE_TIME)
    # Add repeated legitimate access
    for idx in range(6):
        benign_sens_events.append({
            "event_id": f"ROUTINE-SENS-{idx}",
            "timestamp": (BASE_TIME + timedelta(minutes=idx * 20)).isoformat(),
            "event_type": "file_access",
            "user_id": "U106",
            "user_name": "User U106",
            "device_id": "DEV-25",
            "device_name": "Host-DEV-25",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "excel.exe",
            "file_path": "/finance/q3_actuals.xlsx",
            "file_sensitivity": "HIGH",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "file_access",
            "status": "success"
        })
    benign_sens_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "benign_sensitive_access_logs.csv", benign_sens_events)
    ground_truth["benign_sensitive_access_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 0,
        "max_severity_allowed": "MEDIUM",
        "description": "Routine authorized access to sensitive financial files; zero incidents."
    }

    # -------------------------------------------------------------------------
    # 10. noisy_failed_logins_logs.csv (Hard Negative)
    # -------------------------------------------------------------------------
    failed_events = generate_baseline_background(310, BASE_TIME)
    t_fail = BASE_TIME + timedelta(hours=2)
    for f_idx in range(4):
        failed_events.append({
            "event_id": f"NOISE-FAIL-{f_idx}",
            "timestamp": (t_fail + timedelta(seconds=f_idx * 15)).isoformat(),
            "event_type": "login_failure",
            "user_id": "U105",
            "user_name": "User U105",
            "device_id": "DEV-20",
            "device_name": "Host-DEV-20",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "login_service",
            "file_path": "",
            "file_sensitivity": "",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "login_failure",
            "status": "failed"
        })
    failed_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "noisy_failed_logins_logs.csv", failed_events)
    ground_truth["noisy_failed_logins_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 1,
        "max_severity_allowed": "LOW",
        "expected_severity_range": ["INFO", "LOW"],
        "description": "Failed login burst without subsequent access; gated to LOW severity."
    }

    # -------------------------------------------------------------------------
    # 11. mixed_users_logs.csv (Decoy / Separation Test)
    # Two distinct users with weak anomalies in same hour; MUST NOT merge into one incident
    # -------------------------------------------------------------------------
    mixed_events = generate_baseline_background(310, BASE_TIME)
    t_mix = BASE_TIME + timedelta(hours=1, minutes=30)
    mixed_events.append({
        "event_id": "MIX-U101",
        "timestamp": t_mix.isoformat(),
        "event_type": "login_success",
        "user_id": "U101",
        "user_name": "User U101",
        "device_id": "DEV-11",
        "device_name": "Host-DEV-11",
        "ip_address": "203.0.113.11",
        "country": "Canada",
        "city": "Toronto",
        "application": "chrome.exe",
        "file_path": "",
        "file_sensitivity": "",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "login_success",
        "status": "success"
    })
    mixed_events.append({
        "event_id": "MIX-U105",
        "timestamp": (t_mix + timedelta(minutes=5)).isoformat(),
        "event_type": "login_success",
        "user_id": "U105",
        "user_name": "User U105",
        "device_id": "DEV-25",
        "device_name": "Host-DEV-25",
        "ip_address": "203.0.113.55",
        "country": "Japan",
        "city": "Tokyo",
        "application": "firefox.exe",
        "file_path": "",
        "file_sensitivity": "",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "login_success",
        "status": "success"
    })
    mixed_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "mixed_users_logs.csv", mixed_events)
    ground_truth["mixed_users_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 2,
        "must_not_merge": True,
        "max_severity_allowed": "MEDIUM",
        "description": "Two unrelated users with weak login anomalies; entity-aware clustering keeps them separated."
    }

    # -------------------------------------------------------------------------
    # 12. network_exfiltration_logs.csv (Advanced Scenario 27.1)
    # Sensitive file access -> large transfer -> unknown destination
    # -------------------------------------------------------------------------
    net_events = generate_baseline_background(320, BASE_TIME)
    t_net = BASE_TIME + timedelta(hours=1, minutes=45)
    net_events.append({
        "event_id": "NET-01",
        "timestamp": t_net.isoformat(),
        "event_type": "file_access",
        "user_id": "U102",
        "user_name": "User U102",
        "device_id": "DEV-17",
        "device_name": "Host-DEV-17",
        "ip_address": "198.51.100.10",
        "country": "United States",
        "city": "Austin",
        "application": "powershell.exe",
        "file_path": "/database/customer_pii_vault.sql",
        "file_sensitivity": "CRITICAL",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "file_access",
        "status": "success"
    })
    net_events.append({
        "event_id": "NET-02",
        "timestamp": (t_net + timedelta(minutes=4)).isoformat(),
        "event_type": "network_transfer",
        "user_id": "U102",
        "user_name": "User U102",
        "device_id": "DEV-17",
        "device_name": "Host-DEV-17",
        "ip_address": "198.51.100.10",
        "country": "United States",
        "city": "Austin",
        "application": "curl.exe",
        "file_path": "/database/customer_pii_vault.sql",
        "file_sensitivity": "CRITICAL",
        "usb_id": "",
        "destination_ip": "203.0.113.199",
        "destination_domain": "exfil-drop.suspicious.net",
        "bytes_transferred": 45000000,
        "action": "network_transfer",
        "status": "success"
    })
    net_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "network_exfiltration_logs.csv", net_events)
    ground_truth["network_exfiltration_logs.csv"] = {
        "is_benign": False,
        "expected_incident_count": 1,
        "expected_severity_range": ["HIGH", "CRITICAL"],
        "expected_stages": ["Collection", "Exfiltration"],
        "expected_attack_type": "Potential Network Exfiltration / External Egress",
        "description": "Network egress exfiltration of critical SQL database dump to unknown host."
    }

    # -------------------------------------------------------------------------
    # 13. credential_takeover_logs.csv (Scenario 27.2)
    # Failed logins -> successful login -> new country/IP -> sensitive file access
    # -------------------------------------------------------------------------
    takeover_events = generate_baseline_background(320, BASE_TIME)
    t_to = BASE_TIME + timedelta(hours=2, minutes=15)
    for i in range(3):
        takeover_events.append({
            "event_id": f"ATO-FAIL-{i}",
            "timestamp": (t_to + timedelta(seconds=i * 20)).isoformat(),
            "event_type": "login_failure",
            "user_id": "U103",
            "user_name": "User U103",
            "device_id": "DEV-12",
            "device_name": "Host-DEV-12",
            "ip_address": "203.0.113.66",
            "country": "Brazil",
            "city": "Sao Paulo",
            "application": "login_service",
            "file_path": "",
            "file_sensitivity": "",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "login_failure",
            "status": "failed"
        })
    takeover_events.append({
        "event_id": "ATO-SUCC",
        "timestamp": (t_to + timedelta(minutes=2)).isoformat(),
        "event_type": "login_success",
        "user_id": "U103",
        "user_name": "User U103",
        "device_id": "DEV-12",
        "device_name": "Host-DEV-12",
        "ip_address": "203.0.113.66",
        "country": "Brazil",
        "city": "Sao Paulo",
        "application": "chrome.exe",
        "file_path": "",
        "file_sensitivity": "",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "login_success",
        "status": "success"
    })
    takeover_events.append({
        "event_id": "ATO-ACCESS",
        "timestamp": (t_to + timedelta(minutes=6)).isoformat(),
        "event_type": "file_access",
        "user_id": "U103",
        "user_name": "User U103",
        "device_id": "DEV-12",
        "device_name": "Host-DEV-12",
        "ip_address": "203.0.113.66",
        "country": "Brazil",
        "city": "Sao Paulo",
        "application": "word.exe",
        "file_path": "/executive/compensation_2026.docx",
        "file_sensitivity": "HIGH",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "file_access",
        "status": "success"
    })
    takeover_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "credential_takeover_logs.csv", takeover_events)
    ground_truth["credential_takeover_logs.csv"] = {
        "is_benign": False,
        "expected_incident_count": 1,
        "expected_severity_range": ["HIGH"],
        "expected_stages": ["Credential Access", "Initial Access", "Collection"],
        "expected_attack_type": "Account Compromise / Credential Takeover",
        "description": "Brute-force credential takeover leading to sensitive document compromise."
    }

    # -------------------------------------------------------------------------
    # 14. off_hours_activity_logs.csv (Scenario 27.4)
    # -------------------------------------------------------------------------
    off_events = generate_baseline_background(310, BASE_TIME)
    t_off = BASE_TIME.replace(hour=2, minute=15)  # 02:15 AM
    off_events.append({
        "event_id": "OFF-01",
        "timestamp": t_off.isoformat(),
        "event_type": "file_access",
        "user_id": "U101",
        "user_name": "User U101",
        "device_id": "DEV-11",
        "device_name": "Host-DEV-11",
        "ip_address": "198.51.100.10",
        "country": "United States",
        "city": "Austin",
        "application": "notepad.exe",
        "file_path": "/shared/meeting_notes.md",
        "file_sensitivity": "LOW",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "file_access",
        "status": "success"
    })
    off_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "off_hours_activity_logs.csv", off_events)
    ground_truth["off_hours_activity_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 0,
        "max_severity_allowed": "MEDIUM",
        "description": "Late-night document editing without attack progression; zero high/critical incidents."
    }

    # -------------------------------------------------------------------------
    # 15. novel_behavior_logs.csv (Scenario 27.5)
    # First-seen application
    # -------------------------------------------------------------------------
    novel_events = generate_baseline_background(310, BASE_TIME)
    novel_events.append({
        "event_id": "NOV-01",
        "timestamp": (BASE_TIME + timedelta(hours=3)).isoformat(),
        "event_type": "process_execution",
        "user_id": "U102",
        "user_name": "User U102",
        "device_id": "DEV-17",
        "device_name": "Host-DEV-17",
        "ip_address": "198.51.100.10",
        "country": "United States",
        "city": "Austin",
        "application": "wireshark_portable.exe",
        "file_path": "",
        "file_sensitivity": "",
        "usb_id": "",
        "destination_ip": "",
        "destination_domain": "",
        "bytes_transferred": "",
        "action": "process_execution",
        "status": "success"
    })
    novel_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "novel_behavior_logs.csv", novel_events)
    ground_truth["novel_behavior_logs.csv"] = {
        "is_benign": True,
        "expected_incident_count": 0,
        "max_severity_allowed": "MEDIUM",
        "description": "Unusual application launch without exfiltration; supportive signal only."
    }

    # -------------------------------------------------------------------------
    # 16. discovery_activity_logs.csv (Scenario 27.6)
    # Rapid file enumeration (> 5 distinct files in < 15 mins)
    # -------------------------------------------------------------------------
    disc_events = generate_baseline_background(310, BASE_TIME)
    t_disc = BASE_TIME + timedelta(hours=2, minutes=30)
    for i in range(7):
        disc_events.append({
            "event_id": f"DISC-EVT-{i}",
            "timestamp": (t_disc + timedelta(seconds=i * 20)).isoformat(),
            "event_type": "file_access",
            "user_id": "U105",
            "user_name": "User U105",
            "device_id": "DEV-20",
            "device_name": "Host-DEV-20",
            "ip_address": "198.51.100.10",
            "country": "United States",
            "city": "Austin",
            "application": "cmd.exe",
            "file_path": f"/shares/department/folder_{i}/index.txt",
            "file_sensitivity": "LOW",
            "usb_id": "",
            "destination_ip": "",
            "destination_domain": "",
            "bytes_transferred": "",
            "action": "file_access",
            "status": "success"
        })
    disc_events.sort(key=lambda e: e["timestamp"])
    write_csv(output_dir / "discovery_activity_logs.csv", disc_events)
    ground_truth["discovery_activity_logs.csv"] = {
        "is_benign": False,
        "expected_incident_count": 1,
        "expected_stages": ["Discovery"],
        "expected_severity_range": ["LOW", "MEDIUM"],
        "description": "Rapid directory scanning detected as MITRE Discovery stage."
    }

    # -------------------------------------------------------------------------
    # Write ground_truth.json
    # -------------------------------------------------------------------------
    gt_path = output_dir / "ground_truth.json"
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"Successfully generated all {len(ground_truth)} datasets and ground_truth.json in {output_dir}")


if __name__ == "__main__":
    main()
