"""Tests for log parsing, malformed row preservation, duplicate detection, and UTC normalization."""
import json
from datetime import datetime, timezone
import pytest
from sentinelgraph.ingestion.parsers import LogParser
from sentinelgraph.ingestion.normalizer import parse_utc_timestamp, compute_event_fingerprint


def test_csv_parser():
    csv_data = """event_id,timestamp,event_type,user_id,device_id,ip_address,country
EVT-01,2026-10-12T09:00:00Z,login,U101,DEV-01,198.51.100.1,US
EVT-02,2026-10-12T09:05:00+00:00,file_access,U101,DEV-01,198.51.100.1,US
"""
    events, invalids, dups, meta = LogParser.parse_content(csv_data, "test.csv")
    assert len(events) == 2
    assert len(invalids) == 0
    assert dups == 0
    assert events[0].event_id == "EVT-01"
    assert events[0].event_type == "login_success"
    assert events[0].timestamp.tzinfo == timezone.utc


def test_json_parser():
    json_data = json.dumps([
        {"event_id": "J1", "timestamp": "2026-10-12 10:00:00", "event_type": "login", "user": "U102"},
        {"event_id": "J2", "timestamp": "2026-10-12 10:15:00", "event_type": "usb_connected", "usb": "USB-01"}
    ])
    events, invalids, dups, meta = LogParser.parse_content(json_data, "test.json")
    assert len(events) == 2
    assert len(invalids) == 0
    assert events[0].user_id == "U102"
    assert events[1].usb_id == "USB-01"


def test_jsonl_parser():
    jsonl_data = """{"event_id": "L1", "timestamp": "2026-10-12T10:00:00Z", "event_type": "login"}
{"event_id": "L2", "timestamp": "2026-10-12T10:05:00Z", "event_type": "file_access"}
"""
    events, invalids, dups, meta = LogParser.parse_content(jsonl_data, "test.jsonl")
    assert len(events) == 2
    assert len(invalids) == 0


def test_invalid_rows():
    csv_data = """event_id,timestamp,event_type
E1,2026-10-12T09:00:00Z,login
E2,NOT_A_TIMESTAMP,login
E3,2026-10-12T09:10:00Z
"""
    events, invalids, dups, meta = LogParser.parse_content(csv_data, "invalid.csv")
    assert len(events) == 1
    assert len(invalids) == 2
    assert any("timestamp" in inv.reason.lower() for inv in invalids)
    assert any("mismatch" in inv.validation_error.lower() for inv in invalids)


def test_duplicate_events():
    csv_data = """event_id,timestamp,event_type,user_id
DUP-1,2026-10-12T09:00:00Z,login,U101
DUP-1,2026-10-12T09:00:00Z,login,U101
DUP-2,2026-10-12T09:05:00Z,login,U101
"""
    events, invalids, dups, meta = LogParser.parse_content(csv_data, "dups.csv")
    assert len(events) == 2
    assert dups == 1


def test_timezone_normalization():
    dt1 = parse_utc_timestamp("2026-10-12T14:30:00+05:30")
    assert dt1.tzinfo == timezone.utc
    assert dt1.hour == 9
    assert dt1.minute == 0

    dt2 = parse_utc_timestamp("2026-10-12 12:00:00")
    assert dt2.tzinfo == timezone.utc
    assert dt2.hour == 12
