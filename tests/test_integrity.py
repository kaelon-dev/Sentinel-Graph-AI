"""Tests for SHA-256 provenance integrity and deterministic event fingerprinting."""
from datetime import datetime, timezone
from sentinelgraph.ingestion.integrity import compute_sha256, generate_source_metadata
from sentinelgraph.ingestion.normalizer import compute_event_fingerprint


def test_source_hash():
    content = b"event_id,timestamp,event_type\nE1,2026-10-12T09:00:00Z,login\n"
    h1 = compute_sha256(content)
    h2 = compute_sha256(content)
    assert len(h1) == 64
    assert h1 == h2

    meta = generate_source_metadata("sample.csv", content, "RUN-TEST")
    assert meta.file_name == "sample.csv"
    assert meta.sha256 == h1
    assert meta.size == len(content)


def test_event_fingerprint():
    ts = datetime(2026, 10, 12, 9, 15, 0, tzinfo=timezone.utc)
    fp1 = compute_event_fingerprint(
        timestamp=ts,
        event_type="login_success",
        user_id="U102",
        device_id="DEV-17",
        ip_address="203.0.113.42",
        file_path=None,
        usb_id=None,
        destination_ip=None,
        bytes_transferred=None
    )
    fp2 = compute_event_fingerprint(
        timestamp=ts,
        event_type="login_success",
        user_id="U102",
        device_id="DEV-17",
        ip_address="203.0.113.42",
        file_path=None,
        usb_id=None,
        destination_ip=None,
        bytes_transferred=None
    )
    assert len(fp1) == 64
    assert fp1 == fp2  # Deterministic repeatability

    # Altering field produces different fingerprint
    fp3 = compute_event_fingerprint(
        timestamp=ts,
        event_type="login_success",
        user_id="U103",
        device_id="DEV-17",
        ip_address="203.0.113.42",
        file_path=None,
        usb_id=None,
        destination_ip=None,
        bytes_transferred=None
    )
    assert fp1 != fp3
