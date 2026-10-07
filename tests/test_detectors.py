"""Tests for detection rules 1 through 17 and score deduplication."""
from datetime import datetime, timezone
from sentinelgraph.models import NormalizedEvent
from sentinelgraph.baseline.profiler import BaselineProfiler
from sentinelgraph.detection.rules import DetectionEngine
from sentinelgraph.detection.scoring import ScoringEngine


def get_test_baseline():
    events = [
        NormalizedEvent(
            event_id=f"B-{i}",
            timestamp=datetime(2026, 10, 12, 8, i, 0, tzinfo=timezone.utc),
            event_type="login_success",
            user_id="U102",
            device_id="DEV-17",
            country="United States",
            ip_address="198.51.100.10"
        )
        for i in range(20)
    ]
    return BaselineProfiler.build_baseline(events)


def test_unusual_country():
    baseline = get_test_baseline()
    engine = DetectionEngine(baseline=baseline)
    evt = NormalizedEvent(
        event_id="EVT-C1",
        timestamp=datetime(2026, 10, 12, 9, 15, 0, tzinfo=timezone.utc),
        event_type="login_success",
        user_id="U102",
        device_id="DEV-17",
        country="Ukraine",
        ip_address="198.51.100.10"
    )
    signals = engine.detect_signals([evt])
    assert any(s.detector_name == "unusual_country_login" for s in signals)


def test_new_ip():
    baseline = get_test_baseline()
    engine = DetectionEngine(baseline=baseline)
    evt = NormalizedEvent(
        event_id="EVT-IP1",
        timestamp=datetime(2026, 10, 12, 9, 15, 0, tzinfo=timezone.utc),
        event_type="login_success",
        user_id="U102",
        device_id="DEV-17",
        country="United States",
        ip_address="203.0.113.88"
    )
    signals = engine.detect_signals([evt])
    assert any(s.detector_name == "new_ip_login" for s in signals)


def test_signal_deduplication():
    """Ensure one login event does not inflate its score redundantly with co-occurring country and IP."""
    baseline = get_test_baseline()
    engine = DetectionEngine(baseline=baseline)
    # Event with BOTH new country AND new IP
    evt = NormalizedEvent(
        event_id="EVT-BOTH",
        timestamp=datetime(2026, 10, 12, 9, 15, 0, tzinfo=timezone.utc),
        event_type="login_success",
        user_id="U102",
        device_id="DEV-17",
        country="Ukraine",
        ip_address="203.0.113.88"
    )
    signals = engine.detect_signals([evt])
    assert len(signals) == 2
    # Verify scoring deduplication caps redundant IP contribution to 5 pts
    risk, sev, contributions = ScoringEngine.calculate_score(signals, stages=[])
    ip_contrib = [c for c in contributions if c.rule_or_factor == "new_ip_login"][0]
    assert ip_contrib.capped_points == 5.0  # Capped from 10.0 to 5.0
    assert "Deduplicated" in ip_contrib.reason


def test_sensitive_file_usb_copy():
    baseline = get_test_baseline()
    engine = DetectionEngine(baseline=baseline)
    evt = NormalizedEvent(
        event_id="EVT-USBCOPY",
        timestamp=datetime(2026, 10, 12, 9, 34, 0, tzinfo=timezone.utc),
        event_type="usb_file_copy",
        user_id="U102",
        device_id="DEV-17",
        file_path="/finance/payroll_2026.xlsx",
        file_sensitivity="HIGH",
        usb_id="USB-8891"
    )
    signals = engine.detect_signals([evt])
    assert any(s.detector_name == "sensitive_file_usb_copy" for s in signals)
    assert any(s.recommended_stage == "Exfiltration" for s in signals)


def test_repeated_login_failures():
    baseline = get_test_baseline()
    engine = DetectionEngine(baseline=baseline)
    t = datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc)
    evts = [
        NormalizedEvent(
            event_id=f"FAIL-{i}",
            timestamp=datetime(2026, 10, 12, 9, 0, i * 10, tzinfo=timezone.utc),
            event_type="login_failure",
            user_id="U102",
            device_id="DEV-17"
        )
        for i in range(3)
    ]
    signals = engine.detect_signals(evts)
    assert any(s.detector_name == "repeated_login_failures" for s in signals)
