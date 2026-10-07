"""Tests for behavioral baseline construction, strength calculation, and entity profiling."""
from datetime import datetime, timezone
from sentinelgraph.models import NormalizedEvent
from sentinelgraph.baseline.profiler import BaselineProfiler


def test_baseline_creation():
    events = [
        NormalizedEvent(
            event_id=f"B-{i}",
            timestamp=datetime(2026, 10, 12, 9, i, 0, tzinfo=timezone.utc),
            event_type="login_success",
            user_id="U101",
            device_id="DEV-01",
            country="United States",
            ip_address="198.51.100.10"
        )
        for i in range(10)
    ]
    baseline = BaselineProfiler.build_baseline(events)
    assert "U101" in baseline.users
    assert "DEV-01" in baseline.devices
    assert BaselineProfiler.is_country_known(baseline, "U101", "United States") is True
    assert BaselineProfiler.is_country_known(baseline, "U101", "Ukraine") is False
    assert BaselineProfiler.is_ip_known(baseline, "U101", "198.51.100.10") is True
    assert BaselineProfiler.is_ip_known(baseline, "U101", "203.0.113.50") is False


def test_baseline_strength():
    assert BaselineProfiler.calculate_strength(2) == "INSUFFICIENT"
    assert BaselineProfiler.calculate_strength(10) == "WEAK"
    assert BaselineProfiler.calculate_strength(25) == "MODERATE"
    assert BaselineProfiler.calculate_strength(50) == "STRONG"
