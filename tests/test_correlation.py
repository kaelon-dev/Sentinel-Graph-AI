"""Tests for temporal and entity correlation, incident clustering, and decoy separation."""
from datetime import datetime, timedelta, timezone
from sentinelgraph.models import NormalizedEvent, DetectionSignal
from sentinelgraph.correlation.attack_chain import AttackChainReconstructor


def test_three_hour_separation():
    """Verify two suspicious sequences three hours apart do NOT merge into one incident under 60-min window."""
    t0 = datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(hours=3)  # 3 hours apart

    events = [
        # Sequence A (09:00)
        NormalizedEvent(
            event_id="EVT-A1",
            timestamp=t0,
            event_type="login_success",
            user_id="U102",
            device_id="DEV-17",
            country="Ukraine",
            ip_address="203.0.113.1"
        ),
        NormalizedEvent(
            event_id="EVT-A2",
            timestamp=t0 + timedelta(minutes=10),
            event_type="file_access",
            user_id="U102",
            device_id="DEV-17",
            file_path="/finance/payroll.xlsx",
            file_sensitivity="HIGH"
        ),
        # Sequence B (12:00)
        NormalizedEvent(
            event_id="EVT-B1",
            timestamp=t1,
            event_type="login_success",
            user_id="U102",
            device_id="DEV-17",
            country="Ukraine",
            ip_address="203.0.113.1"
        ),
        NormalizedEvent(
            event_id="EVT-B2",
            timestamp=t1 + timedelta(minutes=10),
            event_type="usb_file_copy",
            user_id="U102",
            device_id="DEV-17",
            file_path="/finance/payroll.xlsx",
            file_sensitivity="HIGH",
            usb_id="USB-999"
        )
    ]

    signals = [
        DetectionSignal(
            signal_id="SIG-A1",
            detector_name="unusual_country_login",
            signal_score=25.0,
            severity="MEDIUM",
            confidence=0.9,
            explanation="Country anomaly A",
            event_ids=["EVT-A1"],
            timestamp=t0,
            recommended_stage="Initial Access"
        ),
        DetectionSignal(
            signal_id="SIG-A2",
            detector_name="sensitive_file_first_access",
            signal_score=25.0,
            severity="MEDIUM",
            confidence=0.9,
            explanation="File anomaly A",
            event_ids=["EVT-A2"],
            timestamp=t0 + timedelta(minutes=10),
            recommended_stage="Collection"
        ),
        DetectionSignal(
            signal_id="SIG-B1",
            detector_name="unusual_country_login",
            signal_score=25.0,
            severity="MEDIUM",
            confidence=0.9,
            explanation="Country anomaly B",
            event_ids=["EVT-B1"],
            timestamp=t1,
            recommended_stage="Initial Access"
        ),
        DetectionSignal(
            signal_id="SIG-B2",
            detector_name="sensitive_file_usb_copy",
            signal_score=45.0,
            severity="HIGH",
            confidence=0.9,
            explanation="USB Copy anomaly B",
            event_ids=["EVT-B2"],
            timestamp=t1 + timedelta(minutes=10),
            recommended_stage="Exfiltration"
        )
    ]

    reconstructor = AttackChainReconstructor()
    incidents = reconstructor.correlate(events, signals, use_extended_window=False)

    # Must produce TWO distinct incidents under normal 60-minute window
    assert len(incidents) == 2, f"Expected 2 separate incidents, got {len(incidents)}"
    # Event IDs must not cross over
    inc1_eids = {e.event_id for e in incidents[0].evidence_items}
    inc2_eids = {e.event_id for e in incidents[1].evidence_items}
    assert inc1_eids.isdisjoint(inc2_eids)


def test_mixed_users_not_merged():
    """Verify two distinct users with anomalies do NOT merge into a single incident."""
    t0 = datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(
            event_id="U1-EVT",
            timestamp=t0,
            event_type="login_success",
            user_id="U101",
            device_id="DEV-01",
            country="Canada"
        ),
        NormalizedEvent(
            event_id="U2-EVT",
            timestamp=t0 + timedelta(minutes=5),
            event_type="login_success",
            user_id="U105",
            device_id="DEV-02",
            country="Japan"
        )
    ]
    signals = [
        DetectionSignal(
            signal_id="S1",
            detector_name="unusual_country_login",
            signal_score=25.0,
            severity="LOW",
            confidence=0.8,
            explanation="U101 country",
            event_ids=["U1-EVT"],
            timestamp=t0
        ),
        DetectionSignal(
            signal_id="S2",
            detector_name="unusual_country_login",
            signal_score=25.0,
            severity="LOW",
            confidence=0.8,
            explanation="U105 country",
            event_ids=["U2-EVT"],
            timestamp=t0 + timedelta(minutes=5)
        )
    ]
    reconstructor = AttackChainReconstructor()
    incidents = reconstructor.correlate(events, signals, use_extended_window=False)
    assert len(incidents) == 2
    assert incidents[0].affected_users != incidents[1].affected_users
