"""Tests for deterministic derived sessionization."""
from datetime import datetime, timezone
from sentinelgraph.models import NormalizedEvent
from sentinelgraph.correlation.sessionization import Sessionizer


def test_sessionization():
    events = [
        NormalizedEvent(
            event_id="E1",
            timestamp=datetime(2026, 10, 12, 9, 0, 0, tzinfo=timezone.utc),
            event_type="login_success",
            user_id="U101",
            device_id="DEV-01"
        ),
        NormalizedEvent(
            event_id="E2",
            timestamp=datetime(2026, 10, 12, 9, 15, 0, tzinfo=timezone.utc),
            event_type="file_access",
            user_id="U101",
            device_id="DEV-01"
        ),
        # Idle gap of 45 mins (> 30 mins default gap)
        NormalizedEvent(
            event_id="E3",
            timestamp=datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc),
            event_type="file_access",
            user_id="U101",
            device_id="DEV-01"
        )
    ]
    res = Sessionizer.sessionize(events, inactivity_gap_minutes=30)
    assert res[0].derived_session_id == res[1].derived_session_id
    assert res[0].derived_session_id != res[2].derived_session_id
