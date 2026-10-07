"""Deterministic sessionization engine based on inactivity timeout gaps and entity continuity."""
from typing import Dict, List, Tuple
from sentinelgraph.config import settings
from sentinelgraph.models import NormalizedEvent


class Sessionizer:
    """Groups chronological events into derived sessions using inactivity gap thresholds."""

    @classmethod
    def sessionize(
        cls,
        events: List[NormalizedEvent],
        inactivity_gap_minutes: int = settings.correlation.session_inactivity_minutes
    ) -> List[NormalizedEvent]:
        """Assign derived_session_id to each event based on user, device, and temporal proximity."""
        if not events:
            return []

        # Sort chronologically
        sorted_events = sorted(events, key=lambda e: (e.timestamp, e.event_id))

        # Track active sessions: key = (user_id, device_id) -> (last_timestamp, session_id, session_counter)
        active_sessions: Dict[Tuple[str, str], Dict] = {}
        session_counters: Dict[Tuple[str, str], int] = {}

        for evt in sorted_events:
            u_key = evt.user_id or "ANON_USER"
            d_key = evt.device_id or "UNKNOWN_DEVICE"
            entity_key = (u_key, d_key)

            current_time = evt.timestamp
            need_new_session = False

            if entity_key not in active_sessions:
                need_new_session = True
            else:
                last_time = active_sessions[entity_key]["last_time"]
                gap_seconds = (current_time - last_time).total_seconds()
                if gap_seconds > inactivity_gap_minutes * 60:
                    need_new_session = True

            if need_new_session:
                count = session_counters.get(entity_key, 0) + 1
                session_counters[entity_key] = count
                sess_id = f"SESS-{u_key}-{d_key}-{count:03d}"
                active_sessions[entity_key] = {
                    "last_time": current_time,
                    "session_id": sess_id
                }
            else:
                active_sessions[entity_key]["last_time"] = current_time

            evt.derived_session_id = active_sessions[entity_key]["session_id"]

        return sorted_events
