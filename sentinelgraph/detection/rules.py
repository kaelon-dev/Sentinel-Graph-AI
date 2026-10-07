"""Deterministic detection engine implementing Rules 1 through 17."""
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sentinelgraph.config import settings
from sentinelgraph.models import NormalizedEvent, BaselineProfile, DetectionSignal
from sentinelgraph.baseline.profiler import BaselineProfiler


class DetectionEngine:
    """Evaluates normalized events against behavioral baselines using deterministic rules."""

    def __init__(self, baseline: Optional[BaselineProfile] = None):
        self.baseline = baseline or BaselineProfile()
        self.weights = settings.rules

    def detect_signals(self, events: List[NormalizedEvent]) -> List[DetectionSignal]:
        """Run all detection rules across a sequence of events."""
        signals: List[DetectionSignal] = []
        
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: (e.timestamp, e.event_id))

        # Track user login failures for Rule 15 (repeated_login_failures)
        failed_logins: Dict[str, List[NormalizedEvent]] = {}
        # Track file accesses for Discovery Rule (Rule 17)
        user_file_accesses: Dict[str, List[NormalizedEvent]] = {}

        for evt in sorted_events:
            user_id = evt.user_id
            device_id = evt.device_id
            b_strength = BaselineProfiler.get_user_baseline_strength(self.baseline, user_id)
            confidence_multiplier = 0.5 if b_strength == "INSUFFICIENT" else (0.75 if b_strength == "WEAK" else 1.0)

            # ------------------------------------------------------------------
            # Rule 15: repeated_login_failures (Credential Access)
            # ------------------------------------------------------------------
            if evt.event_type == "login_failure" and user_id:
                user_fails = failed_logins.setdefault(user_id, [])
                # Keep failures within last 30 minutes
                user_fails.append(evt)
                user_fails = [f for f in user_fails if (evt.timestamp - f.timestamp).total_seconds() <= 1800]
                failed_logins[user_id] = user_fails
                if len(user_fails) >= 3:
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-FAIL-{evt.event_id}",
                            detector_name="repeated_login_failures",
                            signal_score=self.weights.repeated_login_failures,
                            severity="LOW",
                            confidence=0.85 * confidence_multiplier,
                            explanation=f"Multiple failed login attempts ({len(user_fails)}) observed for user {user_id}",
                            event_ids=[f.event_id for f in user_fails],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            affected_ip_address=evt.ip_address,
                            baseline_comparison={"prior_failures_count": len(user_fails)},
                            recommended_stage="Credential Access",
                            evidence={"failure_timestamps": [f.timestamp.isoformat() for f in user_fails]}
                        )
                    )

            # ------------------------------------------------------------------
            # Rule 1 & 2 & 3 & 4: Login Anomaly Rules (Initial Access)
            # ------------------------------------------------------------------
            if evt.event_type == "login_success" and user_id:
                has_country_anomaly = False
                has_ip_anomaly = False

                # Rule 1: unusual_country_login
                if evt.country and not BaselineProfiler.is_country_known(self.baseline, user_id, evt.country):
                    # Only trigger if baseline has known countries
                    if user_id in self.baseline.users and self.baseline.users[user_id].known_countries:
                        has_country_anomaly = True
                        signals.append(
                            DetectionSignal(
                                signal_id=f"SIG-COUNTRY-{evt.event_id}",
                                detector_name="unusual_country_login",
                                signal_score=self.weights.unusual_country_login,
                                severity="MEDIUM",
                                confidence=0.90 * confidence_multiplier,
                                explanation=(
                                    f"User {user_id} logged in from unfamiliar country '{evt.country}' "
                                    f"(known: {', '.join(self.baseline.users[user_id].known_countries)})"
                                ),
                                event_ids=[evt.event_id],
                                timestamp=evt.timestamp,
                                affected_user_id=user_id,
                                affected_device_id=device_id,
                                affected_ip_address=evt.ip_address,
                                baseline_comparison={
                                    "observed_country": evt.country,
                                    "known_countries": self.baseline.users[user_id].known_countries
                                },
                                recommended_stage="Initial Access",
                                evidence={"event_id": evt.event_id, "country": evt.country, "ip": evt.ip_address}
                            )
                        )

                # Rule 2: new_ip_login
                if evt.ip_address and not BaselineProfiler.is_ip_known(self.baseline, user_id, evt.ip_address):
                    if user_id in self.baseline.users and self.baseline.users[user_id].known_ips:
                        has_ip_anomaly = True
                        # If country anomaly was already triggered for this exact event, mark combined flag
                        score = self.weights.new_ip_login
                        signals.append(
                            DetectionSignal(
                                signal_id=f"SIG-IP-{evt.event_id}",
                                detector_name="new_ip_login",
                                signal_score=score,
                                severity="LOW",
                                confidence=0.85 * confidence_multiplier,
                                explanation=f"User {user_id} authenticated from previously unseen IP address '{evt.ip_address}'",
                                event_ids=[evt.event_id],
                                timestamp=evt.timestamp,
                                affected_user_id=user_id,
                                affected_device_id=device_id,
                                affected_ip_address=evt.ip_address,
                                baseline_comparison={
                                    "observed_ip": evt.ip_address,
                                    "known_ips": self.baseline.users[user_id].known_ips[:5]
                                },
                                recommended_stage="Initial Access",
                                evidence={"event_id": evt.event_id, "ip": evt.ip_address},
                                metadata={"co_occurs_with_country_anomaly": has_country_anomaly}
                            )
                        )

                # Rule 3: new_device_login
                if device_id and not BaselineProfiler.is_device_known(self.baseline, user_id, device_id):
                    if user_id in self.baseline.users and self.baseline.users[user_id].known_devices:
                        signals.append(
                            DetectionSignal(
                                signal_id=f"SIG-DEV-{evt.event_id}",
                                detector_name="new_device_login",
                                signal_score=self.weights.new_device_login,
                                severity="LOW",
                                confidence=0.80 * confidence_multiplier,
                                explanation=f"User {user_id} logged into unfamiliar device '{device_id}'",
                                event_ids=[evt.event_id],
                                timestamp=evt.timestamp,
                                affected_user_id=user_id,
                                affected_device_id=device_id,
                                affected_ip_address=evt.ip_address,
                                baseline_comparison={
                                    "observed_device": device_id,
                                    "known_devices": self.baseline.users[user_id].known_devices
                                },
                                recommended_stage="Initial Access",
                                evidence={"event_id": evt.event_id, "device_id": device_id}
                            )
                        )

                # Rule 4: unusual_login_hour
                if not BaselineProfiler.is_login_hour_usual(self.baseline, user_id, evt.timestamp.hour):
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-HOUR-{evt.event_id}",
                            detector_name="unusual_login_hour",
                            signal_score=self.weights.unusual_login_hour,
                            severity="INFO",
                            confidence=0.70 * confidence_multiplier,
                            explanation=f"User {user_id} logged in at unusual hour ({evt.timestamp.hour}:00 UTC)",
                            event_ids=[evt.event_id],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            affected_ip_address=evt.ip_address,
                            baseline_comparison={
                                "observed_hour": evt.timestamp.hour,
                                "usual_hours": self.baseline.users[user_id].usual_login_hours
                            },
                            recommended_stage="Initial Access",
                            evidence={"event_id": evt.event_id, "hour": evt.timestamp.hour}
                        )
                    )

            # ------------------------------------------------------------------
            # Rule 5 & 6: Sensitive File Access Rules (Collection)
            # ------------------------------------------------------------------
            if evt.event_type == "file_access" and evt.file_path and user_id:
                # Rule 17: Track for Discovery
                u_files = user_file_accesses.setdefault(user_id, [])
                u_files.append(evt)
                # Keep accesses in last 15 mins
                u_files = [f for f in u_files if (evt.timestamp - f.timestamp).total_seconds() <= 900]
                user_file_accesses[user_id] = u_files
                distinct_files = set(f.file_path for f in u_files if f.file_path)
                is_recon_tool = any(f.application in ("cmd.exe", "powershell.exe", "bash", "sh") for f in u_files)
                has_recon_path = any("folder" in (f.file_path or "").lower() or "share" in (f.file_path or "").lower() for f in u_files)
                if (len(distinct_files) >= 5 and (is_recon_tool or has_recon_path)) or len(distinct_files) >= 12:
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-DISC-{evt.event_id}",
                            detector_name="discovery_activity",
                            signal_score=self.weights.discovery_activity,
                            severity="LOW",
                            confidence=0.85,
                            explanation=f"Rapid file enumeration/discovery: {len(distinct_files)} distinct files accessed in <15 minutes by {user_id}",
                            event_ids=[f.event_id for f in u_files],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            affected_ip_address=evt.ip_address,
                            baseline_comparison={"distinct_files_count": len(distinct_files)},
                            recommended_stage="Discovery",
                            evidence={"distinct_files": list(distinct_files)}
                        )
                    )

                is_sensitive = evt.file_sensitivity in ("HIGH", "CRITICAL", "CONFIDENTIAL")
                has_prior = BaselineProfiler.has_accessed_sensitive_file(self.baseline, user_id, evt.file_path)

                if is_sensitive and not has_prior:
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-FILEFIRST-{evt.event_id}",
                            detector_name="sensitive_file_first_access",
                            signal_score=self.weights.sensitive_file_first_access,
                            severity="MEDIUM",
                            confidence=0.92,
                            explanation=f"User {user_id} accessed high-sensitivity file '{evt.file_path}' for the first time",
                            event_ids=[evt.event_id],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            affected_ip_address=evt.ip_address,
                            baseline_comparison={
                                "file": evt.file_path,
                                "sensitivity": evt.file_sensitivity,
                                "prior_access": False
                            },
                            recommended_stage="Collection",
                            evidence={"event_id": evt.event_id, "file_path": evt.file_path, "sensitivity": evt.file_sensitivity}
                        )
                    )
                elif is_sensitive and has_prior:
                    # User routinely accesses this file - check if accessed from novel device
                    if device_id and not BaselineProfiler.is_device_known(self.baseline, user_id, device_id):
                        signals.append(
                            DetectionSignal(
                                signal_id=f"SIG-FILEDEV-{evt.event_id}",
                                detector_name="unusual_sensitive_file_access",
                                signal_score=self.weights.unusual_sensitive_file_access,
                                severity="LOW",
                                confidence=0.75,
                                explanation=f"User {user_id} accessed sensitive file '{evt.file_path}' from unfamiliar device {device_id}",
                                event_ids=[evt.event_id],
                                timestamp=evt.timestamp,
                                affected_user_id=user_id,
                                affected_device_id=device_id,
                                baseline_comparison={"file": evt.file_path, "device": device_id},
                                recommended_stage="Collection",
                                evidence={"event_id": evt.event_id, "file_path": evt.file_path}
                            )
                        )

            # ------------------------------------------------------------------
            # Rule 7: unapproved_usb
            # ------------------------------------------------------------------
            if evt.event_type in ("usb_connected", "usb_file_copy") and evt.usb_id:
                if not BaselineProfiler.is_usb_approved(self.baseline, device_id, evt.usb_id):
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-USB-{evt.event_id}",
                            detector_name="unapproved_usb",
                            signal_score=self.weights.unapproved_usb,
                            severity="LOW",
                            confidence=0.90,
                            explanation=f"Unapproved removable USB device '{evt.usb_id}' connected to endpoint {device_id or 'unknown'}",
                            event_ids=[evt.event_id],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            baseline_comparison={"usb_id": evt.usb_id, "approved": False},
                            recommended_stage="Unknown / Suspicious Activity",
                            evidence={"event_id": evt.event_id, "usb_id": evt.usb_id, "device_id": device_id}
                        )
                    )

            # ------------------------------------------------------------------
            # Rule 8: sensitive_file_usb_copy (Primary Exfiltration)
            # ------------------------------------------------------------------
            if evt.event_type == "usb_file_copy" and evt.file_path:
                is_sensitive = evt.file_sensitivity in ("HIGH", "CRITICAL", "CONFIDENTIAL")
                if is_sensitive:
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-USBCOPY-{evt.event_id}",
                            detector_name="sensitive_file_usb_copy",
                            signal_score=self.weights.sensitive_file_usb_copy,
                            severity="HIGH",
                            confidence=0.95,
                            explanation=(
                                f"High-sensitivity file '{evt.file_path}' ({evt.file_sensitivity}) "
                                f"copied to removable USB device '{evt.usb_id or 'UNKNOWN'}'"
                            ),
                            event_ids=[evt.event_id],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            baseline_comparison={
                                "file_path": evt.file_path,
                                "file_sensitivity": evt.file_sensitivity,
                                "usb_id": evt.usb_id
                            },
                            recommended_stage="Exfiltration",
                            evidence={
                                "event_id": evt.event_id,
                                "file_path": evt.file_path,
                                "sensitivity": evt.file_sensitivity,
                                "usb_id": evt.usb_id
                            }
                        )
                    )

            # ------------------------------------------------------------------
            # Rule 9: unusual_external_transfer (Exfiltration)
            # ------------------------------------------------------------------
            if evt.event_type == "network_transfer":
                is_sensitive = evt.file_sensitivity in ("HIGH", "CRITICAL", "CONFIDENTIAL")
                is_large = (evt.bytes_transferred or 0) >= 5 * 1024 * 1024  # >= 5MB
                dest = evt.destination_ip or evt.destination_domain
                dest_known = dest in self.baseline.global_known_destinations if dest else True

                if (is_sensitive or is_large) and not dest_known:
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-NETEXFIL-{evt.event_id}",
                            detector_name="unusual_external_transfer",
                            signal_score=self.weights.unusual_external_transfer,
                            severity="HIGH",
                            confidence=0.92,
                            explanation=(
                                f"External transfer of sensitive or large payload ({evt.bytes_transferred or 0} bytes) "
                                f"to unfamiliar destination '{dest}'"
                            ),
                            event_ids=[evt.event_id],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            baseline_comparison={"destination": dest, "known": False},
                            recommended_stage="Exfiltration",
                            evidence={
                                "event_id": evt.event_id,
                                "destination": dest,
                                "bytes": evt.bytes_transferred,
                                "file_path": evt.file_path
                            }
                        )
                    )

            # ------------------------------------------------------------------
            # Rule 16: off_hours_activity (Supportive)
            # ------------------------------------------------------------------
            if evt.event_type in ("file_access", "usb_file_copy", "network_transfer") and user_id:
                if not BaselineProfiler.is_login_hour_usual(self.baseline, user_id, evt.timestamp.hour):
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-OFFHOUR-{evt.event_id}",
                            detector_name="off_hours_activity",
                            signal_score=self.weights.off_hours_activity,
                            severity="INFO",
                            confidence=0.65,
                            explanation=f"Activity performed outside typical hours ({evt.timestamp.hour}:00 UTC) by {user_id}",
                            event_ids=[evt.event_id],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            baseline_comparison={"hour": evt.timestamp.hour},
                            recommended_stage="Unknown / Suspicious Activity",
                            evidence={"event_id": evt.event_id, "hour": evt.timestamp.hour}
                        )
                    )

            # ------------------------------------------------------------------
            # Rule 12, 13, 14: Novel behavior (Supportive low-weight)
            # ------------------------------------------------------------------
            if evt.application and user_id in self.baseline.users and self.baseline.users[user_id].known_applications:
                if evt.application not in self.baseline.users[user_id].known_applications:
                    signals.append(
                        DetectionSignal(
                            signal_id=f"SIG-NOVELAPP-{evt.event_id}",
                            detector_name="first_seen_application",
                            signal_score=self.weights.first_seen_application,
                            severity="INFO",
                            confidence=0.60,
                            explanation=f"Application '{evt.application}' observed for the first time for user {user_id}",
                            event_ids=[evt.event_id],
                            timestamp=evt.timestamp,
                            affected_user_id=user_id,
                            affected_device_id=device_id,
                            affected_application=evt.application,
                            baseline_comparison={"app": evt.application},
                            recommended_stage="Unknown / Suspicious Activity",
                            evidence={"event_id": evt.event_id, "application": evt.application}
                        )
                    )

        # Deduplicate identical signals
        return self._deduplicate_signals(signals)

    def _deduplicate_signals(self, signals: List[DetectionSignal]) -> List[DetectionSignal]:
        """Eliminate redundant signal duplications while preserving explainability."""
        unique_signals: List[DetectionSignal] = []
        seen = set()

        for sig in signals:
            key = (sig.detector_name, tuple(sorted(sig.event_ids)))
            if key not in seen:
                seen.add(key)
                unique_signals.append(sig)

        return unique_signals
