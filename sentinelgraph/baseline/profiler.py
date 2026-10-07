"""Behavioral baseline profiling engine for users and devices."""
from typing import List, Optional
from sentinelgraph.models import NormalizedEvent, BaselineProfile, UserProfile, DeviceProfile


class BaselineProfiler:
    """Constructs and queries behavioral baselines for anomaly detection."""

    @staticmethod
    def calculate_strength(event_count: int) -> str:
        """Determine baseline maturity based on historical observation volume."""
        if event_count < 5:
            return "INSUFFICIENT"
        elif event_count <= 15:
            return "WEAK"
        elif event_count <= 40:
            return "MODERATE"
        return "STRONG"

    @classmethod
    def build_baseline(
        cls,
        events: List[NormalizedEvent],
        initial_approved_usbs: Optional[List[str]] = None
    ) -> BaselineProfile:
        """Build a comprehensive baseline from a sequence of events."""
        profile = BaselineProfile(
            global_approved_usbs=list(initial_approved_usbs or ["USB-CORP-001", "USB-CORP-002", "USB-CORP-003", "USB-SEC-OK"])
        )

        for evt in events:
            cls.update_baseline(profile, evt)

        return profile

    @classmethod
    def update_baseline(cls, profile: BaselineProfile, evt: NormalizedEvent) -> None:
        """Update user and device profiles with observations from an event."""
        profile.total_events_observed += 1

        # User profile update
        if evt.user_id:
            user_prof = profile.users.setdefault(
                evt.user_id,
                UserProfile(user_id=evt.user_id)
            )
            user_prof.event_count += 1
            user_prof.baseline_strength = cls.calculate_strength(user_prof.event_count)

            if evt.country and evt.country not in user_prof.known_countries:
                user_prof.known_countries.append(evt.country)
            if evt.city and evt.city not in user_prof.known_cities:
                user_prof.known_cities.append(evt.city)
            if evt.ip_address and evt.ip_address not in user_prof.known_ips:
                user_prof.known_ips.append(evt.ip_address)
            if evt.device_id and evt.device_id not in user_prof.known_devices:
                user_prof.known_devices.append(evt.device_id)
            if evt.application and evt.application not in user_prof.known_applications:
                user_prof.known_applications.append(evt.application)

            hour = evt.timestamp.hour
            if hour not in user_prof.usual_login_hours:
                user_prof.usual_login_hours.append(hour)

            if evt.file_path:
                if evt.file_path not in user_prof.common_files:
                    user_prof.common_files.append(evt.file_path)
                if evt.file_sensitivity in ("HIGH", "CRITICAL", "CONFIDENTIAL"):
                    if evt.file_path not in user_prof.sensitive_files_accessed:
                        user_prof.sensitive_files_accessed.append(evt.file_path)

        # Device profile update
        if evt.device_id:
            dev_prof = profile.devices.setdefault(
                evt.device_id,
                DeviceProfile(device_id=evt.device_id)
            )
            dev_prof.event_count += 1
            dev_prof.baseline_strength = cls.calculate_strength(dev_prof.event_count)

            if evt.user_id and evt.user_id not in dev_prof.known_users:
                dev_prof.known_users.append(evt.user_id)
            if evt.ip_address and evt.ip_address not in dev_prof.known_ips:
                dev_prof.known_ips.append(evt.ip_address)
            if evt.application and evt.application not in dev_prof.known_applications:
                dev_prof.known_applications.append(evt.application)

        # Global destinations
        if evt.destination_ip and evt.destination_ip not in profile.global_known_destinations:
            profile.global_known_destinations.append(evt.destination_ip)
        if evt.destination_domain and evt.destination_domain not in profile.global_known_destinations:
            profile.global_known_destinations.append(evt.destination_domain)

    @classmethod
    def is_country_known(cls, profile: BaselineProfile, user_id: str, country: Optional[str]) -> bool:
        """Check if country has been previously observed for user."""
        if not country or user_id not in profile.users:
            return False
        return country in profile.users[user_id].known_countries

    @classmethod
    def is_ip_known(cls, profile: BaselineProfile, user_id: str, ip: Optional[str]) -> bool:
        """Check if IP address has been previously observed for user."""
        if not ip or user_id not in profile.users:
            return False
        return ip in profile.users[user_id].known_ips

    @classmethod
    def is_device_known(cls, profile: BaselineProfile, user_id: str, device_id: Optional[str]) -> bool:
        """Check if device has been previously observed for user."""
        if not device_id or user_id not in profile.users:
            return False
        return device_id in profile.users[user_id].known_devices

    @classmethod
    def is_login_hour_usual(cls, profile: BaselineProfile, user_id: str, hour: int) -> bool:
        """Check if hour falls within user's usual activity hours."""
        if user_id not in profile.users or not profile.users[user_id].usual_login_hours:
            return True  # Avoid false alarms without prior data
        # Usual hours or adjacent (+/- 1 hr)
        known_hours = profile.users[user_id].usual_login_hours
        return any(abs(h - hour) in (0, 1, 23) for h in known_hours)

    @classmethod
    def is_usb_approved(cls, profile: BaselineProfile, device_id: Optional[str], usb_id: Optional[str]) -> bool:
        """Check if USB device is approved on device or globally."""
        if not usb_id:
            return True
        if usb_id in profile.global_approved_usbs:
            return True
        if device_id and device_id in profile.devices:
            return usb_id in profile.devices[device_id].approved_usb_devices
        return False

    @classmethod
    def has_accessed_sensitive_file(cls, profile: BaselineProfile, user_id: str, file_path: Optional[str]) -> bool:
        """Check if user has prior legitimate access to this sensitive file."""
        if not file_path or user_id not in profile.users:
            return False
        return file_path in profile.users[user_id].sensitive_files_accessed

    @classmethod
    def get_user_baseline_strength(cls, profile: BaselineProfile, user_id: Optional[str]) -> str:
        """Get baseline maturity level for user."""
        if not user_id or user_id not in profile.users:
            return "INSUFFICIENT"
        return profile.users[user_id].baseline_strength
