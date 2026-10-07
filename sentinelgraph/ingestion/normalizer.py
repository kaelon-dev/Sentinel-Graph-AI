"""Event normalization, schema mapping, and deterministic fingerprinting."""
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from sentinelgraph.models import NormalizedEvent, InvalidEventRecord


def parse_utc_timestamp(val: Any) -> datetime:
    """Parse various datetime representations into UTC timezone-aware datetime."""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    if isinstance(val, (int, float)):
        # Epoch timestamp (check if seconds or milliseconds)
        if val > 1e11:  # Milliseconds
            return datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(val, tz=timezone.utc)

    if isinstance(val, str):
        val = val.strip()
        # Common ISO format with Z
        if val.endswith("Z"):
            val = val[:-1] + "+00:00"
        
        try:
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # Try standard formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%m/%d/%Y %H:%M:%S",
            "%d-%m-%Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(val, fmt)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                continue

    raise ValueError(f"Unable to parse timestamp '{val}' into UTC datetime.")


def normalize_event_type(raw_type: Optional[str]) -> str:
    """Map raw event types or action strings to standard taxonomy."""
    if not raw_type:
        return "alert"
    t = str(raw_type).strip().lower()
    mapping = {
        "login": "login_success",
        "login_success": "login_success",
        "auth_success": "login_success",
        "user_login": "login_success",
        "login_failure": "login_failure",
        "auth_failure": "login_failure",
        "failed_login": "login_failure",
        "file_access": "file_access",
        "file_read": "file_access",
        "file_open": "file_access",
        "read_file": "file_access",
        "usb_connected": "usb_connected",
        "usb_insert": "usb_connected",
        "device_attached": "usb_connected",
        "usb_mount": "usb_connected",
        "usb_file_copy": "usb_file_copy",
        "usb_write": "usb_file_copy",
        "file_copy_to_usb": "usb_file_copy",
        "copy_to_usb": "usb_file_copy",
        "network_transfer": "network_transfer",
        "data_transfer": "network_transfer",
        "egress_transfer": "network_transfer",
        "process_execution": "process_execution",
        "process_spawn": "process_execution",
        "proc_start": "process_execution",
        "alert": "alert",
        "security_alert": "alert",
    }
    return mapping.get(t, t)


def normalize_sensitivity(val: Optional[str]) -> Optional[str]:
    """Standardize file sensitivity labels."""
    if not val:
        return None
    s = str(val).strip().lower()
    if s in ("high", "confidential", "secret", "critical", "restricted"):
        return "HIGH"
    if s in ("medium", "internal", "sensitive"):
        return "MEDIUM"
    if s in ("low", "public", "unrestricted"):
        return "LOW"
    return s.upper()


def compute_event_fingerprint(
    timestamp: datetime,
    event_type: str,
    user_id: Optional[str],
    device_id: Optional[str],
    ip_address: Optional[str],
    file_path: Optional[str],
    usb_id: Optional[str],
    destination_ip: Optional[str],
    bytes_transferred: Optional[int]
) -> str:
    """Generate deterministic SHA-256 fingerprint for normalized event content."""
    ts_str = timestamp.isoformat()
    raw = (
        f"{ts_str}|{event_type}|{user_id or ''}|{device_id or ''}|{ip_address or ''}|"
        f"{file_path or ''}|{usb_id or ''}|{destination_ip or ''}|{bytes_transferred or 0}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_record(
    raw: Dict[str, Any],
    row_num: int,
    source_file: str
) -> Tuple[Optional[NormalizedEvent], Optional[InvalidEventRecord]]:
    """Convert raw dictionary into a NormalizedEvent or an InvalidEventRecord."""
    # Clean keys
    cleaned = {k.strip().lower(): v for k, v in raw.items() if k is not None}

    # Extract or generate event_id
    event_id = str(cleaned.get("event_id") or cleaned.get("id") or f"EVT-ROW-{row_num}").strip()

    # Extract timestamp
    ts_raw = cleaned.get("timestamp") or cleaned.get("time") or cleaned.get("date") or cleaned.get("@timestamp")
    if not ts_raw:
        return None, InvalidEventRecord(
            source_file=source_file,
            row_number=row_num,
            raw_record=raw,
            validation_error="Missing timestamp",
            reason="Timestamp field was not provided or is empty",
            event_id=event_id
        )

    try:
        ts = parse_utc_timestamp(ts_raw)
    except Exception as e:
        return None, InvalidEventRecord(
            source_file=source_file,
            row_number=row_num,
            raw_record=raw,
            validation_error=str(e),
            reason=f"Failed to parse timestamp '{ts_raw}'",
            timestamp=str(ts_raw),
            event_id=event_id
        )

    # Event type / action
    raw_event_type = cleaned.get("event_type") or cleaned.get("action") or cleaned.get("event") or "alert"
    event_type = normalize_event_type(str(raw_event_type))

    # Entity fields with synonym resolution
    user_id = cleaned.get("user_id") or cleaned.get("user") or cleaned.get("username") or cleaned.get("actor")
    user_id = str(user_id).strip() if user_id is not None and str(user_id).strip() != "" else None

    user_name = cleaned.get("user_name") or cleaned.get("full_name") or user_id

    device_id = cleaned.get("device_id") or cleaned.get("device") or cleaned.get("hostname") or cleaned.get("host") or cleaned.get("workstation")
    device_id = str(device_id).strip() if device_id is not None and str(device_id).strip() != "" else None

    device_name = cleaned.get("device_name") or device_id

    ip_address = cleaned.get("ip_address") or cleaned.get("ip") or cleaned.get("src_ip") or cleaned.get("source_ip")
    ip_address = str(ip_address).strip() if ip_address is not None and str(ip_address).strip() != "" else None

    country = cleaned.get("country") or cleaned.get("src_country") or cleaned.get("geo_country")
    country = str(country).strip() if country is not None and str(country).strip() != "" else None

    city = cleaned.get("city") or cleaned.get("src_city")
    city = str(city).strip() if city is not None and str(city).strip() != "" else None

    application = cleaned.get("application") or cleaned.get("app") or cleaned.get("process")
    application = str(application).strip() if application is not None and str(application).strip() != "" else None

    file_path = cleaned.get("file_path") or cleaned.get("file") or cleaned.get("filename") or cleaned.get("target_file")
    file_path = str(file_path).strip() if file_path is not None and str(file_path).strip() != "" else None

    raw_sens = cleaned.get("file_sensitivity") or cleaned.get("sensitivity") or cleaned.get("classification")
    file_sensitivity = normalize_sensitivity(raw_sens)

    usb_id = cleaned.get("usb_id") or cleaned.get("usb") or cleaned.get("serial_number") or cleaned.get("usb_serial")
    usb_id = str(usb_id).strip() if usb_id is not None and str(usb_id).strip() != "" else None

    dest_ip = cleaned.get("destination_ip") or cleaned.get("dest_ip") or cleaned.get("dst_ip")
    destination_ip = str(dest_ip).strip() if dest_ip is not None and str(dest_ip).strip() != "" else None

    dest_dom = cleaned.get("destination_domain") or cleaned.get("domain") or cleaned.get("target_domain")
    destination_domain = str(dest_dom).strip() if dest_dom is not None and str(dest_dom).strip() != "" else None

    bytes_raw = cleaned.get("bytes_transferred") or cleaned.get("bytes") or cleaned.get("transfer_size")
    bytes_transferred = None
    if bytes_raw is not None and str(bytes_raw).strip() != "":
        try:
            bytes_transferred = int(float(str(bytes_raw).strip()))
        except Exception:
            bytes_transferred = None

    action = cleaned.get("action")
    status = cleaned.get("status")
    session_id = cleaned.get("session_id") or cleaned.get("session")

    fingerprint = compute_event_fingerprint(
        timestamp=ts,
        event_type=event_type,
        user_id=user_id,
        device_id=device_id,
        ip_address=ip_address,
        file_path=file_path,
        usb_id=usb_id,
        destination_ip=destination_ip,
        bytes_transferred=bytes_transferred
    )

    event = NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        event_type=event_type,
        user_id=user_id,
        user_name=str(user_name) if user_name else None,
        device_id=device_id,
        device_name=str(device_name) if device_name else None,
        ip_address=ip_address,
        country=country,
        city=city,
        application=application,
        file_path=file_path,
        file_sensitivity=file_sensitivity,
        usb_id=usb_id,
        destination_ip=destination_ip,
        destination_domain=destination_domain,
        bytes_transferred=bytes_transferred,
        action=str(action) if action else None,
        status=str(status) if status else None,
        source_file=source_file,
        raw_event=raw,
        event_fingerprint=fingerprint,
        session_id=str(session_id) if session_id else None
    )

    return event, None
