"""Configuration settings and constants for SentinelGraph AI."""
from typing import Dict, List
from pydantic import BaseModel, Field


class CorrelationConfig(BaseModel):
    """Configuration for temporal and entity correlation."""
    standard_window_minutes: int = Field(default=60, description="Standard correlation window in minutes")
    extended_window_minutes: int = Field(default=4320, description="Extended window for multi-day slow-burn attacks (72h)")
    session_inactivity_minutes: int = Field(default=30, description="Session idle timeout gap in minutes")
    min_correlation_score: float = Field(default=0.45, description="Minimum correlation score required to link events")
    
    # Entity correlation weights
    weight_same_user: float = 30.0
    weight_same_device: float = 20.0
    weight_same_session: float = 20.0
    weight_same_file: float = 15.0
    weight_same_usb: float = 20.0
    weight_same_ip: float = 10.0
    weight_same_application: float = 5.0
    weight_temporal_proximity: float = 10.0
    weight_stage_continuity: float = 15.0


class RuleWeights(BaseModel):
    """Base weights for deterministic detection rules."""
    unusual_country_login: float = 25.0
    new_ip_login: float = 10.0
    new_device_login: float = 15.0
    unusual_login_hour: float = 10.0
    sensitive_file_first_access: float = 25.0
    unusual_sensitive_file_access: float = 20.0
    unapproved_usb: float = 20.0
    sensitive_file_usb_copy: float = 45.0
    unusual_external_transfer: float = 35.0
    multi_stage_correlation: float = 15.0
    same_user_device_correlation: float = 10.0
    first_seen_application: float = 5.0
    first_seen_device: float = 5.0
    first_seen_destination: float = 5.0
    repeated_login_failures: float = 15.0
    off_hours_activity: float = 10.0
    discovery_activity: float = 15.0


class ConfidenceWeights(BaseModel):
    """Weights for the 5-dimension confidence decomposition."""
    evidence_completeness: float = 0.30
    entity_linkage: float = 0.25
    temporal_consistency: float = 0.20
    baseline_strength: float = 0.15
    stage_coverage: float = 0.10


class Settings(BaseModel):
    """System-wide configuration settings."""
    app_name: str = "SentinelGraph AI"
    version: str = "1.0.0"
    risk_maximum: float = 100.0
    max_upload_size_bytes: int = 50 * 1024 * 1024  # 50 MB
    allowed_extensions: List[str] = [".csv", ".json", ".jsonl"]
    
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    rules: RuleWeights = Field(default_factory=RuleWeights)
    confidence: ConfidenceWeights = Field(default_factory=ConfidenceWeights)
    
    # Severity risk ranges
    severity_ranges: Dict[str, tuple[float, float]] = {
        "INFO": (0.0, 19.99),
        "LOW": (20.0, 39.99),
        "MEDIUM": (40.0, 59.99),
        "HIGH": (60.0, 79.99),
        "CRITICAL": (80.0, 100.0),
    }


settings = Settings()
