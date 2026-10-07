"""Core Pydantic data models for SentinelGraph AI."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    """Normalized security event representing activities across all log sources."""
    event_id: str
    timestamp: datetime
    event_type: str  # login_success, login_failure, file_access, usb_connected, usb_file_copy, network_transfer, process_execution, alert
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    ip_address: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    application: Optional[str] = None
    file_path: Optional[str] = None
    file_sensitivity: Optional[str] = None  # low, medium, high, confidential, public
    usb_id: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_domain: Optional[str] = None
    bytes_transferred: Optional[int] = None
    action: Optional[str] = None
    status: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source_file: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None
    event_fingerprint: str = ""
    session_id: Optional[str] = None
    derived_session_id: Optional[str] = None


class InvalidEventRecord(BaseModel):
    """Preserves malformed, corrupted or unparseable log records."""
    source_file: str
    row_number: int
    raw_record: Any
    validation_error: str
    reason: str
    timestamp: Optional[str] = None
    event_id: Optional[str] = None


class SourceFileMetadata(BaseModel):
    """Integrity and provenance metadata for ingested log files."""
    file_name: str
    size: int
    sha256: str
    ingestion_timestamp: datetime
    analysis_run_id: str
    application_version: str


class UserProfile(BaseModel):
    """Behavioral baseline profile for an individual user."""
    user_id: str
    known_countries: List[str] = Field(default_factory=list)
    known_cities: List[str] = Field(default_factory=list)
    known_ips: List[str] = Field(default_factory=list)
    known_devices: List[str] = Field(default_factory=list)
    known_applications: List[str] = Field(default_factory=list)
    usual_login_hours: List[int] = Field(default_factory=list)
    common_files: List[str] = Field(default_factory=list)
    sensitive_files_accessed: List[str] = Field(default_factory=list)
    approved_usb_devices: List[str] = Field(default_factory=list)
    event_count: int = 0
    baseline_strength: str = "INSUFFICIENT"  # INSUFFICIENT, WEAK, MODERATE, STRONG


class DeviceProfile(BaseModel):
    """Behavioral baseline profile for an individual workstation or server."""
    device_id: str
    known_users: List[str] = Field(default_factory=list)
    approved_usb_devices: List[str] = Field(default_factory=list)
    known_ips: List[str] = Field(default_factory=list)
    known_applications: List[str] = Field(default_factory=list)
    event_count: int = 0
    baseline_strength: str = "INSUFFICIENT"


class BaselineProfile(BaseModel):
    """Global baseline containing individual entity profiles."""
    users: Dict[str, UserProfile] = Field(default_factory=dict)
    devices: Dict[str, DeviceProfile] = Field(default_factory=dict)
    global_approved_usbs: List[str] = Field(default_factory=list)
    global_known_destinations: List[str] = Field(default_factory=list)
    total_events_observed: int = 0


class DetectionSignal(BaseModel):
    """Atomic security signal produced by deterministic detectors or ML models."""
    signal_id: str
    detector_name: str
    signal_score: float
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    explanation: str
    event_ids: List[str] = Field(default_factory=list)
    timestamp: datetime
    affected_user_id: Optional[str] = None
    affected_device_id: Optional[str] = None
    affected_ip_address: Optional[str] = None
    affected_application: Optional[str] = None
    baseline_comparison: Dict[str, Any] = Field(default_factory=dict)
    recommended_stage: str = "Unknown / Suspicious Activity"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    """Structured evidence item linking an individual log event to an attack stage."""
    evidence_id: str
    event_id: str
    timestamp: datetime
    event_type: str
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    application: Optional[str] = None
    file_path: Optional[str] = None
    file_sensitivity: Optional[str] = None
    usb_id: Optional[str] = None
    destination_ip: Optional[str] = None
    raw_json: Dict[str, Any] = Field(default_factory=dict)
    normalized_json: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str
    explanation: str
    strength: float = 1.0


class AttackStage(BaseModel):
    """Attack stage model representing MITRE-style phases supported by evidence."""
    stage_id: str
    stage_name: str  # Initial Access, Credential Access, Discovery, Collection, Exfiltration, Impact, Unknown / Suspicious Activity
    status: str  # confirmed, suspected, insufficient evidence
    confidence: float
    summary: str
    evidence_event_ids: List[str] = Field(default_factory=list)
    evidence_strength: float = 0.0
    explanation: str
    supporting_signals: List[str] = Field(default_factory=list)
    contradictory_signals: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)


class ScoreContribution(BaseModel):
    """Detailed score contribution for explainability and counterfactual analysis."""
    rule_or_factor: str
    raw_points: float
    capped_points: float
    weight: float
    reason: str
    event_ids: List[str] = Field(default_factory=list)


class CorrelationExplanation(BaseModel):
    """Explicit explanation of why two events belong to the same incident."""
    source_event_id: str
    target_event_id: str
    same_user: bool = False
    same_device: bool = False
    same_ip: bool = False
    same_application: bool = False
    same_file: bool = False
    same_usb: bool = False
    same_session: bool = False
    temporal_distance_minutes: float = 0.0
    stage_continuity: bool = False
    total_score: float = 0.0
    normalized_score: float = 0.0
    explanation: str = ""


class CounterfactualResult(BaseModel):
    """What-if outcome demonstrating the impact of removing a specific evidence item."""
    removed_event_id: str
    event_description: str
    original_risk: float
    counterfactual_risk: float
    risk_delta: float
    original_severity: str
    counterfactual_severity: str
    affected_stages: List[str]
    explanation: str


class GraphNode(BaseModel):
    """Temporal attack graph node."""
    id: str
    label: str
    node_type: str  # User, Device, IP, Country, Application, File, USB, Destination, Event, Session, Incident
    status: str = "normal"  # normal, suspicious, confirmed, baseline
    color: str = "#38BDF8"  # blue/green normal, yellow/orange suspicious, red confirmed
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Temporal attack graph directed edge."""
    source: str
    target: str
    relationship: str  # logged_into, used, accessed, executed, connected, copied_to, transferred_to, occurred_before, same_session, same_device, same_user, correlated_with
    confidence: float = 1.0
    event_ids: List[str] = Field(default_factory=list)
    timestamp: Optional[datetime] = None
    strength: float = 1.0
    color: str = "#64748B"


class TemporalGraphData(BaseModel):
    """Complete serialized attack graph."""
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class AttackStory(BaseModel):
    """First-class human-readable, fully explainable attack story."""
    story_id: str
    headline: str
    what_happened: str
    why_it_matters: str
    confidence: float
    risk_score: float
    attack_stages: List[str] = Field(default_factory=list)
    evidence_chain: List[str] = Field(default_factory=list)
    entity_relationships: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)


class ConfidenceDecomposition(BaseModel):
    """Decomposed confidence metrics across 5 deterministic dimensions."""
    overall_confidence: float
    evidence_completeness: float
    entity_linkage: float
    temporal_consistency: float
    baseline_strength: float
    stage_coverage: float
    explanation: str


class Incident(BaseModel):
    """A fully correlated, evidence-backed security incident."""
    incident_id: str
    title: str
    status: str = "ACTIVE"
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float
    confidence: float
    confidence_decomposition: Optional[ConfidenceDecomposition] = None
    attack_type: str
    start_time: datetime
    end_time: datetime
    affected_users: List[str] = Field(default_factory=list)
    affected_devices: List[str] = Field(default_factory=list)
    affected_ips: List[str] = Field(default_factory=list)
    affected_countries: List[str] = Field(default_factory=list)
    affected_applications: List[str] = Field(default_factory=list)
    affected_files: List[str] = Field(default_factory=list)
    affected_usb_devices: List[str] = Field(default_factory=list)
    affected_destinations: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    attack_stages: List[AttackStage] = Field(default_factory=list)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    score_breakdown: List[ScoreContribution] = Field(default_factory=list)
    correlation_rationale: List[str] = Field(default_factory=list)
    entity_relationships: List[CorrelationExplanation] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    attack_fingerprint: str
    source_metadata: Optional[SourceFileMetadata] = None
    attack_story: Optional[AttackStory] = None
    counterfactuals: List[CounterfactualResult] = Field(default_factory=list)
    graph_data: Optional[TemporalGraphData] = None


class AnalysisResult(BaseModel):
    """Complete output produced by SentinelGraph AI analysis pipeline."""
    run_id: str
    analysis_timestamp: datetime
    source_metadata: SourceFileMetadata
    total_raw_records: int
    valid_event_count: int
    invalid_records: List[InvalidEventRecord] = Field(default_factory=list)
    duplicate_count: int = 0
    signals_detected: List[DetectionSignal] = Field(default_factory=list)
    incidents: List[Incident] = Field(default_factory=list)
    baseline_summary: Dict[str, Any] = Field(default_factory=dict)
    execution_time_seconds: float = 0.0
