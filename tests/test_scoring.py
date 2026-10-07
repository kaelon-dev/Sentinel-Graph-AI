"""Tests for risk scoring bounds, severity gating, and counterfactuals."""
from datetime import datetime, timezone
from sentinelgraph.models import DetectionSignal, AttackStage
from sentinelgraph.detection.scoring import ScoringEngine


def test_risk_score_bounds():
    signals = [
        DetectionSignal(
            signal_id=f"S-{i}",
            detector_name="test_signal",
            signal_score=50.0,
            severity="HIGH",
            confidence=0.9,
            explanation="Test signal",
            event_ids=[f"E-{i}"],
            timestamp=datetime.now(timezone.utc)
        )
        for i in range(10)  # 500 total points
    ]
    stages = [
        AttackStage(
            stage_id="STG-01",
            stage_name="Initial Access",
            status="confirmed",
            confidence=0.9,
            summary="Access",
            explanation="Confirmed"
        ),
        AttackStage(
            stage_id="STG-05",
            stage_name="Exfiltration",
            status="confirmed",
            confidence=0.95,
            summary="Exfil",
            explanation="Confirmed"
        )
    ]
    score, sev, contribs = ScoringEngine.calculate_score(signals, stages)
    assert score <= 100.0
    assert score >= 0.0
    assert sev == "CRITICAL"


def test_single_anomaly_not_critical():
    """Verify an isolated single anomaly is strictly gated and never critical."""
    signals = [
        DetectionSignal(
            signal_id="S-1",
            detector_name="unusual_country_login",
            signal_score=25.0,
            severity="MEDIUM",
            confidence=0.9,
            explanation="Unfamiliar country",
            event_ids=["E-1"],
            timestamp=datetime.now(timezone.utc)
        )
    ]
    score, sev, contribs = ScoringEngine.calculate_score(signals, stages=[])
    assert sev in ("LOW", "MEDIUM")
    assert sev not in ("HIGH", "CRITICAL")
    assert score <= 45.0
