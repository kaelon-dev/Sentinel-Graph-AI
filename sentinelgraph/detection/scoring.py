"""Deterministic risk scoring, score deduplication, and severity gating."""
from typing import List, Tuple
from sentinelgraph.config import settings
from sentinelgraph.models import DetectionSignal, ScoreContribution, AttackStage


class ScoringEngine:
    """Calculates deterministic risk scores, applies severity gates, and exposes explainable contributions."""

    @classmethod
    def calculate_score(
        cls,
        signals: List[DetectionSignal],
        stages: List[AttackStage],
        is_extended_window: bool = False
    ) -> Tuple[float, str, List[ScoreContribution]]:
        """Compute bounded risk score (0-100), severity tier, and line-item contributions."""
        contributions: List[ScoreContribution] = []
        raw_total = 0.0

        # Track per-event login anomalies to prevent duplicate inflation (Rule 2 / Section 33)
        login_events_with_country = set()
        for sig in signals:
            if sig.detector_name == "unusual_country_login":
                login_events_with_country.update(sig.event_ids)

        # Track seen detector categories
        seen_detectors = set()

        for sig in signals:
            detector = sig.detector_name
            points = sig.signal_score
            capped_points = points
            reason = sig.explanation

            # Redundant login IP signal cap
            if detector == "new_ip_login":
                co_occurring = any(eid in login_events_with_country for eid in sig.event_ids)
                if co_occurring:
                    # Score deduplication: redundant IP on top of country anomaly gets reduced bonus
                    capped_points = 5.0
                    reason += " [Deduplicated: co-occurs with country anomaly on same authentication]"

            # Cap repeated instances of supportive signals
            if detector in ("off_hours_activity", "first_seen_application", "unusual_login_hour"):
                if detector in seen_detectors:
                    capped_points = 2.0  # Diminishing returns for duplicate supportive noise
                    reason += " [Diminishing contribution for repeated supportive signal]"

            seen_detectors.add(detector)
            raw_total += capped_points
            contributions.append(
                ScoreContribution(
                    rule_or_factor=detector,
                    raw_points=points,
                    capped_points=capped_points,
                    weight=1.0,
                    reason=reason,
                    event_ids=sig.event_ids
                )
            )

        # Multi-stage correlation bonus (Rule 10)
        confirmed_stage_names = {s.stage_name for s in stages if s.status == "confirmed"}
        if len(confirmed_stage_names) >= 2:
            bonus = settings.rules.multi_stage_correlation
            raw_total += bonus
            contributions.append(
                ScoreContribution(
                    rule_or_factor="multi_stage_correlation_bonus",
                    raw_points=bonus,
                    capped_points=bonus,
                    weight=1.0,
                    reason=f"Incident spans multiple confirmed attack stages: {', '.join(sorted(confirmed_stage_names))}",
                    event_ids=[]
                )
            )

        # Slow-burn correlation penalty (Section 27.3: confidence/risk reduced relative to tight attack)
        if is_extended_window:
            penalty = 10.0
            raw_total = max(0.0, raw_total - penalty)
            contributions.append(
                ScoreContribution(
                    rule_or_factor="extended_window_temporal_decay",
                    raw_points=-penalty,
                    capped_points=-penalty,
                    weight=1.0,
                    reason="Events span multi-day extended window; temporal proximity decay applied",
                    event_ids=[]
                )
            )

        # Clamp raw score to [0, 100]
        clamped_score = min(settings.risk_maximum, max(0.0, raw_total))

        # ------------------------------------------------------------------
        # Severity Gating (Section 100 & Section 34)
        # ------------------------------------------------------------------
        has_exfiltration = "Exfiltration" in confirmed_stage_names
        has_collection = "Collection" in confirmed_stage_names
        has_initial_access = "Initial Access" in confirmed_stage_names
        has_credential_access = "Credential Access" in confirmed_stage_names
        
        # Determine natural severity based on score
        if clamped_score >= 80.0:
            severity = "CRITICAL"
        elif clamped_score >= 60.0:
            severity = "HIGH"
        elif clamped_score >= 40.0:
            severity = "MEDIUM"
        elif clamped_score >= 20.0:
            severity = "LOW"
        else:
            severity = "INFO"

        # Gate 1: CRITICAL requires confirmed Exfiltration + corroborating stage
        if severity == "CRITICAL":
            corroborating = len(confirmed_stage_names - {"Exfiltration"}) >= 1
            if not (has_exfiltration and corroborating):
                severity = "HIGH"
                clamped_score = min(78.0, clamped_score)
                contributions.append(
                    ScoreContribution(
                        rule_or_factor="critical_severity_gate",
                        raw_points=0.0,
                        capped_points=0.0,
                        weight=1.0,
                        reason="Gated from CRITICAL to HIGH: Critical requires confirmed Exfiltration and corroborating attack stage",
                        event_ids=[]
                    )
                )

        # Gate 2: HIGH requires either Exfiltration OR (Credential/Initial Access + Collection)
        if severity == "HIGH":
            valid_high = has_exfiltration or ((has_initial_access or has_credential_access) and has_collection)
            if not valid_high:
                severity = "MEDIUM"
                clamped_score = min(58.0, clamped_score)
                contributions.append(
                    ScoreContribution(
                        rule_or_factor="high_severity_gate",
                        raw_points=0.0,
                        capped_points=0.0,
                        weight=1.0,
                        reason="Gated from HIGH to MEDIUM: High severity requires confirmed multi-stage progression or exfiltration",
                        event_ids=[]
                    )
                )

        # Gate 3: Single anomaly suppression (Section 101)
        if len(signals) <= 1:
            if severity in ("HIGH", "CRITICAL"):
                severity = "MEDIUM"
                clamped_score = min(45.0, clamped_score)

        return round(clamped_score, 1), severity, contributions
