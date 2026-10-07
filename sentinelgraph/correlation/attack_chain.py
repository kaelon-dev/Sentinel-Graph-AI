"""Correlation engine, attack chain reconstruction, evidence ledger, and counterfactual analysis."""
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import networkx as nx

from sentinelgraph.config import settings
from sentinelgraph.models import (
    NormalizedEvent,
    DetectionSignal,
    AttackStage,
    EvidenceItem,
    CorrelationExplanation,
    CounterfactualResult,
    ConfidenceDecomposition,
    AttackStory,
    Incident,
    BaselineProfile,
)
from sentinelgraph.baseline.profiler import BaselineProfiler
from sentinelgraph.detection.scoring import ScoringEngine


class AttackChainReconstructor:
    """Correlates atomic signals and events into explainable, evidence-backed attack stories."""

    def __init__(self, baseline: Optional[BaselineProfile] = None):
        self.baseline = baseline or BaselineProfile()
        self.config = settings.correlation
        self.weights = settings.confidence

    def correlate(
        self,
        events: List[NormalizedEvent],
        signals: List[DetectionSignal],
        use_extended_window: bool = False
    ) -> List[Incident]:
        """Correlate events and signals into attack incidents."""
        if not events:
            return []

        window_minutes = (
            self.config.extended_window_minutes if use_extended_window else self.config.standard_window_minutes
        )

        event_map: Dict[str, NormalizedEvent] = {e.event_id: e for e in events}
        signal_event_ids: Set[str] = {eid for s in signals for eid in s.event_ids}

        # If there are no suspicious signals, no attack incidents are formed
        if not signal_event_ids:
            return []

        # Build correlation graph across signal-associated events
        suspicious_events = [e for e in events if e.event_id in signal_event_ids]
        suspicious_events.sort(key=lambda e: (e.timestamp, e.event_id))

        G = nx.Graph()
        for e in suspicious_events:
            G.add_node(e.event_id)

        pairwise_explanations: Dict[Tuple[str, str], CorrelationExplanation] = {}

        # Evaluate pairwise temporal & entity correlation
        for i in range(len(suspicious_events)):
            for j in range(i + 1, len(suspicious_events)):
                e1 = suspicious_events[i]
                e2 = suspicious_events[j]

                delta_minutes = abs((e2.timestamp - e1.timestamp).total_seconds()) / 60.0
                if delta_minutes > window_minutes:
                    continue  # Strict temporal boundary

                expl = self._evaluate_pairwise_correlation(e1, e2, delta_minutes, window_minutes)
                pairwise_explanations[(e1.event_id, e2.event_id)] = expl
                pairwise_explanations[(e2.event_id, e1.event_id)] = expl

                if expl.normalized_score >= self.config.min_correlation_score:
                    G.add_edge(e1.event_id, e2.event_id, weight=expl.normalized_score)

        # Connected components represent candidate incident clusters
        clusters = list(nx.connected_components(G))
        incidents: List[Incident] = []

        for idx, cluster in enumerate(clusters, start=1):
            cluster_events = sorted([event_map[eid] for eid in cluster], key=lambda e: (e.timestamp, e.event_id))
            cluster_event_ids = set(cluster)
            cluster_signals = [s for s in signals if any(eid in cluster_event_ids for eid in s.event_ids)]

            incident = self._build_incident(
                incident_id=f"INC-{idx:03d}",
                events=cluster_events,
                signals=cluster_signals,
                explanations=pairwise_explanations,
                is_extended_window=use_extended_window
            )
            incidents.append(incident)

        # Sort incidents by risk score descending
        incidents.sort(key=lambda inc: inc.risk_score, reverse=True)
        return incidents

    def _evaluate_pairwise_correlation(
        self,
        e1: NormalizedEvent,
        e2: NormalizedEvent,
        delta_minutes: float,
        window_minutes: float
    ) -> CorrelationExplanation:
        """Calculate weighted correlation score between two events."""
        same_user = bool(e1.user_id and e2.user_id and e1.user_id == e2.user_id)
        same_device = bool(e1.device_id and e2.device_id and e1.device_id == e2.device_id)
        same_session = bool(
            e1.derived_session_id and e2.derived_session_id and e1.derived_session_id == e2.derived_session_id
        )
        same_file = bool(e1.file_path and e2.file_path and e1.file_path == e2.file_path)
        same_usb = bool(e1.usb_id and e2.usb_id and e1.usb_id == e2.usb_id)
        same_ip = bool(e1.ip_address and e2.ip_address and e1.ip_address == e2.ip_address)
        same_app = bool(e1.application and e2.application and e1.application == e2.application)

        # Stage continuity: login -> file_access/usb -> copy/exfil
        stage_continuity = False
        t1, t2 = e1.event_type, e2.event_type
        if ("login" in t1 and ("file" in t2 or "usb" in t2 or "network" in t2)) or \
           ("file_access" in t1 and ("usb" in t2 or "network" in t2)) or \
           ("usb_connected" in t1 and "usb_file_copy" in t2):
            stage_continuity = True

        # Temporal proximity contribution (decays linearly with distance)
        time_ratio = max(0.0, 1.0 - (delta_minutes / max(1.0, window_minutes)))
        temporal_contrib = self.config.weight_temporal_proximity * time_ratio

        total_score = 0.0
        reasons = []

        if same_user:
            total_score += self.config.weight_same_user
            reasons.append(f"+{int(self.config.weight_same_user)} Same user: {e1.user_id}")
        if same_device:
            total_score += self.config.weight_same_device
            reasons.append(f"+{int(self.config.weight_same_device)} Same device: {e1.device_id}")
        if same_session:
            total_score += self.config.weight_same_session
            reasons.append(f"+{int(self.config.weight_same_session)} Same session: {e1.derived_session_id}")
        if same_file:
            total_score += self.config.weight_same_file
            reasons.append(f"+{int(self.config.weight_same_file)} Same file: {e1.file_path}")
        if same_usb:
            total_score += self.config.weight_same_usb
            reasons.append(f"+{int(self.config.weight_same_usb)} Same USB: {e1.usb_id}")
        if same_ip:
            total_score += self.config.weight_same_ip
            reasons.append(f"+{int(self.config.weight_same_ip)} Same IP: {e1.ip_address}")
        if same_app:
            total_score += self.config.weight_same_application
            reasons.append(f"+{int(self.config.weight_same_application)} Same application: {e1.application}")

        if delta_minutes <= window_minutes:
            total_score += temporal_contrib
            reasons.append(f"+{round(temporal_contrib, 1)} Temporal proximity ({round(delta_minutes, 1)} mins apart)")

        if stage_continuity:
            total_score += self.config.weight_stage_continuity
            reasons.append(f"+{int(self.config.weight_stage_continuity)} Matches attack stage progression ({t1} -> {t2})")

        # Theoretical max score: 30+20+20+15+20+10+5+10+15 = 145
        normalized_score = round(min(1.0, total_score / 145.0), 2)
        explanation_text = "; ".join(reasons)

        return CorrelationExplanation(
            source_event_id=e1.event_id,
            target_event_id=e2.event_id,
            same_user=same_user,
            same_device=same_device,
            same_ip=same_ip,
            same_application=same_app,
            same_file=same_file,
            same_usb=same_usb,
            same_session=same_session,
            temporal_distance_minutes=round(delta_minutes, 1),
            stage_continuity=stage_continuity,
            total_score=round(total_score, 1),
            normalized_score=normalized_score,
            explanation=explanation_text
        )

    def _build_incident(
        self,
        incident_id: str,
        events: List[NormalizedEvent],
        signals: List[DetectionSignal],
        explanations: Dict[Tuple[str, str], CorrelationExplanation],
        is_extended_window: bool
    ) -> Incident:
        """Construct full Incident object with stages, evidence ledger, and confidence."""
        # 1. Timeline & Entities
        users = sorted(list({e.user_id for e in events if e.user_id}))
        devices = sorted(list({e.device_id for e in events if e.device_id}))
        ips = sorted(list({e.ip_address for e in events if e.ip_address}))
        countries = sorted(list({e.country for e in events if e.country}))
        apps = sorted(list({e.application for e in events if e.application}))
        files = sorted(list({e.file_path for e in events if e.file_path}))
        usbs = sorted(list({e.usb_id for e in events if e.usb_id}))
        dests = sorted(list({e.destination_ip for e in events if e.destination_ip} | {e.destination_domain for e in events if e.destination_domain}))

        timeline = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "user": e.user_id,
                "device": e.device_id,
                "detail": e.file_path or e.usb_id or e.destination_ip or e.ip_address or e.action or ""
            }
            for e in events
        ]

        # 2. Evidence Items
        evidence_items: List[EvidenceItem] = []
        for e in events:
            # Find matching signal explanation if any
            sig_expl = [s.explanation for s in signals if e.event_id in s.event_ids]
            expl_text = sig_expl[0] if sig_expl else f"Corroborating activity in incident timeline: {e.event_type}"
            evidence_items.append(
                EvidenceItem(
                    evidence_id=f"EVD-{e.event_id}",
                    event_id=e.event_id,
                    timestamp=e.timestamp,
                    event_type=e.event_type,
                    user_id=e.user_id,
                    device_id=e.device_id,
                    ip_address=e.ip_address,
                    application=e.application,
                    file_path=e.file_path,
                    file_sensitivity=e.file_sensitivity,
                    usb_id=e.usb_id,
                    destination_ip=e.destination_ip,
                    raw_json=e.raw_event or {},
                    normalized_json=e.model_dump(exclude={"raw_event"}),
                    fingerprint=e.event_fingerprint,
                    explanation=expl_text,
                    strength=0.95 if sig_expl else 0.70
                )
            )

        # 3. Attack Stages
        stages = self._reconstruct_attack_stages(events, signals)

        # 4. Deterministic Risk Scoring
        risk_score, severity, score_breakdown = ScoringEngine.calculate_score(
            signals=signals,
            stages=stages,
            is_extended_window=is_extended_window
        )

        # 5. Attack Type Classification
        has_usb_exfil = any(e.event_type == "usb_file_copy" for e in events)
        has_net_exfil = any(e.event_type == "network_transfer" for e in events)
        has_login_anomaly = any("login" in s.detector_name for s in signals)
        has_cred_access = any("fail" in s.detector_name for s in signals)

        if has_usb_exfil:
            attack_type = "Potential Data Exfiltration / Removable Media Theft"
            title = f"Data Exfiltration via Removable USB ({', '.join(usbs) or 'Unknown USB'})"
        elif has_net_exfil:
            attack_type = "Potential Network Exfiltration / External Egress"
            title = f"Data Exfiltration via Network Egress to {', '.join(dests) or 'External Host'}"
        elif has_cred_access and has_login_anomaly:
            attack_type = "Account Compromise / Credential Takeover"
            title = f"Credential Compromise and Unauthorized Access for {', '.join(users)}"
        elif has_login_anomaly:
            attack_type = "Suspicious Authentication Anomaly"
            title = f"Anomalous Login Activity for {', '.join(users)}"
        else:
            attack_type = "Coordinated Behavioral Anomaly"
            title = f"Multi-Signal Suspicious Activity on {', '.join(devices)}"

        # 6. Confidence Decomposition (5 dimensions)
        confidence_decomp = self._calculate_confidence(events, stages, users, is_extended_window)

        # 7. Correlation Rationale & Pairwise entity relationships
        correlation_rationale = []
        cluster_rels: List[CorrelationExplanation] = []
        for i in range(len(events)):
            for j in range(i + 1, len(events)):
                pair = (events[i].event_id, events[j].event_id)
                if pair in explanations:
                    expl = explanations[pair]
                    cluster_rels.append(expl)
                    correlation_rationale.append(
                        f"Event {expl.source_event_id} -> {expl.target_event_id}: {expl.explanation} (Score: {expl.normalized_score})"
                    )

        # 8. Attack Fingerprint
        stage_names_seq = "-".join([s.stage_name[:3].upper() for s in stages if s.status == "confirmed"])
        event_types_seq = "-".join([e.event_type for e in events])
        fingerprint_raw = f"{stage_names_seq}|{event_types_seq}|{users}|{devices}"
        attack_fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

        # 9. Attack Story
        attack_story = self._generate_attack_story(
            incident_id=incident_id,
            title=title,
            risk_score=risk_score,
            confidence=confidence_decomp.overall_confidence,
            events=events,
            signals=signals,
            stages=stages,
            users=users,
            devices=devices,
            files=files,
            usbs=usbs
        )

        # 10. Recommended Analyst Actions
        recommended_actions = self._generate_recommendations(attack_type, users, devices, usbs)

        # 11. Uncertainties & Alternative Explanations
        uncertainties = []
        if is_extended_window:
            uncertainties.append("Events occurred across an extended correlation window; relationship continuity assumes long-dwell adversary activity.")
        if any(s.status == "insufficient evidence" for s in stages):
            uncertainties.append("Certain MITRE stages remain unproven due to telemetry gaps.")
        for u in users:
            b_str = BaselineProfiler.get_user_baseline_strength(self.baseline, u)
            if b_str in ("INSUFFICIENT", "WEAK"):
                uncertainties.append(f"Baseline for user {u} is {b_str}; anomaly signals may reflect normal user workflow changes.")

        alt_explanations = []
        if countries:
            alt_explanations.append(f"Legitimate international business travel or corporate VPN usage could account for login from {', '.join(countries)}.")
        if usbs:
            alt_explanations.append(f"Emergency local backup or authorized administrative file transfer could explain USB copy to {', '.join(usbs)}.")

        # 12. Counterfactual Analysis
        counterfactuals = self._generate_counterfactuals(
            events=events,
            signals=signals,
            original_risk=risk_score,
            original_severity=severity,
            is_extended_window=is_extended_window
        )

        return Incident(
            incident_id=incident_id,
            title=title,
            status="ACTIVE",
            severity=severity,
            risk_score=risk_score,
            confidence=confidence_decomp.overall_confidence,
            confidence_decomposition=confidence_decomp,
            attack_type=attack_type,
            start_time=events[0].timestamp,
            end_time=events[-1].timestamp,
            affected_users=users,
            affected_devices=devices,
            affected_ips=ips,
            affected_countries=countries,
            affected_applications=apps,
            affected_files=files,
            affected_usb_devices=usbs,
            affected_destinations=dests,
            timeline=timeline,
            attack_stages=stages,
            evidence_items=evidence_items,
            score_breakdown=score_breakdown,
            correlation_rationale=correlation_rationale,
            entity_relationships=cluster_rels,
            recommended_actions=recommended_actions,
            uncertainties=uncertainties,
            alternative_explanations=alt_explanations,
            attack_fingerprint=attack_fingerprint,
            attack_story=attack_story,
            counterfactuals=counterfactuals
        )

    def _reconstruct_attack_stages(
        self,
        events: List[NormalizedEvent],
        signals: List[DetectionSignal]
    ) -> List[AttackStage]:
        """Verify each MITRE stage with strict evidence requirements."""
        stages: List[AttackStage] = []

        # 1. Initial Access
        ia_events = [e for e in events if "login" in e.event_type]
        ia_signals = [s for s in signals if s.recommended_stage == "Initial Access"]
        if ia_events and ia_signals:
            stages.append(
                AttackStage(
                    stage_id="STG-01",
                    stage_name="Initial Access",
                    status="confirmed",
                    confidence=0.92,
                    summary="Authentication from unfamiliar external IP/country outside user baseline",
                    evidence_event_ids=[e.event_id for e in ia_events],
                    evidence_strength=0.95,
                    explanation=f"Authentication observed for {ia_events[0].user_id} with verified anomalous attributes.",
                    supporting_signals=[s.detector_name for s in ia_signals]
                )
            )
        elif ia_events:
            stages.append(
                AttackStage(
                    stage_id="STG-01",
                    stage_name="Initial Access",
                    status="suspected",
                    confidence=0.50,
                    summary="Login occurred but lacked decisive anomaly indicators",
                    evidence_event_ids=[e.event_id for e in ia_events],
                    evidence_strength=0.50,
                    explanation="User logged in within incident window; baseline match inconclusive.",
                    supporting_signals=[]
                )
            )
        else:
            stages.append(
                AttackStage(
                    stage_id="STG-01",
                    stage_name="Initial Access",
                    status="insufficient evidence",
                    confidence=0.10,
                    summary="Insufficient evidence to classify this as a confirmed attack stage.",
                    evidence_event_ids=[],
                    evidence_strength=0.0,
                    explanation="Insufficient evidence to classify this as a confirmed attack stage.",
                    missing_evidence=["Authentication telemetry", "Source IP login logs"]
                )
            )

        # 2. Credential Access
        cred_signals = [s for s in signals if s.recommended_stage == "Credential Access"]
        cred_events = [e for e in events if e.event_type == "login_failure"]
        if cred_signals and cred_events:
            stages.append(
                AttackStage(
                    stage_id="STG-02",
                    stage_name="Credential Access",
                    status="confirmed",
                    confidence=0.88,
                    summary="Multiple repeated failed authentications indicating potential brute-force or spraying",
                    evidence_event_ids=[e.event_id for e in cred_events],
                    evidence_strength=0.90,
                    explanation=f"Cluster of {len(cred_events)} failed logins observed prior to successful entry.",
                    supporting_signals=[s.detector_name for s in cred_signals]
                )
            )

        # 3. Discovery
        disc_signals = [s for s in signals if s.recommended_stage == "Discovery"]
        if disc_signals:
            disc_events = [e for e in events if any(e.event_id in s.event_ids for s in disc_signals)]
            stages.append(
                AttackStage(
                    stage_id="STG-03",
                    stage_name="Discovery",
                    status="confirmed",
                    confidence=0.85,
                    summary="Rapid file enumeration or directory reconnaissance",
                    evidence_event_ids=[e.event_id for e in disc_events],
                    evidence_strength=0.85,
                    explanation="Rapid succession of file access events indicating exploratory enumeration.",
                    supporting_signals=[s.detector_name for s in disc_signals]
                )
            )
        else:
            stages.append(
                AttackStage(
                    stage_id="STG-03",
                    stage_name="Discovery",
                    status="insufficient evidence",
                    confidence=0.10,
                    summary="Insufficient evidence to classify this as a confirmed attack stage.",
                    evidence_event_ids=[],
                    evidence_strength=0.0,
                    explanation="Insufficient evidence to classify this as a confirmed attack stage.",
                    missing_evidence=["Command-line process telemetry", "Rapid directory listing events"]
                )
            )

        # 4. Collection
        coll_events = [e for e in events if e.event_type == "file_access" and e.file_sensitivity in ("HIGH", "CRITICAL", "CONFIDENTIAL")]
        coll_signals = [s for s in signals if s.recommended_stage == "Collection"]
        if coll_events and coll_signals:
            stages.append(
                AttackStage(
                    stage_id="STG-04",
                    stage_name="Collection",
                    status="confirmed",
                    confidence=0.93,
                    summary=f"First-time or unauthorized access to sensitive file ({coll_events[0].file_path})",
                    evidence_event_ids=[e.event_id for e in coll_events],
                    evidence_strength=0.95,
                    explanation=f"File {coll_events[0].file_path} classified as {coll_events[0].file_sensitivity} was accessed by {coll_events[0].user_id}.",
                    supporting_signals=[s.detector_name for s in coll_signals]
                )
            )
        elif coll_events:
            stages.append(
                AttackStage(
                    stage_id="STG-04",
                    stage_name="Collection",
                    status="suspected",
                    confidence=0.60,
                    summary="Sensitive file accessed, but user has routine historical access",
                    evidence_event_ids=[e.event_id for e in coll_events],
                    evidence_strength=0.60,
                    explanation="Sensitive access observed but matches baseline history.",
                    supporting_signals=[]
                )
            )
        else:
            stages.append(
                AttackStage(
                    stage_id="STG-04",
                    stage_name="Collection",
                    status="insufficient evidence",
                    confidence=0.10,
                    summary="Insufficient evidence to classify this as a confirmed attack stage.",
                    evidence_event_ids=[],
                    evidence_strength=0.0,
                    explanation="Insufficient evidence to classify this as a confirmed attack stage.",
                    missing_evidence=["Sensitive document access logs", "Database query telemetry"]
                )
            )

        # 5. Exfiltration
        exfil_usb = [e for e in events if e.event_type == "usb_file_copy" and e.file_sensitivity in ("HIGH", "CRITICAL", "CONFIDENTIAL")]
        exfil_net = [e for e in events if e.event_type == "network_transfer" and any(s.recommended_stage == "Exfiltration" for s in signals if e.event_id in s.event_ids)]
        exfil_events = exfil_usb + exfil_net

        if exfil_events:
            summary_desc = (
                f"Sensitive payroll/confidential file copied to unapproved USB {exfil_events[0].usb_id}"
                if exfil_usb else f"Sensitive payload egressed via network transfer to {exfil_events[0].destination_ip}"
            )
            stages.append(
                AttackStage(
                    stage_id="STG-05",
                    stage_name="Exfiltration",
                    status="confirmed",
                    confidence=0.96,
                    summary=summary_desc,
                    evidence_event_ids=[e.event_id for e in exfil_events],
                    evidence_strength=0.98,
                    explanation="Physical or network exfiltration of sensitive assets verified through event telemetry.",
                    supporting_signals=[s.detector_name for s in signals if s.recommended_stage == "Exfiltration"]
                )
            )
        else:
            stages.append(
                AttackStage(
                    stage_id="STG-05",
                    stage_name="Exfiltration",
                    status="insufficient evidence",
                    confidence=0.10,
                    summary="Insufficient evidence to classify this as a confirmed attack stage.",
                    evidence_event_ids=[],
                    evidence_strength=0.0,
                    explanation="Insufficient evidence to classify this as a confirmed attack stage.",
                    missing_evidence=[
                        "No confirmed data transfer.",
                        "No confirmed USB copy.",
                        "No network destination associated with sensitive file movement."
                    ]
                )
            )

        # 6. Impact
        stages.append(
            AttackStage(
                stage_id="STG-06",
                stage_name="Impact",
                status="insufficient evidence",
                confidence=0.05,
                summary="Insufficient evidence to classify this as a confirmed attack stage.",
                evidence_event_ids=[],
                evidence_strength=0.0,
                explanation="Insufficient evidence to classify this as a confirmed attack stage.",
                missing_evidence=["Service disruption logs", "Ransomware encryption notes", "Data destruction events"]
            )
        )

        return stages

    def _calculate_confidence(
        self,
        events: List[NormalizedEvent],
        stages: List[AttackStage],
        users: List[str],
        is_extended_window: bool
    ) -> ConfidenceDecomposition:
        """Decompose confidence into 5 transparent, deterministic mathematical factors."""
        # 1. Evidence completeness: confirmed stages with actual evidence events / total confirmed stages
        confirmed_stages = [s for s in stages if s.status == "confirmed"]
        if confirmed_stages:
            evd_comp = sum(1 for s in confirmed_stages if len(s.evidence_event_ids) > 0) / len(confirmed_stages)
        else:
            evd_comp = 0.50

        # 2. Entity linkage: proportion of events tied to primary user and primary device
        primary_user = users[0] if users else None
        user_matches = sum(1 for e in events if e.user_id == primary_user)
        entity_link = user_matches / max(1, len(events))

        # 3. Temporal consistency: 0.95 for tight standard window; 0.70 for slow-burn
        temporal_cons = 0.70 if is_extended_window else 0.95

        # 4. Baseline strength
        user_b_strengths = [BaselineProfiler.get_user_baseline_strength(self.baseline, u) for u in users]
        if "STRONG" in user_b_strengths:
            b_val = 0.95
        elif "MODERATE" in user_b_strengths:
            b_val = 0.85
        elif "WEAK" in user_b_strengths:
            b_val = 0.70
        else:
            b_val = 0.50

        # 5. Stage coverage: ratio of confirmed stages vs expected kill chain core (Initial Access, Collection, Exfiltration)
        core_confirmed = sum(1 for s in confirmed_stages if s.stage_name in ("Initial Access", "Collection", "Exfiltration"))
        stage_cov = min(1.0, core_confirmed / 3.0)

        # Weighted combination
        weights = self.weights
        total_conf = (
            weights.evidence_completeness * evd_comp +
            weights.entity_linkage * entity_link +
            weights.temporal_consistency * temporal_cons +
            weights.baseline_strength * b_val +
            weights.stage_coverage * stage_cov
        )

        overall = round(total_conf, 2)
        expl = (
            f"Evidence completeness: {int(evd_comp*100)}%, "
            f"Entity linkage: {int(entity_link*100)}%, "
            f"Temporal consistency: {int(temporal_cons*100)}%, "
            f"Baseline strength: {int(b_val*100)}%, "
            f"Stage coverage: {int(stage_cov*100)}%"
        )

        return ConfidenceDecomposition(
            overall_confidence=overall,
            evidence_completeness=round(evd_comp, 2),
            entity_linkage=round(entity_link, 2),
            temporal_consistency=round(temporal_cons, 2),
            baseline_strength=round(b_val, 2),
            stage_coverage=round(stage_cov, 2),
            explanation=expl
        )

    def _generate_attack_story(
        self,
        incident_id: str,
        title: str,
        risk_score: float,
        confidence: float,
        events: List[NormalizedEvent],
        signals: List[DetectionSignal],
        stages: List[AttackStage],
        users: List[str],
        devices: List[str],
        files: List[str],
        usbs: List[str]
    ) -> AttackStory:
        """Construct grounded, deterministic human-readable attack narrative."""
        user_str = ", ".join(users) or "an unidentified user"
        dev_str = ", ".join(devices) or "an endpoint"
        file_str = ", ".join(files) or "sensitive files"
        usb_str = ", ".join(usbs) or "a removable media device"

        # Find key events
        login_evts = [e for e in events if "login" in e.event_type]
        file_evts = [e for e in events if e.event_type == "file_access"]
        usb_evts = [e for e in events if e.event_type == "usb_file_copy"]
        net_evts = [e for e in events if e.event_type == "network_transfer"]

        narrative_parts = []
        if login_evts:
            l0 = login_evts[0]
            narrative_parts.append(
                f"User {l0.user_id} authenticated from IP {l0.ip_address or 'unknown'} "
                f"({l0.country or 'unknown country'}), which deviated from normal baseline activity."
            )
        if file_evts:
            f0 = file_evts[0]
            narrative_parts.append(
                f"Subsequently, the same account accessed high-sensitivity file '{f0.file_path}' "
                f"({f0.file_sensitivity or 'CONFIDENTIAL'}) for the first time."
            )
        if usb_evts:
            u0 = usb_evts[0]
            narrative_parts.append(
                f"An unapproved USB device ('{u0.usb_id}') was attached to workstation {u0.device_id}, "
                f"and '{u0.file_path}' was directly copied to the removable storage."
            )
        elif net_evts:
            n0 = net_evts[0]
            narrative_parts.append(
                f"A high-volume outbound network transfer ({n0.bytes_transferred or 0} bytes) "
                f"egressed to external destination {n0.destination_ip or n0.destination_domain}."
            )

        what_happened = " ".join(narrative_parts) or f"Multiple correlated security signals observed on {dev_str} involving {user_str}."

        why_it_matters = (
            f"The combination of initial access anomaly, first-time sensitive asset access, and physical/network "
            f"data staging presents strong indicators of unauthorized data exfiltration and potential corporate espionage."
        )

        evidence_chain = [f"{e.event_id}: {e.event_type} at {e.timestamp.strftime('%H:%M:%S UTC')}" for e in events]
        entity_relationships = [
            f"User {user_str} operated on Device {dev_str}",
            f"Workstation {dev_str} accessed file {file_str}",
            f"Removable media {usb_str} connected to {dev_str}"
        ]

        uncertainties = []
        if not usb_evts and not net_evts:
            uncertainties.append("Missing definitive exfiltration evidence; sequence may represent benign reconnaissance.")

        alt_explanations = [
            "Authorized emergency administrative operation or sanctioned local disaster-recovery copy.",
            "Legitimate employee travel using commercial roaming network."
        ]

        return AttackStory(
            story_id=f"STORY-{incident_id}",
            headline=f"Likely Sensitive Data Exfiltration Sequence: {user_str} on {dev_str}",
            what_happened=what_happened,
            why_it_matters=why_it_matters,
            confidence=confidence,
            risk_score=risk_score,
            attack_stages=[s.stage_name for s in stages if s.status == "confirmed"],
            evidence_chain=evidence_chain,
            entity_relationships=entity_relationships,
            uncertainties=uncertainties,
            alternative_explanations=alt_explanations
        )

    def _generate_recommendations(
        self,
        attack_type: str,
        users: List[str],
        devices: List[str],
        usbs: List[str]
    ) -> List[str]:
        """Generate safe, defensive analyst-in-the-loop triage guidance."""
        recs = [
            f"Verify account ownership and authentication history for {', '.join(users)} with data owner.",
            f"Review MFA and identity provider records for unusual token requests or geographic anomalies.",
            f"Inspect endpoint logs on {', '.join(devices)} for unauthorized process execution or staging archives.",
            "Preserve forensic integrity: Export evidence ledger and memory artifacts before applying host remediation.",
            "Human Approval Gate: Follow organizational incident response policy prior to session revocation or host containment."
        ]
        if usbs:
            recs.append(f"Audit physical custody of removable storage serial number(s): {', '.join(usbs)}.")
        return recs

    def _generate_counterfactuals(
        self,
        events: List[NormalizedEvent],
        signals: List[DetectionSignal],
        original_risk: float,
        original_severity: str,
        is_extended_window: bool
    ) -> List[CounterfactualResult]:
        """Perform deterministic what-if analysis by systematically removing key evidence events."""
        results: List[CounterfactualResult] = []

        for evt in events:
            # Filter out signals that rely strictly on this event
            remaining_signals = [s for s in signals if s.event_ids != [evt.event_id]]
            remaining_events = [e for e in events if e.event_id != evt.event_id]

            # Reconstruct stages without this event
            cf_stages = self._reconstruct_attack_stages(remaining_events, remaining_signals)
            cf_risk, cf_severity, _ = ScoringEngine.calculate_score(
                signals=remaining_signals,
                stages=cf_stages,
                is_extended_window=is_extended_window
            )

            delta = round(original_risk - cf_risk, 1)
            affected = [
                s.stage_name for s in cf_stages
                if s.status != "confirmed" and any(orig.stage_name == s.stage_name and orig.status == "confirmed" for orig in self._reconstruct_attack_stages(events, signals))
            ]

            expl = (
                f"Removing {evt.event_type} ({evt.event_id}) reduces risk by {delta} points "
                f"(from {original_risk} to {cf_risk}) and shifts severity from {original_severity} to {cf_severity}."
            )

            results.append(
                CounterfactualResult(
                    removed_event_id=evt.event_id,
                    event_description=f"{evt.event_type} ({evt.file_path or evt.usb_id or evt.ip_address or evt.event_id})",
                    original_risk=original_risk,
                    counterfactual_risk=cf_risk,
                    risk_delta=delta,
                    original_severity=original_severity,
                    counterfactual_severity=cf_severity,
                    affected_stages=affected,
                    explanation=expl
                )
            )

        # Sort by impact (highest delta first)
        results.sort(key=lambda r: r.risk_delta, reverse=True)
        return results
