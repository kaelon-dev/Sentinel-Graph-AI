"""Natural language explanation templates and forensic narratives."""
from typing import List
from sentinelgraph.models import Incident, AttackStage, CounterfactualResult


class NarrativeExplainer:
    """Generates explainability narratives for incidents, counterfactuals, and benign twins."""

    @classmethod
    def explain_benign_twin(cls, incident: Incident) -> str:
        """Explain why this attack differs from a structurally similar benign sequence."""
        return (
            f"BENIGN TWIN COMPARISON:\n"
            f"A benign twin sequence (Routine login -> Expected file access -> Corporate approved USB -> Public transfer) "
            f"shares structural workflow stages with this incident. However, this incident is classified as {incident.severity} "
            f"because contextual telemetry is anomalous: the authentication originated outside the baseline, "
            f"the file '{', '.join(incident.affected_files) or 'sensitive target'}' has High/Critical sensitivity without prior access, "
            f"and removable storage '{', '.join(incident.affected_usb_devices) or 'USB'}' is unapproved. "
            f"Simple event counting is insufficient; behavioural context differentiates legitimate operations from insider threats."
        )

    @classmethod
    def explain_signal_vs_story(cls, signal_count: int, incident_count: int) -> str:
        """Articulate the distinction between individual atomic alerts and correlated attack stories."""
        return (
            f"SIGNAL VS STORY RECONSTRUCTION:\n"
            f"The detection pipeline identified {signal_count} disparate security signal(s). "
            f"Rather than flooding the analyst queue with {signal_count} isolated alerts, SentinelGraph AI correlated "
            f"these events across entity relationships (same user, device, and payload) into {incident_count} explainable attack story. "
            f"{signal_count} alerts != {signal_count} attacks. We reconstruct what the adversary achieved from initial access to egress."
        )
