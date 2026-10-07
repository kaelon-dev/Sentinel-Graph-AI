"""End-to-end analysis pipeline orchestrator for SentinelGraph AI."""
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from sentinelgraph.config import settings
from sentinelgraph.models import (
    AnalysisResult,
    Incident,
    NormalizedEvent,
    BaselineProfile,
)
from sentinelgraph.ingestion.parsers import LogParser
from sentinelgraph.baseline.profiler import BaselineProfiler
from sentinelgraph.detection.rules import DetectionEngine
from sentinelgraph.detection.anomaly_ml import MLAnomalyDetector
from sentinelgraph.correlation.sessionization import Sessionizer
from sentinelgraph.correlation.attack_chain import AttackChainReconstructor
from sentinelgraph.graph.entity_graph import GraphEngine
from sentinelgraph.storage.repository import repository


class SentinelPipeline:
    """Orchestrates end-to-end ingestion, detection, correlation, and explanation."""

    @classmethod
    def analyze(
        cls,
        content: Union[str, bytes],
        file_name: str,
        run_id: Optional[str] = None,
        use_extended_window: bool = False,
        baseline_events: Optional[List[NormalizedEvent]] = None,
        enable_ml: bool = False
    ) -> AnalysisResult:
        """Execute full 16-step analysis pipeline deterministically."""
        start_time = time.time()
        run_id = run_id or f"RUN-{uuid.uuid4().hex[:8].upper()}"

        # 1-3. Ingest, Parse, Normalize
        valid_events, invalid_records, dup_count, source_meta = LogParser.parse_content(
            content=content,
            file_name=file_name,
            run_id=run_id
        )

        # 4. Build Behavioral Baseline
        all_baseline_events = list(baseline_events or [])
        if not all_baseline_events:
            normal_csv = Path("data/generated/normal_logs.csv")
            if normal_csv.exists() and file_name != "normal_logs.csv":
                norm_events, _, _, _ = LogParser.parse_file(normal_csv, run_id="BASELINE-INIT")
                all_baseline_events = norm_events
            elif valid_events:
                all_baseline_events = valid_events

        baseline_profile = BaselineProfiler.build_baseline(all_baseline_events)

        # 5-6. Detect Signals & Deduplicate
        detector = DetectionEngine(baseline=baseline_profile)
        signals = detector.detect_signals(valid_events)

        # Optional ML anomaly detector (Section 71)
        if enable_ml and len(valid_events) >= 10:
            ml_detector = MLAnomalyDetector(random_seed=42)
            ml_signals = ml_detector.fit_predict(valid_events)
            signals.extend(ml_signals)

        # 7. Sessionize
        sessionized_events = Sessionizer.sessionize(valid_events)

        # 8-15. Correlate, Reconstruct Attack Chains, Score, Graph, Counterfactuals
        reconstructor = AttackChainReconstructor(baseline=baseline_profile)
        incidents: List[Incident] = reconstructor.correlate(
            events=sessionized_events,
            signals=signals,
            use_extended_window=use_extended_window
        )

        # Attach graph to each incident
        event_map = {e.event_id: e for e in sessionized_events}
        for inc in incidents:
            inc_events = [event_map[item.event_id] for item in inc.evidence_items if item.event_id in event_map]
            inc.graph_data = GraphEngine.build_incident_graph(inc, inc_events)
            inc.source_metadata = source_meta

        # Baseline summary
        baseline_summary = {
            "total_users_profiled": len(baseline_profile.users),
            "total_devices_profiled": len(baseline_profile.devices),
            "events_observed": baseline_profile.total_events_observed,
            "approved_usbs_tracked": len(baseline_profile.global_approved_usbs)
        }

        exec_time = round(time.time() - start_time, 3)

        result = AnalysisResult(
            run_id=run_id,
            analysis_timestamp=datetime.now(timezone.utc),
            source_metadata=source_meta,
            total_raw_records=len(valid_events) + len(invalid_records) + dup_count,
            valid_event_count=len(valid_events),
            invalid_records=invalid_records,
            duplicate_count=dup_count,
            signals_detected=signals,
            incidents=incidents,
            baseline_summary=baseline_summary,
            execution_time_seconds=exec_time
        )

        # Persist to repository
        repository.save_run(result)

        return result

    @classmethod
    def analyze_file(
        cls,
        file_path: Union[str, Path],
        run_id: Optional[str] = None,
        use_extended_window: bool = False,
        baseline_events: Optional[List[NormalizedEvent]] = None,
        enable_ml: bool = False
    ) -> AnalysisResult:
        """Analyze a file located on the local filesystem."""
        p = Path(file_path)
        with open(p, "rb") as f:
            content = f.read()
        return cls.analyze(
            content=content,
            file_name=p.name,
            run_id=run_id,
            use_extended_window=use_extended_window,
            baseline_events=baseline_events,
            enable_ml=enable_ml
        )
