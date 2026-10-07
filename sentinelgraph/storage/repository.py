"""In-memory and file-backed storage repository for analysis runs and incidents."""
from pathlib import Path
from typing import Dict, List, Optional
from sentinelgraph.models import AnalysisResult, Incident


class AnalysisRepository:
    """Stores and retrieves analysis results and incidents."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or Path("outputs/analysis_runs")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._runs: Dict[str, AnalysisResult] = {}
        self._incidents: Dict[str, Incident] = {}

    def save_run(self, result: AnalysisResult) -> None:
        """Store an analysis run in memory and persist as JSON."""
        self._runs[result.run_id] = result
        for inc in result.incidents:
            self._incidents[inc.incident_id] = inc

        # Persist to disk
        run_file = self.storage_dir / f"{result.run_id}.json"
        run_file.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    def get_run(self, run_id: str) -> Optional[AnalysisResult]:
        """Retrieve run by ID."""
        if run_id in self._runs:
            return self._runs[run_id]
        run_file = self.storage_dir / f"{run_id}.json"
        if run_file.exists():
            result = AnalysisResult.model_validate_json(run_file.read_text(encoding="utf-8"))
            self._runs[result.run_id] = result
            for inc in result.incidents:
                self._incidents[inc.incident_id] = inc
            return result
        return None

    def get_latest_run(self) -> Optional[AnalysisResult]:
        """Return the most recently saved run."""
        if self._runs:
            return list(self._runs.values())[-1]
        json_files = sorted(self.storage_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        if json_files:
            return self.get_run(json_files[-1].stem)
        return None

    def get_all_incidents(self) -> List[Incident]:
        """Return all indexed incidents."""
        return list(self._incidents.values())

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an individual incident by ID."""
        if incident_id in self._incidents:
            return self._incidents[incident_id]
        # Try loading latest runs
        latest = self.get_latest_run()
        if latest:
            for inc in latest.incidents:
                if inc.incident_id == incident_id:
                    return inc
        return None


repository = AnalysisRepository()
