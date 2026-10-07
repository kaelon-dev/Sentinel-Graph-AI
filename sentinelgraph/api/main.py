"""FastAPI REST service providing endpoints for SentinelGraph AI."""
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sentinelgraph.version import __version__, __app_name__, __tagline__
from sentinelgraph.config import settings
from sentinelgraph.models import (
    AnalysisResult,
    Incident,
    EvidenceItem,
    TemporalGraphData,
    AttackStory,
    CounterfactualResult,
)
from sentinelgraph.pipeline import SentinelPipeline
from sentinelgraph.storage.repository import repository
from sentinelgraph.evaluation.metrics import compute_metrics, EvaluationMetrics
from scripts.evaluate_detection import evaluate_all

app = FastAPI(
    title=__app_name__,
    version=__version__,
    description="Explainable Cyber Threat Intelligence and Attack Story Reconstruction API"
)

# CORS configured for local dashboard usage only
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

START_TIME = datetime.now(timezone.utc)


class AnalyzeRequest(BaseModel):
    dataset_name: Optional[str] = None
    file_content: Optional[str] = None
    use_extended_window: bool = False
    enable_ml: bool = False


@app.get("/health")
def get_health() -> Dict[str, Any]:
    """Health check returning engine status and system provenance."""
    uptime_sec = round((datetime.now(timezone.utc) - START_TIME).total_seconds(), 1)
    return {
        "status": "HEALTHY",
        "app_name": __app_name__,
        "version": __version__,
        "tagline": __tagline__,
        "uptime_seconds": uptime_sec,
        "active_incidents_count": len(repository.get_all_incidents()),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/sample-datasets")
def list_sample_datasets() -> List[Dict[str, Any]]:
    """List all available benchmark sample datasets in data/generated."""
    gen_dir = Path("data/generated")
    if not gen_dir.exists():
        return []

    datasets = []
    for f in sorted(gen_dir.glob("*.csv")):
        lines_count = sum(1 for _ in open(f, "r", encoding="utf-8", errors="replace")) - 1
        datasets.append({
            "name": f.name,
            "size_bytes": f.stat().st_size,
            "event_count": max(0, lines_count),
            "file_path": str(f)
        })
    return datasets


@app.post("/api/upload-logs")
async def upload_logs(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Upload and validate log files safely without execution."""
    filename = file.filename or "uploaded_logs.csv"
    ext = Path(filename).suffix.lower()
    if ext not in settings.allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Supported formats: {', '.join(settings.allowed_extensions)}"
        )

    content = await file.read()
    if len(content) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file exceeds maximum limit of {settings.max_upload_size_bytes // (1024*1024)} MB."
        )

    # Save to data/raw
    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    target_path = raw_dir / filename
    target_path.write_bytes(content)

    return {
        "status": "UPLOADED",
        "file_name": filename,
        "size_bytes": len(content),
        "target_path": str(target_path)
    }


@app.post("/api/analyze", response_model=AnalysisResult)
def run_analysis(req: AnalyzeRequest) -> AnalysisResult:
    """Run full 16-step analysis pipeline on a dataset or uploaded content."""
    if req.dataset_name:
        dataset_path = Path("data/generated") / req.dataset_name
        if not dataset_path.exists():
            dataset_path = Path("data/raw") / req.dataset_name
        if not dataset_path.exists():
            raise HTTPException(status_code=404, detail=f"Dataset '{req.dataset_name}' not found.")

        return SentinelPipeline.analyze_file(
            file_path=dataset_path,
            use_extended_window=req.use_extended_window,
            enable_ml=req.enable_ml
        )

    if req.file_content:
        return SentinelPipeline.analyze(
            content=req.file_content,
            file_name="direct_input.csv",
            use_extended_window=req.use_extended_window,
            enable_ml=req.enable_ml
        )

    # Default to primary attack dataset
    primary_dataset = Path("data/generated/data_exfiltration_attack_logs.csv")
    if primary_dataset.exists():
        return SentinelPipeline.analyze_file(
            file_path=primary_dataset,
            use_extended_window=req.use_extended_window,
            enable_ml=req.enable_ml
        )

    raise HTTPException(status_code=400, detail="No dataset_name or file_content specified.")


@app.get("/api/incidents", response_model=List[Incident])
def get_incidents() -> List[Incident]:
    """List all incidents from the latest analysis run."""
    latest = repository.get_latest_run()
    if latest:
        return latest.incidents
    return repository.get_all_incidents()


@app.get("/api/incidents/{incident_id}", response_model=Incident)
def get_incident_detail(incident_id: str) -> Incident:
    """Retrieve full incident details including stages, timeline, and score breakdown."""
    inc = repository.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc


@app.get("/api/incidents/{incident_id}/evidence", response_model=List[EvidenceItem])
def get_incident_evidence(incident_id: str) -> List[EvidenceItem]:
    """Retrieve the Evidence Ledger for an individual incident."""
    inc = repository.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc.evidence_items


@app.get("/api/incidents/{incident_id}/graph", response_model=TemporalGraphData)
def get_incident_graph(incident_id: str) -> TemporalGraphData:
    """Retrieve the serialized temporal attack graph for an incident."""
    inc = repository.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    if inc.graph_data:
        return inc.graph_data
    raise HTTPException(status_code=404, detail="Graph data not available for this incident.")


@app.get("/api/incidents/{incident_id}/story", response_model=AttackStory)
def get_incident_story(incident_id: str) -> AttackStory:
    """Retrieve the first-class human-readable Attack Story for an incident."""
    inc = repository.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    if inc.attack_story:
        return inc.attack_story
    raise HTTPException(status_code=404, detail="Attack story not generated for this incident.")


@app.get("/api/incidents/{incident_id}/counterfactuals", response_model=List[CounterfactualResult])
def get_incident_counterfactuals(incident_id: str) -> List[CounterfactualResult]:
    """Retrieve deterministic counterfactual what-if analysis for an incident."""
    inc = repository.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc.counterfactuals


@app.get("/api/evaluation", response_model=EvaluationMetrics)
def get_evaluation() -> EvaluationMetrics:
    """Retrieve or run detection quality evaluation benchmark against ground truth."""
    report_file = Path("outputs/sample_reports/evaluation_report.json")
    if report_file.exists():
        return EvaluationMetrics.model_validate_json(report_file.read_text(encoding="utf-8"))
    return evaluate_all()
