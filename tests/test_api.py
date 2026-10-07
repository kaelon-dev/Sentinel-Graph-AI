"""Comprehensive FastAPI integration tests using TestClient."""
import io
import json
import pytest
from fastapi.testclient import TestClient
from sentinelgraph.api.main import app

client = TestClient(app)


def test_api_health():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "HEALTHY"
    assert "version" in data
    assert "uptime_seconds" in data


def test_sample_datasets():
    res = client.get("/api/sample-datasets")
    assert res.status_code == 200
    datasets = res.json()
    assert isinstance(datasets, list)
    assert any("normal_logs.csv" in d["name"] for d in datasets)


def test_upload_csv():
    csv_bytes = b"event_id,timestamp,event_type,user_id\nE1,2026-10-12T09:00:00Z,login,U101\n"
    res = client.post(
        "/api/upload-logs",
        files={"file": ("test_upload.csv", io.BytesIO(csv_bytes), "text/csv")}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UPLOADED"
    assert data["file_name"] == "test_upload.csv"


def test_invalid_upload():
    # Unsupported extension (.exe)
    res = client.post(
        "/api/upload-logs",
        files={"file": ("malware.exe", io.BytesIO(b"binary"), "application/octet-stream")}
    )
    assert res.status_code == 400
    assert "Unsupported file format" in res.json()["detail"]


def test_analysis():
    # Run analysis on primary dataset
    res = client.post(
        "/api/analyze",
        json={"dataset_name": "data_exfiltration_attack_logs.csv"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid_event_count"] > 0
    assert len(data["incidents"]) >= 1
    assert data["incidents"][0]["severity"] in ("HIGH", "CRITICAL")


def test_incidents_and_details():
    # Fetch list
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert len(incidents) >= 1
    inc_id = incidents[0]["incident_id"]

    # Detail
    detail_res = client.get(f"/api/incidents/{inc_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["incident_id"] == inc_id

    # Evidence
    evd_res = client.get(f"/api/incidents/{inc_id}/evidence")
    assert evd_res.status_code == 200
    assert len(evd_res.json()) >= 1

    # Graph
    graph_res = client.get(f"/api/incidents/{inc_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data

    # Story
    story_res = client.get(f"/api/incidents/{inc_id}/story")
    assert story_res.status_code == 200
    story = story_res.json()
    assert "headline" in story
    assert "what_happened" in story

    # Counterfactuals
    cf_res = client.get(f"/api/incidents/{inc_id}/counterfactuals")
    assert cf_res.status_code == 200
    cfs = cf_res.json()
    assert len(cfs) >= 1


def test_evaluation_endpoint():
    res = client.get("/api/evaluation")
    assert res.status_code == 200
    data = res.json()
    assert data["precision"] == 1.0
    assert data["recall"] == 1.0
    assert data["false_positive_rate"] == 0.0
