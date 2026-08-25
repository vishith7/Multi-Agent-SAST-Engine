import os
import sys
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# Ensure we can import web package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from web.backend.main import app

client = TestClient(app)

def test_health_endpoint():
    # Mock shutil.which to verify joern detection
    with patch("shutil.which", return_value="/usr/bin/joern"):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "taintlace-web"
        assert data["engine"] == "available"
        assert data["joern_found"] is True

def test_dashboard_summary():
    mock_scans = [
        {"scan_id": "findings_test_123", "repo": "test-repo", "timestamp": "2026-08-21T18:00:00", "findings_count": 2}
    ]
    mock_repos = [
        {"name": "test-repo", "path_or_url": "/path/to/test-repo", "last_scan": "2026-08-21T18:00:00"}
    ]
    mock_findings = [
        {"fingerprint": "fp1", "category": "injection", "subtype": "CWE-78", "verdict": "VALID", "severity": "Critical", "priority": "P1", "sla_status": {"status": "overdue"}},
        {"fingerprint": "fp2", "category": "xxe", "subtype": "CWE-611", "verdict": "NEEDS_REVIEW", "severity": "High", "priority": "P2", "sla_status": {"status": "on-track"}}
    ]

    with patch("web.backend.services.result_service.ResultService.get_all_scans", return_value=mock_scans), \
         patch("web.backend.services.repository_service.RepositoryService.get_all_repositories", return_value=mock_repos), \
         patch("web.backend.services.finding_service.FindingService.get_all_findings", return_value=mock_findings):
        
        response = client.get("/api/dashboard/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_scans"] == 1
        assert data["total_findings"] == 2
        assert data["severity_stats"]["Critical"] == 1
        assert data["severity_stats"]["High"] == 1
        assert data["verdict_stats"]["VALID"] == 1
        assert data["verdict_stats"]["NEEDS_REVIEW"] == 1
        assert data["sla_stats"]["overdue"] == 1

def test_list_scans():
    mock_scans = [
        {"scan_id": "findings_test_1", "repo": "repo-1", "timestamp": "2026-08-21T18:00:00", "status": "completed", "findings_count": 3}
    ]
    
    with patch("web.backend.services.result_service.ResultService.get_all_scans", return_value=mock_scans):
        response = client.get("/api/scans")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["scan_id"] == "findings_test_1"
        assert data[0]["repo"] == "repo-1"

def test_start_scan():
    with patch("web.backend.services.scan_service.ScanService.start_scan_thread", return_value="findings_test_999"):
        payload = {
            "repo_path": "/path/to/my-repo",
            "scan_mode": "AUTO",
            "cpg_name": "cpg.bin"
        }
        response = client.post("/api/scans", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["success"] is True
        assert data["scan_id"] == "findings_test_999"

def test_scan_status_not_found():
    with patch("web.backend.services.scan_service.ScanService.get_scan_status", return_value=None):
        response = client.get("/api/scans/missing_scan_id/status")
        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False
        assert "not exist" in data["error"]["message"]

def test_sync_scan_defectdojo():
    mock_scan = {
        "scan_metadata": {"repo": "test-repo", "timestamp": "2026-08-21T18:00:00"},
        "findings": []
    }
    with patch("web.backend.services.result_service.ResultService.get_scan", return_value=mock_scan):
        response = client.post("/api/scans/findings_test_123/sync-defectdojo")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["scan_id"] == "findings_test_123"

def test_defectdojo_config():
    mock_config = {
        "url": "http://defectdojo.test",
        "engagement_id": "5",
        "has_token": True,
        "configured": True
    }
    with patch("web.backend.services.defectdojo_service.DefectDojoService.get_config", return_value=mock_config):
        response = client.get("/api/defectdojo/config")
        assert response.status_code == 200
        data = response.json()
        assert data["url"] == "http://defectdojo.test"
        assert data["configured"] is True

def test_mongodb_fallback():
    from web.backend.utils.mongo import get_mongo_db
    with patch.dict(os.environ, {"MONGODB_URI": "mongodb+srv://noobmaster:<db_password>@cluster0.xd9qw.mongodb.net/taintlace?appName=Cluster0"}):
        db = get_mongo_db()
        assert db is None

def test_defectdojo_config_save():
    with patch("web.backend.services.defectdojo_service.DefectDojoService.save_config", return_value={"success": True, "message": "Saved"}):
        payload = {
            "url": "http://defectdojo.test",
            "token": "some_token",
            "engagement_id": "5"
        }
        response = client.post("/api/defectdojo/config", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Saved"

def test_delete_scan_endpoint():
    mock_scan = {"scan_metadata": {"repo": "test-repo"}}
    with patch("web.backend.services.result_service.ResultService.get_scan", return_value=mock_scan), \
         patch("web.backend.services.result_service.ResultService.delete_scan", return_value=True):
         
        response = client.delete("/api/scans/test_scan_id")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["scan_id"] == "test_scan_id"


