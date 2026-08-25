import pytest
import sys
import os
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
sys.path.append(str(Path(__file__).resolve().parent.parent.parent / "sast-engine"))

from llm.schemas import validate_cascade_response
from security_intel.enrichment_service import enrich_finding_metadata
from web.backend.services.finding_service import FindingService
from web.backend.services.result_service import ResultService

# 1. Schema Validation Tests
def test_validation_schema_valid():
    valid_payload = {
        "verdict": "VALID",
        "verdict_confidence": 0.95,
        "reasoning": "Standard SQL injection vulnerability found.",
        "remediation": "Use parameterized queries.",
        "security_metadata": {
            "cwe_id": "CWE-89",
            "cwe_name": "SQL Injection",
            "vulnerability_id": "sql_injection",
            "cve_ids": [],
            "owasp_category": "A03:2021 Injection"
        },
        "fix": {
            "available": True,
            "summary": "Use safe SQL parameters",
            "strategy": "Change query string to placeholder binding",
            "files": ["main.py"],
            "patch": "--- main.py\n+++ main.py\n...",
            "before": "query = 'SELECT * FROM users WHERE id = ' + user_id",
            "after": "query = 'SELECT * FROM users WHERE id = %s'; cursor.execute(query, (user_id,))",
            "explanation": "Parameters prevent injection.",
            "confidence": 0.98
        },
        "references": [],
        "proof_of_concept": {
            "available": True,
            "type": "input",
            "description": "Trigger sql injection via query param",
            "input": "?id=1 OR 1=1",
            "expected_effect": "SQL Syntax Error or all rows returned",
            "verification_status": "NOT_EXECUTED"
        }
    }
    
    is_valid, err = validate_cascade_response(valid_payload)
    assert is_valid is True, f"Failed validation: {err}"

def test_validation_schema_invalid():
    invalid_payload = {
        "verdict": "VALID",
        "verdict_confidence": 0.95
        # missing reasoning, remediation, fix, etc.
    }
    is_valid, err = validate_cascade_response(invalid_payload)
    assert is_valid is False
    assert "Missing required field" in err

# 2. Enrichment Service Tests
@patch("security_intel.enrichment_service._fetch_with_timeout")
@patch("security_intel.enrichment_service._get_cisa_kev_catalog")
def test_enrichment_service(mock_kev, mock_fetch):
    # Mock EPSS Response
    mock_fetch.return_value = json.dumps({
        "data": [{
            "cve": "CVE-2021-44228",
            "epss": "0.97405",
            "percentile": "0.99981"
        }]
    })
    
    # Mock KEV Catalog
    mock_kev.return_value = {
        "vulnerabilities": [{
            "cveID": "CVE-2021-44228",
            "dateAdded": "2021-12-10",
            "knownRansomwareCampaignUse": "Known"
        }]
    }
    
    finding = {
        "security_metadata": {
            "cve_ids": ["CVE-2021-44228"]
        }
    }
    
    enriched = enrich_finding_metadata(finding)
    sec_meta = enriched["security_metadata"]
    
    assert sec_meta["epss_score"] == 0.97405
    assert sec_meta["epss_percentile"] == 0.99981
    assert sec_meta["known_exploited"] is True
    assert sec_meta["used_in_ransomware"] is True
    assert sec_meta["date_added_to_kev"] == "2021-12-10"

# 3. Patch Application Tests
@patch("web.backend.services.finding_service.FindingService.get_finding_by_fingerprint")
@patch("web.backend.services.result_service.ResultService.get_scan")
@patch("web.backend.services.finding_service.FindingService._save_updated_finding")
def test_safe_patch_application_success(mock_save, mock_get_scan, mock_get_finding):
    temp_dir = tempfile.mkdtemp()
    target_file = "app.py"
    target_path = os.path.join(temp_dir, target_file)
    
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("def run():\n    db.execute('SELECT * FROM users WHERE id = ' + req_id)\n")
        
    finding = {
        "fingerprint": "test_fp",
        "verdict": "VALID",
        "file_path": target_file,
        "scan_id": "test_scan",
        "human_validation": {
            "status": "APPROVED"
        },
        "fix": {
            "available": True,
            "status": "APPROVED",
            "before": "db.execute('SELECT * FROM users WHERE id = ' + req_id)",
            "after": "db.execute('SELECT * FROM users WHERE id = %s', (req_id,))"
        }
    }
    
    scan_data = {
        "scan_metadata": {
            "repo": temp_dir
        },
        "findings": [finding]
    }
    
    mock_get_finding.return_value = finding
    mock_get_scan.return_value = scan_data
    
    res = FindingService.apply_fix("test_fp", "TestReviewer")
    
    assert res["success"] is True
    
    # Verify file content is updated
    with open(target_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "db.execute('SELECT * FROM users WHERE id = %s', (req_id,))" in content
    assert finding["fix"]["status"] == "APPLIED"
    
    shutil.rmtree(temp_dir)

@patch("web.backend.services.finding_service.FindingService.get_finding_by_fingerprint")
@patch("web.backend.services.result_service.ResultService.get_scan")
@patch("web.backend.services.finding_service.FindingService._save_updated_finding")
def test_safe_patch_application_conflict(mock_save, mock_get_scan, mock_get_finding):
    temp_dir = tempfile.mkdtemp()
    target_file = "app.py"
    target_path = os.path.join(temp_dir, target_file)
    
    # File does NOT contain original line (it has changed)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("def run():\n    # Line has been changed/deleted\n    pass\n")
        
    finding = {
        "fingerprint": "test_fp",
        "verdict": "VALID",
        "file_path": target_file,
        "scan_id": "test_scan",
        "human_validation": {
            "status": "APPROVED"
        },
        "fix": {
            "available": True,
            "status": "APPROVED",
            "before": "db.execute('SELECT * FROM users WHERE id = ' + req_id)",
            "after": "db.execute('SELECT * FROM users WHERE id = %s', (req_id,))"
        }
    }
    
    scan_data = {
        "scan_metadata": {
            "repo": temp_dir
        },
        "findings": [finding]
    }
    
    mock_get_finding.return_value = finding
    mock_get_scan.return_value = scan_data
    
    res = FindingService.apply_fix("test_fp", "TestReviewer")
    
    assert res["success"] is False
    assert "Conflict" in res["error"]
    assert finding["fix"]["status"] == "CONFLICT"
    
    shutil.rmtree(temp_dir)
