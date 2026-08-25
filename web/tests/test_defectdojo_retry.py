import pytest
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from web.backend.services.defectdojo_service import DefectDojoService
from web.backend.services.result_service import ResultService
from integrations.defectdojo.client import DefectDojoClient
from integrations.defectdojo.finding_mapper import map_finding_to_defectdojo

# --- Finding Mapper Tests ---

def test_mapper_valid_llm_finding_to_defectdojo():
    # Test 1: Valid LLM finding -> correct DefectDojo payload
    finding = {
        "fingerprint": "fp1234567890",
        "category": "default_credentials",
        "subtype": "CWE-798-HARDCODED-CREDENTIALS",
        "severity": "High",
        "verdict": "VALID",
        "verdict_confidence": 0.95,
        "reasoning": "Hardcoded password found on main.py line 20",
        "instances": [
            {
                "sink_file": "main.py",
                "sink_line": 20
            }
        ],
        "generated_poc": {
            "poc_type": "cURL Command",
            "payload": "curl -X POST ...",
            "instructions": "Run curl..."
        },
        "remediation": "Do not hardcode credentials."
    }
    
    payload = map_finding_to_defectdojo(finding)
    
    assert payload["unique_id_from_tool"] == "fp1234567890"
    assert payload["vuln_id_from_tool"] == "default_credentials"
    assert payload["severity"] == "High"
    assert payload["cwe"] == 798
    assert payload["verified"] is True
    assert payload["active"] is True
    assert payload["false_p"] is False
    assert payload["file_path"] == "main.py"
    assert payload["line"] == 20
    assert "cURL Command" in payload["description"]
    assert "Hardcoded password" in payload["description"]
    assert payload["title"] == "Taintlace: default_credentials - CWE-798-HARDCODED-CREDENTIALS"
    assert payload["mitigation"] == "Do not hardcode credentials."

def test_mapper_false_positive_verdict():
    # Test 2: FALSE_POSITIVE -> verified=false, false_p=true, active=false
    finding = {
        "fingerprint": "fp_fp",
        "category": "xss",
        "subtype": "CWE-79",
        "verdict": "FALSE_POSITIVE"
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["verified"] is False
    assert payload["false_p"] is True
    assert payload["active"] is False

def test_mapper_approved_verdict():
    # Test 3: APPROVED/VALID -> verified=true, false_p=false, active=true
    finding = {
        "fingerprint": "fp_approved",
        "category": "xss",
        "verdict": "APPROVED"
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["verified"] is True
    assert payload["false_p"] is False
    assert payload["active"] is True

def test_mapper_cwe_extraction():
    # Test 4: CWE-798-HARDCODED-CREDENTIALS -> cwe=798
    finding = {
        "fingerprint": "fp_cwe",
        "category": "xss",
        "subtype": "CWE-798-HARDCODED-CREDENTIALS"
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["cwe"] == 798

def test_mapper_missing_cwe():
    # Test 5: Missing CWE -> cwe=None
    finding = {
        "fingerprint": "fp_cwe_none",
        "category": "xss",
        "subtype": "UNKNOWN"
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["cwe"] is None

def test_mapper_severity_preservation():
    # Test 6: Existing severity is preserved exactly
    finding = {
        "fingerprint": "fp_sev",
        "category": "xss",
        "severity": "Low"
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["severity"] == "Low"

def test_mapper_severity_fallback():
    # Test 7: Severity fallback is only used when final severity is missing
    finding = {
        "fingerprint": "fp_fallback",
        "category": "default_credentials",
        "subtype": "CWE-798-HARDCODED-CREDENTIALS"
        # no severity
    }
    payload = map_finding_to_defectdojo(finding)
    # CWE-798 fallback is Medium
    assert payload["severity"] == "Medium"

def test_mapper_fingerprint_preservation():
    # Test 8: Existing fingerprint is preserved exactly
    finding = {
        "fingerprint": "exact_fp_123",
        "category": "xss"
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["unique_id_from_tool"] == "exact_fp_123"

def test_mapper_missing_fingerprint_fails():
    # Test 9: Missing fingerprint causes a clear validation error
    finding = {
        "category": "xss"
    }
    with pytest.raises(ValueError, match="missing the mandatory 'fingerprint' field"):
        map_finding_to_defectdojo(finding)

def test_mapper_generated_poc_preservation():
    # Test 10: Generated PoC is preserved in description
    finding = {
        "fingerprint": "fp_poc",
        "category": "xss",
        "generated_poc": {
            "poc_type": "Exploit script",
            "payload": "payload_content",
            "instructions": "Step 1: run payload"
        }
    }
    payload = map_finding_to_defectdojo(finding)
    assert "Exploit script" in payload["description"]
    assert "payload_content" in payload["description"]
    assert "Step 1: run payload" in payload["description"]

def test_mapper_reasoning_preservation():
    # Test 11: LLM reasoning is preserved in description
    finding = {
        "fingerprint": "fp_reason",
        "category": "xss",
        "reasoning": "Reasoning details here."
    }
    payload = map_finding_to_defectdojo(finding)
    assert "Reasoning details here." in payload["description"]

def test_mapper_remediation_preservation():
    # Test 12: Remediation is mapped to mitigation
    finding = {
        "fingerprint": "fp_remedy",
        "category": "xss",
        "remediation": "Do X instead of Y."
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["mitigation"] == "Do X instead of Y."

# --- Retry Flow Integration Tests ---

def test_retry_uses_persisted_findings_no_gemini():
    # Test 13: Retry uses persisted findings and does not invoke Gemini
    mock_scan_data = {
        "scan_metadata": {
            "repo": "test-repo",
            "timestamp": "2026-08-23T12:00:00",
            "defectdojo_upload_status": "failed",
            "defectdojo_engagement_id": None
        },
        "findings": [
            {
                "fingerprint": "fp_retry",
                "category": "xss",
                "subtype": "CWE-79",
                "severity": "Medium",
                "verdict": "VALID"
            }
        ]
    }
    
    with patch.object(ResultService, "get_scan", return_value=mock_scan_data) as mock_get_scan, \
         patch.object(ResultService, "save_scan") as mock_save_scan, \
         patch.object(DefectDojoClient, "validate_credentials", return_value=(True, "CONNECTED")), \
         patch.object(DefectDojoClient, "get_or_create_product_type", return_value=1), \
         patch.object(DefectDojoClient, "get_or_create_product", return_value=2), \
         patch.object(DefectDojoClient, "get_or_create_engagement", return_value=3), \
         patch.object(DefectDojoClient, "create_test", return_value=4), \
         patch.object(DefectDojoClient, "push_findings") as mock_push:
         
        mock_push.return_value = [
            {
                "fingerprint": "fp_retry",
                "category": "xss",
                "subtype": "CWE-79",
                "severity": "Medium",
                "verdict": "VALID",
                "defectdojo_id": 999
            }
        ]
        
        # Trigger sync retry
        res = DefectDojoService.push_findings(scan_id="test_scan")
        assert res["success"] is True
        
        # Verify push_findings received the exact cached finding, not regenerated
        mock_push.assert_called_once()
        args = mock_push.call_args[0]
        assert args[1][0]["fingerprint"] == "fp_retry"
        assert args[1][0]["verdict"] == "VALID"

def test_retry_stable_fingerprint():
    # Test 14: Same fingerprint on retry does not generate a new fingerprint
    finding = {
        "fingerprint": "fp_retry_stable",
        "category": "xss"
    }
    payload = map_finding_to_defectdojo(finding)
    assert payload["unique_id_from_tool"] == "fp_retry_stable"
