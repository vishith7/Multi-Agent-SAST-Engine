import pytest
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from web.backend.services.defectdojo_service import DefectDojoService
from web.backend.utils.errors import InvalidInputException
from integrations.defectdojo.client import DefectDojoClient

def test_random_engagement_id_fails():
    # Test A - Random Engagement ID
    client = DefectDojoClient()
    client.url = "http://valid-url"
    client.token = "valid-token"
    client.engagement_config = "ed123"
    
    with patch.object(DefectDojoClient, "_request") as mock_request:
        mock_request.return_value = {"results": [{"id": 1}]}
        
        # Should fail locally because it's not an int
        is_valid, status = client.validate_credentials()
        assert is_valid is False
        assert "must be an integer" in status
    
    # Also Test A.2 - Integer but not found
    client.engagement_config = "999999"
    with patch.object(DefectDojoClient, "_request") as mock_request:
        # Mock /api/v2/users/ success, but /api/v2/engagements/999999/ raises 404
        def side_effect(path, **kwargs):
            if "/api/v2/engagements/999999/" in path:
                raise RuntimeError("DefectDojo API HTTP error 404 on GET")
            return {"results": [{"id": 1}]}
        mock_request.side_effect = side_effect
        
        is_valid, status = client.validate_credentials()
        assert is_valid is False
        assert "not found" in status

def test_invalid_api_token():
    # Test B
    client = DefectDojoClient()
    client.url = "http://valid-url"
    client.token = "invalid-token"
    client.engagement_config = ""
    
    with patch.object(DefectDojoClient, "_request") as mock_request:
        mock_request.side_effect = RuntimeError("DefectDojo API HTTP error 401 on GET")
        is_valid, status = client.validate_credentials()
        assert is_valid is False
        assert "AUTHENTICATION FAILED" in status

def test_invalid_url():
    # Test C
    client = DefectDojoClient()
    client.url = "http://does-not-exist"
    client.token = "valid-token"
    client.engagement_config = ""
    
    with patch.object(DefectDojoClient, "_request") as mock_request:
        mock_request.side_effect = Exception("Failed to establish a new connection")
        is_valid, status = client.validate_credentials()
        assert is_valid is False
        assert "CONNECTION FAILED" in status

def test_valid_token_no_engagement():
    # Test D
    client = DefectDojoClient()
    client.url = "http://valid-url"
    client.token = "valid-token"
    client.engagement_config = ""
    
    with patch.object(DefectDojoClient, "_request") as mock_request:
        mock_request.return_value = {"results": [{"id": 1}]}
        is_valid, status = client.validate_credentials()
        assert is_valid is True
        assert "CONNECTED" in status

def test_valid_token_valid_engagement():
    # Test E
    client = DefectDojoClient()
    client.url = "http://valid-url"
    client.token = "valid-token"
    client.engagement_config = "1"
    
    with patch.object(DefectDojoClient, "_request") as mock_request:
        mock_request.return_value = {"id": 1, "name": "Valid Eng"}
        is_valid, status = client.validate_credentials()
        assert is_valid is True
        assert "CONNECTED" in status

def test_valid_token_insufficient_permissions():
    # Test F
    client = DefectDojoClient()
    client.url = "http://valid-url"
    client.token = "valid-token"
    client.engagement_config = "1"
    
    with patch.object(DefectDojoClient, "_request") as mock_request:
        def side_effect(path, **kwargs):
            if "/engagements/1/" in path:
                raise RuntimeError("DefectDojo API HTTP error 403 on GET")
            return {"results": [{"id": 1}]}
        mock_request.side_effect = side_effect
        
        is_valid, status = client.validate_credentials()
        assert is_valid is False
        assert "PERMISSION DENIED" in status
