import os
import sys
import json
import pytest

# Add sast-engine to search path so we can import risk directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sast-engine")))

from risk.priority_policy import determine_severity

def test_determine_severity_critical():
    # command injection
    f = {"category": "injection", "subtype": "CWE-78-COMMAND-INJECTION"}
    assert determine_severity(f) == "Critical"
    
    # deserialization
    f = {"category": "deserialization"}
    assert determine_severity(f) == "Critical"

def test_determine_severity_high():
    # xxe
    f = {"category": "xxe", "subtype": "CWE-611-XXE"}
    assert determine_severity(f) == "High"
    
    # ssrf
    f = {"category": "ssrf"}
    assert determine_severity(f) == "High"
    
    # path traversal
    f = {"category": "path_traversal", "subtype": "CWE-22"}
    assert determine_severity(f) == "High"
    
    # SQL injection with high confidence -> Critical
    f1 = {"category": "injection", "subtype": "CWE-89-SQL-INJECTION", "verdict_confidence": 0.9}
    assert determine_severity(f1) == "Critical"
    
    # SQL injection with low confidence -> High
    f2 = {"category": "injection", "subtype": "CWE-89-SQL-INJECTION", "verdict_confidence": 0.5}
    assert determine_severity(f2) == "High"

def test_determine_severity_medium_and_low():
    # xss
    f = {"category": "xss"}
    assert determine_severity(f) == "Medium"
    
    # default credentials
    f = {"category": "default_credentials", "subtype": "CWE-798"}
    assert determine_severity(f) == "Medium"
    
    # low fallback
    f = {"category": "unknown_cat"}
    assert determine_severity(f) == "Low"
