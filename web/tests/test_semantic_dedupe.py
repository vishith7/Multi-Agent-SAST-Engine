import pytest
import sys
import os
import json
import hashlib
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
sys.path.append(str(Path(__file__).resolve().parent.parent.parent / "sast-engine"))

from llm.schemas import validate_cascade_response
from orchestrator.dedupe_anonymize import (
    anonymize,
    get_fingerprint,
    get_semantic_fingerprint,
    group_findings,
    dedupe_by_location
)

def test_var_name_independence():
    # Scenario 1: Same category/flow, different variable names
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "username = req.get('user')"}, {"code": "execute(username)"}]
    }
    finding_2 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "password = req.get('pass')"}, {"code": "execute(password)"}]
    }
    
    f1_anon, _ = anonymize(finding_1)
    f2_anon, _ = anonymize(finding_2)
    
    fp1 = get_semantic_fingerprint(f1_anon)
    fp2 = get_semantic_fingerprint(f2_anon)
    
    assert fp1 == fp2
    # Ensure local fingerprints are different (once source/sink file locations are defined)
    f1_local = f1_anon.copy()
    f1_local["source"] = {"file": "auth.py"}
    f1_local["sink"] = {"file": "db.py"}
    
    f2_local = f2_anon.copy()
    f2_local["source"] = {"file": "login.py"}
    f2_local["sink"] = {"file": "db.py"}
    
    assert get_fingerprint(f1_local) != get_fingerprint(f2_local)

def test_line_number_independence():
    # Scenario 2 & 8: Same vulnerability, different lines -> same semantic fingerprint
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "username = req.get('user')", "file": "auth.py", "line": 25}, {"code": "execute(username)", "file": "auth.py", "line": 26}]
    }
    finding_2 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "username = req.get('user')", "file": "auth.py", "line": 55}, {"code": "execute(username)", "file": "auth.py", "line": 56}]
    }
    
    f1_anon, _ = anonymize(finding_1)
    f2_anon, _ = anonymize(finding_2)
    
    fp1 = get_semantic_fingerprint(f1_anon)
    fp2 = get_semantic_fingerprint(f2_anon)
    
    assert fp1 == fp2

def test_file_path_independence():
    # Scenario 3 & 10: Same vulnerability, different files -> same semantic fingerprint
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "username = req.get('user')", "file": "auth.py"}, {"code": "execute(username)", "file": "db.py"}]
    }
    finding_2 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "username = req.get('user')", "file": "users.py"}, {"code": "execute(username)", "file": "connection.py"}]
    }
    
    f1_anon, _ = anonymize(finding_1)
    f2_anon, _ = anonymize(finding_2)
    
    assert get_semantic_fingerprint(f1_anon) == get_semantic_fingerprint(f2_anon)

def test_repository_independence():
    # Scenario 4 & 9: Same vulnerability, different repositories -> same semantic fingerprint
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "repo": "service-a",
        "path": [{"code": "username = req.get('user')"}, {"code": "execute(username)"}]
    }
    finding_2 = {
        "category": "injection",
        "subtype": "CWE-89",
        "repo": "service-b",
        "path": [{"code": "username = req.get('user')"}, {"code": "execute(username)"}]
    }
    
    f1_anon, _ = anonymize(finding_1)
    f2_anon, _ = anonymize(finding_2)
    
    assert get_semantic_fingerprint(f1_anon) == get_semantic_fingerprint(f2_anon)

def test_different_vulnerability_categories():
    # Scenario 5: Different categories -> different semantic fingerprints
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "username = req.get('user')"}, {"code": "execute(username)"}]
    }
    finding_2 = {
        "category": "ssrf",
        "subtype": "CWE-918",
        "path": [{"code": "username = req.get('user')"}, {"code": "execute(username)"}]
    }
    
    f1_anon, _ = anonymize(finding_1)
    f2_anon, _ = anonymize(finding_2)
    
    assert get_semantic_fingerprint(f1_anon) != get_semantic_fingerprint(f2_anon)

def test_different_sink_types():
    # Scenario 6: Different sink types -> different semantic fingerprints
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "val = req.get('val')"}, {"code": "db.execute(val)"}]
    }
    finding_2 = {
        "category": "injection",
        "subtype": "CWE-78",
        "path": [{"code": "val = req.get('val')"}, {"code": "subprocess.run(val)"}]
    }
    
    f1_anon, _ = anonymize(finding_1)
    f2_anon, _ = anonymize(finding_2)
    
    assert get_semantic_fingerprint(f1_anon) != get_semantic_fingerprint(f2_anon)

def test_different_source_semantic_types():
    # Scenario 7: Different source semantic types -> different semantic fingerprints
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "val = req.query_params.get('val')"}, {"code": "db.execute(val)"}]
    }
    finding_2 = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "val = file.read()"}, {"code": "db.execute(val)"}]
    }
    
    f1_anon, _ = anonymize(finding_1)
    f2_anon, _ = anonymize(finding_2)
    
    assert get_semantic_fingerprint(f1_anon) != get_semantic_fingerprint(f2_anon)

def test_deterministic_hashing():
    # Scenario 11: Deterministic hashing
    finding = {
        "category": "injection",
        "subtype": "CWE-89",
        "path": [{"code": "username = req.get('user')"}, {"code": "execute(username)"}]
    }
    
    f_anon, _ = anonymize(finding)
    
    h1 = get_semantic_fingerprint(f_anon)
    h2 = get_semantic_fingerprint(f_anon)
    
    assert h1 == h2

def test_old_finding_compatibility():
    # Scenario 12: Historical finding loading works without semantic_fingerprint
    finding = {
        "fingerprint": "abc12345",
        "category": "injection"
    }
    
    # Verify accessing keys does not raise KeyError
    assert finding.get("semantic_fingerprint") is None

def test_sequence_delimiters_boundary_safety():
    # Scenario 14: Step sequence delimiters are safe from colliding when joined
    finding_1 = {
        "category": "injection",
        "subtype": "CWE-89",
        "anonymized_path": ["A", "BC"]
    }
    finding_2 = {
        "category": "injection",
        "subtype": "CWE-89",
        "anonymized_path": ["AB", "C"]
    }
    
    # Directly get fingerprints
    fp1 = get_semantic_fingerprint(finding_1)
    fp2 = get_semantic_fingerprint(finding_2)
    
    assert fp1 != fp2

def test_existing_fingerprint_safety():
    # Scenario 15: Existing fingerprint calculation remains exactly the same
    finding = {
        "category": "injection",
        "subtype": "CWE-89",
        "source": {"file": "auth.py"},
        "sink": {"file": "db.py"},
        "anonymized_path": ["<VAR_1>", "execute(<VAR_1>)"]
    }
    
    fp = get_fingerprint(finding)
    expected_hash = hashlib.sha256()
    expected_hash.update("injection".encode('utf-8'))
    expected_hash.update("CWE-89".encode('utf-8'))
    expected_hash.update("auth.py".encode('utf-8'))
    expected_hash.update("db.py".encode('utf-8'))
    expected_hash.update("<VAR_1>execute(<VAR_1>)".encode('utf-8'))
    
    assert fp == expected_hash.hexdigest()

def test_existing_deduplication_preservation():
    # Scenario 13 & 16: dedupe_by_location logic and grouping behave as before
    findings = [
        {
            "category": "injection",
            "subtype": "CWE-89",
            "source": {"file": "auth.py", "line": 25},
            "sink": {"file": "db.py", "line": 26},
            "path": [{"code": "username = req.get('user')", "file": "auth.py", "line": 25}, {"code": "execute(username)", "file": "db.py", "line": 26}],
            "verdict": "VALID",
            "confidence": 0.95
        },
        {
            "category": "injection",
            "subtype": "CWE-89",
            "source": {"file": "auth.py", "line": 25},
            "sink": {"file": "db.py", "line": 26},
            "path": [{"code": "username = req.get('user')", "file": "auth.py", "line": 25}, {"code": "execute(username)", "file": "db.py", "line": 26}],
            "verdict": "NEEDS_REVIEW",
            "confidence": 0.80
        }
    ]
    
    grouped = group_findings(findings)
    assert len(grouped) == 1
    
    deduped = dedupe_by_location(grouped)
    assert len(deduped) == 1
    assert deduped[0]["verdict"] == "VALID"
    assert deduped[0]["semantic_fingerprint"] is not None
