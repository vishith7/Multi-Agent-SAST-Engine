import pytest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sast-engine", "orchestrator")))

from dedupe_anonymize import anonymize, get_fingerprint, group_findings

def test_anonymize_must_match():
    # Same structure, different variable names
    f1 = {
        "category": "injection",
        "sink": {"function": "execute"},
        "path": ["user_input = request.args.get('id')", "db.execute(user_input)"]
    }
    
    f2 = {
        "category": "injection",
        "sink": {"function": "execute"},
        "path": ["malicious_val = request.args.get('id')", "db.execute(malicious_val)"]
    }
    
    config_names = {"request", "args", "get", "execute"}
    
    f1_anon, _ = anonymize(f1, config_names=config_names)
    f2_anon, _ = anonymize(f2, config_names=config_names)
    
    assert f1_anon["anonymized_path"] == f2_anon["anonymized_path"]
    assert get_fingerprint(f1_anon) == get_fingerprint(f2_anon)

def test_anonymize_must_not_match():
    # Different sink functions
    f1 = {
        "category": "injection",
        "sink": {"function": "execute"},
        "path": ["user_input = request.args.get('id')", "db.execute(user_input)"]
    }
    
    f2 = {
        "category": "injection",
        "sink": {"function": "query"},
        "path": ["user_input = request.args.get('id')", "db.query(user_input)"]
    }
    
    config_names = {"request", "args", "get", "execute", "query"}
    
    f1_anon, _ = anonymize(f1, config_names=config_names)
    f2_anon, _ = anonymize(f2, config_names=config_names)
    
    assert get_fingerprint(f1_anon) != get_fingerprint(f2_anon)
    
def test_commutative_ops():
    f1 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["x = a + b", "sink(x)"]
    }
    f2 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["x = b + a", "sink(x)"]
    }
    
    f1_anon, _ = anonymize(f1, config_names={"sink"})
    f2_anon, _ = anonymize(f2, config_names={"sink"})
    
    assert f1_anon["anonymized_path"] == f2_anon["anonymized_path"]
    assert get_fingerprint(f1_anon) == get_fingerprint(f2_anon)

def test_nested_commutative_ops():
    f1 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["user_id == get_user_id(req.get_session().get_id())", "sink(user_id)"]
    }
    f2 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["get_user_id(req.get_session().get_id()) == user_id", "sink(user_id)"]
    }
    
    config_names = {"sink", "req", "get_session", "get_id", "get_user_id"}
    f1_anon, _ = anonymize(f1, config_names=config_names)
    f2_anon, _ = anonymize(f2, config_names=config_names)
    
    assert f1_anon["anonymized_path"] == f2_anon["anonymized_path"]
    assert get_fingerprint(f1_anon) == get_fingerprint(f2_anon)

def test_language_specific_operators():
    # JavaScript strict equality
    f1 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["user_id === req.session.userId", "sink(user_id)"]
    }
    f2 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["req.session.userId === user_id", "sink(user_id)"]
    }
    config_names = {"sink", "req", "session", "userId"}
    f1_anon, _ = anonymize(f1, config_names=config_names)
    f2_anon, _ = anonymize(f2, config_names=config_names)
    assert f1_anon["anonymized_path"] == f2_anon["anonymized_path"]

    # Logical AND
    f3 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["is_admin && has_permission", "sink()"]
    }
    f4 = {
        "category": "test",
        "sink": {"function": "sink"},
        "path": ["has_permission && is_admin", "sink()"]
    }
    f3_anon, _ = anonymize(f3, config_names={"sink"})
    f4_anon, _ = anonymize(f4, config_names={"sink"})
    assert f3_anon["anonymized_path"] == f4_anon["anonymized_path"]
