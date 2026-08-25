import os
import json
import tempfile
import pytest
import sys

# Ensure sast-engine is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sast-engine")))
from llm.tokenizer import BPEWithLearningTokenizer, bytes_to_unicode

@pytest.fixture
def temp_tokenizer_paths():
    # Setup temporary files for testing to ensure isolation
    with tempfile.TemporaryDirectory() as tmpdir:
        merges_path = os.path.join(tmpdir, "merges.json")
        learned_vocab_path = os.path.join(tmpdir, "learned_vocab.json")
        word_freq_path = os.path.join(tmpdir, "word_freq.json")
        
        # Write dummy merges.json
        dummy_merges = [
            ["s", "e"],
            ["t", "e"],
            ["se", "t"],
            ["g", "e"],
            ["e", "t"],
            ["ge", "t"]
        ]
        with open(merges_path, "w", encoding="utf-8") as f:
            json.dump(dummy_merges, f)
            
        yield merges_path, learned_vocab_path, word_freq_path

def test_text_extraction_and_normalization(temp_tokenizer_paths):
    merges_path, learned_vocab_path, word_freq_path = temp_tokenizer_paths
    tokenizer = BPEWithLearningTokenizer(merges_path, learned_vocab_path, word_freq_path)
    
    finding = {
        "category": "injection",
        "subtype": "CWE-78",
        "severity": "HIGH",
        "verdict_confidence": 0.85,
        "path": [
            {
                "code": "  SELECT *   FROM  users\u00A0where id = 1  ",
                "file": "src/db.py",
                "line": 42
            },
            {
                "code": "execute(query)",
                "file": "src/exec.py",
                "line": 100
            }
        ]
    }
    
    normalized = tokenizer.extract_and_normalize(finding)
    
    # Check that unicode characters like \u00A0 are normalized (to standard space) and double spaces consolidated
    assert "SELECT * FROM users where id = 1" in normalized
    assert "CWE: CWE-78" in normalized
    assert "Severity: HIGH" in normalized
    assert "Confidence: 0.85" in normalized
    assert "Source: SELECT * FROM users where id = 1 | Metadata: src/db.py:42" in normalized
    assert "Sink: execute(query) | Metadata: src/exec.py:100" in normalized

def test_byte_level_pre_tokenization(temp_tokenizer_paths):
    merges_path, learned_vocab_path, word_freq_path = temp_tokenizer_paths
    tokenizer = BPEWithLearningTokenizer(merges_path, learned_vocab_path, word_freq_path)
    
    text = "hello \u2605 world"
    pre_tokens = tokenizer.byte_level_pre_tokenize(text)
    
    # Verify that all characters are mapped to BPE characters
    assert len(pre_tokens) > len(text) # unicode character \u2605 (star) takes 3 bytes in UTF-8
    assert all(isinstance(c, str) for c in pre_tokens)

def test_bpe_tokenization_merges(temp_tokenizer_paths):
    merges_path, learned_vocab_path, word_freq_path = temp_tokenizer_paths
    tokenizer = BPEWithLearningTokenizer(merges_path, learned_vocab_path, word_freq_path)
    
    # Our merges has ["s", "e"], ["t", "e"], ["se", "t"]
    # So "set" -> "s" "e" "t" -> "se" "t" -> "set" (single token)
    tokens = tokenizer.bpe_tokenize_segment("set")
    assert tokens == ["set"]
    
    # "get" -> "g" "e" "t" -> "ge" "t" -> "get"
    tokens_get = tokenizer.bpe_tokenize_segment("get")
    assert tokens_get == ["get"]
    
    # Check IDs mapping
    assert tokenizer.vocab["set"] == 258
    assert tokenizer.vocab["get"] == 261

def test_learned_vocabulary_greedy_matching(temp_tokenizer_paths):
    merges_path, learned_vocab_path, word_freq_path = temp_tokenizer_paths
    
    # Manually populate learned vocabulary file
    initial_learned = {
        "patterns": {
            "SELECT * FROM users": {
                "token": "[SQL_SELECT_USERS_001]",
                "id": 100001
            },
            "SELECT": {
                "token": "[SQL_SELECT_002]",
                "id": 100002
            }
        },
        "next_id": 100003,
        "next_index": 3
    }
    with open(learned_vocab_path, "w", encoding="utf-8") as f:
        json.dump(initial_learned, f)
        
    tokenizer = BPEWithLearningTokenizer(merges_path, learned_vocab_path, word_freq_path)
    
    finding = {
        "category": "injection",
        "subtype": "CWE-89",
        "severity": "HIGH",
        "verdict_confidence": 0.99,
        "path": [
            {
                "code": "SELECT * FROM users WHERE id = 1",
                "file": "db.py",
                "line": 1
            }
        ]
    }
    
    tokens, token_ids, norm_text = tokenizer.tokenize(finding)
    
    # The longest match "SELECT * FROM users" should be greedily matched first
    assert "[SQL_SELECT_USERS_001]" in tokens
    assert 100001 in token_ids
    # "SELECT" on its own should not match because it's part of the longer match
    assert "[SQL_SELECT_002]" not in tokens

def test_dynamic_learning_promotion(temp_tokenizer_paths):
    merges_path, learned_vocab_path, word_freq_path = temp_tokenizer_paths
    tokenizer = BPEWithLearningTokenizer(merges_path, learned_vocab_path, word_freq_path)
    
    # Create findings that repeat the same pattern
    findings = []
    for _ in range(10):
        findings.append({
            "category": "injection",
            "subtype": "CWE-89",
            "severity": "HIGH",
            "verdict_confidence": 0.9,
            "path": [
                {
                    "code": "SELECT * FROM users WHERE active = 1",
                    "file": "db.py",
                    "line": 10
                }
            ]
        })
        
    # Learning should promote the repeating pattern
    promoted = tokenizer.learn_from_findings(findings)
    
    assert len(promoted) > 0
    promoted_patterns = [p[0] for p in promoted]
    assert "SELECT * FROM users WHERE active = 1" in promoted_patterns
    
    # The promoted token should start with the SQL prefix
    sql_token = [p[1] for p in promoted if p[0] == "SELECT * FROM users WHERE active = 1"][0]
    assert sql_token.startswith("[SQL_")
    
    # Verify it was saved to the state file
    with open(learned_vocab_path, "r", encoding="utf-8") as f:
        saved_vocab = json.load(f)
    assert "SELECT * FROM users WHERE active = 1" in saved_vocab["patterns"]

def test_general_text_context_compression(temp_tokenizer_paths):
    merges_path, learned_vocab_path, word_freq_path = temp_tokenizer_paths
    
    # Pre-populate learned vocab
    initial_learned = {
        "patterns": {
            "SELECT * FROM users": {
                "token": "[SQL_SELECT_USERS_001]",
                "id": 100001
            }
        },
        "next_id": 100002,
        "next_index": 2
    }
    with open(learned_vocab_path, "w", encoding="utf-8") as f:
        json.dump(initial_learned, f)
        
    from llm.tokenizer import compress_text_context
    tokenizer = BPEWithLearningTokenizer(merges_path, learned_vocab_path, word_freq_path)
    
    raw_prompt = "Code Context:\n  query = \"SELECT * FROM users\"\n  execute(query)"
    compressed = compress_text_context(raw_prompt, tokenizer)
    
    # Verify definition header is prepended and pattern is replaced in body
    assert "[LEARNED VOCABULARY DEFINITIONS]" in compressed
    assert "[SQL_SELECT_USERS_001] = SELECT * FROM users" in compressed
    assert "query = \"[SQL_SELECT_USERS_001]\"" in compressed

