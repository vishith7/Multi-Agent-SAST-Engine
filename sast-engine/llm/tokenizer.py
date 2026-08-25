import os
import json
import re
import unicodedata

def bytes_to_unicode():
    """
    Returns list of utf-8 byte and a corresponding list of unicode strings.
    Matches GPT-2/GPT-3 byte-level encoder mapping.
    """
    bs = list(range(ord("!"), ord("~")+1)) + list(range(ord("¡"), ord("¬")+1)) + list(range(ord("®"), ord("ÿ")+1))
    cs = bs[:]
    n = 0
    for b in range(2**8):
        if b not in bs:
            bs.append(b)
            cs.append(2**8 + n)
            n += 1
    cs = [chr(n) for n in cs]
    return dict(zip(bs, cs))

def get_pairs(word):
    """Return set of symbol pairs in a word."""
    pairs = set()
    prev_char = word[0]
    for char in word[1:]:
        pairs.add((prev_char, char))
        prev_char = char
    return pairs

class BPEWithLearningTokenizer:
    def __init__(self, merges_path=None, learned_vocab_path=None, word_freq_path=None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        self.merges_path = merges_path or os.path.join(base_dir, "config", "merges.json")
        self.learned_vocab_path = learned_vocab_path or os.path.join(base_dir, ".state", "tokenizer_learned_vocabulary.json")
        self.word_freq_path = word_freq_path or os.path.join(base_dir, ".state", "tokenizer_word_frequency.json")
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.learned_vocab_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.word_freq_path), exist_ok=True)
        
        # Load rule files
        self.merges = self._load_merges()
        self.learned_vocab = self._load_learned_vocab()
        self.word_frequencies = self._load_word_frequencies()
        
        # Build base BPE vocabulary and merge priority dict
        self.b2u = bytes_to_unicode()
        self.vocab, self.merges_dict = self._build_vocab_and_merges()

    def _load_merges(self):
        if os.path.exists(self.merges_path):
            try:
                with open(self.merges_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Tokenizer] Error loading merges.json: {e}")
        return []

    def _load_learned_vocab(self):
        if os.path.exists(self.learned_vocab_path):
            try:
                with open(self.learned_vocab_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Tokenizer] Error loading learned vocabulary: {e}")
        return {
            "patterns": {},
            "next_id": 100000,
            "next_index": 1
        }

    def _load_word_frequencies(self):
        if os.path.exists(self.word_freq_path):
            try:
                with open(self.word_freq_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Tokenizer] Error loading word frequencies: {e}")
        return {}

    def save_state(self):
        try:
            with open(self.learned_vocab_path, "w", encoding="utf-8") as f:
                json.dump(self.learned_vocab, f, indent=2)
            with open(self.word_freq_path, "w", encoding="utf-8") as f:
                json.dump(self.word_frequencies, f, indent=2)
        except Exception as e:
            print(f"[Tokenizer] Error saving state files: {e}")

    def _build_vocab_and_merges(self):
        # Base vocabulary covers 0..255 byte tokens mapped to GPT-2 style characters
        vocab = {self.b2u[b]: b for b in range(256)}
        next_id = 256
        
        merges_dict = {}
        for i, pair in enumerate(self.merges):
            if isinstance(pair, str):
                parts = pair.split()
            else:
                parts = pair
            if len(parts) == 2:
                a, b = parts[0], parts[1]
                merges_dict[(a, b)] = i
                merged = a + b
                if merged not in vocab:
                    vocab[merged] = next_id
                    next_id += 1
        return vocab, merges_dict

    def extract_and_normalize(self, finding):
        """
        Step 1: Text Extraction & Normalization
        Extracts relevant fields from a finding and cleans whitespace & unicode characters.
        """
        category = finding.get("category", "unknown")
        subtype = finding.get("subtype", finding.get("rule_id", "unknown"))
        severity = finding.get("severity", "unknown")
        
        confidence = finding.get("verdict_confidence", finding.get("confidence", "unknown"))
        if confidence is None:
            confidence = "unknown"
            
        path = finding.get("path", [])
        
        source_snippet = ""
        source_meta = ""
        sink_snippet = ""
        sink_meta = ""
        path_snippets = []
        
        if path:
            src_node = path[0]
            if isinstance(src_node, dict):
                source_snippet = src_node.get("code", "")
                source_meta = f"{src_node.get('file', 'unknown')}:{src_node.get('line', -1)}"
            else:
                source_snippet = str(src_node)
                source_meta = "unknown"
                
            snk_node = path[-1]
            if isinstance(snk_node, dict):
                sink_snippet = snk_node.get("code", "")
                sink_meta = f"{snk_node.get('file', 'unknown')}:{snk_node.get('line', -1)}"
            else:
                sink_snippet = str(snk_node)
                sink_meta = "unknown"
                
            for node in path:
                if isinstance(node, dict):
                    code = node.get("code", "")
                    if code:
                        path_snippets.append(code)
                else:
                    path_snippets.append(str(node))

        def clean(t):
            if not t:
                return ""
            # Normalizes Unicode characters
            t = unicodedata.normalize('NFC', str(t))
            # Cleans whitespace (consistent formatting including unicode spaces)
            t = re.sub(r'[\s\xa0]+', ' ', t)
            return t.strip()

        source_snippet = clean(source_snippet)
        source_meta = clean(source_meta)
        sink_snippet = clean(sink_snippet)
        sink_meta = clean(sink_meta)
        path_snippets = [clean(p) for p in path_snippets if p]
        
        lines = [
            f"CWE: {clean(subtype)}",
            f"Severity: {clean(severity)}",
            f"Confidence: {str(confidence).strip()}",
            f"Source: {source_snippet} | Metadata: {source_meta}",
            f"Sink: {sink_snippet} | Metadata: {sink_meta}",
            "Path Nodes:"
        ]
        for i, p in enumerate(path_snippets, 1):
            lines.append(f"  [{i}] {p}")
            
        return "\n".join(lines)

    def byte_level_pre_tokenize(self, text_str):
        """
        Step 2: Byte-Level Pre-Tokenization
        Converts all Unicode characters to their byte-level counterparts.
        """
        # All UTF-8 strings are transformed into a sequence of bytes
        # Each byte becomes a base token mapped using self.b2u
        return [self.b2u[b] for b in text_str.encode('utf-8')]

    def learned_vocab_check(self, text_str):
        """
        Step 3: Learned Vocabulary Check
        Segments the text greedily matching patterns from learned_vocabulary.json.
        """
        patterns_dict = self.learned_vocab.get("patterns", {})
        if not patterns_dict:
            return [(False, text_str)]
            
        # Sort patterns by length descending to match greedily
        sorted_patterns = sorted(patterns_dict.keys(), key=len, reverse=True)
        
        segments = [(False, text_str)]
        for pattern in sorted_patterns:
            if not pattern:
                continue
            new_segments = []
            for is_learned, content in segments:
                if is_learned:
                    new_segments.append((is_learned, content))
                else:
                    parts = content.split(pattern)
                    for i, part in enumerate(parts):
                        if part:
                            new_segments.append((False, part))
                        if i < len(parts) - 1:
                            new_segments.append((True, pattern))
            segments = new_segments
            
        return segments

    def bpe_tokenize_segment(self, segment_str):
        """
        Step 4: BPE Tokenization merges for a non-learned segment.
        """
        word = tuple(self.b2u[b] for b in segment_str.encode('utf-8'))
        if len(word) <= 1:
            return list(word)
            
        pairs = get_pairs(word)
        if not pairs:
            return list(word)
            
        while True:
            # Find the pair with the lowest merge rank
            bigram = min(pairs, key=lambda p: self.merges_dict.get(p, float('inf')))
            if bigram not in self.merges_dict:
                break
            
            # Apply merges.json rules
            new_word = []
            i = 0
            while i < len(word):
                if i < len(word) - 1 and word[i] == bigram[0] and word[i+1] == bigram[1]:
                    new_word.append(bigram[0] + bigram[1])
                    i += 2
                else:
                    new_word.append(word[i])
                    i += 1
            word = tuple(new_word)
            if len(word) <= 1:
                break
            pairs = get_pairs(word)
            
        return list(word)

    def tokenize(self, finding):
        """
        Tokenize a single finding using the 4-step pipeline.
        Returns (tokens, token_ids, normalized_text)
        """
        normalized_text = self.extract_and_normalize(finding)
        
        # Step 3: Learned Vocabulary Check / Segmentation
        segments = self.learned_vocab_check(normalized_text)
        
        final_tokens = []
        final_ids = []
        
        for is_learned, content in segments:
            if is_learned:
                # Direct token ID lookup from learned vocabulary
                entry = self.learned_vocab["patterns"][content]
                final_tokens.append(entry["token"])
                final_ids.append(entry["id"])
            else:
                # Step 4: BPE Tokenization for patterns not in learned vocabulary
                bpe_tokens = self.bpe_tokenize_segment(content)
                for tok in bpe_tokens:
                    final_tokens.append(tok)
                    # Generate token ID from base BPE vocabulary
                    final_ids.append(self.vocab.get(tok, -1))
                    
        return final_tokens, final_ids, normalized_text

    def extract_candidate_patterns(self, normalized_text):
        """
        Extracts candidate sub-phrases, lines, and patterns for dynamic learning.
        """
        candidates = set()
        
        # 1. Individual lines (stripped)
        lines = normalized_text.split('\n')
        for line in lines:
            line_clean = line.strip()
            if not line_clean:
                continue
                
            # If it's a code snippet in source/sink or path nodes
            if line_clean.startswith("Source:") or line_clean.startswith("Sink:"):
                parts = line_clean.split('| Metadata:')
                if parts:
                    snippet = parts[0].replace("Source:", "").replace("Sink:", "").strip()
                    if 8 <= len(snippet) <= 120:
                        candidates.add(snippet)
            elif line_clean.startswith("  ["):
                # "  [1] code"
                match = re.match(r'^\s*\[\d+\]\s*(.*)$', line_clean)
                if match:
                    snippet = match.group(1).strip()
                    if 8 <= len(snippet) <= 120:
                        candidates.add(snippet)
            else:
                # General lines if they contain code-like text
                if 10 <= len(line_clean) <= 120:
                    candidates.add(line_clean)

            # 2. SQL queries or quote strings if present
            sql_quotes = re.findall(r'[\'"](.*?)[\'"]', line_clean)
            for sq in sql_quotes:
                sq_clean = sq.strip()
                if any(k in sq_clean.upper() for k in ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]):
                    if len(sq_clean) >= 10:
                        candidates.add(sq_clean)

            # 3. Word n-grams (sequences of 2 to 6 words)
            words = re.findall(r'[a-zA-Z0-9_*#@$-]+', line_clean)
            for n in range(2, 7):
                for i in range(len(words) - n + 1):
                    phrase = " ".join(words[i:i+n])
                    if 10 <= len(phrase) <= 80:
                        candidates.add(phrase)
                        
        return candidates

    def learn_from_findings(self, findings):
        """
        Step 5: Dynamic Learning (Background Process)
        Tracks frequency of all patterns and promotes those >= 10 times to learned_vocabulary.json.
        Returns a list of newly promoted patterns: [(pattern, token, id)]
        """
        promoted = []
        
        for finding in findings:
            normalized_text = self.extract_and_normalize(finding)
            candidates = self.extract_candidate_patterns(normalized_text)
            
            for pattern in candidates:
                # We skip patterns that are already promoted
                if pattern in self.learned_vocab["patterns"]:
                    continue
                    
                # Increment usage count in word_frequency.json
                self.word_frequencies[pattern] = self.word_frequencies.get(pattern, 0) + 1
                
                # Promotion Threshold >= 10
                if self.word_frequencies[pattern] >= 10:
                    next_idx = self.learned_vocab.get("next_index", 1)
                    next_id = self.learned_vocab.get("next_id", 100000)
                    
                    # Generate a unique token name
                    pattern_upper = pattern.upper()
                    if any(k in pattern_upper for k in ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]):
                        prefix = "SQL"
                    elif any(k in pattern for k in ["function", "def ", "class ", "import ", "const ", "let ", "var "]):
                        prefix = "CODE"
                    else:
                        prefix = "PAT"
                        
                    token_name = f"[{prefix}_PATTERN_{next_idx:03d}]"
                    
                    # Add to learned_vocabulary.json
                    entry = {
                        "token": token_name,
                        "id": next_id
                    }
                    self.learned_vocab["patterns"][pattern] = entry
                    promoted.append((pattern, token_name, next_id))
                    
                    self.learned_vocab["next_index"] = next_idx + 1
                    self.learned_vocab["next_id"] = next_id + 1
                    
        if promoted:
            self.save_state()
            
        return promoted

def estimate_gpt_tokens(text: str) -> int:
    """
    Model-aware token estimation method.
    For source code text, characters-to-token ratio is typically lower (more dense).
    We estimate 1 token ≈ 3.2 characters for code-rich context.
    """
    return int(len(text) / 3.2)

def compress_text_context(text_str, tokenizer):
    """
    Utility that compresses raw prompt text using the BPE tokenizer's learned vocabulary.
    Prepend definitions of used tokens as a header so the LLM understands the abbreviation mappings.
    Preserves critical security/code logic patterns so they remain directly readable.
    """
    segments = tokenizer.learned_vocab_check(text_str)
    
    used_patterns = {}
    compressed_parts = []
    
    for is_learned, content in segments:
        if is_learned:
            content_lower = content.lower()
            # Prevent compression of critical syntax keywords
            critical_keywords = [
                "select", "insert", "update", "delete", "from", "where",
                "escape", "sanitize", "encode", "clean", "htmlspecial", "esapi",
                "csrf", "disable", "password", "secret", "token", "apikey",
                "execute", "exec", "run", "processbuilder", "unmarshal", "parse",
                "parameter", "bind", "prepare", "db", "query"
            ]
            if any(k in content_lower for k in critical_keywords):
                compressed_parts.append(content)
            else:
                entry = tokenizer.learned_vocab["patterns"][content]
                token_name = entry["token"]
                used_patterns[token_name] = content
                compressed_parts.append(token_name)
        else:
            compressed_parts.append(content)
            
    compressed_body = "".join(compressed_parts)
    
    if not used_patterns:
        return text_str
        
    # Prepend dynamic mappings header
    header_lines = [
        "==================================================",
        "[LEARNED VOCABULARY DEFINITIONS]",
        "=================================================="
    ]
    for tok_name, original_text in sorted(used_patterns.items()):
        header_lines.append(f"{tok_name} = {original_text}")
    header_lines.append("==================================================\n")
    
    return "\n".join(header_lines) + compressed_body

