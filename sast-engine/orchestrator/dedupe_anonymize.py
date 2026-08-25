import re
import hashlib
from collections import defaultdict

WHITELIST = {
    # General Python built-ins & types
    "len", "str", "print", "int", "float", "bool", "list", "dict", "set", "tuple", "range", 
    "open", "type", "isinstance", "getattr", "setattr", "hasattr", "any", "all", "sum", "min", "max",
    
    # Python keywords
    "def", "class", "return", "if", "elif", "else", "try", "except", "finally", "raise", "with", 
    "for", "while", "break", "continue", "pass", "in", "is", "not", "and", "or", "import", "from", "as",
    
    # Java types & core classes
    "String", "Integer", "Double", "Float", "Boolean", "Long", "Short", "Byte", "Character", "Object",
    "System", "Math", "List", "Map", "Set", "ArrayList", "HashMap", "HashSet", "Exception", "Throwable",
    
    # Java keywords
    "public", "private", "protected", "static", "final", "void", "char", "byte", "short", "long",
    "new", "this", "super", "extends", "implements", "instanceof", "synchronized", "throws",
    
    # JavaScript / TypeScript built-ins & types
    "console", "log", "error", "warn", "info", "process", "env", "require", "module", "exports", 
    "JSON", "parse", "stringify", "Promise", "resolve", "reject", "async", "await", "window", "document",
    
    # JS/TS/Java/PHP common keywords
    "const", "let", "var", "function", "interface", "enum", "package", "switch", "case", "default",
    
    # PHP built-ins & globals
    "echo", "var_dump", "die", "exit", "isset", "empty", "unset", "array", "eval",
    "GLOBALS", "_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_SESSION", "_FILES", "_ENV",
    "this", "self", "parent"
}

def tokenize_balanced(text):
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        # Check whitespace
        if text[i].isspace():
            start = i
            while i < n and text[i].isspace():
                i += 1
            tokens.append(('space', text[start:i]))
            continue
            
        # Check string literals
        if text[i] in ("'", '"'):
            quote = text[i]
            start = i
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(('string', text[start:i]))
            continue
            
        # Check brackets/parentheses nesting (balanced bracket tracking)
        if text[i] in ('(', '[', '{'):
            start = i
            brackets = []
            matching = {')': '(', ']': '[', '}': '{'}
            opening = {'(': ')', '[': ']', '{': '}'}
            
            while i < n:
                char = text[i]
                if char in opening:
                    brackets.append(char)
                elif char in matching:
                    if brackets and brackets[-1] == matching[char]:
                        brackets.pop()
                    else:
                        pass
                
                i += 1
                if not brackets:
                    break
            tokens.append(('bracketed', text[start:i]))
            continue
            
        # Check 3-char operators (===, !==)
        if text[i:i+3] in ('===', '!=='):
            tokens.append(('operator', text[i:i+3]))
            i += 3
            continue

        # Check 2-char operators (==, !=, &&, ||)
        if text[i:i+2] in ('==', '!=', '&&', '||'):
            tokens.append(('operator', text[i:i+2]))
            i += 2
            continue
            
        # Check single-char operators (+, *, &, |, ^)
        if text[i] in ('+', '*', '&', '|', '^'):
            tokens.append(('operator', text[i]))
            i += 1
            continue
            
        # Check identifiers/numbers/dots
        start = i
        while i < n and not text[i].isspace() and text[i] not in ("'", '"', '(', '[', '{', ')', ']', '}', '+', '*', '&', '|', '^', '=', '!'):
            i += 1
        if start < i:
            tokens.append(('word', text[start:i]))
        else:
            # Fallback to consume the unhandled character (like single '=' or '!') to prevent infinite loop
            tokens.append(('operator', text[i]))
            i += 1
    return tokens

def canonicalize_ops(text):
    try:
        tokens = tokenize_balanced(text)
    except Exception:
        # Fallback to original text if parsing fails for any reason
        return text

    comm_ops = {'+', '*', '==', '!=', '===', '!==', '&&', '||', '&', '|', '^'}
    op_indices = [idx for idx, t in enumerate(tokens) if t[0] == 'operator' and t[1] in comm_ops]
    
    if not op_indices:
        return text
        
    for op_idx in reversed(op_indices):
        left_start = 0
        for prev_idx in range(op_idx - 1, -1, -1):
            if tokens[prev_idx][0] == 'operator':
                left_start = prev_idx + 1
                break
                
        right_end = len(tokens)
        for next_idx in range(op_idx + 1, len(tokens)):
            if tokens[next_idx][0] == 'operator':
                right_end = next_idx
                break
                
        left_tokens = tokens[left_start:op_idx]
        right_tokens = tokens[op_idx+1:right_end]
        
        def strip_tokens(toks):
            start = 0
            while start < len(toks) and toks[start][0] == 'space':
                start += 1
            end = len(toks)
            while end > start and toks[end-1][0] == 'space':
                end -= 1
            return toks[start:end]
            
        left_val_toks = strip_tokens(left_tokens)
        right_val_toks = strip_tokens(right_tokens)
        
        if not left_val_toks or not right_val_toks:
            continue
            
        left_str = "".join(t[1] for t in left_val_toks)
        right_str = "".join(t[1] for t in right_val_toks)
        
        if left_str > right_str:
            left_space_start = 0
            while left_space_start < len(left_tokens) and left_tokens[left_space_start][0] == 'space':
                left_space_start += 1
            left_space_end = len(left_tokens)
            while left_space_end > left_space_start and left_tokens[left_space_end-1][0] == 'space':
                left_space_end -= 1
                
            left_leading = left_tokens[:left_space_start]
            left_trailing = left_tokens[left_space_end:]
            
            right_space_start = 0
            while right_space_start < len(right_tokens) and right_tokens[right_space_start][0] == 'space':
                right_space_start += 1
            right_space_end = len(right_tokens)
            while right_space_end > right_space_start and right_tokens[right_space_end-1][0] == 'space':
                right_space_end -= 1
                
            right_leading = right_tokens[:right_space_start]
            right_trailing = right_tokens[right_space_end:]
            
            swapped = left_leading + right_val_toks + right_leading + [tokens[op_idx]] + left_trailing + left_val_toks + right_trailing
            tokens[left_start:right_end] = swapped
            
    return "".join(t[1] for t in tokens)

def anonymize(finding, shared_map=None, config_names=None):
    if config_names is None:
        config_names = set()
        
    # NOTE: Deterministic placeholder assignment is strict first-appearance order.
    # Random assignment is explicitly avoided as it breaks deduplication silently.
    m = shared_map if shared_map is not None else {}
    counters = {"VAR": 1, "FUNC": 1, "ATTR": 1, "PARAM": 1, "CLASS": 1}
    
    if shared_map is not None:
        # Reconstruct counters from shared map to continue safely
        for (role, _), val in shared_map.items():
            try:
                num = int(val.split("_")[1].strip(">"))
                counters[role] = max(counters[role], num + 1)
            except Exception:
                pass

    token_pattern = re.compile(
        r'(?P<STR>\'(?:\\\'|[^\'])*\'|"(?:\\"|[^"])*")|'
        r'(?P<NUM>\b\d+\.?\d*\b)|'
        r'(?P<BOOL>\b(?:True|False)\b)|'
        r'(?P<IDENT>\b[a-zA-Z_]\w*\b)|'
        r'(?P<OTHER>\S)'
    )

    anonymized_paths = []
    
    # Always process the nodes in strict path order
    for path_node in finding.get("path", []):
        node_code = ""
        if isinstance(path_node, dict):
            node_code = path_node.get("code", "")
        else:
            node_code = str(path_node)
            
        node_code = canonicalize_ops(node_code)
        tokens = []
        for match in token_pattern.finditer(node_code):
            tokens.append((match.lastgroup, match.group()))
            
        out = []
        for i, (kind, value) in enumerate(tokens):
            if kind == 'STR':
                out.append("<STR>")
            elif kind == 'NUM':
                out.append("<NUM>")
            elif kind == 'BOOL':
                out.append("<BOOL>")
            elif kind == 'IDENT':
                if value in WHITELIST or value in config_names:
                    out.append(value)
                    continue
                
                prev_val = tokens[i-1][1] if i > 0 else None
                next_val = tokens[i+1][1] if i < len(tokens)-1 else None
                
                if prev_val == '.':
                    role = "ATTR"
                elif next_val == '(':
                    role = "FUNC"
                else:
                    role = "VAR"
                    
                key = (role, value)
                if key not in m:
                    m[key] = f"<{role}_{counters[role]}>"
                    counters[role] += 1
                out.append(m[key])
            else:
                out.append(value)
                
        anonymized_paths.append("".join(out))
        
    finding["anonymized_path"] = anonymized_paths
    return finding, m

def get_fingerprint(finding):
    # Hash semantic location instead of line numbers
    sink_file = finding.get("sink", {}).get("file", "unknown")
    source_file = finding.get("source", {}).get("file", "unknown")
    category = finding.get("category", "unknown")
    subtype = finding.get("subtype", "unknown")
    
    # Use the anonymized path structure to uniquely identify this flow structurally
    anon_path = finding.get("anonymized_path", [])
    path_str = "".join(anon_path)
    
    h = hashlib.sha256()
    h.update(category.encode('utf-8'))
    h.update(subtype.encode('utf-8'))
    h.update(source_file.encode('utf-8'))
    h.update(sink_file.encode('utf-8'))
    h.update(path_str.encode('utf-8'))
    return h.hexdigest()

def get_semantic_fingerprint(finding):
    import json
    category = finding.get("category", "unknown")
    subtype = finding.get("subtype", "unknown")
    
    # Extract the anonymized flow path list
    anon_path = finding.get("anonymized_path", [])
    
    # Build deterministic semantic representation (excluding physical location fields)
    semantic_repr = {
        "category": category,
        "subtype": subtype,
        "anonymized_flow": anon_path
    }
    
    # Serialize deterministically with sorting and canonical delimiters
    serialized = json.dumps(
        semantic_repr,
        sort_keys=True,
        separators=(",", ":")
    )
    
    h = hashlib.sha256()
    h.update(serialized.encode('utf-8'))
    return h.hexdigest()

def get_context_hash(finding):
    category = finding.get("category", "unknown")
    subtype = finding.get("subtype", "unknown")
    
    # We want the normalized actual code text to verify no security logic has changed
    raw_path_code = []
    for node in finding.get("path", []):
        code = ""
        if isinstance(node, dict):
            code = node.get("code", "")
        else:
            code = str(node)
        # Strip all whitespace to handle formatting-only changes
        code = re.sub(r'\s+', '', code)
        raw_path_code.append(code)
        
    path_str = "".join(raw_path_code)
    
    if not path_str:
        return None # Fallback to cache miss if data is insufficient
        
    h = hashlib.sha256()
    h.update(category.encode('utf-8'))
    h.update(subtype.encode('utf-8'))
    h.update(path_str.encode('utf-8'))
    return h.hexdigest()

def group_findings(findings, config_names=None):
    groups = defaultdict(list)
    
    # First pass: anonymize all
    chain_maps = {}
    
    for f in findings:
        chain_id = f.get("chain_id")
        m = None
        if chain_id:
            m = chain_maps.get(chain_id, {})
            
        f, m_out = anonymize(f, shared_map=m, config_names=config_names)
        
        if chain_id:
            chain_maps[chain_id] = m_out
            
        fp = get_fingerprint(f)
        groups[fp].append(f)
        
    # Collapse
    collapsed = []
    for fp, insts in groups.items():
        rep = insts[0].copy()
        rep["fingerprint"] = fp
        rep["semantic_fingerprint"] = get_semantic_fingerprint(rep)
        ctx_hash = get_context_hash(rep)
        if ctx_hash:
            rep["context_hash"] = ctx_hash
        
        instances = []
        for i in insts:
            src = i.get("source") or {}
            snk = i.get("sink") or {}
            instances.append({
                "repo": i.get("repo", "unknown"),
                "source_file": src.get("file", "unknown"),
                "source_line": src.get("line", -1),
                "sink_file": snk.get("file", "unknown"),
                "sink_line": snk.get("line", -1)
            })
        
        rep["instances"] = instances
        # Keep path[] anonymous or strip it
        rep.pop("source", None)
        rep.pop("sink", None)
        collapsed.append(rep)
        
    return collapsed

VERDICT_PRIORITY = {"VALID": 3, "NEEDS_REVIEW": 2, "FALSE_POSITIVE": 1}

def _get_source_sink_key(finding):
    """Extract a (category, subtype, source_file, source_line, sink_file, sink_line) key."""
    category = finding.get("category", "unknown")
    subtype = finding.get("subtype", "unknown")
    
    path = finding.get("path", [])
    if path and isinstance(path[0], dict):
        src_file = path[0].get("file", "unknown")
        src_line = path[0].get("line", -1)
    elif finding.get("instances") and len(finding["instances"]) > 0:
        src_file = finding["instances"][0].get("source_file", "unknown")
        src_line = finding["instances"][0].get("source_line", -1)
    else:
        src_file = "unknown"
        src_line = -1
    
    if path and isinstance(path[-1], dict):
        sink_file = path[-1].get("file", "unknown")
        sink_line = path[-1].get("line", -1)
    elif finding.get("instances") and len(finding["instances"]) > 0:
        sink_file = finding["instances"][0].get("sink_file", "unknown")
        sink_line = finding["instances"][0].get("sink_line", -1)
    else:
        sink_file = "unknown"
        sink_line = -1
    
    return (category, subtype, src_file, str(src_line), sink_file, str(sink_line))

def dedupe_by_location(findings):
    """
    Secondary dedup pass: collapse findings that share the same
    (category, subtype, source_file, source_line, sink_file, sink_line).
    
    When duplicates exist, keep the one with the best verdict
    (VALID > NEEDS_REVIEW > FALSE_POSITIVE) and highest confidence.
    PoC data is preserved from the best candidate.
    """
    groups = defaultdict(list)
    
    for f in findings:
        key = _get_source_sink_key(f)
        groups[key].append(f)
    
    deduped = []
    for key, group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue
        
        # Sort: best verdict first, then highest confidence
        group.sort(key=lambda f: (
            VERDICT_PRIORITY.get(f.get("verdict", "NEEDS_REVIEW"), 0),
            float(f.get("confidence", f.get("verdict_confidence", 0)))
        ), reverse=True)
        
        best = group[0]
        if "semantic_fingerprint" not in best:
            best["semantic_fingerprint"] = get_semantic_fingerprint(best)
        
        # Merge: if best has no PoC but another does, take the PoC
        if not best.get("generated_poc") or "error" in best.get("generated_poc", {}):
            for other in group[1:]:
                poc = other.get("generated_poc")
                if poc and "error" not in poc:
                    best["generated_poc"] = poc
                    break
        
        # Merge instances from all duplicates
        all_instances = []
        seen_instance_keys = set()
        for f in group:
            for inst in f.get("instances", []):
                inst_key = (inst.get("source_file"), inst.get("source_line"),
                           inst.get("sink_file"), inst.get("sink_line"))
                if inst_key not in seen_instance_keys:
                    seen_instance_keys.add(inst_key)
                    all_instances.append(inst)
        if all_instances:
            best["instances"] = all_instances
        
        deduped.append(best)
    
    return deduped
