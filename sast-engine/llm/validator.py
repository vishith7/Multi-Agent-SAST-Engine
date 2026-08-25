import os
import yaml
try:
    from llm.rules_metadata import RULES_DESCRIPTIONS
except ImportError:
    from rules_metadata import RULES_DESCRIPTIONS

def extract_code_context(filepath, start_line, end_line=None, context_lines=30, repo_path=None):
    """
    Legacy method for extracting a window of code around reported lines.
    Preserved for backward compatibility.
    """
    if repo_path and not os.path.isabs(filepath):
        filepath = os.path.join(repo_path, filepath)
        
    if not os.path.exists(filepath):
        return "Code unavailable", False
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        if end_line:
            first = min(start_line, end_line)
            last = max(start_line, end_line)
            start_idx = max(0, first - context_lines - 1)
            end_idx = min(len(lines), last + context_lines)
        else:
            start_idx = max(0, start_line - context_lines - 1)
            end_idx = min(len(lines), start_line + context_lines)
        
        snippet = ""
        for i in range(start_idx, end_idx):
            snippet += f"{i+1:4d} | {lines[i]}"
            
        return snippet, True
    except Exception:
        return "Code unavailable", False

def _resolve_logical_start(lines, brace_idx):
    """Scan upwards from the `{` to find the method signature and annotations."""
    sig_start = brace_idx
    while sig_start > 0:
        prev_line = lines[sig_start - 1].strip()
        if prev_line.endswith(';') or prev_line.endswith('}'):
            break
        if not prev_line and sig_start < brace_idx and not lines[sig_start].strip().startswith('@'):
            break
        sig_start -= 1
        if brace_idx - sig_start > 15:
            sig_start = max(0, brace_idx - 5)
            break
            
    while sig_start > 0:
        prev = lines[sig_start-1].strip()
        if prev.startswith('@'):
            sig_start -= 1
        elif prev == "":
            sig_start -= 1
        else:
            break
            
    return sig_start

def _extract_method_bounds(filepath, target_line_1_indexed):
    """
    Heuristic to extract the full method block containing target_line.
    Returns (start_line_0_indexed, end_line_0_indexed, snippet_string, success_bool)
    """
    if not os.path.exists(filepath):
        return -1, -1, "Code unavailable", False
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return -1, -1, "Code unavailable", False

    target_idx = target_line_1_indexed - 1
    if target_idx < 0 or target_idx >= len(lines):
        return -1, -1, "Code unavailable", False

    blocks = []
    stack = []
    in_block_comment = False
    
    for i, line in enumerate(lines):
        clean_line = ""
        j = 0
        while j < len(line):
            if in_block_comment:
                if line[j:j+2] == "*/":
                    in_block_comment = False
                    j += 2
                else:
                    j += 1
                continue
                
            if line[j:j+2] == "/*":
                in_block_comment = True
                j += 2
                continue
                
            if line[j:j+2] == "//":
                break
                
            if line[j] == '"' or line[j] == "'":
                quote = line[j]
                j += 1
                while j < len(line):
                    if line[j] == '\\':
                        j += 2
                    elif line[j] == quote:
                        j += 1
                        break
                    else:
                        j += 1
                continue
                
            clean_line += line[j]
            j += 1
            
        for char in clean_line:
            if char == '{':
                stack.append(i)
            elif char == '}':
                if stack:
                    start_i = stack.pop()
                    blocks.append((start_i, i))

    logical_blocks = []
    for start_i, end_i in blocks:
        sig_start = _resolve_logical_start(lines, start_i)
        logical_blocks.append((sig_start, end_i))
        
    containing_blocks = [b for b in logical_blocks if b[0] <= target_idx <= b[1]]
    
    if containing_blocks:
        best_block = sorted(containing_blocks, key=lambda b: b[1]-b[0])[0]
        start_idx, end_idx = best_block
        if end_idx - start_idx > 150:
            start_idx = max(0, target_idx - 5)
            end_idx = min(len(lines) - 1, target_idx + 5)
    else:
        start_idx = max(0, target_idx - 5)
        end_idx = min(len(lines) - 1, target_idx + 5)

    snippet = ""
    for i in range(start_idx, end_idx + 1):
        snippet += f"{i+1:4d} | {lines[i]}"
        
    return start_idx, end_idx, snippet, True

def _extract_limited_context(filepath, line_num, context_lines=3):
    if not os.path.exists(filepath):
        return -1, -1, "Code unavailable", False
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return -1, -1, "Code unavailable", False
    idx = line_num - 1
    if idx < 0 or idx >= len(lines):
        return -1, -1, "Code unavailable", False
    start_idx = max(0, idx - context_lines)
    end_idx = min(len(lines), idx + context_lines + 1)
    snippet = ""
    for i in range(start_idx, end_idx):
        snippet += f"{i+1:4d} | {lines[i]}"
    return start_idx, end_idx - 1, snippet, True

def build_finding_context(finding, repo_path=None, limit_to_lines=False, critical_only=False):
    """
    Constructs the semantic path-aware text context sent to the LLM.
    Groups nodes that fall into the same method to prevent duplication.
    Supports limit_to_lines and critical_only to manage context sizing.
    """
    category = finding.get("category", "unknown")
    cwe = finding.get("subtype", "unknown")
    
    path_nodes = finding.get("path", [])
    if not path_nodes:
        return "No path data available."
        
    # If critical_only is set, keep only the first (SOURCE) and last (SINK) node
    if critical_only and len(path_nodes) > 2:
        path_nodes = [path_nodes[0], path_nodes[-1]]
        
    processed_nodes = []
    for i, node in enumerate(path_nodes):
        if isinstance(node, str):
            processed_nodes.append({
                "type": "legacy",
                "label": "Path Trace",
                "code": node,
                "original_index": i
            })
            continue
            
        if not isinstance(node, dict):
            continue
            
        file_path = node.get("file", "unknown")
        line_num = node.get("line", -1)
        raw_code = node.get("code", "")
        
        if i == 0:
            node_label = "SOURCE"
        elif i == len(path_nodes) - 1:
            node_label = "SINK"
        else:
            if "valid" in raw_code.lower() or "sanit" in raw_code.lower():
                node_label = "VALIDATOR / SANITIZER"
            else:
                node_label = "INTERMEDIATE HOP"
                
        if file_path != "unknown" and line_num > 0:
            full_path = os.path.join(repo_path, file_path) if repo_path and not os.path.isabs(file_path) else file_path
            
            if limit_to_lines:
                start_idx, end_idx, snippet, success = _extract_limited_context(full_path, line_num, context_lines=3)
            else:
                start_idx, end_idx, snippet, success = _extract_method_bounds(full_path, line_num)
            
            processed_nodes.append({
                "type": "code",
                "label": node_label,
                "file": file_path,
                "line": line_num,
                "start_idx": start_idx,
                "end_idx": end_idx,
                "snippet": snippet,
                "success": success,
                "raw_code": raw_code,
                "original_index": i
            })
        else:
            processed_nodes.append({
                "type": "unknown_loc",
                "label": node_label,
                "code": raw_code,
                "original_index": i
            })

    groups = []
    current_group = None
    
    for node in processed_nodes:
        if node["type"] != "code" or not node["success"]:
            if current_group:
                groups.append(current_group)
                current_group = None
            groups.append([node])
            continue
            
        if current_group and current_group[0]["type"] == "code":
            last = current_group[0]
            if node["file"] == last["file"] and node["start_idx"] == last["start_idx"] and node["end_idx"] == last["end_idx"]:
                current_group.append(node)
                continue
                
        if current_group:
            groups.append(current_group)
        current_group = [node]
        
    if current_group:
        groups.append(current_group)
        
    context_blocks = []
    total_nodes = len(path_nodes)
    
    for group in groups:
        if group[0]["type"] == "legacy":
            idx = group[0]["original_index"] + 1
            context_blocks.append(f"==================================================\n[{idx}/{total_nodes}] {group[0]['label']} (Legacy Format)\n==================================================\n{group[0]['code']}")
        elif group[0]["type"] == "unknown_loc":
            idx = group[0]["original_index"] + 1
            context_blocks.append(f"==================================================\n[{idx}/{total_nodes}] {group[0]['label']} (Unknown Location)\n==================================================\n{group[0]['code']}")
        else:
            labels_str = ""
            for node in group:
                idx = node["original_index"] + 1
                labels_str += f"[{idx}/{total_nodes}] {node['label']}\n"
                
            file_path = group[0]['file']
            start_line = group[0]['start_idx'] + 1
            end_line = group[0]['end_idx'] + 1
            
            block = f"==================================================\n{labels_str.strip()}\n{file_path}:{start_line}-{end_line}\n==================================================\n{group[0]['snippet']}"
            context_blocks.append(block)

    full_context = "\n\n".join(context_blocks)
    
    # Load detailed rule matching category
    rule_desc = RULES_DESCRIPTIONS.get(category, f"Verify if finding satisfies {cwe} criteria.")
    
    # Load sinks/sources regex from sinks_sources.yaml if possible
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "sinks_sources.yaml")
    rule_patterns_str = ""
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                rules_config = yaml.safe_load(f) or {}
                cat_rule = rules_config.get(category, {})
                if cat_rule:
                    sources = cat_rule.get("sources", [])
                    sinks = [s.get("pattern") if isinstance(s, dict) else s for s in cat_rule.get("sinks", [])]
                    sanitizers = cat_rule.get("sanitizers", [])
                    rule_patterns_str = f"Sources Regex: {', '.join(sources[:4])}\nSinks Regex: {', '.join(sinks[:4])}\nSanitizers Regex: {', '.join(sanitizers[:4])}"
        except Exception:
            pass

    rule_header = f"""Security Rule & Expected Patterns:
{rule_desc}
{rule_patterns_str}"""

    context = f"""Vulnerability Category: {category}
CWE: {cwe}

{rule_header}

Dataflow Path Context:

{full_context}"""

    return context.strip()
