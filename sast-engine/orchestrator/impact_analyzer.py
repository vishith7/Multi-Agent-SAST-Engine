import os
import subprocess
import re

GLOBAL_FILES = {"package.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod", "yarn.lock", "package-lock.json"}
SECURITY_PATHS = ["auth", "security", "login", "middleware", "guard", "sinks_sources.yaml"]

def analyze_impact(repo_path, diff_map=None):
    """
    Conservatively classifies a git diff as SAFE_LOCAL or FULL_SCAN.
    Returns (strategy, reason, files_changed, functions_changed)
    strategy: "SAFE_LOCAL" | "FULL_SCAN"
    """
    repo_path = os.path.abspath(repo_path)
    files_changed = 0
    functions_changed = 0

    if diff_map:
        files_changed = len(diff_map)
        
    try:
        # Get unified diff with context
        result = subprocess.run(
            ["git", "diff", "HEAD", "-U3"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        diff_text = result.stdout
        
        if not diff_text.strip():
            # If no diff output from git diff HEAD, check untracked files
            untracked = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()
            
            if untracked:
                # If there are brand new files, we have to assume FULL_SCAN unless we parse them entirely.
                # Being conservative: new files could introduce new sources/sinks or cross-module exports.
                return "FULL_SCAN", "NEW_UNTRACKED_FILES_DETECTED", len(untracked.splitlines()), 0
            
            # No changes at all?
            return "FULL_SCAN", "NO_DIFF_DETECTED", 0, 0

    except Exception as e:
        return "FULL_SCAN", f"IMPACT_ANALYSIS_UNCERTAIN_ERROR_{e}", files_changed, 0

    current_file = None
    
    # Patterns that denote an external contract change or security boundary
    # This is conservative. We match additions or deletions of these keywords.
    contract_patterns = re.compile(r'^\s*[\+\-]\s*(def\s|function\s|class\s|export\s|import\s|from\s|require\(|return\s)')

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            parts = line.split(" ")
            if len(parts) >= 4:
                file_b = parts[3]
                if file_b.startswith("b/"):
                    current_file = os.path.normpath(file_b[2:])
                    basename = os.path.basename(current_file)
                    lower_path = current_file.lower()
                    
                    if basename in GLOBAL_FILES:
                        return "FULL_SCAN", f"GLOBAL_CONFIG_CHANGED_{basename}", files_changed, functions_changed
                        
                    if any(sec in lower_path for sec in SECURITY_PATHS):
                        return "FULL_SCAN", f"SECURITY_BOUNDARY_CHANGED_{current_file}", files_changed, functions_changed

        elif line.startswith("@@"):
            # A new hunk usually has a function context at the end
            functions_changed += 1

        elif line.startswith("+") or line.startswith("-"):
            # Ignore +++ / ---
            if line.startswith("+++") or line.startswith("---"):
                continue
                
            # Check for signature, return, or export changes
            if contract_patterns.match(line):
                return "FULL_SCAN", f"CROSS_MODULE_OR_SIGNATURE_CHANGED_IN_{current_file}", files_changed, functions_changed
                
            # Check for changes that might indicate adding/removing sinks or sources
            lower_line = line.lower()
            if "exec" in lower_line or "eval" in lower_line or "query" in lower_line or "sql" in lower_line or "request" in lower_line:
                # Very conservative: if a line modifying sinks/sources/SQL/exec is touched, it's safer to full scan
                return "FULL_SCAN", f"POTENTIAL_SINK_SOURCE_MODIFICATION_IN_{current_file}", files_changed, functions_changed
                
            # Check for sanitizer changes
            if "sanitize" in lower_line or "escape" in lower_line or "validate" in lower_line:
                return "FULL_SCAN", f"POTENTIAL_SANITIZER_MODIFICATION_IN_{current_file}", files_changed, functions_changed

    return "SAFE_LOCAL", "LOCAL_LOGIC", files_changed, functions_changed
