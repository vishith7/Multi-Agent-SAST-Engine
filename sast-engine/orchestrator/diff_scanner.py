import os
import sys
import tempfile
import json
import time

try:
    from orchestrator.diff import get_git_diff_lines
    from orchestrator.server import JoernServer
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from diff import get_git_diff_lines
    from server import JoernServer

import yaml

GLOBAL_FILES = {"package.json", "requirements.txt", "pom.xml", "build.gradle", "go.mod"}

def run_diff_scan(repo_path):
    print(f"[*] Starting Diff-Scoped Incremental Taint Pipeline for {repo_path}")
    diff_map = get_git_diff_lines(repo_path)
    if not diff_map:
        print("[!] No git diff found or not a git repository.")
        return [], []

    # Check for global file changes
    for filepath in diff_map.keys():
        basename = os.path.basename(filepath)
        if basename in GLOBAL_FILES:
            print(f"[!] Global configuration file '{filepath}' modified.")
            print("[!] A full repository scan is required to capture dependency/structural changes.")
            return [], []

    server = JoernServer()
    # Ensure server is running
    try:
        if not server.is_running():
            server.start()
    except Exception as e:
        print(f"[!] Failed to check/start Joern server: {e}")
        return [], []

    all_findings = []
    telemetry = []

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "sinks_sources.yaml")
    script_path = os.path.join(base_dir, "queries", "scoped_scan.sc")

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    for rel_path, diff_info in diff_map.items():
        full_path = os.path.join(repo_path, rel_path)
        if not os.path.exists(full_path):
            continue

        lines_to_check = []
        if isinstance(diff_info, set):
            lines_to_check = list(diff_info)
        elif isinstance(diff_info, dict):
            if diff_info.get("all_flagged"):
                lines_to_check = list(diff_info.get("lines", []))
            else:
                # Large file, we skip for diff scan or just don't pass lines? 
                # Let's skip large new files for this fast-path.
                print(f"[!] Skipping large new file: {rel_path}")
                continue

        if not lines_to_check:
            continue

        print(f"[*] Analyzing modified file: {rel_path} ({len(lines_to_check)} changed lines)")

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp_cpg:
            tmp_cpg_path = tmp_cpg.name

        try:
            # Build isolated CPG
            success = server.build_cpg(full_path, tmp_cpg_path)
            if not success:
                print(f"[!] Failed to build isolated CPG for {rel_path}")
                continue

            lines_str = ",".join(map(str, sorted(lines_to_check)))

            for category, patterns in config.items():
                sources = ",".join(patterns.get("sources", []))
                
                sinks_list = []
                for s in patterns.get("sinks", []):
                    if isinstance(s, dict) and "pattern" in s and "subtype" in s:
                        sinks_list.append(f"{s['pattern']}:::{s['subtype']}")
                    elif isinstance(s, str):
                        sinks_list.append(f"{s}:::UNKNOWN")
                sinks = ",".join(sinks_list)
                
                sanitizers = ",".join(patterns.get("sanitizers", []))

                params = {
                    "category": category,
                    "sources": sources,
                    "sinks": sinks,
                    "sanitizers": sanitizers,
                    "cpg_path": tmp_cpg_path.replace("\\", "/"),
                    "changed_lines": lines_str
                }

                output = server.execute_script(script_path, params)
                if not output:
                    continue

                for line in output.splitlines():
                    if line.startswith("JSON_START:") and line.endswith(":JSON_END"):
                        json_str = line[11:-9]
                        try:
                            finding = json.loads(json_str)
                            finding["chain_id"] = None
                            all_findings.append(finding)
                        except json.JSONDecodeError as e:
                            print(f"[!] Failed to parse JSON finding: {e}")
                    elif line.startswith("TELEMETRY_START:") and line.endswith(":TELEMETRY_END"):
                        json_str = line[16:-14]
                        try:
                            telemetry.append(json.loads(json_str))
                        except json.JSONDecodeError:
                            pass
        finally:
            if os.path.exists(tmp_cpg_path):
                try:
                    os.remove(tmp_cpg_path)
                except Exception:
                    pass

    return all_findings, telemetry
