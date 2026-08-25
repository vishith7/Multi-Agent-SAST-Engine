import os
import subprocess
import json
import yaml
import tempfile

def run_scan(repo_path, scope=None, cpg_name="cpg.bin", output="findings_output.json"):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "sinks_sources.yaml")
    script_path = os.path.join(base_dir, "queries", "runner.sc")
    repo_name = os.path.basename(os.path.abspath(repo_path))
    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".taintlace", "workspace", repo_name))
    cpg_path = os.path.join(workspace_dir, cpg_name).replace("\\", "/")
    
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        
    all_findings = []
    telemetry = []
    
    for category, patterns in config.items():
        print(f"Running scan for category: {category}")
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
            "cpg_path": cpg_path,
            "maxDepth": "30"
        }
        if scope:
            params["scope"] = scope
            
        try:
            from orchestrator.server import JoernServer
        except ImportError:
            from server import JoernServer
            
        server = JoernServer()
        output = server.execute_script(script_path, params)
        
        if output is None:
            print(f"Scan failed for category {category}: Server query returned None")
            continue
            
        for line in output.splitlines():
            if line.startswith("JSON_START:") and line.endswith(":JSON_END"):
                json_str = line[11:-9]
                try:
                    finding = json.loads(json_str)
                    finding["chain_id"] = None
                    all_findings.append(finding)
                except json.JSONDecodeError as e:
                    print(f"Failed to parse JSON finding: {e}")
            elif line.startswith("TELEMETRY_START:") and line.endswith(":TELEMETRY_END"):
                json_str = line[16:-14]
                try:
                    telemetry.append(json.loads(json_str))
                except json.JSONDecodeError as e:
                    print(f"Failed to parse JSON telemetry: {e}")
            
    return all_findings, telemetry

if __name__ == "__main__":
    import sys
    import chain_detection
    if len(sys.argv) > 1:
        findings, telemetry = run_scan(sys.argv[1])
        findings = chain_detection.detect_chains(findings)
        print(json.dumps({"findings": findings, "telemetry": telemetry}, indent=2))
