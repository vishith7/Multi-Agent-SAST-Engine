import os
import sys
import json
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sast-engine")))

from orchestrator.dedupe_anonymize import group_findings, dedupe_by_location
import cli

def main():
    json_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scan_history", "testing0019.json"))
    print(f"Loading findings from: {json_path}")
    
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    findings = data.get("findings", [])
    print(f"Loaded {len(findings)} findings.")
    
    start_time = time.time()
    print("Fetching config names...")
    config_names = cli.get_config_names()
    print(f"Fetched {len(config_names)} config names.")
    
    print("Grouping findings...")
    for idx, f in enumerate(findings):
        print(f"  Anonymizing finding {idx+1}/{len(findings)}: fingerprint={f.get('fingerprint')}")
        path_nodes = f.get("path", [])
        print(f"    Path has {len(path_nodes)} nodes.")
        for n_idx, node in enumerate(path_nodes):
            code = node.get("code", "") if isinstance(node, dict) else str(node)
            # print(f"      Node {n_idx+1}: code_len={len(code)}")
            t0 = time.time()
            from orchestrator.dedupe_anonymize import anonymize
            # We will trace inside anonymize by manually invoking canonicalize_ops here to see if it hangs
            from orchestrator.dedupe_anonymize import canonicalize_ops
            canonicalize_ops(code)
            # print(f"      Node {n_idx+1} canonicalized in {time.time() - t0:.4f}s")
            
        anonymize(f, config_names=config_names)
        
    grouped = group_findings(findings, config_names)
    print("Deduplication by location...")
    grouped = dedupe_by_location(grouped)
    
    end_time = time.time()
    print(f"Deduplication completed in {end_time - start_time:.4f} seconds.")
    print(f"Grouped unique findings count: {len(grouped)}")

if __name__ == "__main__":
    main()
