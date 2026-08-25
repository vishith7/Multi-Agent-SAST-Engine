import os
import sys
import time
import json
import uuid
import datetime
import shutil
import threading
from typing import Dict, Any, List, Optional
from pathlib import Path

# Setup paths to import cli and sast-engine
from web.backend.utils.paths import WORKSPACE_ROOT, SAST_ENGINE_DIR, SCAN_HISTORY_DIR
sys.path.append(str(WORKSPACE_ROOT))
sys.path.append(str(SAST_ENGINE_DIR))

import cli
from orchestrator.prepare import build_or_update_cpg, build_full_cpg
from orchestrator.scan import run_scan
from orchestrator.chain_detection import detect_chains
from web.backend.services.result_service import ResultService
from orchestrator.dedupe_anonymize import group_findings
try:
    from orchestrator.dedupe_anonymize import dedupe_by_location
except ImportError:
    dedupe_by_location = None
from orchestrator.cascade import run_cascade_on_findings

# Global active scans state
ACTIVE_SCANS: Dict[str, Dict[str, Any]] = {}

class ScanService:
    @staticmethod
    def start_scan_thread(
        repo_path: str,
        scan_mode: str = "AUTO",
        cpg_name: str = "cpg.bin",
        output_filename: Optional[str] = None,
        verbose: bool = False,
        revalidate: bool = False
    ) -> str:
        # Resolve target repository name
        # If GitHub URL, extract repo name, otherwise get folder name
        repo_clean = repo_path.strip().rstrip('/')
        if repo_clean.lower().endswith('.git'):
            repo_clean = repo_clean[:-4]
            
        repo_name = os.path.basename(repo_clean)
        
        # Generate scan ID and final output filename
        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        scan_id = f"findings_{repo_name}_{timestamp_str}"
        
        if not output_filename:
            output_filename = f"{scan_id}.json"
        elif not output_filename.endswith(".json"):
            output_filename += ".json"
            
        # Register in ACTIVE_SCANS
        ACTIVE_SCANS[scan_id] = {
            "scan_id": scan_id,
            "repo": repo_name,
            "status": "running",
            "stage": "QUEUED",
            "progress": 0,
            "start_time": datetime.datetime.now().isoformat(),
            "end_time": None,
            "finding_count": 0,
            "error": None,
            "scan_type": "full"  # defaults to full, smart router will update
        }
        
        # Start thread
        t = threading.Thread(
            target=ScanService._run_pipeline,
            args=(scan_id, repo_path, scan_mode, cpg_name, output_filename, verbose, revalidate)
        )
        t.daemon = True
        t.start()
        
        return scan_id

    @staticmethod
    def get_scan_status(scan_id: str) -> Optional[Dict[str, Any]]:
        # If it's currently running/recently finished in memory
        if scan_id in ACTIVE_SCANS:
            return ACTIVE_SCANS[scan_id]
            
        # Otherwise, check scan history directory
        file_path = SCAN_HISTORY_DIR / f"{scan_id}.json"
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                metadata = data.get("scan_metadata", {})
                return {
                    "scan_id": scan_id,
                    "repo": metadata.get("repo", "unknown"),
                    "status": "completed",
                    "stage": "COMPLETED",
                    "progress": 100,
                    "start_time": metadata.get("timestamp"),
                    "end_time": metadata.get("timestamp"),
                    "finding_count": len(data.get("findings", [])),
                    "error": None,
                    "scan_type": metadata.get("scan_type", "full")
                }
            except Exception:
                pass
                
        return None

    @staticmethod
    def _run_pipeline(
        scan_id: str,
        repo_path: str,
        scan_mode: str,
        cpg_name: str,
        output_filename: str,
        verbose: bool,
        revalidate: bool
    ):
        status = ACTIVE_SCANS[scan_id]
        
        try:
            # 1. Prepare stage
            status["stage"] = "PREPARING"
            status["progress"] = 10
            
            # Use cli.handle_github_repo to clone/pull if github link
            local_repo_path = cli.handle_github_repo(repo_path)
            
            # Determine scan strategy (Smart Router)
            strategy = "FULL_SCAN"
            reason = "USER_REQUESTED"
            diff_map = None
            
            if scan_mode == "DIFF_SCAN":
                strategy = "DIFF_LOCAL"
            elif scan_mode == "AUTO":
                # Smart routing logic
                if not shutil.which("git"):
                    strategy = "FULL_SCAN"
                    reason = "GIT_NOT_AVAILABLE"
                else:
                    try:
                        from orchestrator.diff import get_git_diff_lines
                        from orchestrator.impact_analyzer import analyze_impact
                        
                        diff_map = get_git_diff_lines(local_repo_path)
                        if diff_map:
                            strategy, reason, files_changed, functions_changed = analyze_impact(local_repo_path, diff_map)
                            if strategy == "SAFE_LOCAL":
                                strategy = "DIFF_LOCAL"
                            else:
                                strategy = "FULL_SCAN"
                        else:
                            strategy = "FULL_SCAN"
                            reason = "NO_DIFF_DETECTED"
                    except Exception as e:
                        strategy = "FULL_SCAN"
                        reason = f"IMPACT_ANALYSIS_UNCERTAIN ({e})"
            
            status["scan_type"] = "diff-scoped" if strategy == "DIFF_LOCAL" else "full"
            
            # 2. CPG Build/Diff Scan stage
            status["stage"] = "CPG_BUILD"
            status["progress"] = 30
            
            grouped_findings = []
            telemetry = []
            
            if strategy == "DIFF_LOCAL":
                # Diff scoped scan
                from orchestrator.diff_scanner import run_diff_scan
                from orchestrator.dedupe_anonymize import dedupe_and_anonymize
                
                raw_findings, telemetry = run_diff_scan(local_repo_path)
                status["stage"] = "DEDUPLICATION"
                status["progress"] = 70
                
                if raw_findings:
                    grouped_findings = dedupe_and_anonymize(raw_findings, local_repo_path)
            else:
                # Full Scan
                repo_name = os.path.basename(os.path.abspath(local_repo_path))
                workspace_dir = os.path.join(WORKSPACE_ROOT, ".taintlace", "workspace", repo_name)
                os.makedirs(workspace_dir, exist_ok=True)
                cpg_path = os.path.join(workspace_dir, cpg_name)
                
                # Build/Update CPG
                success = build_or_update_cpg(local_repo_path, cpg_path, force_rebuild=False)
                if not success:
                    raise RuntimeError("Joern CPG parse execution failed.")
                
                # Execute Scans
                status["stage"] = "SCANNING"
                status["progress"] = 50
                raw_findings, telemetry = run_scan(local_repo_path, cpg_name=cpg_name)
                
                # Chain Detection
                status["stage"] = "CHAIN_DETECTION"
                status["progress"] = 65
                chained_findings = detect_chains(raw_findings)
                
                # Deduplication
                status["stage"] = "DEDUPLICATION"
                status["progress"] = 75
                config_names = cli.get_config_names()
                grouped_findings = group_findings(chained_findings, config_names)
                if dedupe_by_location:
                    grouped_findings = dedupe_by_location(grouped_findings)
                    
            # 3. LLM Validation stage
            status["stage"] = "LLM_VALIDATION"
            status["progress"] = 80
            validated_findings = run_cascade_on_findings(
                grouped_findings,
                local_repo_path,
                force_revalidate=revalidate
            )
            
            # 4. Prove stage (Proof-of-Concept exploits)
            status["stage"] = "PROVING"
            status["progress"] = 90
            from orchestrator.prove import run_prove_on_findings
            proved_findings = run_prove_on_findings(
                validated_findings,
                local_repo_path
            )
            
            # Save scan results to history (initial completion save)
            status["stage"] = "RISK_ANALYSIS"
            status["progress"] = 98
            
            timestamp = datetime.datetime.now().isoformat()
            output_data = {
                "scan_metadata": {
                    "repo": status["repo"],
                    "timestamp": timestamp,
                    "raw_findings": len(raw_findings) if strategy != "DIFF_LOCAL" else len(proved_findings),
                    "unique_findings": len(proved_findings),
                    "scan_type": status["scan_type"],
                    "per_rule_stats": telemetry,
                    "defectdojo_upload_status": "not_configured",
                    "defectdojo_engagement_id": None,
                    "defectdojo_test_id": None,
                    "defectdojo_last_error": None,
                    "defectdojo_last_attempt": None
                },
                "findings": proved_findings
            }
            
            # Write previous scan manifest
            manifest_path = os.path.join(WORKSPACE_ROOT, ".taintlace", "workspace", status["repo"], "previous_scan_manifest.json")
            try:
                os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
                current_commit = shutil.which("git") and os.path.exists(local_repo_path) and \
                                 shutil.os.system(f"git -C {local_repo_path} rev-parse HEAD") == 0
                if current_commit:
                    import subprocess
                    commit_hash = subprocess.run(["git", "rev-parse", "HEAD"], cwd=local_repo_path, capture_output=True, text=True).stdout.strip()
                    manifest_data = {
                        "last_scanned_commit": commit_hash,
                        "timestamp": timestamp
                    }
                    with open(manifest_path, "w") as mf:
                        json.dump(manifest_data, mf)
            except Exception:
                pass
                
            # Update status as completed first
            status["status"] = "completed"
            status["stage"] = "COMPLETED"
            status["progress"] = 100
            status["end_time"] = datetime.datetime.now().isoformat()
            status["finding_count"] = len(proved_findings)

            # Persist the initial completed scan
            ResultService.save_scan(scan_id, output_data)

            # 5. Push findings to DefectDojo automatically
            try:
                from integrations.defectdojo.client import DefectDojoClient
                dd_client = DefectDojoClient()
                if dd_client.is_configured():
                    output_data["scan_metadata"]["defectdojo_upload_status"] = "syncing"
                    output_data["scan_metadata"]["defectdojo_last_attempt"] = datetime.datetime.now().isoformat()
                    # Re-save with syncing status
                    ResultService.save_scan(scan_id, output_data)

                    # Resolve full context
                    org_id = dd_client.get_or_create_product_type()
                    prod_id = dd_client.get_or_create_product(org_id, status["repo"])
                    engagement_id = dd_client.get_or_create_engagement(prod_id, status["repo"])
                    test_id = dd_client.create_test(engagement_id, status["repo"], scan_id)
                    proved_findings = dd_client.push_findings(test_id, proved_findings, status["repo"])

                    output_data["findings"] = proved_findings
                    output_data["scan_metadata"]["defectdojo_engagement_id"] = str(engagement_id)
                    output_data["scan_metadata"]["defectdojo_test_id"] = str(test_id)
                    output_data["scan_metadata"]["defectdojo_upload_status"] = "success"
                    output_data["scan_metadata"]["defectdojo_last_error"] = None
                else:
                    output_data["scan_metadata"]["defectdojo_upload_status"] = "not_configured"
            except Exception as e:
                err_msg = str(e)
                print(f"[ScanService] DefectDojo automatic push failed: {err_msg}")
                output_data["scan_metadata"]["defectdojo_upload_status"] = "failed"
                output_data["scan_metadata"]["defectdojo_last_error"] = err_msg
            
            # Save scan details with upload findings & statuses
            ResultService.save_scan(scan_id, output_data)
            
        except Exception as e:
            status["status"] = "failed"
            status["stage"] = "FAILED"
            status["error"] = str(e)
            status["end_time"] = datetime.datetime.now().isoformat()
            print(f"[ScanService] Scan {scan_id} failed: {e}")
