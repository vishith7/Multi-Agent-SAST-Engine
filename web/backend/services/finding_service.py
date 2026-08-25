import os
from typing import List, Dict, Any, Optional
from web.backend.services.result_service import ResultService
from web.backend.utils.errors import FindingNotFoundException

class FindingService:
    @staticmethod
    def get_all_findings(
        category: Optional[str] = None,
        verdict: Optional[str] = None,
        priority: Optional[str] = None,
        severity: Optional[str] = None,
        repo: Optional[str] = None,
        sla_status: Optional[str] = None,
        scan_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        from web.backend.utils.mongo import get_mongo_db
        db = get_mongo_db()
        if db is not None:
            try:
                # Construct MongoDB filter
                q = {}
                if scan_id:
                    q["scan_id"] = scan_id
                if category:
                    q["category"] = {"$regex": f"^{category}$", "$options": "i"}
                if verdict:
                    q["verdict"] = verdict.upper()
                if priority:
                    q["priority"] = priority.upper()
                if severity:
                    q["severity"] = {"$regex": f"^{severity}$", "$options": "i"}
                if repo:
                    q["repo"] = {"$regex": f"^{repo}$", "$options": "i"}

                findings_cursor = db.findings.find(q, {"_id": 0})
                findings = list(findings_cursor)

                filtered_findings = []
                for f in findings:
                    f["sla_status"] = ResultService.map_defectdojo_sla(f)
                    
                    # Dynamic SLA status filter
                    if sla_status and f.get("sla_status", {}).get("status", "").lower() != sla_status.lower():
                        continue
                        
                    filtered_findings.append(f)
                    
                return filtered_findings
            except Exception as e:
                print(f"[MongoDB] Failed to query findings: {e}. Falling back to FS.")

        all_findings = []
        scans_to_check = []
        
        if scan_id:
            scan = ResultService.get_scan(scan_id)
            if scan:
                scans_to_check.append(scan)
        else:
            scan_summaries = ResultService.get_all_scans()
            for summary in scan_summaries:
                scan = ResultService.get_scan(summary["scan_id"])
                if scan:
                    scans_to_check.append(scan)

        seen_fingerprints = set()

        for scan in scans_to_check:
            metadata = scan.get("scan_metadata", {})
            findings = scan.get("findings", [])
            repo_name = metadata.get("repo", "unknown")
            scan_timestamp = metadata.get("timestamp")
            
            for f in findings:
                fingerprint = f.get("fingerprint")
                if not fingerprint:
                    continue
                
                # Check uniqueness (if scan_id is not specified, we can show unique findings globally)
                f_copy = dict(f)
                f_copy["repo"] = repo_name
                f_copy["scan_id"] = scan.get("scan_metadata", {}).get("scan_id") or scan.get("scan_id") or ""
                f_copy["scan_timestamp"] = scan_timestamp
                
                # Apply filters
                if category and f_copy.get("category", "").lower() != category.lower():
                    continue
                if verdict and f_copy.get("verdict", "").upper() != verdict.upper():
                    continue
                if priority and f_copy.get("priority", "").upper() != priority.upper():
                    continue
                if severity and f_copy.get("severity", "").lower() != severity.lower():
                    continue
                if repo and f_copy.get("repo", "").lower() != repo.lower():
                    continue
                if sla_status and f_copy.get("sla_status", {}).get("status", "").lower() != sla_status.lower():
                    continue

                all_findings.append(f_copy)
                seen_fingerprints.add(fingerprint)

        return all_findings

    @staticmethod
    def get_finding_by_fingerprint(fingerprint: str) -> Optional[Dict[str, Any]]:
        from web.backend.utils.mongo import get_mongo_db
        db = get_mongo_db()
        if db is not None:
            try:
                finding = db.findings.find_one({"fingerprint": fingerprint}, {"_id": 0})
                if finding:
                    finding["sla_status"] = ResultService.map_defectdojo_sla(finding)
                    return finding
            except Exception as e:
                print(f"[MongoDB] Failed to fetch finding by fingerprint: {e}. Falling back to FS.")

        # Search all scans for the finding
        scan_summaries = ResultService.get_all_scans()
        for summary in scan_summaries:
            scan = ResultService.get_scan(summary["scan_id"])
            if not scan:
                continue
            
            for f in scan.get("findings", []):
                if f.get("fingerprint") == fingerprint:
                    f_copy = dict(f)
                    f_copy["repo"] = scan["scan_metadata"].get("repo", "unknown")
                    f_copy["scan_id"] = summary["scan_id"]
                    f_copy["scan_timestamp"] = scan["scan_metadata"].get("timestamp")
                    f_copy["sla_status"] = ResultService.map_defectdojo_sla(f_copy)
                    return f_copy
        return None

    @staticmethod
    def update_approval_state(fingerprint: str, state: str) -> bool:
        # Local approval state is deprecated in favor of DefectDojo. 
        # Returns False to prevent local changes.
        return False

    @staticmethod
    def update_human_validation(fingerprint: str, status: str, reviewer: str = None, comment: str = None) -> bool:
        import datetime
        from web.backend.services.result_service import ResultService
        
        finding = FindingService.get_finding_by_fingerprint(fingerprint)
        if not finding:
            return False
            
        scan_id = finding.get("scan_id")
        scan_data = ResultService.get_scan(scan_id)
        if not scan_data:
            return False
            
        human_val = finding.setdefault("human_validation", {})
        human_val["status"] = status
        human_val["reviewer"] = reviewer
        human_val["comment"] = comment
        human_val["reviewed_at"] = datetime.datetime.now().isoformat()
        
        # Update fix status based on validation status
        fix_block = finding.get("fix") or {}
        if fix_block.get("available"):
            if status == "APPROVED":
                fix_block["status"] = "APPROVED"
            elif status == "REJECTED":
                fix_block["status"] = "REJECTED"
            elif status == "NEEDS_REVIEW":
                fix_block["status"] = "PROPOSED"
            finding["fix"] = fix_block
            
        FindingService._save_updated_finding(scan_id, fingerprint, finding, scan_data)
        return True

    @staticmethod
    def apply_fix(fingerprint: str, reviewer: str = "Admin") -> Dict[str, Any]:
        import datetime
        from web.backend.services.result_service import ResultService
        
        finding = FindingService.get_finding_by_fingerprint(fingerprint)
        if not finding:
            return {"success": False, "error": f"Finding {fingerprint} not found"}
            
        # ai_val verdict checking
        verdict = finding.get("verdict")
        if verdict not in ("VALID", "APPROVED"):
            return {"success": False, "error": f"Finding verdict is not VALID/APPROVED (verdict: {verdict})"}
            
        fix_block = finding.get("fix") or {}
        if not fix_block.get("available"):
            return {"success": False, "error": "No proposed fix is available for this finding"}
            
        human_val = finding.get("human_validation") or {}
        if human_val.get("status") != "APPROVED":
            return {"success": False, "error": f"Human validation status is not APPROVED (status: {human_val.get('status')})"}
            
        if fix_block.get("status") == "APPLIED":
            return {"success": False, "error": "This patch has already been applied"}
            
        # Target file details
        target_file = finding.get("file_path") or (finding.get("instances")[0].get("sink_file") if finding.get("instances") else None)
        if not target_file:
            return {"success": False, "error": "Target file location is missing from the finding"}
            
        scan_id = finding.get("scan_id")
        scan_data = ResultService.get_scan(scan_id)
        if not scan_data:
            return {"success": False, "error": f"Scan result {scan_id} not found"}
            
        repo_path = scan_data["scan_metadata"]["repo"]
        
        try:
            from cli import handle_github_repo
            local_repo_path = handle_github_repo(repo_path)
        except Exception as e:
            return {"success": False, "error": f"Failed to resolve repository path: {e}"}
            
        # Determine target file full path
        full_file_path = os.path.join(local_repo_path, target_file)
        # Ensure path safety (prevent directory traversal)
        if not os.path.abspath(full_file_path).startswith(os.path.abspath(local_repo_path)):
            return {"success": False, "error": "Security check failed: target file path lies outside repository bounds"}
            
        if not os.path.exists(full_file_path):
            return {"success": False, "error": f"Target file {target_file} does not exist"}
            
        # Perform patch validation and application
        try:
            with open(full_file_path, "r", encoding="utf-8") as f_in:
                content = f_in.read()
                
            before_snippet = fix_block.get("before", "").strip()
            after_snippet = fix_block.get("after", "").strip()
            
            if not before_snippet:
                return {"success": False, "error": "Proposed patch contains no 'before' snippet to match"}
                
            # If the original content does not contain the exact 'before' snippet, raise conflict
            if before_snippet not in content:
                # Set fix status to CONFLICT
                fix_block["status"] = "CONFLICT"
                FindingService._save_updated_finding(scan_id, fingerprint, finding, scan_data)
                return {
                    "success": False,
                    "error": "Conflict: Target file content has changed and the expected 'before' snippet is no longer present. The patch cannot be applied safely."
                }
                
            # Perform atomic replacement
            updated_content = content.replace(before_snippet, after_snippet, 1)
            
            # Write back atomically
            tmp_file = full_file_path + ".tmp"
            with open(tmp_file, "w", encoding="utf-8") as f:
                f.write(updated_content)
            os.replace(tmp_file, full_file_path)
            
            # Save audit state
            fix_block["status"] = "APPLIED"
            fix_block["applied_at"] = datetime.datetime.now().isoformat()
            fix_block["applied_by"] = reviewer
            
            finding["fix"] = fix_block
            FindingService._save_updated_finding(scan_id, fingerprint, finding, scan_data)
            
            return {"success": True, "message": "Fix applied successfully"}
            
        except Exception as e:
            fix_block["status"] = "FAILED"
            finding["fix"] = fix_block
            FindingService._save_updated_finding(scan_id, fingerprint, finding, scan_data)
            return {"success": False, "error": f"Failed to apply patch: {e}"}

    @staticmethod
    def _save_updated_finding(scan_id: str, fingerprint: str, finding: Dict[str, Any], scan_data: Dict[str, Any]):
        from web.backend.services.result_service import ResultService
        from web.backend.utils.mongo import get_mongo_db
        
        # 1. Update the finding object in the scan_data findings list
        findings = scan_data.get("findings", [])
        for i, f in enumerate(findings):
            if f.get("fingerprint") == fingerprint:
                findings[i] = finding
                break
                
        # 2. Save back to the scan results JSON file
        ResultService.save_scan(scan_id, scan_data)
        
        # 3. Update in MongoDB if available
        db = get_mongo_db()
        if db is not None:
            try:
                # Update in findings collection
                db.findings.update_many(
                    {"scan_id": scan_id, "fingerprint": fingerprint},
                    {"$set": finding}
                )
            except Exception as e:
                print(f"[MongoDB] Failed to update finding in database: {e}")
