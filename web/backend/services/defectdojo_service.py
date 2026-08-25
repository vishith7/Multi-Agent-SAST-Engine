import os
import sys
import json
import keyring
import datetime
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

# Setup paths for importing priority policy
from web.backend.utils.paths import SAST_ENGINE_DIR, WORKSPACE_ROOT
sys.path.append(str(SAST_ENGINE_DIR))
sys.path.append(str(WORKSPACE_ROOT))

from risk.priority_policy import determine_severity
from web.backend.services.finding_service import FindingService
from web.backend.services.result_service import ResultService
from web.backend.utils.errors import InvalidInputException
from integrations.defectdojo.client import DefectDojoClient

class DefectDojoService:
    @staticmethod
    def get_config() -> Dict[str, Any]:
        client = DefectDojoClient()
        is_valid, status = client.validate_credentials()
        return {
            "url": client.url,
            "engagement_id": client.engagement_config,
            "organization": client.organization,
            "default_engagement": client.default_engagement,
            "has_token": bool(client.token),
            "configured": is_valid,
            "status": status
        }

    @staticmethod
    def validate_credentials(url: str, token: str, engagement_id: str) -> bool:
        client = DefectDojoClient()
        # Override with values to check
        client.url = url.strip().rstrip('/')
        client.token = token.strip()
        client.engagement_config = engagement_id.strip() if engagement_id else ""
        
        is_valid, status = client.validate_credentials()
        if not is_valid:
            raise InvalidInputException(status)
        return True

    @staticmethod
    def save_config(url: str, token: Optional[str], engagement_id: Optional[str] = "",
                    organization: Optional[str] = "", default_engagement: Optional[str] = "") -> Dict[str, Any]:
        token_to_save = token.strip() if token else ""
        if not token_to_save or token_to_save.startswith(('•', '*')):
            token_to_save = keyring.get_password("taintlace_defectdojo", "token") or os.environ.get('DEFECTDOJO_API_KEY') or ""
            
        if not token_to_save:
            raise InvalidInputException("DefectDojo API Token is required.")
            
        eng_id = engagement_id.strip() if engagement_id else ""
            
        client = DefectDojoClient()
        client.url = url.strip().rstrip('/')
        client.token = token_to_save
        client.engagement_config = eng_id
        client.organization = organization.strip() if organization else "Multi-Agentic SAST Engine"
        client.default_engagement = default_engagement.strip() if default_engagement else "Continuous SAST Scanning"
        
        # Test validation but do not raise exception if we want to save anyway.
        # Actually, the prompt says: "If the project intentionally allows saving invalid credentials for later correction, it may store them securely but MUST show: CONFIGURED BUT NOT VERIFIED rather than ACTIVE"
        # We will save first, then return the status.
        
        # 1. Update Keyring credentials
        try:
            keyring.set_password("taintlace_defectdojo", "url", client.url)
            keyring.set_password("taintlace_defectdojo", "engagement_id", eng_id)
            keyring.set_password("taintlace_defectdojo", "token", token_to_save)
        except Exception as e:
            print(f"[DefectDojoService] Keyring update failed: {e}")

        # 2. Update local .env file
        try:
            env_file = WORKSPACE_ROOT / ".env"
            lines = []
            if env_file.exists():
                with open(env_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            
            new_lines = []
            for line in lines:
                stripped = line.strip()
                if not stripped.startswith(("DEFECTDOJO_URL=", "DEFECTDOJO_API_KEY=", "DEFECTDOJO_ENGAGEMENT_ID=", "DEFECTDOJO_ORGANIZATION=", "DEFECTDOJO_DEFAULT_ENGAGEMENT=")):
                    new_lines.append(line)
            
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines[-1] += "\n"
                
            new_lines.append(f"DEFECTDOJO_URL={client.url}\n")
            new_lines.append(f"DEFECTDOJO_API_KEY={token_to_save}\n")
            new_lines.append(f"DEFECTDOJO_ENGAGEMENT_ID={eng_id}\n")
            new_lines.append(f"DEFECTDOJO_ORGANIZATION={client.organization}\n")
            new_lines.append(f"DEFECTDOJO_DEFAULT_ENGAGEMENT={client.default_engagement}\n")
            
            with open(env_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
                
            # Update runtime env
            os.environ["DEFECTDOJO_URL"] = client.url
            os.environ["DEFECTDOJO_API_KEY"] = token_to_save
            os.environ["DEFECTDOJO_ENGAGEMENT_ID"] = eng_id
            os.environ["DEFECTDOJO_ORGANIZATION"] = client.organization
            os.environ["DEFECTDOJO_DEFAULT_ENGAGEMENT"] = client.default_engagement
            
            # Now run real validation
            is_valid, status = client.validate_credentials()
            
            if not is_valid:
                return {
                    "success": False,
                    "message": status,
                    "configured": False
                }
                
            return {
                "success": True,
                "message": "DefectDojo credentials validated and updated successfully.",
                "configured": True,
                "status": status
            }
        except Exception as e:
            raise InvalidInputException(f"Failed to save credentials to .env file: {e}")

    @staticmethod
    def push_findings(
        fingerprint: Optional[str] = None,
        scan_id: Optional[str] = None,
        custom_url: Optional[str] = None,
        custom_token: Optional[str] = None,
        custom_engagement_id: Optional[str] = None
    ) -> Dict[str, Any]:
        # Resolve client
        client = DefectDojoClient()
        if custom_url:
            client.url = custom_url.strip().rstrip('/')
        if custom_token and not custom_token.startswith(('•', '*')):
            client.token = custom_token.strip()
        if custom_engagement_id is not None:
            client.engagement_config = custom_engagement_id.strip()

        # Identify which findings to push
        findings_to_push = []
        repo_name = "unknown"
        scan_to_update = None
        
        if fingerprint:
            finding = FindingService.get_finding_by_fingerprint(fingerprint)
            if not finding:
                raise InvalidInputException(f"Finding with fingerprint '{fingerprint}' not found.")
            findings_to_push.append(finding)
            repo_name = finding.get("repo", "unknown")
            scan_id = finding.get("scan_id", f"auto-{int(time.time())}")
            if scan_id and not scan_id.startswith("auto-"):
                scan_to_update = ResultService.get_scan(scan_id)
        elif scan_id:
            scan = ResultService.get_scan(scan_id)
            if not scan:
                raise InvalidInputException(f"Scan '{scan_id}' not found.")
            findings_to_push = scan.get("findings", [])
            repo_name = scan.get("scan_metadata", {}).get("repo", "unknown")
            scan_to_update = scan
        else:
            raise InvalidInputException("Either fingerprint or scan_id must be provided to push findings.")

        if not findings_to_push:
            return {"success": True, "pushed": 0, "errors": ["No findings to push."]}

        # Helper to update error state in scan result
        def save_fail_status(err_msg: str):
            if scan_to_update and scan_id and not scan_id.startswith("auto-"):
                scan_to_update["scan_metadata"]["defectdojo_upload_status"] = "failed"
                scan_to_update["scan_metadata"]["defectdojo_last_error"] = err_msg
                ResultService.save_scan(scan_id, scan_to_update)

        # Validate credentials
        is_valid, status = client.validate_credentials()
        if not is_valid:
            err_msg = f"DefectDojo configuration invalid: {status}"
            save_fail_status(err_msg)
            return {"success": False, "pushed": 0, "errors": [err_msg]}

        # Set syncing status
        if scan_to_update and scan_id and not scan_id.startswith("auto-"):
            scan_to_update["scan_metadata"]["defectdojo_upload_status"] = "syncing"
            scan_to_update["scan_metadata"]["defectdojo_last_attempt"] = datetime.datetime.now().isoformat()
            ResultService.save_scan(scan_id, scan_to_update)

        # Resolve complete context: Org -> Asset -> Engagement -> Test
        eng_id = None
        test_id = None
        try:
            org_id = client.get_or_create_product_type()
            prod_id = client.get_or_create_product(org_id, repo_name)
            eng_id = client.get_or_create_engagement(prod_id, repo_name)
            test_id = client.create_test(eng_id, repo_name, scan_id)
        except Exception as e:
            err_msg = f"DefectDojo context provisioning failed: {e}"
            save_fail_status(err_msg)
            return {"success": False, "pushed": 0, "errors": [err_msg]}

        # Push findings idempotently
        try:
            pushed = client.push_findings(test_id, findings_to_push, repo_name)
            
            # Save the updated findings back to the database and JSON files
            if scan_to_update and scan_id and not scan_id.startswith("auto-"):
                # Update scan metadata with engagement ID and test ID used
                scan_to_update["scan_metadata"]["defectdojo_engagement_id"] = str(eng_id)
                scan_to_update["scan_metadata"]["defectdojo_test_id"] = str(test_id)
                scan_to_update["scan_metadata"]["defectdojo_upload_status"] = "success"
                scan_to_update["scan_metadata"]["defectdojo_last_error"] = None
                
                # Replace findings list with the pushed findings containing dojo metadata
                pushed_map = {f.get("fingerprint"): f for f in pushed}
                orig_findings = scan_to_update.get("findings", [])
                for f in orig_findings:
                    fp = f.get("fingerprint")
                    if fp in pushed_map:
                        f.update(pushed_map[fp])
                        
                ResultService.save_scan(scan_id, scan_to_update)
                
            return {
                "success": True,
                "pushed": len(pushed),
                "engagement_id": eng_id,
                "test_id": test_id,
                "errors": []
            }
        except Exception as e:
            err_msg = str(e)
            save_fail_status(err_msg)
            return {
                "success": False,
                "pushed": 0,
                "engagement_id": eng_id,
                "errors": [err_msg]
            }
