import os
import sys
import json
import ssl
import time
import urllib.request
import urllib.parse
import urllib.error
import keyring
from typing import Dict, Any, List, Optional, Tuple

from integrations.defectdojo.finding_mapper import map_finding_to_defectdojo

class DefectDojoClient:
    def __init__(self):
        # Load configuration
        url = keyring.get_password("taintlace_defectdojo", "url") or os.environ.get('DEFECTDOJO_URL') or ""
        token = keyring.get_password("taintlace_defectdojo", "token") or os.environ.get('DEFECTDOJO_API_KEY') or ""
        engagement = keyring.get_password("taintlace_defectdojo", "engagement_id") or os.environ.get('DEFECTDOJO_ENGAGEMENT') or os.environ.get('DEFECTDOJO_ENGAGEMENT_ID') or ""
        
        # New configurable defaults
        organization = os.environ.get('DEFECTDOJO_ORGANIZATION') or "Multi-Agentic SAST Engine"
        default_engagement = os.environ.get('DEFECTDOJO_DEFAULT_ENGAGEMENT') or "Continuous SAST Scanning"
        verify_ssl = os.environ.get('DEFECTDOJO_VERIFY_SSL', 'true').lower() != 'false'

        self.url = url.strip().rstrip('/')
        self.token = token.strip()
        self.engagement_config = engagement.strip()
        self.organization = organization.strip()
        self.default_engagement = default_engagement.strip()
        self.verify_ssl = verify_ssl

        # Initialize SSL context
        self.ssl_context = ssl.create_default_context()
        if not self.verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def is_configured(self) -> bool:
        return bool(self.url and self.token)

    def _request(self, path: str, method: str = "GET", data: Optional[Dict[str, Any]] = None) -> Any:
        if not self.is_configured():
            raise RuntimeError("DefectDojo client is not configured (missing URL or API Key).")

        full_url = f"{self.url}{path}"
        req = urllib.request.Request(full_url, method=method)
        req.add_header("Authorization", f"Token {self.token}")
        req.add_header("Accept", "application/json")

        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, data=body, context=self.ssl_context, timeout=10) as resp:
                content_type = resp.headers.get("Content-Type", "")
                resp_bytes = resp.read()
                
                if "application/json" in content_type:
                    return json.loads(resp_bytes.decode("utf-8"))
                else:
                    # Return parsed raw text or mock response
                    return {"raw_text": resp_bytes.decode("utf-8", errors="ignore")}
        except urllib.error.HTTPError as e:
            content_type = e.headers.get("Content-Type", "")
            try:
                err_bytes = e.read()
                if "application/json" in content_type:
                    err_content = err_bytes.decode("utf-8")
                else:
                    # Summarize non-JSON content
                    raw_err = err_bytes.decode("utf-8", errors="ignore").strip()
                    err_content = raw_err[:200] + "..." if len(raw_err) > 200 else raw_err
            except Exception:
                err_content = "Could not parse response content."
                
            raise RuntimeError(f"DefectDojo API HTTP error {e.code} on {method} {path}: {err_content}")
        except Exception as e:
            raise RuntimeError(f"DefectDojo connection failed on {method} {path}: {e}")

    def validate_credentials(self) -> Tuple[bool, str]:
        """
        Validates DefectDojo credentials by making a lightweight API request.
        Returns (is_valid, status_message).
        """
        if not self.is_configured():
            return False, "NOT CONFIGURED"
            
        try:
            # 1. Test Server & Authentication
            self._request("/api/v2/users/?limit=1")
            
            # 2. Test optional Engagement ID if provided
            if self.engagement_config:
                try:
                    int(self.engagement_config)
                except ValueError:
                    return False, "CONNECTION FAILED: Engagement ID must be an integer."
                
                try:
                    self._request(f"/api/v2/engagements/{self.engagement_config}/")
                except RuntimeError as e:
                    err_msg = str(e)
                    if "404" in err_msg:
                        return False, f"Engagement ID '{self.engagement_config}' was not found."
                    elif "401" in err_msg or "403" in err_msg:
                        return False, "PERMISSION DENIED accessing configured Engagement ID."
                    raise
            
            return True, "CONNECTED"
            
        except RuntimeError as e:
            err_msg = str(e)
            if "401" in err_msg or "403" in err_msg:
                return False, "AUTHENTICATION FAILED"
            elif "404" in err_msg:
                return False, "CONNECTION FAILED"
            else:
                return False, f"CONNECTION FAILED: {err_msg}"
        except Exception as e:
            return False, f"CONNECTION FAILED: {e}"

    def get_or_create_product_type(self) -> int:
        """Resolves the DefectDojo Organization (Product Type)."""
        encoded_name = urllib.parse.quote(self.organization)
        res = self._request(f"/api/v2/product_types/?name={encoded_name}")
        if res.get("results"):
            return res["results"][0]["id"]
            
        # Create
        payload = {
            "name": self.organization,
            "description": "Auto-created by Taintlace SAST."
        }
        res = self._request("/api/v2/product_types/", method="POST", data=payload)
        return res["id"]

    def get_or_create_product(self, product_type_id: int, repo_name: str) -> int:
        """Resolves the DefectDojo Asset (Product)."""
        encoded_name = urllib.parse.quote(repo_name)
        res = self._request(f"/api/v2/products/?name={encoded_name}")
        if res.get("results"):
            return res["results"][0]["id"]

        # Create
        payload = {
            "name": repo_name,
            "description": f"Auto-created by Taintlace SAST for repository {repo_name}.",
            "prod_type": product_type_id
        }
        res = self._request("/api/v2/products/", method="POST", data=payload)
        return res["id"]

    def get_or_create_engagement(self, product_id: int, repo_name: str) -> int:
        """Resolves the DefectDojo Engagement."""
        if self.engagement_config:
            try:
                return int(self.engagement_config)
            except ValueError:
                pass

        encoded_name = urllib.parse.quote(self.default_engagement)
        res = self._request(f"/api/v2/engagements/?product={product_id}&name={encoded_name}&active=true")
        if res.get("results"):
            return res["results"][0]["id"]

        # Create
        today = time.strftime("%Y-%m-%d")
        future_time = time.time() + (30 * 86400)
        end_date = time.strftime("%Y-%m-%d", time.localtime(future_time))
        
        payload = {
            "name": self.default_engagement,
            "product": product_id,
            "target_start": today,
            "target_end": end_date,
            "status": "In Progress",
            "engagement_type": "CI/CD"
        }
        res = self._request("/api/v2/engagements/", method="POST", data=payload)
        return res["id"]

    def create_test(self, engagement_id: int, repo_name: str, scan_id: str) -> int:
        """Creates a Test for the current scan execution."""
        payload = {
            "title": f"Taintlace Scan - {repo_name}",
            "engagement": engagement_id,
            "target_start": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "target_end": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "version": scan_id,
            "status": "Completed"
        }
        
        # Try to find a valid test type
        try:
            res_types = self._request("/api/v2/test_types/?limit=1")
            if res_types.get("results"):
                payload["test_type"] = res_types["results"][0]["id"]
            else:
                payload["test_type"] = 1
        except Exception as e:
            print(f"[DefectDojo] Warning: Could not fetch test_types, using default 1. {e}")
            payload["test_type"] = 1
            
        # Try to find a valid environment
        try:
            res_env = self._request("/api/v2/environments/?limit=1")
            if res_env.get("results"):
                payload["environment"] = res_env["results"][0]["id"]
        except Exception as e:
            print(f"[DefectDojo] Warning: Could not fetch environments. {e}")
            
        res = self._request("/api/v2/tests/", method="POST", data=payload)
        return res["id"]

    def push_findings(self, test_id: int, findings: List[Dict[str, Any]], repo_name: str) -> List[Dict[str, Any]]:
        pushed_findings = []
        
        # Find the engagement_id from the test_id to get existing findings
        engagement_id = None
        test_type_id = 1
        try:
            test_info = self._request(f"/api/v2/tests/{test_id}/")
            engagement_id = test_info.get("engagement")
            test_type_id = test_info.get("test_type", 1)
        except Exception:
            pass

        existing_map = {}
        if engagement_id:
            try:
                res = self._request(f"/api/v2/findings/?engagement={engagement_id}&limit=1000")
                for f_dojo in res.get("results", []):
                    uid = f_dojo.get("unique_id_from_tool")
                    if uid:
                        existing_map[uid] = f_dojo
                    elif f_dojo.get("vuln_id_from_tool") and len(f_dojo.get("vuln_id_from_tool")) == 64:
                        # Fallback for older scans storing fingerprint in vuln_id_from_tool
                        existing_map[f_dojo.get("vuln_id_from_tool")] = f_dojo
            except Exception as e:
                print(f"[DefectDojo] Warning: Failed to query existing findings: {e}")

        for f in findings:
            fp = f.get("fingerprint")
            if not fp:
                continue

            try:
                payload = map_finding_to_defectdojo(f)
            except ValueError as e:
                print(f"[DefectDojo] Skipping finding: {e}")
                continue

            payload["test"] = test_id
            payload["found_by"] = [test_type_id]

            f_dojo = existing_map.get(fp)
            if f_dojo:
                finding_id = f_dojo["id"]
                try:
                    res_update = self._request(f"/api/v2/findings/{finding_id}/", method="PATCH", data=payload)
                    f["defectdojo_id"] = res_update["id"]
                    f["defectdojo_url"] = f"{self.url}/finding/{res_update['id']}"
                    f["defectdojo_status"] = self._resolve_status(res_update)
                    f["defectdojo_sla_status"] = res_update.get("sla_status", "active")
                    f["defectdojo_sla_deadline"] = res_update.get("sla_expiration_date")
                except Exception as e:
                    print(f"[DefectDojo] Failed to update finding {finding_id}: {e}")
            else:
                try:
                    res_create = self._request("/api/v2/findings/", method="POST", data=payload)
                    f["defectdojo_id"] = res_create["id"]
                    f["defectdojo_url"] = f"{self.url}/finding/{res_create['id']}"
                    f["defectdojo_status"] = self._resolve_status(res_create)
                    f["defectdojo_sla_status"] = res_create.get("sla_status", "active")
                    f["defectdojo_sla_deadline"] = res_create.get("sla_expiration_date")
                except Exception as e:
                    print(f"[DefectDojo] Failed to create finding: {e}")

            pushed_findings.append(f)
        return pushed_findings

    def get_findings_status_map(self, engagement_id: int) -> Dict[str, Dict[str, Any]]:
        status_map = {}
        try:
            res = self._request(f"/api/v2/findings/?engagement={engagement_id}&limit=1000")
            for f in res.get("results", []):
                fp = f.get("vuln_id_from_tool")
                if fp:
                    status_map[fp] = {
                        "defectdojo_id": f["id"],
                        "defectdojo_url": f"{self.url}/finding/{f['id']}",
                        "defectdojo_status": self._resolve_status(f),
                        "defectdojo_sla_status": f.get("sla_status", "active"),
                        "defectdojo_sla_deadline": f.get("sla_expiration_date")
                    }
        except Exception as e:
            print(f"[DefectDojo] Failed to query engagement findings status: {e}")
        return status_map

    def _resolve_status(self, f: Dict[str, Any]) -> str:
        if f.get("false_p") or f.get("duplicate") or f.get("out_of_scope"):
            return "False Positive"
        elif f.get("verified"):
            return "Verified"
        elif not f.get("active"):
            return "Closed"
        else:
            return "Awaiting Verification"
