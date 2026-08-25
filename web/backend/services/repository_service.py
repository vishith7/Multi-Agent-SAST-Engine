import os
from typing import List, Dict, Any
from web.backend.services.result_service import ResultService
from web.backend.utils.paths import CLONED_REPOS_DIR

class RepositoryService:
    @staticmethod
    def get_all_repositories() -> List[Dict[str, Any]]:
        scans = ResultService.get_all_scans()
        repos_map = {}
        
        for scan in scans:
            repo_name = scan.get("repo", "unknown")
            if repo_name == "corrupt_scan" or repo_name == "unknown":
                continue
                
            timestamp = scan.get("timestamp")
            
            # If we already have a record, only update if this scan is newer
            if repo_name in repos_map:
                existing = repos_map[repo_name]
                if timestamp > existing["last_scan"]:
                    existing["last_scan"] = timestamp
                    existing["last_scan_type"] = scan.get("scan_type", "full")
                    existing["finding_count"] = scan.get("findings_count", 0)
                    existing["last_status"] = scan.get("status", "completed")
            else:
                # Attempt to determine path/URL
                # Check cloned_repos recursively for a folder with repo_name
                path_or_url = f"./workspace/{repo_name}"  # Default fallback
                
                # Check cloned_repos
                found_path = False
                if CLONED_REPOS_DIR.exists():
                    for owner_dir in CLONED_REPOS_DIR.iterdir():
                        if owner_dir.is_dir():
                            repo_dir = owner_dir / repo_name
                            if repo_dir.exists():
                                path_or_url = str(repo_dir)
                                found_path = True
                                break
                
                repos_map[repo_name] = {
                    "name": repo_name,
                    "path_or_url": path_or_url,
                    "last_scan": timestamp,
                    "last_scan_type": scan.get("scan_type", "full"),
                    "finding_count": scan.get("findings_count", 0),
                    "last_status": scan.get("status", "completed")
                }
                
        return list(repos_map.values())
