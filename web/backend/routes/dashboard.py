from fastapi import APIRouter
from typing import Dict, Any
from web.backend.services.result_service import ResultService
from web.backend.services.finding_service import FindingService
from web.backend.services.repository_service import RepositoryService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

@router.get("/summary", response_model=Dict[str, Any])
def get_dashboard_summary():
    scans = ResultService.get_all_scans()
    total_scans = len(scans)
    
    # Identify latest scan for each repository
    repos = RepositoryService.get_all_repositories()
    
    severity_stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    verdict_stats = {"VALID": 0, "NEEDS_REVIEW": 0, "FALSE_POSITIVE": 0}
    sla_stats = {"overdue": 0, "approaching": 0, "on-track": 0}
    total_findings = 0
    
    # Gather findings from the latest scans of each repo
    for repo in repos:
        # Get scan id for the last scan
        # We can find all findings for this repo in FindingService
        findings = FindingService.get_all_findings(repo=repo["name"])
        
        # Deduplicate findings by fingerprint to get unique active findings in this repo
        repo_findings_map = {}
        for f in findings:
            fp = f.get("fingerprint")
            if fp:
                # If we have duplicates, keep the latest one (FindingService returns them in scan order)
                repo_findings_map[fp] = f
                
        for f in repo_findings_map.values():
            total_findings += 1
            
            # Severity
            sev = f.get("severity", "Medium")
            if sev in severity_stats:
                severity_stats[sev] += 1
            else:
                severity_stats["Medium"] += 1
                
            # Verdict
            verdict = f.get("verdict", "NEEDS_REVIEW")
            if verdict in verdict_stats:
                verdict_stats[verdict] += 1
            else:
                verdict_stats["NEEDS_REVIEW"] += 1
                
            # SLA status (only applies to VALID or NEEDS_REVIEW)
            if verdict != "FALSE_POSITIVE":
                sla_status = f.get("sla_status", {}).get("status", "on-track")
                if sla_status in sla_stats:
                    sla_stats[sla_status] += 1
                else:
                    sla_stats["on-track"] += 1
    
    # Get 5 recent scans
    recent_scans = scans[:5]
    
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_stats": severity_stats,
        "verdict_stats": verdict_stats,
        "sla_stats": sla_stats,
        "recent_scans": recent_scans
    }
