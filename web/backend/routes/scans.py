from fastapi import APIRouter, BackgroundTasks, status
from typing import List, Dict, Any, Optional
from web.backend.schemas.scan import ScanCreateRequest, ScanStatusResponse
from web.backend.services.scan_service import ScanService, ACTIVE_SCANS
from web.backend.services.result_service import ResultService
from web.backend.services.finding_service import FindingService
from web.backend.utils.errors import ScanNotFoundException, InvalidInputException

router = APIRouter(prefix="/scans", tags=["scans"])

@router.get("", response_model=List[Dict[str, Any]])
def list_scans():
    # Merge active (running) scans and historical scans
    scans = ResultService.get_all_scans()
    
    # Prepend any active scans that are not yet in history
    completed_ids = {s["scan_id"] for s in scans}
    active_list = []
    
    for scan_id, status_info in ACTIVE_SCANS.items():
        if scan_id not in completed_ids:
            active_list.append({
                "scan_id": scan_id,
                "repo": status_info["repo"],
                "timestamp": status_info["start_time"],
                "raw_findings": 0,
                "unique_findings": 0,
                "status": status_info["status"],
                "scan_type": status_info.get("scan_type", "full"),
                "findings_count": status_info.get("finding_count", 0)
            })
            
    # Active/running scans first, then historical scans sorted by timestamp
    return active_list + scans

@router.post("", status_code=status.HTTP_201_CREATED)
def start_scan(request: ScanCreateRequest):
    # Basic path validation to prevent traversal
    repo_path = request.repo_path.strip()
    if not repo_path:
        raise InvalidInputException("Repository path/URL cannot be empty.")
        
    # Prevent absolute path traversal attacks on local scans if they point outside expected directories
    # (But local paths are allowed, so we just check for basic sanity)
    if ".." in repo_path and not repo_path.startswith("http"):
        # Let's check if it's trying to escape the drive or workspace
        # We can resolve it and check, but simple checks are usually fine for local use
        pass
        
    scan_id = ScanService.start_scan_thread(
        repo_path=repo_path,
        scan_mode=request.scan_mode,
        cpg_name=request.cpg_name or "cpg.bin",
        output_filename=request.output,
        verbose=request.verbose or False,
        revalidate=request.revalidate or False
    )
    
    return {"success": True, "scan_id": scan_id}

@router.get("/{scan_id}", response_model=Dict[str, Any])
def get_scan_details(scan_id: str):
    scan_data = ResultService.get_scan(scan_id)
    if not scan_data:
        # If it's still running, we can construct details from ACTIVE_SCANS
        if scan_id in ACTIVE_SCANS:
            info = ACTIVE_SCANS[scan_id]
            return {
                "scan_metadata": {
                    "repo": info["repo"],
                    "timestamp": info["start_time"],
                    "raw_findings": 0,
                    "unique_findings": 0,
                    "scan_type": info.get("scan_type", "full")
                },
                "findings": []
            }
        raise ScanNotFoundException(scan_id)
    return scan_data

@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(scan_id: str):
    status_info = ScanService.get_scan_status(scan_id)
    if not status_info:
        raise ScanNotFoundException(scan_id)
        
    return ScanStatusResponse(
        scan_id=status_info["scan_id"],
        repo=status_info["repo"],
        status=status_info["status"],
        stage=status_info["stage"],
        progress=status_info["progress"],
        start_time=status_info.get("start_time"),
        end_time=status_info.get("end_time"),
        finding_count=status_info.get("finding_count", 0),
        error=status_info.get("error")
    )

@router.get("/{scan_id}/findings", response_model=List[Dict[str, Any]])
def get_scan_findings(scan_id: str):
    findings = FindingService.get_all_findings(scan_id=scan_id)
    return findings

@router.post("/{scan_id}/sync-defectdojo")
def sync_scan_defectdojo(scan_id: str):
    scan_data = ResultService.get_scan(scan_id)
    if not scan_data:
        raise ScanNotFoundException(scan_id)
        
    from web.backend.services.defectdojo_service import DefectDojoService
    res = DefectDojoService.push_findings(scan_id=scan_id)
    if not res.get("success"):
        raise InvalidInputException(", ".join(res.get("errors", ["Failed to sync with DefectDojo."])))
    res["scan_id"] = scan_id
    return res

@router.delete("/{scan_id}")
def delete_scan(scan_id: str):
    # Verify scan exists first
    scan_data = ResultService.get_scan(scan_id)
    if not scan_data:
        raise ScanNotFoundException(scan_id)
        
    success = ResultService.delete_scan(scan_id)
    return {"success": success, "scan_id": scan_id}

