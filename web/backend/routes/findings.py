from fastapi import APIRouter, Query, status
from typing import List, Dict, Any, Optional
from web.backend.schemas.finding import FindingApprovalRequest
from web.backend.services.finding_service import FindingService
from web.backend.services.defectdojo_service import DefectDojoService
from web.backend.utils.errors import FindingNotFoundException, InvalidInputException

router = APIRouter(prefix="/findings", tags=["findings"])

@router.get("", response_model=List[Dict[str, Any]])
def list_findings(
    category: Optional[str] = Query(None, description="Filter by category"),
    verdict: Optional[str] = Query(None, description="Filter by verdict (VALID, NEEDS_REVIEW, FALSE_POSITIVE)"),
    priority: Optional[str] = Query(None, description="Filter by priority (P1, P2, P3, P4)"),
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low)"),
    repo: Optional[str] = Query(None, description="Filter by repository name"),
    sla_status: Optional[str] = Query(None, description="Filter by SLA status (overdue, approaching, on-track)"),
    scan_id: Optional[str] = Query(None, description="Filter by scan ID")
):
    findings = FindingService.get_all_findings(
        category=category,
        verdict=verdict,
        priority=priority,
        severity=severity,
        repo=repo,
        sla_status=sla_status,
        scan_id=scan_id
    )
    return findings

@router.get("/{fingerprint}", response_model=Dict[str, Any])
def get_finding_details(fingerprint: str):
    finding = FindingService.get_finding_by_fingerprint(fingerprint)
    if not finding:
        raise FindingNotFoundException(fingerprint)
    return finding

@router.post("/{fingerprint}/defectdojo")
def push_finding_defectdojo(fingerprint: str):
    finding = FindingService.get_finding_by_fingerprint(fingerprint)
    if not finding:
        raise FindingNotFoundException(fingerprint)
        
    res = DefectDojoService.push_findings(fingerprint=fingerprint)
    return res

from pydantic import BaseModel

class HumanValidationRequest(BaseModel):
    status: str
    reviewer: Optional[str] = None
    comment: Optional[str] = None

@router.post("/{fingerprint}/human-validation")
def submit_human_validation(fingerprint: str, req: HumanValidationRequest):
    finding = FindingService.get_finding_by_fingerprint(fingerprint)
    if not finding:
        raise FindingNotFoundException(fingerprint)
        
    if req.status.upper() not in ("PENDING", "APPROVED", "REJECTED", "NEEDS_REVIEW"):
        raise InvalidInputException("Invalid validation status")
        
    success = FindingService.update_human_validation(
        fingerprint=fingerprint,
        status=req.status.upper(),
        reviewer=req.reviewer,
        comment=req.comment
    )
    if not success:
        raise InvalidInputException("Failed to update human validation status")
    return {"success": True}

@router.post("/{fingerprint}/apply-fix")
def apply_proposed_fix(fingerprint: str, reviewer: Optional[str] = Query("Admin")):
    res = FindingService.apply_fix(fingerprint, reviewer)
    if not res.get("success"):
        raise InvalidInputException(res.get("error"))
    return res


