from fastapi import APIRouter
from typing import Dict, Any, Optional
from web.backend.schemas.finding import DefectDojoPushRequest, DefectDojoSaveConfigRequest
from web.backend.services.defectdojo_service import DefectDojoService

router = APIRouter(prefix="/defectdojo", tags=["defectdojo"])

@router.get("/config", response_model=Dict[str, Any])
def get_defectdojo_config():
    return DefectDojoService.get_config()

@router.post("/config", response_model=Dict[str, Any])
def save_defectdojo_config(request: DefectDojoSaveConfigRequest):
    return DefectDojoService.save_config(
        url=request.url,
        token=request.token,
        engagement_id=request.engagement_id,
        organization=request.organization,
        default_engagement=request.default_engagement
    )

@router.post("/push", response_model=Dict[str, Any])
def push_findings(request: DefectDojoPushRequest):
    return DefectDojoService.push_findings(
        fingerprint=request.fingerprint,
        custom_url=request.url,
        custom_token=request.token,
        custom_engagement_id=request.engagement_id
    )

