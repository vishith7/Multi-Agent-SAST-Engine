from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict

class FindingApprovalRequest(BaseModel):
    state: str = Field(..., description="APPROVED or REJECTED")

class DefectDojoPushRequest(BaseModel):
    fingerprint: Optional[str] = Field(None, description="Fingerprint of the finding to push. If None, push all approved.")
    url: Optional[str] = None
    token: Optional[str] = None
    engagement_id: Optional[str] = None

class DefectDojoSaveConfigRequest(BaseModel):
    url: str = Field(..., description="DefectDojo Server URL")
    token: Optional[str] = Field(None, description="DefectDojo API Token. If not provided, retains the existing token.")
    engagement_id: Optional[str] = Field("", description="DefectDojo Engagement ID")
    organization: Optional[str] = Field("", description="DefectDojo Organization")
    default_engagement: Optional[str] = Field("", description="DefectDojo Default Engagement")

