from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class ScanCreateRequest(BaseModel):
    repo_path: str = Field(..., description="Local path or Git repository URL to scan")
    scan_mode: str = Field("AUTO", description="AUTO, FULL_SCAN, or DIFF_SCAN")
    cpg_name: Optional[str] = Field("cpg.bin", description="CPG filename (e.g. cpg.bin)")
    output: Optional[str] = Field(None, description="Output filename. If not provided, it will be auto-generated")
    verbose: Optional[bool] = False
    revalidate: Optional[bool] = False

class ScanStatusResponse(BaseModel):
    scan_id: str
    repo: str
    status: str  # queued, running, completed, failed
    stage: str   # QUEUED, PREPARING, CPG_BUILD, SCANNING, CHAIN_DETECTION, DEDUPLICATION, LLM_VALIDATION, COMPLETED, FAILED
    progress: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    finding_count: Optional[int] = 0
    error: Optional[str] = None
