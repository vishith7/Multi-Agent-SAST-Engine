from fastapi import APIRouter
from typing import List, Dict, Any
from web.backend.services.repository_service import RepositoryService

router = APIRouter(prefix="/repositories", tags=["repositories"])

@router.get("", response_model=List[Dict[str, Any]])
def list_repositories():
    return RepositoryService.get_all_repositories()
