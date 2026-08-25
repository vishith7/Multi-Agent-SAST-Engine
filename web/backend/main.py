import os
import sys
import shutil
from pathlib import Path
from dotenv import load_dotenv

# Resolve workspace root and load .env
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
env_path = WORKSPACE_ROOT / ".env"
load_dotenv(env_path, override=True)

# Add sast-engine to python path
sys.path.append(os.path.abspath(os.path.join(str(WORKSPACE_ROOT), "sast-engine")))
sys.path.append(str(WORKSPACE_ROOT))

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from web.backend.routes import dashboard, scans, findings, repositories, defectdojo
from web.backend.utils.errors import TaintlaceAPIException

app = FastAPI(
    title="Taintlace Web UI",
    description="REST API interface for Taintlace Agentic SAST Engine",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    from web.backend.utils.mongo import sync_filesystem_to_mongo
    sync_filesystem_to_mongo()

# Custom exception handling for unified Taintlace error format
@app.exception_handler(TaintlaceAPIException)
async def taintlace_api_exception_handler(request: Request, exc: TaintlaceAPIException):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    msg = errors[0]["msg"] if errors else "Validation error"
    loc = " -> ".join(str(x) for x in errors[0]["loc"]) if errors else ""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "error": {
                "code": "VALIDATION_ERROR",
                "message": f"{msg} at {loc}" if loc else msg
            }
        }
    )

# Include API routers
app.include_router(dashboard.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(repositories.router, prefix="/api")
app.include_router(defectdojo.router, prefix="/api")

# API Health Endpoint
@app.get("/api/health")
def get_health():
    # Check if joern and joern-parse are in the system path
    joern_available = bool(shutil.which("joern") or shutil.which("joern.bat"))
    joern_parse_available = bool(shutil.which("joern-parse") or shutil.which("joern-parse.bat"))
    
    engine_status = "available" if (joern_available and joern_parse_available) else "limited"
    
    return {
        "status": "ok",
        "service": "taintlace-web",
        "engine": engine_status,
        "joern_found": joern_available,
        "joern_parse_found": joern_parse_available
    }

# Serve frontend static files
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="static")
else:
    print(f"Warning: Frontend static directory not found at {frontend_dir}")
