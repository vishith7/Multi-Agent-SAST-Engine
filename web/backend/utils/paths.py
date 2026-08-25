import os
from pathlib import Path

# Resolve the workspace root: the directory containing the 'web' folder
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent

SCAN_HISTORY_DIR = WORKSPACE_ROOT / "scan_history"
CLONED_REPOS_DIR = WORKSPACE_ROOT / "cloned_repos"
TAINTLACE_STATE_DIR = WORKSPACE_ROOT / ".taintlace"
SAST_ENGINE_DIR = WORKSPACE_ROOT / "sast-engine"
CONFIG_DIR = SAST_ENGINE_DIR / "config"

def ensure_directories():
    SCAN_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    CLONED_REPOS_DIR.mkdir(parents=True, exist_ok=True)
    TAINTLACE_STATE_DIR.mkdir(parents=True, exist_ok=True)

ensure_directories()
