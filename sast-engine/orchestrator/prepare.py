import os
import subprocess
import tempfile
import json
import time
import shutil
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from state import get_last_scanned_commit, set_last_scanned_commit

def build_full_cpg(repo_path, output_path, heap_size="8g"):
    print(f"Building full CPG for {repo_path} to {output_path}")
    env = os.environ.copy()
    if 'JAVA_OPTS' not in env:
        env['JAVA_OPTS'] = f"-Xmx{heap_size}"
    
    try:
        from orchestrator.server import JoernServer
    except ImportError:
        from server import JoernServer
        
    start_time = time.time()
    server = JoernServer()
    success = server.build_cpg(repo_path, output_path)
    
    if success:
        print(f"Full build took {time.time() - start_time:.2f} seconds")
        return True
    else:
        print("Failed to build full CPG via Server.")
        return False

# Delta-scans have been removed as they were unsafe.
# A safe incremental CPG merging feature should be implemented here in the future.

def build_or_update_cpg(repo_path, output_path=None, repo_id=None, heap_size="8g", force_rebuild=False):
    repo_path = os.path.abspath(repo_path)
    if output_path:
        cpg_path = output_path
    else:
        repo_name = os.path.basename(repo_path)
        workspace_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".taintlace", "workspace", repo_name)
        os.makedirs(workspace_dir, exist_ok=True)
        cpg_path = os.path.join(workspace_dir, "cpg.bin")
    
    try:
        from orchestrator.cpg_cache import cpg_cache, get_cache_key
        from orchestrator.server import JoernServer
    except ImportError:
        from cpg_cache import cpg_cache, get_cache_key
        from server import JoernServer
        
    cache_key = get_cache_key(repo_path)
    
    if not force_rebuild:
        cached_bin, cached_meta = cpg_cache.get_cached_cpg(repo_path, cache_key)
        if cached_bin and cached_meta:
            import datetime
            built_at = datetime.datetime.fromtimestamp(cached_meta.get("built_at_timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
            print(f"Using cached CPG for commit {cache_key[:8]} (built {built_at} ago).")
            # Load the cached CPG into JoernServer?
            # Actually, the file is at cached_bin. We can just copy it to cpg_path, or tell Joern to use cached_bin.
            # Easiest is to copy it to cpg_path so the rest of the pipeline uses it seamlessly.
            if os.path.abspath(cached_bin) != os.path.abspath(cpg_path):
                shutil.copy2(cached_bin, cpg_path)
            return True
            
    print("Building full CPG")
    success = build_full_cpg(repo_path, cpg_path, heap_size)
    if success:
        cpg_cache.save_cpg_to_cache(repo_path, cpg_path, cache_key)
    return success

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        build_or_update_cpg(sys.argv[1])
