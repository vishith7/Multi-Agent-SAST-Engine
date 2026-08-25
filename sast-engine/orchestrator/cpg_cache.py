import os
import subprocess
import hashlib
import json
import shutil
import time

def hash_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def hash_tree(directory):
    h = hashlib.sha256()
    for root, dirs, files in os.walk(directory):
        # Exclude common ignores to speed up
        dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor', '.venv', '__pycache__']]
        for file in sorted(files):
            filepath = os.path.join(root, file)
            h.update(file.encode('utf-8'))
            try:
                h.update(hash_file(filepath).encode('utf-8'))
            except Exception:
                pass
    return h.hexdigest()

def get_cache_key(repo_path):
    repo_path = os.path.abspath(repo_path)
    git_dir = os.path.join(repo_path, ".git")
    
    if os.path.exists(git_dir):
        try:
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_path, text=True, stderr=subprocess.DEVNULL).strip()
            status = subprocess.check_output(["git", "status", "--porcelain"], cwd=repo_path, text=True, stderr=subprocess.DEVNULL).strip()
            if status:
                # Working tree is dirty, append diff hash
                diff = subprocess.check_output(["git", "diff", "HEAD"], cwd=repo_path, text=True, stderr=subprocess.DEVNULL)
                diff_hash = hashlib.sha256(diff.encode('utf-8')).hexdigest()[:8]
                return f"{head}_{diff_hash}"
            else:
                return head
        except subprocess.CalledProcessError:
            return hash_tree(repo_path)
    else:
        return hash_tree(repo_path)

class CPGCache:
    def __init__(self, max_entries=5):
        self.max_entries = max_entries
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.cache_dir = os.path.join(base_dir, ".taintlace", "cpg_cache")
        
    def _repo_cache_dir(self, repo_path):
        repo_name = os.path.basename(os.path.abspath(repo_path))
        return os.path.join(self.cache_dir, repo_name)
        
    def get_cached_cpg(self, repo_path, cache_key=None):
        if not cache_key:
            cache_key = get_cache_key(repo_path)
            
        repo_dir = self._repo_cache_dir(repo_path)
        bin_path = os.path.join(repo_dir, f"{cache_key}.bin")
        meta_path = os.path.join(repo_dir, f"{cache_key}.meta.json")
        
        if os.path.exists(bin_path) and os.path.exists(meta_path):
            with open(meta_path, "r") as f:
                meta = json.load(f)
                
            # Update access time (mtime) for LRU eviction
            os.utime(bin_path, None)
            os.utime(meta_path, None)
            return bin_path, meta
            
        return None, None
        
    def save_cpg_to_cache(self, repo_path, built_cpg_path, cache_key=None):
        if not cache_key:
            cache_key = get_cache_key(repo_path)
            
        repo_dir = self._repo_cache_dir(repo_path)
        os.makedirs(repo_dir, exist_ok=True)
        
        bin_path = os.path.join(repo_dir, f"{cache_key}.bin")
        meta_path = os.path.join(repo_dir, f"{cache_key}.meta.json")
        
        try:
            shutil.copy2(built_cpg_path, bin_path)
            meta = {
                "repo_path": os.path.abspath(repo_path),
                "cache_key": cache_key,
                "built_at_timestamp": time.time(),
                "joern_version": "unknown"
            }
            with open(meta_path, "w") as f:
                json.dump(meta, f)
                
            self._evict(repo_dir)
            return True
        except Exception as e:
            print(f"Failed to save CPG to cache: {e}")
            return False
            
    def _evict(self, repo_dir):
        # LRU eviction
        files = [f for f in os.listdir(repo_dir) if f.endswith(".bin")]
        if len(files) > self.max_entries:
            files_with_mtime = []
            for f in files:
                p = os.path.join(repo_dir, f)
                files_with_mtime.append((p, os.path.getmtime(p)))
                
            files_with_mtime.sort(key=lambda x: x[1])
            
            # Remove oldest
            for to_remove, _ in files_with_mtime[:-self.max_entries]:
                try:
                    os.remove(to_remove)
                    meta = to_remove.replace(".bin", ".meta.json")
                    if os.path.exists(meta):
                        os.remove(meta)
                except Exception:
                    pass
                    
    def clear(self):
        if os.path.exists(self.cache_dir):
            shutil.rmtree(self.cache_dir)
            
cpg_cache = CPGCache()
