import os
import json
import time
import shutil

class CascadeCache:
    def __init__(self, staleness_days=30):
        self.staleness_days = staleness_days
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.cache_dir = os.path.join(base_dir, ".taintlace", "cascade_cache")
        
    def get_cached_verdict(self, fingerprint, context_hash=None):
        if not fingerprint:
            return None
            
        cache_path = os.path.join(self.cache_dir, f"{fingerprint}.json")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r") as f:
                    data = json.load(f)
                    
                # Strict Context Hash Enforcement
                cached_ctx = data.get("context_hash")
                if context_hash and cached_ctx != context_hash:
                    return None
                    
                # Check staleness
                validated_at = data.get("validated_at_timestamp", 0)
                age_days = (time.time() - validated_at) / (24 * 3600)
                
                if age_days > self.staleness_days:
                    # Stale
                    return None
                    
                return data
            except Exception:
                return None
                
        return None
        
    def save_cached_verdict(self, fingerprint, data):
        if not fingerprint:
            return
            
        os.makedirs(self.cache_dir, exist_ok=True)
        cache_path = os.path.join(self.cache_dir, f"{fingerprint}.json")
        
        # Add timestamp if not present
        if "validated_at_timestamp" not in data:
            data["validated_at_timestamp"] = time.time()
            
        try:
            with open(cache_path, "w") as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Failed to save cascade cache: {e}")
            
    def clear(self):
        if os.path.exists(self.cache_dir):
            shutil.rmtree(self.cache_dir)

cascade_cache = CascadeCache()
