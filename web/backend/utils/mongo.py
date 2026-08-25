import os
import pymongo
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure

_mongo_client = None
_db = None
_enabled = False

def get_mongo_db():
    global _mongo_client, _db, _enabled
    if _db is not None:
        return _db if _enabled else None
        
    uri = os.environ.get("MONGODB_URI")
    if not uri or "<db_password>" in uri:
        # MongoDB is not configured or still has the placeholder password
        _enabled = False
        return None
        
    try:
        # Enforce 2-second timeout to avoid hanging FastAPI startup
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=2000)
        # Force a connection test via ping command
        client.admin.command('ping')
        _mongo_client = client
        _db = client.get_default_database()
        _enabled = True
        print("[MongoDB] Connected successfully to Atlas cluster!")
        
        # Setup indexes for speed
        _db.scans.create_index("scan_id", unique=True)
        _db.findings.create_index("fingerprint")
        _db.findings.create_index("scan_id")
        _db.findings.create_index("category")
        _db.findings.create_index("verdict")
        _db.findings.create_index("repo")
        
        return _db
    except (ServerSelectionTimeoutError, ConnectionFailure) as e:
        print(f"[MongoDB] Connection failed: {e}. Falling back to filesystem storage.")
        _enabled = False
        return None
    except Exception as e:
        print(f"[MongoDB] Error initializing database: {e}. Falling back to filesystem storage.")
        _enabled = False
        return None

def sync_filesystem_to_mongo():
    from web.backend.utils.paths import SCAN_HISTORY_DIR
    from web.backend.services.result_service import ResultService
    import json
    
    db = get_mongo_db()
    if db is None:
        return
        
    try:
        json_files = []
        if SCAN_HISTORY_DIR.exists():
            json_files = [f for f in SCAN_HISTORY_DIR.iterdir() if f.suffix == ".json" and f.name != "previous_scan_manifest.json"]
            
        mongo_scans_count = db.scans.count_documents({})
        if mongo_scans_count < len(json_files):
            print(f"[MongoDB] Syncing {len(json_files)} filesystem scans to MongoDB...")
            for file in json_files:
                scan_id = file.stem
                if db.scans.count_documents({"scan_id": scan_id}) == 0:
                    try:
                        with open(file, "r", encoding="utf-8") as f:
                            scan_data = json.load(f)
                        ResultService.save_scan(scan_id, scan_data)
                    except Exception as e:
                        print(f"[MongoDB] Failed to sync scan {scan_id}: {e}")
            print("[MongoDB] Sync completed successfully.")
    except Exception as e:
        print(f"[MongoDB] Error during filesystem-to-mongo sync: {e}")

