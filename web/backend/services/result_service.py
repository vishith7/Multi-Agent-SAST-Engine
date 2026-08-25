import os
import sys
import json
import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

# Setup sys.path for importing from sast-engine
from web.backend.utils.paths import SCAN_HISTORY_DIR, SAST_ENGINE_DIR, WORKSPACE_ROOT
sys.path.append(str(SAST_ENGINE_DIR))
sys.path.append(str(WORKSPACE_ROOT))

from risk.priority_policy import determine_severity

class ResultService:
    @staticmethod
    def get_all_scans() -> List[Dict[str, Any]]:
        from web.backend.utils.mongo import get_mongo_db
        db = get_mongo_db()
        if db is not None:
            try:
                scans_cursor = db.scans.find({}, {"_id": 0}).sort("timestamp", -1)
                return list(scans_cursor)
            except Exception as e:
                print(f"[MongoDB] Failed to fetch scans from MongoDB: {e}. Falling back to FS.")

        scans = []
        if not SCAN_HISTORY_DIR.exists():
            return scans

        for file in SCAN_HISTORY_DIR.iterdir():
            if file.suffix == ".json" and file.name != "previous_scan_manifest.json":
                scan_id = file.stem
                try:
                    mtime = file.stat().st_mtime
                    with open(file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    metadata = data.get("scan_metadata", {})
                    findings = data.get("findings", [])
                    
                    scans.append({
                        "scan_id": scan_id,
                        "repo": metadata.get("repo", "unknown"),
                        "timestamp": metadata.get("timestamp", datetime.datetime.fromtimestamp(mtime).isoformat()),
                        "raw_findings": metadata.get("raw_findings", len(findings)),
                        "unique_findings": metadata.get("unique_findings", len(findings)),
                        "status": "completed",
                        "scan_type": metadata.get("scan_type", "full"),
                        "findings_count": len(findings)
                    })
                except Exception as e:
                    # Safe fallbacks if json is corrupt or empty
                    scans.append({
                        "scan_id": scan_id,
                        "repo": "corrupt_scan",
                        "timestamp": datetime.datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                        "raw_findings": 0,
                        "unique_findings": 0,
                        "status": "failed",
                        "scan_type": "unknown",
                        "findings_count": 0,
                        "error": str(e)
                    })
        
        # Sort by timestamp newest first
        scans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return scans

    @staticmethod
    def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
        from web.backend.utils.mongo import get_mongo_db
        db = get_mongo_db()
        
        data = None
        if db is not None:
            try:
                scan_record = db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
                if scan_record:
                    findings_cursor = db.findings.find({"scan_id": scan_id}, {"_id": 0})
                    findings = list(findings_cursor)
                    data = {
                        "scan_metadata": scan_record.get("scan_metadata", scan_record),
                        "findings": findings
                    }
            except Exception as e:
                print(f"[MongoDB] Failed to fetch scan details: {e}. Falling back to FS.")

        if data is None:
            file_path = SCAN_HISTORY_DIR / f"{scan_id}.json"
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    return None

        if not data:
            return None

        # Clean scan_metadata
        if "scan_metadata" not in data:
            data["scan_metadata"] = {}
        
        metadata = data["scan_metadata"]
        if "timestamp" not in metadata:
            try:
                metadata["timestamp"] = datetime.datetime.fromtimestamp((SCAN_HISTORY_DIR / f"{scan_id}.json").stat().st_mtime).isoformat()
            except Exception:
                metadata["timestamp"] = datetime.datetime.now().isoformat()
        
        # Sync scan finding statuses dynamically from DefectDojo
        data = ResultService.sync_scan_with_defectdojo(scan_id, data)
        
        findings = data.get("findings", [])
        for finding in findings:
            if "severity" not in finding:
                finding["severity"] = determine_severity(finding)
            # Decorate with read-only SLA details derived from DefectDojo
            finding["sla_status"] = ResultService.map_defectdojo_sla(finding)
            
        return data

    @staticmethod
    def delete_scan(scan_id: str) -> bool:
        from web.backend.utils.mongo import get_mongo_db
        db = get_mongo_db()
        db_success = False
        if db is not None:
            try:
                db.scans.delete_one({"scan_id": scan_id})
                db.findings.delete_many({"scan_id": scan_id})
                db_success = True
            except Exception as e:
                print(f"[MongoDB] Failed to delete scan {scan_id}: {e}")

        file_path = SCAN_HISTORY_DIR / f"{scan_id}.json"
        fs_success = False
        if file_path.exists():
            try:
                os.remove(file_path)
                fs_success = True
            except Exception as e:
                print(f"[ResultService] Failed to delete filesystem JSON {file_path}: {e}")

        return db_success or fs_success

    @staticmethod
    def save_scan(scan_id: str, scan_data: Dict[str, Any]) -> bool:
        file_path = SCAN_HISTORY_DIR / f"{scan_id}.json"
        fs_success = False
        try:
            # First write to tmp file then rename for atomic save
            tmp_path = file_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(scan_data, f, indent=2)
            os.replace(tmp_path, file_path)
            fs_success = True
        except Exception as e:
            print(f"[ResultService] Failed to save filesystem JSON: {e}")

        # Save to MongoDB
        from web.backend.utils.mongo import get_mongo_db
        db = get_mongo_db()
        if db is not None:
            try:
                metadata = scan_data.get("scan_metadata", {})
                findings = scan_data.get("findings", [])
                
                # Make sure timestamp is in ISO format
                timestamp_str = metadata.get("timestamp")
                if timestamp_str:
                    try:
                        timestamp_str = datetime.datetime.fromisoformat(timestamp_str).isoformat()
                    except ValueError:
                        pass
                if not timestamp_str:
                    timestamp_str = datetime.datetime.now().isoformat()
                
                scan_record = {
                    "scan_id": scan_id,
                    "repo": metadata.get("repo", "unknown"),
                    "timestamp": timestamp_str,
                    "raw_findings": metadata.get("raw_findings", len(findings)),
                    "unique_findings": metadata.get("unique_findings", len(findings)),
                    "status": "completed",
                    "scan_type": metadata.get("scan_type", "full"),
                    "findings_count": len(findings),
                    "scan_metadata": metadata
                }
                db.scans.update_one({"scan_id": scan_id}, {"$set": scan_record}, upsert=True)
                
                # Update findings
                db.findings.delete_many({"scan_id": scan_id})
                if findings:
                    findings_to_insert = []
                    for f in findings:
                        f_copy = f.copy()
                        f_copy["scan_id"] = scan_id
                        f_copy["repo"] = metadata.get("repo", "unknown")
                        
                        if "severity" not in f_copy:
                            f_copy["severity"] = determine_severity(f_copy)
                            
                        # Add calculated SLA status derived dynamically
                        f_copy["sla_status"] = ResultService.map_defectdojo_sla(f_copy)
                        
                        f_copy.pop("_id", None)
                        findings_to_insert.append(f_copy)
                        
                    db.findings.insert_many(findings_to_insert)
            except Exception as e:
                print(f"[MongoDB] Failed to write scan to MongoDB: {e}")
                
        return fs_success

    @staticmethod
    def map_defectdojo_sla(f: Dict[str, Any]) -> Dict[str, Any]:
        status = f.get("defectdojo_status")
        sla_status = f.get("defectdojo_sla_status")
        deadline = f.get("defectdojo_sla_deadline")
        
        if status in ("False Positive", "Closed"):
            return {
                "status": "remediated",
                "days_remaining": None,
                "overdue": False,
                "approaching": False,
                "deadline": deadline
            }
            
        if not deadline:
            return {
                "status": "unknown",
                "days_remaining": None,
                "overdue": False,
                "approaching": False,
                "deadline": None
            }
            
        try:
            # We compare the date strings
            # DefectDojo expiration dates are in YYYY-MM-DD
            due_date = datetime.date.fromisoformat(deadline)
            today = datetime.date.today()
            delta = due_date - today
            days_remaining = delta.days
            
            overdue = days_remaining < 0
            approaching = 0 <= days_remaining <= 3
            
            status_str = "overdue" if overdue else ("approaching" if approaching else "on-track")
            if sla_status == "breached" or overdue:
                status_str = "overdue"
                
            return {
                "status": status_str,
                "days_remaining": days_remaining,
                "overdue": overdue,
                "approaching": approaching,
                "deadline": deadline
            }
        except Exception:
            return {
                "status": "unknown",
                "days_remaining": None,
                "overdue": False,
                "approaching": False,
                "deadline": deadline
            }

    @staticmethod
    def sync_scan_with_defectdojo(scan_id: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        metadata = scan_data.get("scan_metadata", {})
        engagement_id = metadata.get("defectdojo_engagement_id")
        
        if not engagement_id:
            return scan_data
            
        from integrations.defectdojo.client import DefectDojoClient
        client = DefectDojoClient()
        if not client.is_configured():
            return scan_data
            
        try:
            status_map = client.get_findings_status_map(int(engagement_id))
            if not status_map:
                return scan_data
                
            findings = scan_data.get("findings", [])
            updated = False
            for f in findings:
                fp = f.get("fingerprint")
                if fp in status_map:
                    info = status_map[fp]
                    for k, v in info.items():
                        if f.get(k) != v:
                            f[k] = v
                            updated = True
                            
                    # Update verdict if False Positive in DefectDojo
                    if info.get("defectdojo_status") == "False Positive" and f.get("verdict") != "FALSE_POSITIVE":
                         f["verdict"] = "FALSE_POSITIVE"
                         updated = True
                         
            if updated:
                # Save the updated scan back
                file_path = SCAN_HISTORY_DIR / f"{scan_id}.json"
                try:
                    tmp_path = file_path.with_suffix(".tmp")
                    with open(tmp_path, "w", encoding="utf-8") as f_out:
                        json.dump(scan_data, f_out, indent=2)
                    os.replace(tmp_path, file_path)
                    
                    # Update MongoDB findings collections directly
                    from web.backend.utils.mongo import get_mongo_db
                    db = get_mongo_db()
                    if db is not None:
                        for f in findings:
                            db.findings.update_many(
                                {"scan_id": scan_id, "fingerprint": f.get("fingerprint")},
                                {"$set": {
                                    "defectdojo_id": f.get("defectdojo_id"),
                                    "defectdojo_url": f.get("defectdojo_url"),
                                    "defectdojo_status": f.get("defectdojo_status"),
                                    "defectdojo_sla_status": f.get("defectdojo_sla_status"),
                                    "defectdojo_sla_deadline": f.get("defectdojo_sla_deadline"),
                                    "verdict": f.get("verdict")
                                }}
                            )
                except Exception as e:
                    print(f"[ResultService] Failed to save updated scan JSON during sync: {e}")
        except Exception as e:
            print(f"[DefectDojo] Failed to sync scan status: {e}")
            
        return scan_data
