import os
import json
import urllib.request
import urllib.error
import urllib.parse
import time
from typing import Dict, Any, List, Optional

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".taintlace", "intel_cache")
CISA_KEV_CACHE_FILE = os.path.join(CACHE_DIR, "cisa_kev.json")
CACHE_TTL = 86400  # 24 hours

def _fetch_with_timeout(url: str, timeout: float = 2.0) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Taintlace SAST Engine/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except Exception as e:
        print(f"[SecurityIntel] Warning: Failed to fetch {url}: {e}")
        return None

def _get_cisa_kev_catalog() -> Optional[Dict[str, Any]]:
    # Ensure cache directory exists
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    # Check if cached file exists and is fresh
    if os.path.exists(CISA_KEV_CACHE_FILE):
        mtime = os.path.getmtime(CISA_KEV_CACHE_FILE)
        if time.time() - mtime < CACHE_TTL:
            try:
                with open(CISA_KEV_CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
                
    # Fetch fresh catalog
    url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data_str = _fetch_with_timeout(url, timeout=3.0)
    if data_str:
        try:
            catalog = json.loads(data_str)
            with open(CISA_KEV_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(catalog, f, indent=2)
            return catalog
        except Exception:
            pass
            
    # Fallback to expired cache if fetch failed
    if os.path.exists(CISA_KEV_CACHE_FILE):
        try:
            with open(CISA_KEV_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
            
    return None

def enrich_finding_metadata(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches a validated finding with EPSS and KEV details.
    This is fail-safe; network/API failures will keep scan execution successful.
    """
    sec_meta = finding.setdefault("security_metadata", {})
    cve_ids = sec_meta.get("cve_ids") or []
    
    # Initialize defaults
    sec_meta.setdefault("epss_score", None)
    sec_meta.setdefault("epss_percentile", None)
    sec_meta.setdefault("known_exploited", None)
    sec_meta.setdefault("used_in_ransomware", None)
    sec_meta.setdefault("date_added_to_kev", None)
    
    if not cve_ids:
        return finding

    # Use the first CVE ID for lookup
    cve_id = cve_ids[0].strip().upper()
    if not cve_id.startswith("CVE-"):
        return finding

    # 1. Fetch EPSS Data
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    epss_data_str = _fetch_with_timeout(epss_url, timeout=2.0)
    if epss_data_str:
        try:
            epss_res = json.loads(epss_data_str)
            data_list = epss_res.get("data", [])
            if data_list:
                item = data_list[0]
                sec_meta["epss_score"] = float(item.get("epss") or 0.0)
                sec_meta["epss_percentile"] = float(item.get("percentile") or 0.0)
        except Exception as e:
            print(f"[SecurityIntel] Failed to parse EPSS response: {e}")

    # 2. Fetch/Lookup CISA KEV Data
    try:
        catalog = _get_cisa_kev_catalog()
        if catalog:
            vulns = catalog.get("vulnerabilities", [])
            matched = False
            for vuln in vulns:
                if vuln.get("cveID", "").strip().upper() == cve_id:
                    sec_meta["known_exploited"] = True
                    sec_meta["date_added_to_kev"] = vuln.get("dateAdded")
                    sec_meta["used_in_ransomware"] = vuln.get("knownRansomwareCampaignUse") == "Known"
                    matched = True
                    break
            if not matched:
                sec_meta["known_exploited"] = False
                sec_meta["date_added_to_kev"] = None
                sec_meta["used_in_ransomware"] = False
    except Exception as e:
        print(f"[SecurityIntel] Failed to parse KEV catalog: {e}")
        
    return finding
