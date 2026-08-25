import os
import yaml

def determine_severity(finding):
    category = (finding.get("category") or "").lower()
    subtype = (finding.get("subtype") or "").lower()
    
    # Critical categories/subtypes
    if "cwe-78" in subtype or "command-injection" in subtype or category == "deserialization":
        return "Critical"
    
    # High categories/subtypes
    if "cwe-89" in subtype or "sql-injection" in subtype or category == "injection":
        conf = float(finding.get("verdict_confidence") or finding.get("confidence") or 0.0)
        return "Critical" if conf >= 0.8 else "High"
    if "cwe-611" in subtype or category == "xxe":
        return "High"
    if "cwe-918" in subtype or category == "ssrf":
        return "High"
    if "cwe-22" in subtype or category == "path_traversal":
        return "High"
        
    # Medium categories/subtypes
    if "cwe-79" in subtype or category == "xss":
        return "Medium"
    if "cwe-798" in subtype or category == "default_credentials":
        return "Medium"
    if "cwe-352" in subtype or category == "csrf":
        return "Medium"
        
    return "Low"

