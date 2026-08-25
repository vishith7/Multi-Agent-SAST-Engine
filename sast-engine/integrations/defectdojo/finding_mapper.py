import re
from typing import Dict, Any, Optional
from risk.priority_policy import determine_severity

def map_finding_to_defectdojo(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms a final Taintlace finding into a DefectDojo finding payload.
    This is a pure transformation function.
    """
    # 1. Reject if fingerprint is missing
    fingerprint = finding.get("fingerprint")
    if not fingerprint:
        raise ValueError("Mapping failed: Finding is missing the mandatory 'fingerprint' field.")

    # 2. Extract Category / Rule ID
    category = finding.get("category")
    if not category:
        raise ValueError("Mapping failed: Finding is missing the mandatory 'category' field.")

    # 3. Resolve Title / Name
    title = finding.get("title")
    if not title:
        subtype = finding.get("subtype")
        if category and subtype:
            title = f"Taintlace: {category} - {subtype}"
        elif category:
            title = f"Taintlace: {category}"
        else:
            title = "Taintlace Finding"

    # 4. Resolve Severity (use stored value, fallback if missing)
    severity = finding.get("severity")
    if not severity:
        severity = determine_severity(finding)
    
    # Normalize case for DefectDojo API
    severity = severity.capitalize()
    if severity not in ("Critical", "High", "Medium", "Low", "Info"):
        severity = "Medium"

    # 5. Extract CWE dynamically
    cwe_val = None
    subtype = finding.get("subtype") or ""
    cwe_match = re.search(r'CWE-(\d+)', subtype, re.IGNORECASE)
    if cwe_match:
        cwe_val = int(cwe_match.group(1))
    elif str(subtype).isdigit():
        cwe_val = int(subtype)

    # 6. Map LLM Verdict
    verdict = finding.get("verdict") or ""
    if verdict in ("VALID", "APPROVED"):
        verified = True
        false_p = False
        active = True
    elif verdict == "FALSE_POSITIVE":
        verified = False
        false_p = True
        active = False
    else:
        verified = False
        false_p = False
        active = True

    # 7. Extract File Path and Line Number
    file_path = None
    line_num = None
    
    instances = finding.get("instances", [])
    if instances and isinstance(instances, list):
        file_path = instances[0].get("sink_file") or instances[0].get("sink_path")
        line_num = instances[0].get("sink_line")
        
    if not file_path or line_num is None:
        path = finding.get("path") or []
        if path and isinstance(path, list):
            file_path = path[-1].get("file")
            line_num = path[-1].get("line")

    if line_num is not None:
        try:
            line_num = int(line_num)
        except (ValueError, TypeError):
            line_num = None

    # 8. Mitigation mapping
    mitigation = finding.get("remediation") or finding.get("recommended_remediation") or ""

    # 9. Format Rich-Text Description
    confidence = finding.get("verdict_confidence") or finding.get("confidence") or 0.0
    reasoning = finding.get("reasoning") or finding.get("llm_reasoning") or "N/A"
    
    desc = f"## Taintlace Finding\n\n"
    desc += f"**Category:** {category}\n"
    if subtype:
        desc += f"**CWE/Subtype:** {subtype}\n"
    desc += f"**Verdict:** {verdict}\n"
    desc += f"**Confidence:** {confidence * 100:.1f}%\n"
    desc += f"**Fingerprint:** `{fingerprint}`\n"
    if file_path:
        desc += f"**Location:** `{file_path}:{line_num if line_num is not None else 'unknown'}`\n"
    
    desc += f"\n## LLM Validation\n\n"
    desc += f"**Verdict Detail:** {verdict}\n"
    desc += f"**Confidence Level:** {confidence * 100:.1f}%\n"
    
    desc += f"\n## Reasoning\n\n{reasoning}\n"

    # Proof of concept mappings
    poc = finding.get("proof_of_concept") or finding.get("generated_poc")
    if poc:
        desc += f"\n## Proof of Concept\n\n"
        if isinstance(poc, dict):
            poc_type = poc.get("poc_type") or "Exploit"
            payload = poc.get("payload")
            instructions = poc.get("instructions")
            
            desc += f"**PoC Type:** {poc_type}\n\n"
            if payload:
                desc += f"**Payload:**\n```\n{payload}\n```\n\n"
            if instructions:
                desc += f"**Instructions:**\n{instructions}\n\n"
            if poc.get("result"):
                desc += f"**Result/Output:**\n{poc.get('result')}\n\n"
        else:
            desc += f"{poc}\n"

    payload = {
        "title": title,
        "description": desc,
        "severity": severity,
        "cwe": cwe_val,
        "file_path": file_path or "unknown",
        "line": line_num,
        "vuln_id_from_tool": category,         # Category maps to vuln_id_from_tool
        "unique_id_from_tool": fingerprint,    # Fingerprint maps to unique_id_from_tool
        "active": active,
        "verified": verified,
        "false_p": false_p,
        "mitigation": mitigation,
        "numerical_severity": "S0"
    }
    
    return payload
