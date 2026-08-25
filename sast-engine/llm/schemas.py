# Pydantic is optional but we can just use basic JSON schema strings or Pydantic if installed.
# We will just define standard expected fields here.

VALID_VERDICTS = {"VALID", "FALSE_POSITIVE", "NEEDS_REVIEW"}

def validate_cascade_response(parsed_json):
    """
    Validates that a parsed JSON response matches the required schema.
    Returns (True, None) if valid, or (False, error_reason) if invalid.
    """
    if not isinstance(parsed_json, dict):
        return False, "Response is not a JSON object."
        
    verdict = parsed_json.get("verdict")
    if verdict not in VALID_VERDICTS:
        return False, f"Invalid verdict: {verdict}. Must be one of {VALID_VERDICTS}."
        
    try:
        confidence = float(parsed_json.get("verdict_confidence", -1))
        if not (0.0 <= confidence <= 1.0):
            return False, f"Invalid verdict_confidence: {confidence}. Must be float between 0.0 and 1.0."
    except (ValueError, TypeError):
        return False, "Invalid verdict_confidence format."
        
    required_fields = ["reasoning", "remediation", "security_metadata", "fix", "proof_of_concept"]
    for field in required_fields:
        if field not in parsed_json:
            return False, f"Missing required field: {field}"
            
    # Validate security_metadata
    sec_meta = parsed_json.get("security_metadata")
    if not isinstance(sec_meta, dict):
        return False, "security_metadata must be a JSON object."
    required_meta = ["cwe_id", "cwe_name", "vulnerability_id", "cve_ids", "owasp_category"]
    for field in required_meta:
        if field not in sec_meta:
            return False, f"Missing required security_metadata field: {field}"
            
    # Validate fix
    fix = parsed_json.get("fix")
    if not isinstance(fix, dict):
        return False, "fix must be a JSON object."
    if "available" not in fix:
        return False, "Missing required fix field: available"
    if not isinstance(fix["available"], bool):
        return False, "fix.available must be a boolean."
        
    if fix["available"]:
        required_fix_fields = ["summary", "strategy", "files", "patch", "before", "after", "explanation"]
        for field in required_fix_fields:
            if field not in fix:
                return False, f"Missing required fix field when available is true: {field}"

    # Validate proof_of_concept
    poc = parsed_json.get("proof_of_concept")
    if not isinstance(poc, dict):
        return False, "proof_of_concept must be a JSON object."
        
    required_poc_fields = ["available", "type", "description", "input", "expected_effect", "verification_status"]
    for f in required_poc_fields:
        if f not in poc:
            return False, f"Missing required proof_of_concept field: {f}"
            
    if not isinstance(poc["available"], bool):
        return False, "proof_of_concept.available must be a boolean."
        
    valid_poc_types = {"input", "request", "code_path", "other"}
    if poc["type"] not in valid_poc_types:
        return False, f"Invalid proof_of_concept.type: {poc['type']}. Must be one of {valid_poc_types}."
        
    valid_statuses = {"NOT_EXECUTED", "VERIFIED", "NOT_APPLICABLE"}
    if poc["verification_status"] not in valid_statuses:
        return False, f"Invalid proof_of_concept.verification_status: {poc['verification_status']}. Must be one of {valid_statuses}."
        
    return True, None

def validate_poc_response(parsed_json):
    """
    Validates that a parsed JSON response for PoC matches the required schema.
    Returns (True, None) if valid, or (False, error_reason) if invalid.
    """
    if not isinstance(parsed_json, dict):
        return False, "Response is not a JSON object."
        
    if not parsed_json.get("poc_type"):
        return False, "Missing or empty poc_type."
        
    if not parsed_json.get("payload"):
        return False, "Missing or empty payload."
        
    if not parsed_json.get("instructions"):
        return False, "Missing or empty instructions."
        
    return True, None

