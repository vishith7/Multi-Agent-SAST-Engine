import json
import re

def parse_cascade_response(raw_text):
    """
    Safely extract JSON from the LLM's raw text response.
    Handles markdown fences and trailing/leading whitespace.
    """
    cleaned = raw_text.strip()
    
    # Check if enclosed in markdown blocks
    if cleaned.startswith("```"):
        cleaned = re.sub(
            r"^```(?:json)?\s*|\s*```$",
            "",
            cleaned,
            flags=re.MULTILINE
        )
        
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Fallback heuristic: Try to find first { and last }
        start_idx = cleaned.find("{")
        end_idx = cleaned.rfind("}")
        
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            try:
                return json.loads(cleaned[start_idx:end_idx+1])
            except json.JSONDecodeError:
                pass
                
        return None
