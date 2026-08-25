import os
import yaml
import time
from llm.groq_client import get_groq_client
from llm.schemas import validate_poc_response
from llm.parser import parse_cascade_response
from llm.rate_limiter import get_rate_limiter
from llm.prompts import POC_SYSTEM_PROMPT, RETRY_PROMPT
from llm.validator import build_finding_context
from llm.redaction import redact_secrets

def load_cascade_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "cascade_config.yaml")
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return None

def invoke_llm_poc(client, model, temperature, context, rate_limiter):
    messages = [
        {"role": "system", "content": POC_SYSTEM_PROMPT},
        {"role": "user", "content": context}
    ]
    
    max_retries = 3
    retry_delay = 2.0
    
    for attempt in range(max_retries):
        rate_limiter.wait_if_needed()
        try:
            start_t = time.time()
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                response_format={"type": "json_object"}
            )
            latency_ms = int((time.time() - start_t) * 1000)
            
            raw_content = response.choices[0].message.content
            parsed = parse_cascade_response(raw_content)
            
            if parsed:
                is_valid, err = validate_poc_response(parsed)
                if is_valid:
                    return parsed, latency_ms, attempt, True
                else:
                    retry_msg = f"Your JSON was valid, but failed schema validation: {err}. Return ONLY valid JSON matching the required schema."
            else:
                retry_msg = RETRY_PROMPT
            
            messages.append({"role": "assistant", "content": raw_content or "{}"})
            messages.append({"role": "user", "content": retry_msg})
            
        except Exception as e:
            print(f"[Prove] LLM API Call Exception: {str(e)}")
            err_str = str(e).lower()
            
            # 1. Parse explicit Google RetryInfo if present
            import re
            retry_match = re.search(r"['\"]retrydelay['\"]:\s*['\"](\d+)s['\"]", err_str)
            if retry_match:
                sleep_sec = int(retry_match.group(1))
                print(f"[Prove] Google API rate limit hit. Sleeping for {sleep_sec}s as requested by RetryInfo...")
                time.sleep(sleep_sec)
                continue
                
            # 2. Check general transient/rate-limiting/quota errors
            if ("429" in err_str or "rate limit" in err_str or "50" in err_str 
                    or "timeout" in err_str or "resource_exhausted" in err_str 
                    or "quota" in err_str or "retry" in err_str):
                print(f"[Prove] Transient error detected. Sleeping for {retry_delay}s before retry...")
                time.sleep(retry_delay)
                retry_delay *= 2
            else:
                # Permanent failure like auth or bad request
                # Ensure we don't treat rate-limiting or INVALID_ARGUMENT retry blocks as permanent failures
                is_perm = False
                if ("401" in err_str or "auth" in err_str) and "json_validate" not in err_str:
                    is_perm = True
                elif "invalid" in err_str and "invalid_argument" not in err_str and "json_validate" not in err_str:
                    is_perm = True
                    
                if is_perm:
                    raise RuntimeError(f"LLM API Error (Check API Key/Model): {e}")
                
                if "json_validate" in err_str:
                    messages.append({
                        "role": "user",
                        "content": "Your previous response failed JSON validation by the API gateway. Please return ONLY valid raw JSON matching the schema, and properly escape all control characters, backslashes, and quotes inside the string values."
                    })
                
                print(f"[Prove] Other error. Sleeping for {retry_delay}s before retry...")
                time.sleep(retry_delay)
                retry_delay *= 2
                
    return None, 0, max_retries, False

def run_prove_on_findings(findings, repo_path=None):
    """
    Runs the LLM Prove phase on a list of findings to generate PoCs for VALID and NEEDS_REVIEW.
    """
    config = load_cascade_config()
    if not config:
        print("[Prove] Warning: cascade_config.yaml not found. Skipping Prove phase.")
        return findings

    try:
        client = get_groq_client()
    except Exception as e:
        raise RuntimeError(f"GROQ_API_KEY is not configured or client failed to initialize: {e}")

    cascade_conf = config.get("cascade", {})
    budget = cascade_conf.get("budget", {})
    rpm = budget.get("requests_per_minute_limit", 25)
    limiter = get_rate_limiter(rpm)
    
    tiers = cascade_conf.get("tiers", [])
    # Re-use tier3 configuration (or tier2) for generating the PoC
    poc_tier = next((t for t in tiers if t.get("name") == "tier3_deep_llm"), None)
    if not poc_tier:
        poc_tier = next((t for t in tiers if t.get("name") == "tier2_fast_llm"), {})
        
    model = poc_tier.get("model", "openai/gpt-oss-120b")
    temperature = poc_tier.get("temperature", 0.3)

    target_findings = [f for f in findings if f.get("verdict") in ["VALID", "NEEDS_REVIEW"]]
    print(f"\\n[Prove] Starting LLM Prove Pipeline on {len(target_findings)} target findings...")
    
    processed = 0
    for finding in findings:
        if finding.get("verdict") not in ["VALID", "NEEDS_REVIEW"]:
            continue
            
        processed += 1
        
        context = build_finding_context(finding, repo_path)
        context = redact_secrets(context)
        
        parsed, latency, retries, success = invoke_llm_poc(client, model, temperature, context, limiter)
        
        if success and parsed:
            finding["generated_poc"] = parsed
            print(f"[{processed}/{len(target_findings)}] Generated PoC for {finding.get('category')} ({finding.get('subtype')})")
        else:
            print(f"[{processed}/{len(target_findings)}] Failed to generate PoC for {finding.get('category')}")
            finding["generated_poc"] = {"error": "Failed to generate valid PoC JSON"}
            
    return findings
