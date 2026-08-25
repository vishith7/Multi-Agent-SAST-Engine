import os
import yaml
import time
import re
from llm.groq_client import get_groq_client
from llm.schemas import validate_cascade_response
from llm.parser import parse_cascade_response
from llm.rate_limiter import get_rate_limiter
from llm.prompts import VALIDATION_SYSTEM_PROMPT, RETRY_PROMPT
from llm.validator import build_finding_context
from llm.tokenizer import estimate_gpt_tokens
from llm.redaction import redact_secrets

def check_contradictory_verdict(finding, config_rules):
    """
    Checks if LLM verdict is FALSE_POSITIVE but deterministic SAST evidence strongly indicates valid vulnerability.
    Also checks if the LLM's own reasoning/evidence contradicts the FALSE_POSITIVE verdict.
    """
    verdict = finding.get("verdict")
    if verdict != "FALSE_POSITIVE":
        return False
        
    path_nodes = finding.get("path", [])
    if not path_nodes:
        return False
        
    category = finding.get("category", "unknown")
    cat_rules = config_rules.get(category, {})
    sanitizer_patterns = cat_rules.get("sanitizers", [])
    
    # Check for any sanitizer matches in path nodes
    has_sanitizer = False
    for node in path_nodes:
        code = node.get("code", "") if isinstance(node, dict) else str(node)
        for pattern in sanitizer_patterns:
            if re.search(pattern, code):
                has_sanitizer = True
                break
        if any(k in code.lower() for k in ["encodefor", "escapehtml", "htmlspecialchars", "htmlentities", "setfeature"]):
            has_sanitizer = True
            
    # Check for string concatenation / interpolation in path nodes (unsafe propagation)
    has_concat = False
    for node in path_nodes:
        code = node.get("code", "") if isinstance(node, dict) else str(node)
        if any(op in code for op in ["+", "%", "f\"", "f'", "StringBuilder.append", "String.format"]):
            has_concat = True
            
    # If no sanitizer matches, and we see string concatenation/interpolation in the flow,
    # the FALSE_POSITIVE is highly contradictory.
    if not has_sanitizer and has_concat:
        return True
        
    # Check if the LLM's reasoning/evidence contradicts the FALSE_POSITIVE verdict
    reasoning = finding.get("reasoning", "").lower()
    evidence_str = str(finding.get("evidence", "")).lower()
    contradictory_keywords = ["tainted input reaches", "reaches the sink", "concatenated directly", "no sanitizer", "unsanitized"]
    if any(k in reasoning or k in evidence_str for k in contradictory_keywords):
        return True
        
    return False

def load_cascade_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "cascade_config.yaml")
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return None

def invoke_llm_tier(client, tier_config, context, rate_limiter):
    model = tier_config.get("model", "openai/gpt-oss-120b")
    temperature = tier_config.get("temperature", 0.1)
    
    messages = [
        {"role": "system", "content": VALIDATION_SYSTEM_PROMPT},
        {"role": "user", "content": context}
    ]
    
    max_retries = 3
    retry_delay = 2.0
    
    for attempt in range(max_retries):
        rate_limiter.wait_if_needed()
        try:
            start_t = time.time()
            
            # DEBUG LOGGING FOR FIX 1 VERIFICATION
            with open("payload_test.json", "w") as f:
                import json
                json.dump({"model": model, "messages": messages}, f, indent=2)
                
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
                is_valid, err = validate_cascade_response(parsed)
                if is_valid:
                    return parsed, latency_ms, attempt, True
                else:
                    retry_msg = f"Your JSON was valid, but failed schema validation: {err}. Return ONLY valid JSON matching the required schema."
            else:
                retry_msg = RETRY_PROMPT
            
            # If invalid format, append retry instruction
            messages.append({"role": "assistant", "content": raw_content or "{}"})
            messages.append({"role": "user", "content": retry_msg})
            
        except Exception as e:
            print(f"[Cascade] LLM API Call Exception: {str(e)}")
            err_str = str(e).lower()
            
            # 1. Parse explicit Google RetryInfo if present
            import re
            retry_match = re.search(r"['\"]retrydelay['\"]:\s*['\"](\d+)s['\"]", err_str)
            if retry_match:
                sleep_sec = int(retry_match.group(1))
                print(f"[Cascade] Google API rate limit hit. Sleeping for {sleep_sec}s as requested by RetryInfo...")
                time.sleep(sleep_sec)
                continue
                
            # 2. Check general transient/rate-limiting/quota errors
            if ("429" in err_str or "rate limit" in err_str or "50" in err_str 
                    or "timeout" in err_str or "resource_exhausted" in err_str 
                    or "quota" in err_str or "retry" in err_str):
                print(f"[Cascade] Transient error detected. Sleeping for {retry_delay}s before retry...")
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
                
                print(f"[Cascade] Other error. Sleeping for {retry_delay}s before retry...")
                time.sleep(retry_delay)
                retry_delay *= 2
                
    return None, 0, max_retries, False

def run_cascade_on_findings(findings, repo_path=None, force_revalidate=False):
    """
    State machine that runs the LLM validation cascade on a list of findings.
    """
    config = load_cascade_config()
    if not config:
        print("[Cascade] Warning: cascade_config.yaml not found. Skipping validation.")
        return findings

    try:
        from orchestrator.cascade_cache import cascade_cache
    except ImportError:
        try:
            from cascade_cache import cascade_cache
        except ImportError:
            cascade_cache = None

    try:
        client = get_groq_client()
    except Exception as e:
        raise RuntimeError(f"GROQ_API_KEY is not configured or client failed to initialize: {e}")

    cascade_conf = config.get("cascade", {})
    budget = cascade_conf.get("budget", {})
    rpm = budget.get("requests_per_minute_limit", 25)
    limiter = get_rate_limiter(rpm)
    
    tiers = cascade_conf.get("tiers", [])
    tier2 = next((t for t in tiers if t.get("name") == "tier2_fast_llm"), {})
    tier3 = next((t for t in tiers if t.get("name") == "tier3_deep_llm"), {})

    print(f"\n[Cascade] Starting LLM Validation Pipeline on {len(findings)} findings...")
    
    try:
        from llm.tokenizer import BPEWithLearningTokenizer
        tokenizer = BPEWithLearningTokenizer()
        print("[Cascade] Loaded custom BPE tokenizer for context compression.")
    except Exception as e:
        tokenizer = None
        print(f"[Cascade] Warning: Could not initialize BPE tokenizer: {e}")
        
    cache_hits = 0
    llm_calls = 0

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "sinks_sources.yaml")
    config_rules = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config_rules = yaml.safe_load(f) or {}
        except Exception:
            pass

    for i, finding in enumerate(findings):
        # Tier 1 (Heuristic Gate)
        instances = finding.get("instances", [])
        if instances and instances[0].get("source_line") == instances[0].get("sink_line"):
            finding["verdict"] = "VALID"
            finding["verdict_confidence"] = 1.0
            finding["reasoning"] = "Tier 1: Path length is 0 (Source and sink on same line)."
            finding["validation_tier"] = "tier1_heuristic_gate"
            continue
            
        fp = finding.get("fingerprint")
        ctx_hash = finding.get("context_hash")
        
        if not force_revalidate and cascade_cache and fp and ctx_hash:
            cached = cascade_cache.get_cached_verdict(fp, context_hash=ctx_hash)
            if cached:
                finding.update(cached)
                cache_hits += 1
                built_at = cached.get("validated_at_timestamp", 0)
                import datetime
                ts_str = datetime.datetime.fromtimestamp(built_at).strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{i+1}/{len(findings)}] Finding {fp[:8]} - reusing cached verdict from {ts_str} (fingerprint match, no LLM call needed).")
                continue
                
        llm_calls += 1
            
        # Context Extraction with Budget check
        limit_to_lines = False
        critical_only = False
        context = ""
        est_tokens = 0
        raw_char_count = 0
        
        while True:
            context = build_finding_context(finding, repo_path, limit_to_lines=limit_to_lines, critical_only=critical_only)
            context = redact_secrets(context)
            raw_char_count = len(context)
            
            # Context Compression
            if tokenizer:
                from llm.tokenizer import compress_text_context
                context = compress_text_context(context, tokenizer)
            
            est_tokens = estimate_gpt_tokens(context)
            
            if est_tokens <= 6000:
                break
                
            if critical_only:
                print(f"[Cascade] Warning: Finding context is still large ({est_tokens} tokens) even after extreme truncation.")
                break
                
            if not limit_to_lines:
                print(f"[Cascade] Context size ({est_tokens} tokens) exceeds budget. Truncating to line-level snippets...")
                limit_to_lines = True
                continue
                
            if not critical_only:
                print(f"[Cascade] Context size ({est_tokens} tokens) still exceeds budget. Truncating to critical nodes only...")
                critical_only = True
                continue
        
        custom_bpe_count = len(tokenizer.tokenize(finding)[1]) if tokenizer else 0
        finding["raw_char_count"] = raw_char_count
        finding["custom_bpe_token_count"] = custom_bpe_count
        finding["model_token_estimate"] = est_tokens
        
        print(f"[Cascade] Context metrics - Chars: {raw_char_count}, BPE: {custom_bpe_count}, Est Model Tokens: {est_tokens}")

        # Tier 2
        parsed, latency, retries, parse_success = invoke_llm_tier(client, tier2, context, limiter)
        
        tier_used = "tier2_fast_llm"
        needs_escalation = False
        
        if not parsed:
            needs_escalation = True
            finding["reasoning"] = "json_parse_failure or api_error"
            finding["verdict"] = "NEEDS_REVIEW"
            finding["verdict_confidence"] = 0.0
        else:
            finding.update(parsed)
            # Enforce NOT_EXECUTED status for generated PoC
            if "proof_of_concept" in finding:
                finding["proof_of_concept"]["verification_status"] = "NOT_EXECUTED"
            if "cwe" in parsed:
                finding["subtype"] = parsed["cwe"]
                
            # Gating against contradictory FALSE_POSITIVE verdict
            contradictory = check_contradictory_verdict(finding, config_rules)
            if contradictory:
                print(f"[Cascade] Deterministic Gate: FALSE_POSITIVE verdict conflicts with SAST evidence. Escalating...")
                needs_escalation = True
                finding["verdict"] = "NEEDS_REVIEW"
                finding["verdict_confidence"] = 0.0
                
            # Check escalation threshold
            esc_conf = tier2.get("escalate_if", {}).get("confidence_below", 0.70)
            esc_verdicts = tier2.get("escalate_if", {}).get("verdicts", ["NEEDS_REVIEW"])
            
            if finding.get("verdict_confidence", 1.0) < esc_conf or finding.get("verdict") in esc_verdicts:
                needs_escalation = True
                
        # Tier 3 (Escalation)
        if needs_escalation and tier3:
            parsed3, latency3, retries3, parse_success3 = invoke_llm_tier(client, tier3, context, limiter)
            
            tier_used = "tier3_deep_llm"
            if parsed3:
                finding.update(parsed3)
                if "proof_of_concept" in finding:
                    finding["proof_of_concept"]["verification_status"] = "NOT_EXECUTED"
                if "cwe" in parsed3:
                    finding["subtype"] = parsed3["cwe"]
                    
                # Gating Tier 3 against contradictory FALSE_POSITIVE verdict
                contradictory3 = check_contradictory_verdict(finding, config_rules)
                esc_conf3 = tier3.get("escalate_if", {}).get("confidence_below", 0.60)
                
                if contradictory3:
                    print(f"[Cascade] Deterministic Gate (Tier 3): FALSE_POSITIVE contradicts SAST evidence. Forcing Human Review.")
                    finding["verdict"] = "NEEDS_REVIEW"
                    finding["verdict_confidence"] = 0.0
                    finding["validation_tier"] = "tier4_human_review_queue"
                elif finding.get("verdict_confidence", 1.0) < esc_conf3 or finding.get("verdict") == "NEEDS_REVIEW":
                    finding["verdict"] = "NEEDS_REVIEW"
                    finding["validation_tier"] = "tier4_human_review_queue"
                else:
                    finding["validation_tier"] = tier_used
            else:
                finding["reasoning"] = "tier3_api_or_parse_error"
                finding["verdict"] = "NEEDS_REVIEW"
                finding["verdict_confidence"] = 0.0
                finding["validation_tier"] = "tier4_human_review_queue"
        else:
            if not needs_escalation:
                finding["validation_tier"] = tier_used
                
        finding["latency_ms"] = latency
        finding["retry_count"] = retries
        finding["parse_success"] = parse_success

        # Enrich finding with EPSS/KEV metadata
        try:
            from security_intel.enrichment_service import enrich_finding_metadata
            finding = enrich_finding_metadata(finding)
        except Exception as e:
            print(f"[Cascade] Warning: Failed to enrich metadata: {e}")

        # Initialize human_validation and fix status details
        finding.setdefault("human_validation", {
            "status": "PENDING",
            "reviewer": None,
            "reviewed_at": None,
            "comment": None
        })
        
        fix_block = finding.get("fix") or {}
        if fix_block:
            if fix_block.get("available"):
                fix_block.setdefault("status", "PROPOSED")
            else:
                fix_block["status"] = "NOT_AVAILABLE"
            finding["fix"] = fix_block

        # Decorate finding with severity, priority, SLA
        try:
            from risk.priority_policy import determine_severity, get_priority, get_sla_days
            # Fallback to determine_severity only if severity is not already set
            sev = finding.get("severity")
            if not sev:
                sev = determine_severity(finding)
            prio = get_priority(finding)
            sla = get_sla_days(prio)
            
            finding["severity"] = sev
            finding["priority"] = prio
            finding["sla_days"] = sla
            finding["exploitability"] = "High" if float(finding.get("verdict_confidence") or finding.get("confidence") or 0.0) >= 0.8 else "Medium"
            if "title" not in finding:
                finding["title"] = f"Taintlace: {finding.get('category')} - {finding.get('subtype')}"
        except Exception as e:
            print(f"[Cascade] Warning: Failed to apply risk priority policies: {e}")

        print(f"[{i+1}/{len(findings)}] Analyzed {finding.get('category')} -> {finding.get('verdict')} ({finding.get('verdict_confidence', 0.0):.2f}) [Tier: {finding.get('validation_tier')}]")
        
        if cascade_cache and fp and finding.get("context_hash"):
            cache_keys = [
                "verdict", "verdict_confidence", "reasoning", "validation_tier",
                "model_used", "subtype", "context_hash", "proof_of_concept",
                "severity", "priority", "sla_days", "exploitability", "title",
                "security_metadata", "remediation", "references", "fix", "human_validation"
            ]
            cache_data = {k: v for k, v in finding.items() if k in cache_keys}
            cascade_cache.save_cached_verdict(fp, cache_data)
        
    print(f"\n[Cascade] {len(findings)} findings validated ({cache_hits} from cache, {llm_calls} fresh LLM calls).")
    return findings
