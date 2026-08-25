import re

def redact_secrets(text: str) -> str:
    """
    Redacts sensitive strings from the provided text before sending to LLM.
    Replaces matches with labeled placeholders.
    """
    if not text:
        return text
        
    # AWS Access Key
    text = re.sub(r'\bAKIA[0-9A-Z]{16}\b', '[REDACTED_AWS_KEY]', text)
    
    # AWS Secret Key
    text = re.sub(r'(?i)(aws_secret[_-]?access[_-]?key\s*[:=]\s*[\'"])[^\'"]+([\'"])', r'\1[REDACTED_AWS_SECRET]\2', text)
    
    # Generic password / secret / token
    text = re.sub(r'(?i)((?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\'"])[^\'"]{4,}([\'"])', r'\1[REDACTED_SECRET]\2', text)
    
    # Private key headers
    text = re.sub(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----.*?-----END \1?PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]', text, flags=re.DOTALL)
    
    # Generic bearer tokens
    text = re.sub(r'(?i)bearer\s+[a-zA-Z0-9\-_.]+', 'Bearer [REDACTED_TOKEN]', text)
    
    return text
