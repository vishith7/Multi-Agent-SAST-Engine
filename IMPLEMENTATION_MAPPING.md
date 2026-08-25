# Feature Implementation Mapping

This document provides a simple, easy-to-understand breakdown of every feature we have implemented in this session, mapping each feature directly to the corresponding code snippet and explaining its purpose.

---

## 1. Token-Based Balanced Bracket Parser for Commutative Operations

### Purpose
Commutative operations (like `a == b` vs `b == a` or `x + y` vs `y + x`) should be normalized so they produce the same vulnerability fingerprint. 

Previously, a simple regular expression was used to swap operands. However, when expressions contained property accesses (e.g. `req.input`) or nested function calls (e.g. `get_user_id(req.get_session().get_id())`), the old regex partially matched the operands and swapped them incorrectly, breaking code syntax (e.g. turning `user_id == req.input` into `req == user_id.input`).

This feature replaces the regex with a scanner that tracks balanced parenthesis depth, ensuring expressions of any complexity are parsed and swapped safely.

### Code Snippet
Implemented in [`sast-engine/orchestrator/dedupe_anonymize.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/orchestrator/dedupe_anonymize.py#L7-L149):

```python
def tokenize_balanced(text):
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        # Check whitespace
        if text[i].isspace():
            start = i
            while i < n and text[i].isspace():
                i += 1
            tokens.append(('space', text[start:i]))
            continue
            
        # Check string literals
        if text[i] in ("'", '"'):
            quote = text[i]
            start = i
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(('string', text[start:i]))
            continue
            
        # Check brackets/parentheses nesting (balanced bracket tracking)
        if text[i] in ('(', '[', '{'):
            start = i
            brackets = []
            matching = {')': '(', ']': '[', '}': '{'}
            opening = {'(': ')', '[': ']', '{': '}'}
            
            while i < n:
                char = text[i]
                if char in opening:
                    brackets.append(char)
                elif char in matching:
                    if brackets and brackets[-1] == matching[char]:
                        brackets.pop()
                    else:
                        pass
                
                i += 1
                if not brackets:
                    break
            tokens.append(('bracketed', text[start:i]))
            continue
        ...
```

---

## 2. Language-Specific Operators for Commutative Normalization

### Purpose
We scan programs written in JavaScript, TypeScript, Java, Python, and PHP. These languages use operators beyond simple symbols:
* JavaScript/TypeScript use strict equality (`===`, `!==`).
* Java, JavaScript, and PHP use logical operations (`&&`, `||`).

If these operators are not supported, the tokenizer splits them up (e.g. `===` becomes `==` and `=`), corrupting normalization. This feature adds full support for multi-character operators, ensuring proper tokenization for all targeted languages.

### Code Snippet
Implemented in [`sast-engine/orchestrator/dedupe_anonymize.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/orchestrator/dedupe_anonymize.py#L59-L84):

```python
        # Check 3-char operators (===, !==)
        if text[i:i+3] in ('===', '!=='):
            tokens.append(('operator', text[i:i+3]))
            i += 3
            continue

        # Check 2-char operators (==, !=, &&, ||)
        if text[i:i+2] in ('==', '!=', '&&', '||'):
            tokens.append(('operator', text[i:i+2]))
            i += 2
            continue
            
        # Check single-char operators (+, *, &, |, ^)
        if text[i] in ('+', '*', '&', '|', '^'):
            tokens.append(('operator', text[i]))
            i += 1
            continue
```

---

## 3. Broad Multi-Language Whitelisting

### Purpose
To find structural matches across findings, the engine anonymizes variable names (replacing them with placeholders like `<VAR_1>`). However, if core language keywords, types, or global objects (like `String` in Java or `console` in JS) are anonymized, the code path becomes illegible for the LLM agents, and hashes change unnecessarily.

This feature expands the `WHITELIST` to cover standard types, globals, and keywords across all four supported languages, preserving them as-is.

### Code Snippet
Implemented in [`sast-engine/orchestrator/dedupe_anonymize.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/orchestrator/dedupe_anonymize.py#L5-L35):

```python
WHITELIST = {
    # General Python built-ins & types
    "len", "str", "print", "int", "float", "bool", "list", "dict", "set", "tuple", "range", 
    "open", "type", "isinstance", "getattr", "setattr", "hasattr", "any", "all", "sum", "min", "max",
    
    # Python keywords
    "def", "class", "return", "if", "elif", "else", "try", "except", "finally", "raise", "with", 
    "for", "while", "break", "continue", "pass", "in", "is", "not", "and", "or", "import", "from", "as",
    
    # Java types & core classes
    "String", "Integer", "Double", "Float", "Boolean", "Long", "Short", "Byte", "Character", "Object",
    "System", "Math", "List", "Map", "Set", "ArrayList", "HashMap", "HashSet", "Exception", "Throwable",
    
    # Java keywords
    "public", "private", "protected", "static", "final", "void", "char", "byte", "short", "long",
    "new", "this", "super", "extends", "implements", "instanceof", "synchronized", "throws",
    
    # JavaScript / TypeScript built-ins & types
    "console", "log", "error", "warn", "info", "process", "env", "require", "module", "exports", 
    "JSON", "parse", "stringify", "Promise", "resolve", "reject", "async", "await", "window", "document",
    
    # JS/TS/Java/PHP common keywords
    "const", "let", "var", "function", "interface", "enum", "package", "switch", "case", "default",
    
    # PHP built-ins & globals
    "echo", "var_dump", "die", "exit", "isset", "empty", "unset", "array", "eval",
    "GLOBALS", "_GET", "_POST", "_REQUEST", "_SERVER", "_COOKIE", "_SESSION", "_FILES", "_ENV",
    "this", "self", "parent"
}
```

---

## 4. Environment-Driven DefectDojo Configuration

### Purpose
Previously, DefectDojo settings had to be manually entered and verified every time the config utility ran. This feature introduces automated environment variable support (`DEFECTDOJO_URL`, `DEFECTDOJO_API_KEY`, `DEFECTDOJO_ENGAGEMENT_ID`), enabling out-of-the-box configuration using standard `.env` configuration files.

### Code Snippet
Implemented in [`.env`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/.env) and [`.env.example`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/.env.example):

```env
DEFECTDOJO_URL=http://localhost:8080
DEFECTDOJO_API_KEY=your_token_here
DEFECTDOJO_ENGAGEMENT_ID=1
```

---

## 5. API Token-Only Interactive Prompts

### Purpose
To streamline the user experience, the CLI configuration utility was redesigned. Instead of forcing the user to repeatedly enter the URL and Engagement ID, the code automatically extracts them from environment variables (or defaults them to URL `http://localhost:8080` and Engagement ID `1`). The user is only prompted for their secure API Token.

### Code Snippet
Implemented in [`cli.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/cli.py#L22  0-L247):

```python
    current_url = os.environ.get("DEFECTDOJO_URL") or keyring.get_password("taintlace_defectdojo", "url") or "http://localhost:8080"
    current_engagement = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID") or keyring.get_password("taintlace_defectdojo", "engagement_id") or "1"
    env_token = os.environ.get("DEFECTDOJO_API_KEY")
    has_token = bool(env_token or keyring.get_password("taintlace_defectdojo", "token"))
    
    url = current_url
    engagement = current_engagement
    
    print(f"DefectDojo URL: {url}")
    print(f"Engagement ID:  {engagement}")
    if has_token:
        print("Current API Token:     [Configured]")
    print("-" * 40)
    
    token = getpass.getpass("Enter DefectDojo API Token: ").strip()
    if not token:
        token = env_token or keyring.get_password("taintlace_defectdojo", "token")
```

---

## 6. Reconfiguring Verification Dashboard Default Port

### Purpose
By default, DefectDojo local instances host on port `8080`. The Taintlace Verification Web Dashboard also defaulted to port `8080`. When both were active, they clashed, causing the dashboard server to crash upon startup.

This feature shifts the dashboard starting scan port to `8081` to allow both applications to run concurrently.

### Code Snippet
Implemented in [`sast-engine/orchestrator/dashboard.py`](file:///c:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/sast-engine/orchestrator/dashboard.py#L21-L236):

```python
def find_free_port(start_port=8081):
    port = start_port
    while port < 65535:
        try:
            with socketserver.TCPServer(("", port), None) as s:
                return port
        except Exception:
            port += 1
    return 8081
```
And matched on line 236:
```python
    port = find_free_port(8081)
```
