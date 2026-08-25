RULES_DESCRIPTIONS = {
    "injection": """[SECURITY RULE FOR INJECTION]
Covers: SQL Injection (CWE-89), Command Injection (CWE-78)
- UNSAFE flow: Attacker-controlled source -> string concatenation/interpolation -> vulnerable SQL/Command execution sink.
- SAFE flow: Parameter binding (parameterized queries, prepared statements) or safe subprocess list invocation without shell=True.
- Note: String concatenation before calling preparedStatement is UNSAFE.
- False Positive Guards: Verify if the input is safely parameterised or strictly validated (e.g., allowlist check).""",

    "ssrf": """[SECURITY RULE FOR SSRF]
Covers: Server-Side Request Forgery (CWE-918)
- UNSAFE flow: User-controlled URL/hostname/IP -> passed directly to HTTP client sinks (HttpURLConnection, HttpClient, requests.get, etc.) without restriction.
- SAFE flow: Target URL is strictly restricted to an allowlist, or IP checks prevent requests to private/internal IP ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16, 169.254.169.254, etc.).""",

    "deserialization": """[SECURITY RULE FOR INSECURE DESERIALIZATION]
Covers: Insecure Deserialization (CWE-502)
- UNSAFE flow: Untrusted byte streams, JSON, XML, or YAML -> deserialized back into active objects (ObjectInputStream.readObject, XMLDecoder, BinaryFormatter.Deserialize, unsafe yaml.load, etc.) without type validation or class allowlisting.
- SAFE flow: Use of secure deserialization configuration, safe parse methods (yaml.safe_load), or strict type/class name allowlisting before object instantiation.""",

    "path_traversal": """[SECURITY RULE FOR PATH TRAVERSAL]
Covers: Path Traversal (CWE-22)
- UNSAFE flow: User-controlled file paths -> opened directly by file access sinks (FileInputStream, open(), fs.readFile(), etc.) without path normalization or boundary validation.
- SAFE flow: Safe path normalization (e.g. canonicalPath), checking startsWith(baseDirectory), or rejecting any input containing traversal sequences like '..' or path separators.""",

    "xxe": """[SECURITY RULE FOR XXE]
Covers: XML External Entity Injection (CWE-611)
- UNSAFE flow: User-controlled XML payload -> parsed by XML parsers (DocumentBuilderFactory, SAXParserFactory, XMLInputFactory, etc.) with external entity resolution enabled.
- SAFE flow: Explicitly disable DOCTYPE declarations (disallow-doctype-decl = true), disable external general/parameter entities, or use a defused parser (like defusedxml).""",

    "csrf": """[SECURITY RULE FOR CSRF]
Covers: Cross-Site Request Forgery (CWE-352)
- UNSAFE flow: State-changing POST/PUT/DELETE endpoints configured with cookie/session authentication, with CSRF protection explicitly disabled (.csrf().disable()).
- SAFE flow: CSRF protection enabled, non-replayable tokens (CSRF tokens) required, or the session creation policy is strictly STATELESS (JWT-only auth with no cookies).""",

    "default_credentials": """[SECURITY RULE FOR DEFAULT/HARDCODED CREDENTIALS]
Covers: Use of Hardcoded Credentials (CWE-798)
- UNSAFE flow: Hardcoded passwords, API keys, signing secrets assigned directly as constants or connection URIs, gating a reachable authentication/login path.
- SAFE flow: Reading credentials strictly from environment variables (os.getenv, process.env), empty string variables, or using mock placeholders (e.g. <YOUR_PASSWORD_HERE>).
- FP Rule: Do not flag DB credentials in infrastructure configs or test fixtures unless reachable via a production login endpoint.""",

    "xss": """[SECURITY RULE FOR XSS]
Covers: Cross-Site Scripting (CWE-79)
- UNSAFE flow: User-controlled string -> dynamically concatenated/injected into HTML/JavaScript rendering sinks (PrintWriter.print, innerHTML, dangerouslySetInnerHTML, v-html, echo) without context-appropriate escaping.
- SAFE flow: Proper HTML/JS escaping (encodeForHTML, htmlspecialchars, etc.) or safe property assignment (textContent, innerText)."""
}
