import uuid

KNOWN_DANGEROUS_CHAINS = [
    ("ssrf", "deserialization"),
    ("file_read", "deserialization")
]

def detect_chains(findings):
    for i, f1 in enumerate(findings):
        for j, f2 in enumerate(findings):
            if i == j:
                continue
            
            pair = (f1["category"], f2["category"])
            if pair in KNOWN_DANGEROUS_CHAINS:
                if f1["sink"]["id"] == f2["source"]["id"]:
                    chain_id = str(uuid.uuid4())
                    f1["chain_id"] = chain_id
                    f2["chain_id"] = chain_id
                    f1["severity_boost"] = True
                    f2["severity_boost"] = True
                    
    return findings
