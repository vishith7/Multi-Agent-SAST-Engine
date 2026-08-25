import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "sast-engine", "orchestrator")))
from dedupe_anonymize import group_findings

# Demo 1 finding
f1 = {
    "repo": "demo-repo-auth",
    "category": "injection",
    "source": {"file": "auth.py", "line": 42},
    "sink": {"function": "execute", "file": "db.py", "line": 105},
    "path": ["token = request.args.get('id')", "db.execute(token)"]
}

# Demo 2 finding (same pattern, different vars)
f2 = {
    "repo": "demo-repo-billing",
    "category": "injection",
    "source": {"file": "invoice.py", "line": 12},
    "sink": {"function": "execute", "file": "query.py", "line": 33},
    "path": ["invoice_id = request.args.get('id')", "db.execute(invoice_id)"]
}

config_names = {"request", "args", "get", "execute"}

grouped = group_findings([f1, f2], config_names=config_names)
print(json.dumps(grouped, indent=2))
