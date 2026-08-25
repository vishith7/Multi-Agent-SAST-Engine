import sys
sys.path.append('./sast-engine')
import json
from orchestrator.cascade import run_cascade_on_findings

finding = {
    'category': 'injection',
    'subtype': 'CWE-89-SQLI',
    'path': [
        {'code': 'def my_func():', 'file': 'fake.py', 'line': 1},
        {'code': '    password = "super_secret_password"', 'file': 'fake.py', 'line': 2},
        {'code': '    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', 'file': 'fake.py', 'line': 3},
        {'code': '    execute("SELECT * FROM users")', 'file': 'fake.py', 'line': 4}
    ]
}

if __name__ == "__main__":
    run_cascade_on_findings([finding])
