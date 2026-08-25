import json
import os

def get_state_dir():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    state_dir = os.path.join(base_dir, ".state")
    os.makedirs(state_dir, exist_ok=True)
    return state_dir

def get_last_scanned_commit(repo_id):
    state_file = os.path.join(get_state_dir(), f"{repo_id}.json")
    if not os.path.exists(state_file):
        return None
    try:
        with open(state_file, 'r') as f:
            data = json.load(f)
            return data.get('last_scanned_commit')
    except Exception:
        return None

def set_last_scanned_commit(repo_id, sha):
    state_file = os.path.join(get_state_dir(), f"{repo_id}.json")
    with open(state_file, 'w') as f:
        json.dump({'last_scanned_commit': sha}, f)
