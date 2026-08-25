import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from prepare import build_or_update_cpg

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <repo_path>")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    print(f"Starting SAST orchestration for {repo_path}")
    
    # Phase 1: Prepare
    print("\n--- STAGE 1: PREPARE ---")
    success = build_or_update_cpg(repo_path)
    if not success:
        print("Prepare stage failed.")
        sys.exit(1)
    
    print("Prepare stage completed successfully.")
    
if __name__ == "__main__":
    main()
