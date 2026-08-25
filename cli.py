import argparse
import sys
import os
import json
import yaml
import time
import subprocess
import datetime
from pathlib import Path
import keyring
import getpass
import urllib.request
import urllib.parse
import urllib.error
import shutil
import re

from rich.console import Console
console = Console()

from dotenv import load_dotenv

# Ensure .env is loaded before anything else starts
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path, override=True)

key = os.environ.get("GROQ_API_KEY", "")

# Add sast-engine to path so we can import orchestrator modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "sast-engine")))

from orchestrator.prepare import build_or_update_cpg, build_full_cpg
from orchestrator.scan import run_scan
from orchestrator.chain_detection import detect_chains
from orchestrator.dedupe_anonymize import group_findings

def browse_history():
    history_dir = "./scan_history"
    if not os.path.exists(history_dir):
        print("No past scans found.")
        return

    files = [f for f in os.listdir(history_dir) if f.endswith(".json")]
    if not files:
        print("No past scans found.")
        return

    files.sort(key=lambda x: os.path.getmtime(os.path.join(history_dir, x)), reverse=True)
    
    print("\nSelect a scan result to view:")
    valid_options = []
    for i, f in enumerate(files, 1):
        filepath = os.path.join(history_dir, f)
        try:
            with open(filepath, "r") as json_f:
                data = json.load(json_f)
                if isinstance(data, dict) and "scan_metadata" in data:
                    meta = data.get("scan_metadata", {})
                    repo = meta.get("repo", "unknown")
                    raw = meta.get("raw_findings", 0)
                    uniq = meta.get("unique_findings", 0)
                    print(f"[{i}] {f}   ({repo}, {raw} raw / {uniq} unique)")
                else:
                    print(f"[{i}] {f}   (Legacy raw format)")
        except Exception:
            print(f"[{i}] {f}   (Invalid format)")
        valid_options.append(filepath)

    choice = input("\nEnter number to view, or 'q' to cancel:\n> ").strip().lower()
    if choice == 'q':
        return
        
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(valid_options):
            print("-" * 60)
            print(f"[*] Viewing {os.path.basename(valid_options[idx])}...")
            render_cmd = ["taintlace", "findings", "--input", valid_options[idx]]
            subprocess.run(render_cmd)
        else:
            print("Invalid choice.")
    except ValueError:
        print("Invalid input.")

def validate_history():
    history_dir = "./scan_history"
    if not os.path.exists(history_dir):
        print("No past scans found.")
        return

    files = [f for f in os.listdir(history_dir) if f.endswith(".json")]
    if not files:
        print("No past scans found.")
        return

    files.sort(key=lambda x: os.path.getmtime(os.path.join(history_dir, x)), reverse=True)
    
    print("\nSelect a scan result to validate:")
    valid_options = []
    for i, f in enumerate(files, 1):
        filepath = os.path.join(history_dir, f)
        try:
            with open(filepath, "r") as json_f:
                data = json.load(json_f)
                if isinstance(data, dict) and "scan_metadata" in data:
                    meta = data.get("scan_metadata", {})
                    repo = meta.get("repo", "unknown")
                    raw = meta.get("raw_findings", 0)
                    uniq = meta.get("unique_findings", 0)
                    print(f"[{i}] {f}   ({repo}, {raw} raw / {uniq} unique)")
                else:
                    print(f"[{i}] {f}   (Legacy raw format)")
        except Exception:
            print(f"[{i}] {f}   (Invalid format)")
        valid_options.append(filepath)

    choice = input("\nEnter number to validate, or 'q' to cancel:\n> ").strip().lower()
    if choice == 'q':
        return
        
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(valid_options):
            repo_path = input("\nEnter the absolute or relative path to the repository so the LLM can extract code:\n> ").strip().strip('"').strip("'")
            if not repo_path:
                print("Error: Repository path is required to extract context.")
                return
                
            try:
                repo_path = handle_github_repo(repo_path)
            except (ValueError, RuntimeError) as e:
                print(f"[!] Error: {e}")
                return
                
            print("-" * 60)
            print(f"[*] Validating {os.path.basename(valid_options[idx])}...")
            cmd = ["taintlace", "validate", "--input", valid_options[idx], "--repo", repo_path]
            res = subprocess.run(cmd)
            
            if res.returncode == 0:
                print("[*] Rendering updated findings table...\n")
                render_cmd = ["taintlace", "findings", "--input", valid_options[idx]]
                subprocess.run(render_cmd)
                
                print("-" * 60)
                dash_choice = input("\nDo you want to launch the Web Dashboard for these results? [y/N]\n> ").strip().lower()
                if dash_choice == 'y':
                    print("[*] Launching Web Dashboard...")
                    dash_cmd = ["taintlace", "dashboard", "--input", valid_options[idx]]
                    subprocess.run(dash_cmd)
                else:
                    print(f"[*] You can view the dashboard later by running: taintlace dashboard --input {valid_options[idx]}")
        else:
            print("Invalid choice.")
    except ValueError:
        print("Invalid input.")

def command_prove(args):
    args.repo = handle_github_repo(args.repo)
    start_time = time.time()
    if not os.path.exists(args.input):
        print(f"Error: File {args.input} not found.")
        sys.exit(1)
        
    try:
        with open(args.input, "r") as f:
            data = json.load(f)
            
        is_wrapped = isinstance(data, dict) and "findings" in data
        findings = data["findings"] if is_wrapped else data
        
        if hasattr(args, "diff") and args.diff:
            from orchestrator.diff import get_git_diff_lines, filter_findings_by_diff
            diff_map = get_git_diff_lines(args.repo)
            if diff_map is not None:
                findings = filter_findings_by_diff(findings, diff_map)
                
        from orchestrator.prove import run_prove_on_findings
        with console.status("[bold green][Prove] Generating Proof-of-Concept exploits...", spinner="dots"):
            try:
                proved = run_prove_on_findings(findings, args.repo)
            except RuntimeError as e:
                print(f"[Prove] Cannot start PoC generation: {e}")
                print(f"No changes made to {args.input}.")
                return
        
        if is_wrapped:
            data["findings"] = proved
        else:
            data = proved
            
        tmp_file = args.input + ".tmp"
        with open(tmp_file, "w") as f:
            json.dump(data, f, indent=2)
            
        os.replace(tmp_file, args.input)
            
        print(f"\\n[Prove] PoC generation complete in {time.time() - start_time:.2f} seconds.")
        print(f"[Prove] Overwrote {args.input} with generated PoCs.")
        
    except Exception as e:
        print(f"Prove failed: {str(e)}")
        sys.exit(1)

def command_dashboard(args):
    if not os.path.exists(args.input):
        print(f"Error: File {args.input} not found.")
        sys.exit(1)
        
    dashboard_script = os.path.join(os.path.dirname(__file__), "sast-engine", "orchestrator", "dashboard.py")
    try:
        subprocess.run([sys.executable, dashboard_script, args.input])
    except KeyboardInterrupt:
        pass

def command_configure_defectdojo(args=None):
    print("\n" + "=" * 40)
    print("      DefectDojo Secure Configuration")
    print("=" * 40)
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
        
    if not url or not token or not engagement:
        print("[!] Error: URL, API Token, and Engagement ID are all required.")
        return

    # Validate URL structure
    try:
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https') or not parsed_url.netloc:
            print("[!] Error: Invalid DefectDojo URL format. It must start with http:// or https:// and contain a valid hostname.")
            return
    except Exception as e:
        print(f"[!] Error: Failed to parse URL: {e}")
        return

    # Validate Engagement ID format
    try:
        engagement_id_int = int(engagement)
        if engagement_id_int <= 0:
            print("[!] Error: Engagement ID must be a positive integer.")
            return
    except ValueError:
        print("[!] Error: Engagement ID must be a valid integer.")
        return

    # Perform live connection verification
    print("[*] Verifying connection to DefectDojo...")
    clean_url = url.rstrip('/')
    req = urllib.request.Request(f"{clean_url}/api/v2/engagements/{engagement}/")
    req.add_header('Authorization', f'Token {token}')
    req.add_header('Content-Type', 'application/json')
    
    verified = False
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                print("[+] Connection verified successfully. Engagement ID exists.")
                verified = True
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("[!] Verification failed: Unauthorized (HTTP 401). Please check your API Token.")
        elif e.code == 404:
            print(f"[!] Verification failed: Engagement ID {engagement} not found on this DefectDojo instance (HTTP 404).")
        else:
            print(f"[!] Verification failed: DefectDojo returned HTTP error {e.code} ({e.reason}).")
    except urllib.error.URLError as e:
        print(f"[!] Verification failed: Connection could not be established ({e.reason}).")
    except Exception as e:
        print(f"[!] Verification failed: {str(e)}")

    if not verified:
        save_anyway = input("Could not verify credentials. Save them anyway? (y/N): ").strip().lower()
        if save_anyway not in ('y', 'yes'):
            print("[!] Configuration aborted.")
            return

    try:
        keyring.set_password("taintlace_defectdojo", "url", url)
        keyring.set_password("taintlace_defectdojo", "token", token)
        keyring.set_password("taintlace_defectdojo", "engagement_id", engagement)
        print("[+] DefectDojo credentials configured successfully and stored in the system keyring.")
    except Exception as e:
        print(f"[!] Failed to save credentials to system keyring: {e}")


def interactive_mode():
    while True:
        print("\n" + "=" * 60)
        print(r"""
  _____     _       _   _               
 |_   _|_ _(_)_ __ | |_| | __ _  ___ ___ 
   | |/ _` | | '_ \| __| |/ _` |/ __/ _ \
   | | (_| | | | | | |_| | (_| | (_|  __/
   |_|\__,_|_|_| |_|\__|_|\__,_|\___\___|
                                        
 Multi-Stage Agentic SAST Engine""")
        print("=" * 60)
        print("[1] New scan")
        print("[2] View past results")
        print("[3] Validate past results with LLM")
        print("[4] Generate Proof-of-Concept (Prove stage)")
        print("[5] View Dashboard (Web UI)")
        
        has_dd_config = bool(keyring.get_password("taintlace_defectdojo", "url") and keyring.get_password("taintlace_defectdojo", "token"))
        if has_dd_config:
            print("[6] Edit DefectDojo credentials")
        else:
            print("[6] Configure DefectDojo credentials")
        print("[7] Exit")
        
        choice = input("> ").strip()
        
        if choice == '7':
            print("Exiting...")
            break
        elif choice == '6':
            command_configure_defectdojo()
            continue
        elif choice == '5':
            history_dir = "./scan_history"
            if not os.path.exists(history_dir):
                print("No past scans found.")
                continue

            files = [f for f in os.listdir(history_dir) if f.endswith(".json")]
            if not files:
                print("No past scans found.")
                continue

            files.sort(key=lambda x: os.path.getmtime(os.path.join(history_dir, x)), reverse=True)
            
            print("\\nSelect a scan result to view in Dashboard:")
            valid_options = []
            for i, f in enumerate(files, 1):
                filepath = os.path.join(history_dir, f)
                try:
                    with open(filepath, "r") as json_f:
                        data = json.load(json_f)
                        if isinstance(data, dict) and "scan_metadata" in data:
                            meta = data.get("scan_metadata", {})
                            repo = meta.get("repo", "unknown")
                            raw = meta.get("raw_findings", 0)
                            uniq = meta.get("unique_findings", 0)
                            print(f"[{i}] {f}   ({repo}, {raw} raw / {uniq} unique)")
                        else:
                            print(f"[{i}] {f}   (Legacy raw format)")
                except Exception:
                    print(f"[{i}] {f}   (Invalid format)")
                valid_options.append(filepath)

            choice = input("\\nEnter number to view, or 'q' to cancel:\\n> ").strip().lower()
            if choice == 'q':
                continue
                
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(valid_options):
                    print("-" * 60)
                    print(f"[*] Launching Dashboard for {os.path.basename(valid_options[idx])}...")
                    cmd = ["taintlace", "dashboard", "--input", valid_options[idx]]
                    subprocess.run(cmd)
                else:
                    print("Invalid choice.")
            except ValueError:
                print("Invalid input.")
        elif choice == '4':
            history_dir = "./scan_history"
            if not os.path.exists(history_dir):
                print("No past scans found.")
                continue

            files = [f for f in os.listdir(history_dir) if f.endswith(".json")]
            if not files:
                print("No past scans found.")
                continue

            files.sort(key=lambda x: os.path.getmtime(os.path.join(history_dir, x)), reverse=True)
            
            print("\\nSelect a scan result to generate PoCs for:")
            valid_options = []
            for i, f in enumerate(files, 1):
                filepath = os.path.join(history_dir, f)
                try:
                    with open(filepath, "r") as json_f:
                        data = json.load(json_f)
                        if isinstance(data, dict) and "scan_metadata" in data:
                            meta = data.get("scan_metadata", {})
                            repo = meta.get("repo", "unknown")
                            raw = meta.get("raw_findings", 0)
                            uniq = meta.get("unique_findings", 0)
                            print(f"[{i}] {f}   ({repo}, {raw} raw / {uniq} unique)")
                        else:
                            print(f"[{i}] {f}   (Legacy raw format)")
                except Exception:
                    print(f"[{i}] {f}   (Invalid format)")
                valid_options.append(filepath)

            choice = input("\\nEnter number to prove, or 'q' to cancel:\\n> ").strip().lower()
            if choice == 'q':
                continue
                
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(valid_options):
                    repo_path = input("\\nEnter the absolute or relative path to the repository so the LLM can extract code:\\n> ").strip().strip('"').strip("'")
                    if not repo_path:
                        print("Error: Repository path is required to extract context.")
                        continue
                        
                    try:
                        repo_path = handle_github_repo(repo_path)
                    except (ValueError, RuntimeError) as e:
                        print(f"[!] Error: {e}")
                        continue
                        
                    print("-" * 60)
                    print(f"[*] Proving {os.path.basename(valid_options[idx])}...")
                    cmd = ["taintlace", "prove", "--input", valid_options[idx], "--repo", repo_path]
                    res = subprocess.run(cmd)
                    
                    if res.returncode == 0:
                        print("-" * 60)
                        print("[*] Rendering updated findings table...\n")
                        render_cmd = ["taintlace", "findings", "--input", valid_options[idx]]
                        subprocess.run(render_cmd)
                        
                        print("-" * 60)
                        dash_choice = input("\nDo you want to launch the Web Dashboard for these results? [y/N]\n> ").strip().lower()
                        if dash_choice == 'y':
                            print("[*] Launching Web Dashboard...")
                            dash_cmd = ["taintlace", "dashboard", "--input", valid_options[idx]]
                            subprocess.run(dash_cmd)
                        else:
                            print(f"[*] You can view the dashboard later by running: taintlace dashboard --input {valid_options[idx]}")
                else:
                    print("Invalid choice.")
            except ValueError:
                print("Invalid input.")
        elif choice == '3':
            validate_history()
        elif choice == '2':
            browse_history()
        elif choice == '1':
            repo = input("\nEnter the absolute or relative path to the repository to scan:\n> ").strip().strip('"').strip("'")
            if not repo:
                print("Error: Repository path is required.")
                continue
                
            try:
                repo = handle_github_repo(repo)
            except (ValueError, RuntimeError) as e:
                print(f"[!] Error: {e}")
                continue
                
            cpg_name = input("CPG file name (press Enter for default 'cpg.bin'):\n> ").strip()
            if not cpg_name:
                cpg_name = "cpg.bin"
                
            if ".." in cpg_name or "/" in cpg_name or "\\" in cpg_name:
                print("Error: CPG filename cannot contain path traversal or directory characters.")
                continue
                
            cmd = ["taintlace"]
            
            cpg_path = os.path.join(repo, cpg_name)
            manifest_path = os.path.join(repo, "previous_scan_manifest.json")
            c_choice = None
            try:
                from orchestrator.cpg_cache import cpg_cache, get_cache_key
            except ImportError:
                import sys
                sys.path.append(os.path.join(os.path.dirname(__file__), "sast-engine"))
                from orchestrator.cpg_cache import cpg_cache, get_cache_key
                
            cache_key = get_cache_key(repo)
            cached_bin, cached_meta = cpg_cache.get_cached_cpg(repo, cache_key)
            
            if cached_bin and cached_meta:
                built_at = datetime.datetime.fromtimestamp(cached_meta.get("built_at_timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
                print(f"\nExisting cached CPG found for commit {cache_key[:8]} (built {built_at} ago).")
                print("How would you like to proceed?")
                print("[1] Use cached CPG (no code changes detected since this commit)")
                print("[2] Full rebuild (ignore cache, rebuild from scratch)")
                
                c_choice = input("> ").strip()

            verbose = input("\nEnable verbose output? (Y/n):\n> ").strip().lower() != 'n'
            if verbose:
                cmd.insert(1, "--verbose")
                
            default_ts = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
            repo_name = os.path.basename(os.path.abspath(repo))
            default_out = f"findings_{repo_name}_{default_ts}.json"
            
            out_name = input(f"\nOutput file name (press Enter for default):\n> ").strip()
            
            history_dir = "./scan_history"
            if not os.path.exists(history_dir):
                os.makedirs(history_dir)
                
            if not out_name:
                out_name = default_out
            
            if not out_name.endswith(".json"):
                out_name += ".json"
                
            if ".." in out_name or "/" in out_name or "\\" in out_name:
                print("Error: Invalid filename. Cannot contain path traversal characters.")
                continue
                
            final_out_path = os.path.join(history_dir, out_name)
            
            if os.path.exists(final_out_path):
                overwrite = input("File already exists. Overwrite? (y/N)\n> ").strip().lower()
                if overwrite != 'y':
                    print("Scan cancelled.")
                    continue
                    
            cmd.extend(["scan", "--repo", repo, "--output", final_out_path, "--cpg-name", cpg_name])
            
            if c_choice == '2':
                cmd.append("--full-rebuild")
            elif c_choice == '3':
                cmd.append("--skip-prepare")
            
            print(f"\n[*] Running command: {' '.join(cmd)}")
            print("-" * 60)
            
            res = subprocess.run(cmd)
            if res.returncode != 0:
                print("Scan process failed. Check the errors above.")
                continue
            
            print("-" * 60)
            print("[*] Scan complete! Rendering findings table...\n")
            
            render_cmd = ["taintlace", "findings", "--input", final_out_path]
            subprocess.run(render_cmd)
            
            print("-" * 60)
            dash_choice = input("\nDo you want to launch the Web Dashboard for these results? [y/N]\n> ").strip().lower()
            if dash_choice == 'y':
                print("[*] Launching Web Dashboard...")
                dash_cmd = ["taintlace", "dashboard", "--input", final_out_path]
                subprocess.run(dash_cmd)
            else:
                print(f"[*] You can view the dashboard later by running: taintlace dashboard --input {final_out_path}")
        else:
            print("Invalid choice.")


def handle_github_repo(repo_input):
    if not repo_input or not isinstance(repo_input, str):
        return repo_input
        
    repo_input_stripped = repo_input.strip()
    
    # Pre-clean trailing slashes and .git suffix
    url_clean = repo_input_stripped.rstrip('/')
    if url_clean.lower().endswith('.git'):
        url_clean = url_clean[:-4]
    
    # Strictly detect GitHub URLs: HTTP, HTTPS, SSH, git@ formats
    github_url_pattern = re.compile(
        r'^(?:https?://(?:www\.)?github\.com/|git@github\.com:|ssh://git@github\.com/)'
        r'([a-zA-Z0-9-]{1,39})/([a-zA-Z0-9._-]{1,100})$',
        re.IGNORECASE
    )
    
    match = github_url_pattern.match(url_clean)
    if not match:
        return repo_input
        
    owner, repo_name = match.groups()
    
    # Further validation to prevent any directory traversal or escaping
    if ".." in owner or "/" in owner or "\\" in owner or owner.startswith(".") or owner.startswith("/"):
        raise ValueError(f"Invalid owner format in GitHub URL: {owner}")
    if ".." in repo_name or "/" in repo_name or "\\" in repo_name or repo_name.startswith(".") or repo_name.startswith("/"):
        raise ValueError(f"Invalid repository name format in GitHub URL: {repo_name}")
        
    print(f"[*] GitHub repository detected: {repo_input_stripped}")
    
    # Verify Git is installed
    if not shutil.which("git"):
        raise RuntimeError("Git is not installed or is not available in PATH.\nPlease install Git and restart the terminal.")
        
    # Local path layout relative to cli.py
    cli_dir = Path(__file__).resolve().parent
    cloned_repos_dir = cli_dir / "cloned_repos"
    local_repo = cloned_repos_dir / owner / repo_name
    
    # Create cloned_repos/<owner> if not existing
    local_repo.parent.mkdir(parents=True, exist_ok=True)
    
    # Try to make output path relative for cleaner console logging
    try:
        rel_display_path = os.path.relpath(local_repo, os.getcwd())
    except ValueError:
        rel_display_path = str(local_repo)
        
    if local_repo.exists():
        # Check if it is a valid git repository
        try:
            subprocess.run(
                ["git", "-C", str(local_repo), "rev-parse", "--is-inside-work-tree"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            raise RuntimeError(f"The clone destination already exists but is not a valid Git repository:\n{local_repo}")
            
        print(f"[*] Existing clone found: {rel_display_path}")
        print("[*] Updating repository with git pull...")
        try:
            subprocess.run(
                ["git", "-C", str(local_repo), "pull"],
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[!] Warning: Git pull failed: {e}")
            print("[*] Proceeding with existing code state.")
    else:
        print(f"[*] Cloning repository...")
        try:
            subprocess.run(
                ["git", "clone", repo_input_stripped, str(local_repo)],
                check=True
            )
            print(f"[*] Repository cloned to: {rel_display_path}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to clone repository: {e}")
            
    # Return path as relative to CWD if possible (same as normal local paths)
    try:
        return os.path.relpath(local_repo, os.getcwd())
    except ValueError:
        return str(local_repo)

def get_config_names():
    config_path = os.path.join(os.path.dirname(__file__), "sast-engine", "config", "sinks_sources.yaml")
    names = set()
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            for cat, data in config.items():
                for lst in ["sources", "sinks", "sanitizers"]:
                    for pat in data.get(lst, []):
                        if isinstance(pat, dict):
                            pat = pat.get("pattern", "")
                        cleaned = pat.replace(".*", "").replace("\\.", ".").replace("\\", "")
                        for p in cleaned.split("."):
                            if p:
                                names.add(p)
    except Exception:
        pass
    return names

def command_scan(args):
    args.repo = handle_github_repo(args.repo)
    start_time = time.time()
    
    # --- Smart Routing Logic ---
    force = getattr(args, "full_rebuild", False) or getattr(args, "no_cache", False)
    
    if not shutil.which("git"):
        print("[SMART-ROUTER]")
        print("Reason: GIT_NOT_AVAILABLE")
        print("Strategy: FULL_CPG_BUILD")
        force = True

    if not force:
        try:
            from orchestrator.diff import get_git_diff_lines
            from orchestrator.impact_analyzer import analyze_impact
            
            diff_map = get_git_diff_lines(args.repo)
            if diff_map:
                strategy, reason, files_changed, functions_changed = analyze_impact(args.repo, diff_map)
                
                if strategy == "SAFE_LOCAL":
                    print("[SMART-ROUTER]")
                    print(f"Files changed: {files_changed}")
                    print(f"Functions changed: {functions_changed}")
                    print(f"Impact: SAFE_LOCAL")
                    print("Strategy: DIFF_LOCAL")
                    try:
                        return command_scan_diff(args)
                    except Exception as e:
                        print("[SMART-ROUTER]")
                        print(f"Reason: DIFF_SCAN_FAILED ({e})")
                        print("Strategy: FULL_SCAN")
                        # fall through to FULL_SCAN
                else:
                    print("[SMART-ROUTER]")
                    print(f"Files changed: {files_changed}")
                    print(f"Reason: {reason}")
                    print("Strategy: FULL_SCAN")
            else:
                print("[SMART-ROUTER]")
                print("Reason: NO_DIFF_DETECTED")
                print("Strategy: FULL_SCAN")
        except Exception as e:
            print("[SMART-ROUTER]")
            print(f"Reason: IMPACT_ANALYSIS_UNCERTAIN ({e})")
            print("Strategy: FULL_SCAN")
    # ---------------------------
    
    repo_name = os.path.basename(os.path.abspath(args.repo))
    workspace_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".taintlace", "workspace", repo_name)
    os.makedirs(workspace_dir, exist_ok=True)
    cpg_path = os.path.join(workspace_dir, args.cpg_name)
    
    try:
        if not args.skip_prepare:
            force = getattr(args, "full_rebuild", False) or getattr(args, "no_cache", False)
            with console.status(f"[bold green][Prepare] Building CPG for {args.repo}...", spinner="dots"):
                if force:
                    success = build_full_cpg(args.repo, cpg_path)
                else:
                    success = build_or_update_cpg(args.repo, cpg_path, force_rebuild=force)
                
            if not success:
                print("Error: Prepare stage failed.")
                sys.exit(1)
        else:
            if args.verbose:
                print(f"[Prepare] Skipping CPG build (--skip-prepare). Reusing existing {args.cpg_name} directly.")
            if not os.path.exists(cpg_path):
                print(f"Error: CPG file not found at {cpg_path}. Cannot skip prepare.")
                sys.exit(1)
            
        with console.status("[bold green][Scan] Running queries across CPG...", spinner="dots"):
            raw_findings, telemetry = run_scan(args.repo, cpg_name=args.cpg_name)
        
        with console.status(f"[bold green][Scan] Found {len(raw_findings)} raw findings. Running chain detection...", spinner="dots"):
            chained_findings = detect_chains(raw_findings)
        
        with console.status("[bold green][Dedupe] Grouping and anonymizing findings...", spinner="dots"):
            config_names = get_config_names()
            grouped = group_findings(chained_findings, config_names)
            
            # Ensure we deduplicate by physical location before validation and saving
            try:
                from orchestrator.dedupe_anonymize import dedupe_by_location
                grouped = dedupe_by_location(grouped)
            except ImportError:
                pass
            
            if hasattr(args, "diff") and args.diff:
                from orchestrator.diff import get_git_diff_lines, filter_findings_by_diff
                diff_map = get_git_diff_lines(args.repo)
                if diff_map is not None:
                    grouped = filter_findings_by_diff(grouped, diff_map)
                
        from orchestrator.cascade import run_cascade_on_findings
        force_reval = getattr(args, "revalidate", False)
        with console.status("[bold green][Validate] Running LLM Cascade Validation...", spinner="dots"):
            grouped = run_cascade_on_findings(grouped, args.repo, force_revalidate=force_reval)
            
        # Run Prove Stage
        from orchestrator.prove import run_prove_on_findings
        with console.status("[bold green][Prove] Generating Proof-of-Concept exploits...", spinner="dots"):
            grouped = run_prove_on_findings(grouped, args.repo)
            
        # Push findings to DefectDojo automatically
        defectdojo_url = ""
        engagement_id = None
        try:
            from integrations.defectdojo.client import DefectDojoClient
            dd_client = DefectDojoClient()
            if dd_client.is_configured():
                with console.status("[bold green][DefectDojo] Uploading findings to DefectDojo...", spinner="dots"):
                    prod_id = dd_client.get_or_create_product(repo_name)
                    engagement_id = dd_client.get_or_create_engagement(prod_id, repo_name)
                    pushed = dd_client.push_findings(engagement_id, grouped, repo_name)
                    defectdojo_url = f"{dd_client.url}/engagement/{engagement_id}"
                    print(f"\n[DefectDojo] Successfully imported/updated {len(pushed)} findings.")
            else:
                print("\n[DefectDojo] Warning: DefectDojo URL or Token not configured. Skipping upload.")
        except Exception as e:
            print(f"\n[DefectDojo] Error: Failed to upload findings to DefectDojo: {e}")
        
        chains_count = len(set(f["chain_id"] for f in raw_findings if f.get("chain_id")))
        
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        repo_name = os.path.basename(os.path.abspath(args.repo))
        
        output_data = {
            "scan_metadata": {
                "repo": repo_name,
                "timestamp": timestamp,
                "raw_findings": len(raw_findings),
                "unique_findings": len(grouped),
                "scan_type": getattr(args, "scan_type", "full"),
                "per_rule_stats": telemetry,
                "defectdojo_engagement_id": str(engagement_id) if engagement_id else None
            },
            "findings": grouped
        }
        
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
            
        # Write previous_scan_manifest.json to the workspace directory
        manifest_path = os.path.join(workspace_dir, "previous_scan_manifest.json")
        try:
            current_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=args.repo, check=True, capture_output=True, text=True).stdout.strip()
            manifest_data = {
                "last_scanned_commit": current_commit,
                "timestamp": timestamp
            }
            with open(manifest_path, "w") as mf:
                json.dump(manifest_data, mf)
        except Exception:
            pass # Not a git repo or failed to write
            
        print("\n=== Scan Summary ===")
        print(f"Raw findings: {len(raw_findings)}")
        print(f"Unique grouped findings: {len(grouped)}")
        print(f"Detected chains: {chains_count}")
        print(f"Total runtime: {time.time() - start_time:.2f} seconds")
        print(f"Output saved to: {args.output}")
        if defectdojo_url:
            print(f"DefectDojo Engagement: {defectdojo_url}")
            print("Human verification and SLA: Managed by DefectDojo.")
        
        if getattr(args, "ci", False):
            valid_findings = [f for f in grouped if f.get("verdict") == "VALID"]
            if len(valid_findings) > 0:
                print(f"\n[!] CI/CD Check Failed: {len(valid_findings)} VALID vulnerabilities were detected.")
                sys.exit(1)
            
    except Exception as e:
        print(f"Pipeline failed: {str(e)}")
        sys.exit(1)

def command_prepare(args):
    args.repo = handle_github_repo(args.repo)
    start_time = time.time()
    cpg_path = os.path.abspath(os.path.join(args.repo, args.cpg_name))
    try:
        if args.verbose:
            print(f"[Prepare] Building CPG for {args.repo}...")
            
        force = getattr(args, "full_rebuild", False) or getattr(args, "no_cache", False)
        if force:
            success = build_full_cpg(args.repo, cpg_path)
        else:
            success = build_or_update_cpg(args.repo, cpg_path, force_rebuild=force)
            
        if not success:
            print("Error: Prepare stage failed.")
            sys.exit(1)
            
        print(f"\nPrepare stage completed.")
        print(f"CPG Path: {cpg_path}")
        print(f"Build time: {time.time() - start_time:.2f} seconds")
    except Exception as e:
        print(f"Prepare stage failed: {str(e)}")
        sys.exit(1)

def command_scan_diff(args):
    args.repo = handle_github_repo(args.repo)
    start_time = time.time()
    repo_path = os.path.abspath(args.repo)
    
    try:
        from orchestrator.diff_scanner import run_diff_scan
    except ImportError:
        import sys
        sys.path.append(os.path.join(os.path.dirname(__file__), "sast-engine"))
        from orchestrator.diff_scanner import run_diff_scan

    try:
        with console.status("[bold green][Diff Scan] Running diff-scoped scan...", spinner="dots"):
            findings, telemetry = run_diff_scan(repo_path)
        if findings:
            with console.status(f"[bold green][Diff Scan] Found {len(findings)} intra-file findings. Deduping...", spinner="dots"):
                # We can run dedupe/cascade here if requested, but for now we output it directly.
                from orchestrator.dedupe_anonymize import dedupe_and_anonymize
                grouped = dedupe_and_anonymize(findings, repo_path)
            
            if getattr(args, 'revalidate', False) or (not getattr(args, 'skip_cascade', False)):
                from orchestrator.cascade import run_cascade_on_findings
                force_reval = getattr(args, "revalidate", False)
                with console.status("[bold green][Validate] Running LLM Cascade Validation...", spinner="dots"):
                    grouped = run_cascade_on_findings(grouped, repo_path, force_revalidate=force_reval)
            
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
            repo_name = os.path.basename(repo_path)
            
            output_data = {
                "scan_metadata": {
                    "repo": repo_name,
                    "timestamp": timestamp,
                    "raw_findings": len(findings),
                    "unique_findings": len(grouped),
                    "scan_type": "diff-scoped"
                },
                "findings": grouped
            }
            
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w") as f:
                json.dump(output_data, f, indent=2)
                
            print(f"[Diff Scan] Wrote findings to {args.output}")
        else:
            print("[Diff Scan] No findings or falling back to full scan.")
    except Exception as e:
        print(f"Diff scan failed: {str(e)}")
        raise e

    if getattr(args, "ci", False):
        valid_findings = [f for f in grouped if f.get("verdict") == "VALID"]
        if len(valid_findings) > 0:
            print(f"\n[!] CI/CD Check Failed: {len(valid_findings)} VALID vulnerabilities were detected.")
            sys.exit(1)

def command_inspect_cpg(args):
    args.repo = handle_github_repo(args.repo)
    repo_name = os.path.basename(os.path.abspath(args.repo))
    workspace_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".taintlace", "workspace", repo_name)
    cpg_path = os.path.join(workspace_dir, "cpg.bin")
    if not os.path.exists(cpg_path):
        # Fallback for older scans
        cpg_path = os.path.abspath(os.path.join(args.repo, "cpg.bin"))
        if not os.path.exists(cpg_path):
            print(f"Error: CPG file not found at {cpg_path}")
            sys.exit(1)
        
    script_path = os.path.join(os.path.dirname(__file__), "sast-engine", "queries", "inspect.sc")
    cmd = f'joern --script {script_path} --param cpg_path="{cpg_path.replace("\\\\", "/")}"'
    
    try:
        with console.status(f"[bold green]Running Joern inspect script on {cpg_path}...", spinner="dots"):
            output = subprocess.run(cmd, check=True, capture_output=True, text=True, shell=True).stdout
        
        in_metadata = False
        for line in output.splitlines():
            if line.startswith("METADATA_START"):
                in_metadata = True
                continue
            if line.startswith("METADATA_END"):
                in_metadata = False
                continue
            if in_metadata:
                print(line)
                
    except subprocess.CalledProcessError as e:
        print(f"Inspect failed: {e.stderr}")
        sys.exit(1)

def command_validate_config(args):
    config_path = args.config
    if not config_path:
        config_path = os.path.join(os.path.dirname(__file__), "sast-engine", "config", "sinks_sources.yaml")
        
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            
        if not isinstance(config, dict):
            print("Error: Config must be a YAML dictionary.")
            sys.exit(1)
            
        from rich.table import Table
        table = Table(show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Category", style="cyan")
        table.add_column("Sources", style="blue")
        table.add_column("Sinks", style="blue")
        table.add_column("Sanitizers", style="green")
        
        for category, data in config.items():
            sources = len(data.get("sources", []))
            sinks = len(data.get("sinks", []))
            sanitizers = len(data.get("sanitizers", []))
            
            if sources == 0 or sinks == 0:
                print(f"Error: Category '{category}' has empty sources or sinks.")
                sys.exit(1)
                
            table.add_row(category, str(sources), str(sinks), str(sanitizers))
            
        console.print(table)
        print("\nConfig validation passed.")
    except Exception as e:
        print(f"Failed to validate config: {str(e)}")
        sys.exit(1)

def command_findings(args):
    from rich.table import Table
    try:
        with open(args.input, "r") as f:
            data = json.load(f)
            
        if isinstance(data, dict) and "findings" in data:
            findings = data["findings"]
        else:
            findings = data
            
        table = Table(show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Category", style="cyan")
        table.add_column("Subtype", style="blue")
        table.add_column("Verdict")
        table.add_column("Conf", justify="right")
        table.add_column("Severity", justify="center")
        table.add_column("Priority", justify="center")
        table.add_column("SLA", justify="center")
        table.add_column("PoC", justify="center")
        table.add_column("Source Location", style="dim", overflow="fold")
        table.add_column("Sink Location", style="dim", overflow="fold")
        
        for f in findings:
            if args.category and f.get("category") != args.category:
                continue
            
            chain_id = f.get("chain_id")
            if args.chains_only and not chain_id:
                continue
                
            cat = f.get("category", "")
            sub = f.get("subtype", "UNKNOWN")
            verdict = f.get("verdict", "N/A")
            conf = f"{f.get('verdict_confidence', 0.0):.2f}"
            
            # Backfill severity, priority, SLA if missing (for backwards compatibility)
            if "severity" not in f:
                try:
                    from risk.priority_policy import determine_severity, get_priority, get_sla_days
                    f["severity"] = determine_severity(f)
                    f["priority"] = get_priority(f)
                    f["sla_days"] = get_sla_days(f["priority"])
                except Exception:
                    pass
                    
            sev = f.get("severity", "Medium")
            prio = f.get("priority", "P3")
            sla_val = f.get("sla_days")
            sla = f"{sla_val}d" if sla_val is not None else "14d"
            
            poc = f.get("proof_of_concept") or f.get("generated_poc")
            has_poc = "No"
            if isinstance(poc, dict):
                is_available = poc.get("available")
                has_input = "input" in poc and poc["input"]
                has_payload = "payload" in poc and poc["payload"]
                if (is_available is not False) and (has_input or has_payload):
                    has_poc = "Yes"
            elif isinstance(poc, str) and poc.strip():
                has_poc = "Yes"
            
            instances = f.get("instances", [])
            if instances:
                inst = instances[0]
                src = f"{inst.get('source_file')}:{inst.get('source_line')}"
                snk = f"{inst.get('sink_file')}:{inst.get('sink_line')}"
            else:
                src = "unknown"
                snk = "unknown"
                
            # Add colorful verdicts
            verdict_display = verdict
            if verdict == "VALID":
                verdict_display = f"[bold red]{verdict}[/bold red]"
            elif verdict == "FALSE_POSITIVE":
                verdict_display = f"[bold green]{verdict}[/bold green]"
            elif verdict == "NEEDS_REVIEW":
                verdict_display = f"[bold yellow]{verdict}[/bold yellow]"
                
            table.add_row(cat, sub, verdict_display, conf, sev, prio, sla, has_poc, src, snk)
            
        console.print(table)
            
    except Exception as e:
        print(f"Failed to render findings: {str(e)}")
        sys.exit(1)

def command_validate(args):
    args.repo = handle_github_repo(args.repo)
    start_time = time.time()
    if not os.path.exists(args.input):
        print(f"Error: File {args.input} not found.")
        sys.exit(1)
        
    try:
        with open(args.input, "r") as f:
            data = json.load(f)
            
        is_wrapped = isinstance(data, dict) and "findings" in data
        findings = data["findings"] if is_wrapped else data
        
        # Deduplicate before sending to LLM
        try:
            from orchestrator.dedupe_anonymize import dedupe_by_location
            findings = dedupe_by_location(findings)
        except ImportError:
            pass
        
        if hasattr(args, "diff") and args.diff:
            from orchestrator.diff import get_git_diff_lines, filter_findings_by_diff
            diff_map = get_git_diff_lines(args.repo)
            if diff_map is not None:
                findings = filter_findings_by_diff(findings, diff_map)
                
        from orchestrator.cascade import run_cascade_on_findings
        with console.status("[bold green][Validate] Running LLM Cascade Validation...", spinner="dots"):
            try:
                force_reval = getattr(args, "revalidate", False)
                validated = run_cascade_on_findings(findings, args.repo, force_revalidate=force_reval)
            except RuntimeError as e:
                print(f"[Cascade] Cannot start validation: {e}")
                print(f"No changes made to {args.input}.")
                return
        
        if is_wrapped:
            data["findings"] = validated
        else:
            data = validated
            
        tmp_file = args.input + ".tmp"
        with open(tmp_file, "w") as f:
            json.dump(data, f, indent=2)
            
        os.replace(tmp_file, args.input)
            
        print(f"\n[Validate] Validation complete in {time.time() - start_time:.2f} seconds.")
        print(f"[Validate] Overwrote {args.input} with LLM results.")
        
    except Exception as e:
        print(f"Validation failed: {str(e)}")
        sys.exit(1)

def command_server(args):
    try:
        from orchestrator.server import JoernServer
    except ImportError:
        import sys
        sys.path.append(os.path.join(os.path.dirname(__file__), "sast-engine"))
        from orchestrator.server import JoernServer
        
    server = JoernServer()
    if args.action == "start":
        server.start()
    elif args.action == "stop":
        server.stop()
    elif args.action == "status":
        server.status()

def command_cache(args):
    if args.action == "clear":
        try:
            from orchestrator.cpg_cache import cpg_cache
        except ImportError:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), "sast-engine"))
            from orchestrator.cpg_cache import cpg_cache
        cpg_cache.clear()
        print("CPG cache cleared.")
    elif args.action == "clear-cascade":
        try:
            from orchestrator.cascade_cache import cascade_cache
        except ImportError:
            import sys
            sys.path.append(os.path.join(os.path.dirname(__file__), "sast-engine"))
            from orchestrator.cascade_cache import cascade_cache
        cascade_cache.clear()
        print("Cascade cache cleared.")

def command_tokenize(args):
    import json
    import os
    import sys
    
    # Ensure sast-engine is importable
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "sast-engine")))
    from llm.tokenizer import BPEWithLearningTokenizer
    
    if not os.path.exists(args.input):
        print(f"Error: File {args.input} not found.")
        sys.exit(1)
        
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        is_wrapped = isinstance(data, dict) and "findings" in data
        findings = data["findings"] if is_wrapped else data
        
        tokenizer = BPEWithLearningTokenizer()
        
        print(f"[*] Loaded {len(findings)} findings from {args.input}")
        
        # Track statistics
        total_chars = 0
        total_tokens = 0
        all_token_strings = []
        all_token_ids = []
        
        for i, finding in enumerate(findings):
            tokens, token_ids, norm_text = tokenizer.tokenize(finding)
            total_chars += len(norm_text)
            total_tokens += len(token_ids)
            all_token_strings.extend(tokens)
            all_token_ids.extend(token_ids)
            
        # Run dynamic learning
        with console.status("[bold green][Tokenize] Running BPE dynamic learning on findings...", spinner="dots"):
            promoted = tokenizer.learn_from_findings(findings)
        
        print("\n=== Tokenizer Summary ===")
        print(f"Total Character Count (Normalized): {total_chars}")
        print(f"Total Token Count (After BPE):      {total_tokens}")
        if total_tokens > 0:
            compression_ratio = total_chars / total_tokens
            print(f"Compression Ratio:                  {compression_ratio:.2f}x")
        else:
            print("Compression Ratio:                  N/A")
            
        # Analyze learned patterns hits
        learned_hits = [t for t in all_token_strings if t.startswith("[") and t.endswith("]")]
        print(f"Learned Vocabulary Hits:            {len(learned_hits)}")
        if learned_hits:
            from collections import Counter
            counts = Counter(learned_hits)
            print("Top Learned Pattern Hits:")
            for tok, count in counts.most_common(5):
                print(f"  {tok}: {count} times")
                
        if promoted:
            print(f"\n[+] Promoted {len(promoted)} new patterns to learned_vocabulary.json:")
            for pattern, tok, tid in promoted[:10]:
                truncated = pattern[:50] + "..." if len(pattern) > 50 else pattern
                print(f"  {tok} (ID: {tid}): \"{truncated}\"")
            if len(promoted) > 10:
                print(f"  ... and {len(promoted) - 10} more.")
        else:
            print("\n[*] No new patterns promoted during this run (frequency threshold < 10 or already promoted).")
            
    except Exception as e:
        print(f"Tokenization failed: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Taintlace - Multi-Stage Agentic SAST Engine")
    parser.add_argument("--verbose", action="store_true", help="Print stage-by-stage progress")
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommands")
    
    # scan
    scan_p = subparsers.add_parser("scan", help="Run the full SAST pipeline")
    scan_p.add_argument("--repo", required=True, help="Path to the target repository to scan")
    scan_p.add_argument("--cpg-name", default="cpg.bin", help="Name of the CPG file to generate or reuse (default: cpg.bin)")
    scan_p.add_argument("--full-rebuild", action="store_true", help="Force a full CPG rebuild")
    scan_p.add_argument("--no-cache", action="store_true", help="Force a fresh full rebuild even if a cache entry exists")
    scan_p.add_argument("--skip-prepare", action="store_true", help="Skip CPG build and reuse existing CPG directly")
    scan_p.add_argument("--output", default="./findings_output.json", help="Path to write the final deduped findings JSON")
    scan_p.add_argument("--diff", action="store_true", help="Filter findings to only those that touch modified lines in git diff")
    scan_p.add_argument("--revalidate", action="store_true", help="Force LLM re-validation even if result is cached")
    scan_p.add_argument("--ci", action="store_true", help="Run in CI mode (exits with code 1 if VALID vulnerabilities are found)")
    scan_p.set_defaults(func=command_scan)
    
    # scan-diff
    scan_diff_p = subparsers.add_parser("scan-diff", help="Run the lightweight Diff-Scoped Incremental Taint Pipeline")
    scan_diff_p.add_argument("--repo", required=True, help="Path to the target repository to scan")
    scan_diff_p.add_argument("--output", default="./findings_output.json", help="Path to write the findings JSON")
    scan_diff_p.add_argument("--skip-cascade", action="store_true", help="Skip LLM validation")
    scan_diff_p.add_argument("--revalidate", action="store_true", help="Force LLM re-validation even if result is cached")
    scan_diff_p.add_argument("--ci", action="store_true", help="Run in CI mode (exits with code 1 if VALID vulnerabilities are found)")
    scan_diff_p.set_defaults(func=command_scan_diff)
    
    # prepare
    prepare_p = subparsers.add_parser("prepare", help="Run only the Prepare stage (CPG generation)")
    prepare_p.add_argument("--repo", required=True, help="Path to the target repository")
    prepare_p.add_argument("--cpg-name", default="cpg.bin", help="Name of the CPG file to generate (default: cpg.bin)")
    prepare_p.add_argument("--full-rebuild", action="store_true", help="Force a full CPG rebuild")
    prepare_p.add_argument("--no-cache", action="store_true", help="Force a fresh full rebuild even if a cache entry exists")
    prepare_p.set_defaults(func=command_prepare)
    
    # inspect-cpg
    inspect_p = subparsers.add_parser("inspect-cpg", help="Inspect an existing CPG file for sanity checks")
    inspect_p.add_argument("--repo", required=True, help="Path to the target repository containing cpg.bin")
    inspect_p.set_defaults(func=command_inspect_cpg)
    
    # validate
    val_p = subparsers.add_parser("validate", help="Validate an existing findings JSON using the LLM Cascade")
    val_p.add_argument("--input", required=True, help="Path to the findings JSON file")
    val_p.add_argument("--repo", required=True, help="Path to the original repository for context extraction")
    val_p.add_argument("--diff", action="store_true", help="Filter findings to only those that touch modified lines in git diff")
    val_p.add_argument("--revalidate", action="store_true", help="Force LLM re-validation even if result is cached")
    val_p.set_defaults(func=command_validate)
    
    # prove
    prove_p = subparsers.add_parser("prove", help="Generate Proof-of-Concept exploits for VALID/NEEDS_REVIEW findings")
    prove_p.add_argument("--input", required=True, help="Path to the findings JSON file")
    prove_p.add_argument("--repo", required=True, help="Path to the original repository for context extraction")
    prove_p.add_argument("--diff", action="store_true", help="Filter findings to only those that touch modified lines in git diff")
    prove_p.set_defaults(func=command_prove)
    
    # validate-config
    val_conf_p = subparsers.add_parser("validate-config", help="Validate the sinks_sources.yaml configuration")
    val_conf_p.add_argument("--config", help="Path to a custom config file (default: config/sinks_sources.yaml)")
    val_conf_p.set_defaults(func=command_validate_config)
    
    # findings
    find_p = subparsers.add_parser("findings", help="Render findings from a generated JSON file")
    find_p.add_argument("--input", required=True, help="Path to the findings JSON file")
    find_p.add_argument("--category", help="Filter by vulnerability category")
    find_p.add_argument("--chains-only", action="store_true", help="Show only findings that are part of a chain")
    find_p.set_defaults(func=command_findings)
    
    # dashboard
    dash_p = subparsers.add_parser("dashboard", help="Start the Web UI Dashboard")
    dash_p.add_argument("--input", required=True, help="Path to the findings JSON file to visualize")
    dash_p.set_defaults(func=command_dashboard)
    
    # server
    server_p = subparsers.add_parser("server", help="Manage the persistent Joern server")
    server_p.add_argument("action", choices=["start", "stop", "status"], help="Action to perform")
    server_p.set_defaults(func=command_server)
    
    # cache
    cache_p = subparsers.add_parser("cache", help="Manage taintlace caches")
    cache_p.add_argument("action", choices=["clear", "clear-cascade"], help="Action to perform")
    cache_p.set_defaults(func=command_cache)
    
    # tokenize
    tok_p = subparsers.add_parser("tokenize", help="Run the multi-stage BPE tokenizer and dynamic learning on findings")
    tok_p.add_argument("--input", required=True, help="Path to findings JSON file")
    tok_p.set_defaults(func=command_tokenize)
    
    # configure-defectdojo
    dd_conf_p = subparsers.add_parser("configure-defectdojo", help="Configure DefectDojo credentials securely")
    dd_conf_p.set_defaults(func=command_configure_defectdojo)
    
    if len(sys.argv) == 1:
        while True:
            try:
                interactive_mode()
                break
            except KeyboardInterrupt:
                print("\n[!] Process interrupted. Returning to main menu...")
        return

    args = parser.parse_args()
    try:
        args.func(args)
    except (RuntimeError, ValueError) as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
