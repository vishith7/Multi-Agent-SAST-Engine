import os
import subprocess
import re
import fnmatch

NEW_FILE_LINE_THRESHOLD = 400

SKIP_PATTERNS = [
    "*.lock", "*.min.js", "*_pb2.py", "*.generated.*",
    "dist/*", "build/*", "vendor/*", "node_modules/*",
    "*.egg-info/*", "__pycache__/*"
]

def get_git_diff_lines(repo_path):
    repo_path = os.path.abspath(repo_path)
    diff_map = {}

    # 1. Get changed lines from staged and unstaged files
    try:
        result = subprocess.run(
            ["git", "diff", "HEAD", "-U0", "-M"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        diff_output = result.stdout
    except Exception as e:
        print(f"[Diff] Warning: Failed to run git diff (is it a git repo?): {e}")
        return None

    current_file = None
    for line in diff_output.splitlines():
        if line.startswith("diff --git"):
            parts = line.split(" ")
            if len(parts) >= 4:
                file_b = parts[3]
                if file_b.startswith("b/"):
                    current_file = os.path.normpath(file_b[2:])
                    diff_map[current_file] = set()
        elif line.startswith("@@") and current_file:
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if match:
                start_line = int(match.group(1))
                count = int(match.group(2)) if match.group(2) is not None else 1
                if count == 0:
                    diff_map[current_file].add(start_line)
                else:
                    for l in range(start_line, start_line + count):
                        diff_map[current_file].add(l)

    # 2. Get untracked files and add them according to rules
    try:
        untracked_result = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        untracked_output = untracked_result.stdout
        for rel_path in untracked_output.splitlines():
            rel_path = os.path.normpath(rel_path.strip())
            if not rel_path:
                continue

            # Check if matching skip patterns using fnmatch
            is_skipped = False
            for pat in SKIP_PATTERNS:
                if fnmatch.fnmatch(rel_path.replace("\\", "/"), pat) or fnmatch.fnmatch(os.path.basename(rel_path), pat):
                    is_skipped = True
                    print(f"[Diff] Debug: Skipping untracked file {rel_path} matching pattern {pat}")
                    break
            
            if is_skipped:
                continue

            full_path = os.path.join(repo_path, rel_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        line_count = len(f.readlines())
                except Exception:
                    line_count = 10000  # fallback

                if line_count < NEW_FILE_LINE_THRESHOLD:
                    diff_map[rel_path] = {"all_flagged": True, "lines": set(range(1, line_count + 1))}
                    print(f"[Diff] Added new untracked file (full): {rel_path} (lines 1-{line_count})")
                else:
                    diff_map[rel_path] = {"all_flagged": False, "reason": "large_new_file", "line_count": line_count}
                    print(f"[Diff] Added new untracked file (large): {rel_path} (threshold {NEW_FILE_LINE_THRESHOLD} exceeded, line count {line_count})")
    except Exception as e:
        print(f"[Diff] Warning: Failed to retrieve untracked files: {e}")

    return diff_map

def filter_findings_by_diff(findings, diff_map):
    if diff_map is None:
        return findings

    normalized_diff_map = {os.path.normpath(k): v for k, v in diff_map.items()}

    def get_match_origin(filepath, line):
        if not filepath:
            return None
        norm_path = os.path.normpath(filepath)
        if norm_path not in normalized_diff_map:
            return None

        val = normalized_diff_map[norm_path]
        if isinstance(val, set):
            if line in val:
                return "modified_line"
        elif isinstance(val, dict):
            if val.get("all_flagged") is True:
                if line in val.get("lines", set()):
                    return "new_file_full"
            elif val.get("all_flagged") is False and val.get("reason") == "large_new_file":
                return "large_new_file"
        return None

    filtered = []
    for f in findings:
        best_origin = None

        # Helper to update best_origin with highest priority:
        # modified_line > new_file_full > large_new_file
        def check_node(file_path, line_no):
            nonlocal best_origin
            origin = get_match_origin(file_path, line_no)
            if not origin:
                return
            if origin == "modified_line":
                best_origin = "modified_line"
            elif origin == "new_file_full" and best_origin != "modified_line":
                best_origin = "new_file_full"
            elif origin == "large_new_file" and best_origin not in ["modified_line", "new_file_full"]:
                best_origin = "large_new_file"

        # Check main source/sink
        src_file = f.get("source_file")
        src_line = f.get("source_line", -1)
        snk_file = f.get("sink_file")
        snk_line = f.get("sink_line", -1)
        
        check_node(src_file, src_line)
        check_node(snk_file, snk_line)

        # Check instances
        for inst in f.get("instances", []):
            check_node(inst.get("source_file"), inst.get("source_line", -1))
            check_node(inst.get("sink_file"), inst.get("sink_line", -1))

        # Check path nodes
        for node in f.get("path", []):
            check_node(node.get("file"), node.get("line", -1))

        if best_origin:
            f["in_diff"] = True
            f["diff_origin"] = best_origin
            filtered.append(f)

    print(f"[Diff] Retained {len(filtered)} findings out of {len(findings)} intersecting modified lines.")
    return filtered

if __name__ == "__main__":
    import tempfile
    import shutil

    print("Running diff.py self-tests...")
    temp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(["git", "init"], cwd=temp_dir, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=temp_dir, check=True)

        init_file = os.path.join(temp_dir, "init.txt")
        with open(init_file, "w") as f:
            f.write("initial")
        subprocess.run(["git", "add", "init.txt"], cwd=temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=temp_dir, check=True)

        small_file_path = os.path.join(temp_dir, "small.py")
        with open(small_file_path, "w") as f:
            f.write("print('hello')\n" * 10)

        large_file_path = os.path.join(temp_dir, "large.py")
        with open(large_file_path, "w") as f:
            f.write("print('hello')\n" * 450)

        skip_file_path = os.path.join(temp_dir, "package.lock")
        with open(skip_file_path, "w") as f:
            f.write("should be skipped")

        diff_map = get_git_diff_lines(temp_dir)
        print("Parsed diff map keys:", list(diff_map.keys()))

        assert "small.py" in diff_map, "small.py should be in diff_map"
        assert diff_map["small.py"]["all_flagged"] is True, "small.py should be fully flagged"
        
        assert "large.py" in diff_map, "large.py should be in diff_map"
        assert diff_map["large.py"]["all_flagged"] is False, "large.py should NOT be fully flagged"
        assert diff_map["large.py"]["reason"] == "large_new_file", "large.py reason should be large_new_file"

        assert "package.lock" not in diff_map, "package.lock should be skipped"

        fake_findings = [
            {
                "category": "injection",
                "subtype": "CWE-78",
                "source_file": "small.py",
                "source_line": 5,
                "sink_file": "small.py",
                "sink_line": 6
            },
            {
                "category": "ssrf",
                "subtype": "CWE-918",
                "source_file": "large.py",
                "source_line": 5,
                "sink_file": "large.py",
                "sink_line": 6
            },
            {
                "category": "path_traversal",
                "subtype": "CWE-22",
                "source_file": "package.lock",
                "source_line": 1,
                "sink_file": "package.lock",
                "sink_line": 2
            }
        ]

        filtered = filter_findings_by_diff(fake_findings, diff_map)
        print("Filtered findings count:", len(filtered))

        assert len(filtered) == 2, f"Should retain exactly 2 findings, got {len(filtered)}"
        
        small_f = next(f for f in filtered if f["source_file"] == "small.py")
        assert small_f["diff_origin"] == "new_file_full", f"small.py origin should be new_file_full, got {small_f['diff_origin']}"
        
        large_f = next(f for f in filtered if f["source_file"] == "large.py")
        assert large_f["diff_origin"] == "large_new_file", f"large.py origin should be large_new_file, got {large_f['diff_origin']}"

        print("All self-tests passed successfully!")

    finally:
        def on_rm_error(func, path, exc_info):
            import stat
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass
        try:
            shutil.rmtree(temp_dir, onerror=on_rm_error)
        except Exception:
            pass
