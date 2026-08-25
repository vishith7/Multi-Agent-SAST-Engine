import os
import subprocess
import time

class JoernServer:
    def __init__(self, port=9000):
        # We keep the constructor identical for compatibility
        self.port = port
        
    def is_running(self):
        # Always True to bypass pipeline checks for daemon readiness
        return True
            
    def start(self):
        # No-op
        return True
        
    def stop(self):
        # No-op
        pass
            
    def status(self):
        print("Joern is running in Stateless JVM Mode (no daemon).")
        return True
            
    def execute_script(self, script_path, params_dict=None):
        if params_dict is None:
            params_dict = {}
            
        executable = "joern.bat" if os.name == 'nt' else "joern"
        cmd_str = f"{executable} --script {script_path}"
        
        for k, v in params_dict.items():
            # Wrap the entire key=value in double quotes to prevent cmd.exe from splitting on =
            # and escape any existing double quotes.
            safe_v = str(v).replace('"', '\\"')
            cmd_str += f' --param "{k}={safe_v}"'
            
        try:
            # We must use shell=True and a single string to let cmd.exe handle the quotes correctly
            res = subprocess.run(cmd_str, check=True, capture_output=True, text=True, shell=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            print(f"Joern script execution failed with code {e.returncode}")
            print(f"Stdout: {e.stdout}")
            print(f"Stderr: {e.stderr}")
            return None
        except Exception as e:
            print(f"Failed to execute joern: {e}")
            return None

    def build_cpg(self, repo_path, output_path):
        executable = "joern-parse.bat" if os.name == 'nt' else "joern-parse"
        cmd_str = f'{executable} "{repo_path}" --output "{output_path}"'
        print(f"Executing JVM: {cmd_str}")
        try:
            res = subprocess.run(cmd_str, check=True, capture_output=True, text=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Joern-parse failed with code {e.returncode}")
            print(f"Stderr: {e.stderr}")
            return False
        except Exception as e:
            print(f"Failed to execute joern-parse: {e}")
            return False
