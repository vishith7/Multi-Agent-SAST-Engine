import sys
import os
import keyring


# Ensure sast-engine is in path for imports
sast_engine_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sast_engine_dir not in sys.path:
    sys.path.insert(0, sast_engine_dir)

import json
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socketserver
import urllib.parse
import urllib.request
import urllib.error
from threading import Thread
import time

def find_free_port(start_port=8081):
    port = start_port
    while port < 65535:
        try:
            with socketserver.TCPServer(("", port), None) as s:
                return port
        except Exception:
            port += 1
    return 8080

def start_dashboard(json_path):
    if not os.path.exists(json_path):
        print(f"Error: JSON file '{json_path}' not found.")
        sys.exit(1)
        
    try:
        with open(json_path, 'r') as f:
            scan_data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON data: {e}")
        sys.exit(1)
    
    # Apply secondary location-based dedup to collapse findings with same source/sink
    from orchestrator.dedupe_anonymize import dedupe_by_location
    if "findings" in scan_data:
        original_count = len(scan_data["findings"])
        scan_data["findings"] = dedupe_by_location(scan_data["findings"])
        deduped_count = len(scan_data["findings"])
        if original_count != deduped_count:
            print(f"[*] Deduplicated findings: {original_count} → {deduped_count}")
        
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    dashboard_dir = os.path.join(base_dir, "dashboard")
    
    if not os.path.exists(dashboard_dir):
        os.makedirs(dashboard_dir, exist_ok=True)
        print(f"Created dashboard directory at {dashboard_dir}")
        
    class DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=dashboard_dir, **kwargs)
            
        def do_GET(self):
            parsed_path = urllib.parse.urlparse(self.path)
            if parsed_path.path == '/api/data':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(scan_data).encode('utf-8'))
            elif parsed_path.path == '/api/defectdojo_config':
                url = keyring.get_password("taintlace_defectdojo", "url") or os.environ.get('DEFECTDOJO_URL') or ""
                engagement_id = keyring.get_password("taintlace_defectdojo", "engagement_id") or os.environ.get('DEFECTDOJO_ENGAGEMENT_ID') or ""
                token = keyring.get_password("taintlace_defectdojo", "token") or os.environ.get('DEFECTDOJO_API_KEY') or ""
                has_token = bool(token)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "url": url,
                    "engagement_id": engagement_id,
                    "has_token": has_token
                }).encode('utf-8'))
            else:
                super().do_GET()
                
        def do_POST(self):
            parsed_path = urllib.parse.urlparse(self.path)
            if parsed_path.path == '/api/approve':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                req_json = json.loads(post_data.decode('utf-8'))
                
                fingerprint = req_json.get('fingerprint')
                state = req_json.get('state')
                
                updated = False
                for f in scan_data.get('findings', []):
                    if f.get('fingerprint') == fingerprint:
                        f['approval_state'] = state
                        updated = True
                        break
                
                if updated:
                    with open(json_path, 'w') as f:
                        json.dump(scan_data, f, indent=2)
                        
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode('utf-8'))
            elif parsed_path.path == '/api/push_defectdojo':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                req_json = json.loads(post_data.decode('utf-8')) if content_length > 0 else {}
                
                dd_url = req_json.get('url') or keyring.get_password("taintlace_defectdojo", "url") or os.environ.get('DEFECTDOJO_URL')
                dd_token = req_json.get('token')
                if not dd_token or dd_token.startswith('••••'):
                    dd_token = keyring.get_password("taintlace_defectdojo", "token") or os.environ.get('DEFECTDOJO_API_KEY')
                engagement_id = req_json.get('engagement_id') or keyring.get_password("taintlace_defectdojo", "engagement_id") or os.environ.get('DEFECTDOJO_ENGAGEMENT_ID')
                
                if not dd_url or not dd_token or not engagement_id:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing DefectDojo configuration (URL, Token, Engagement ID)"}).encode('utf-8'))
                    return
                    
                dd_url = dd_url.strip()
                # Validate URL structure
                try:
                    parsed_url = urllib.parse.urlparse(dd_url)
                    if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https') or not parsed_url.netloc:
                        self.send_response(400)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Invalid DefectDojo URL format. It must start with http:// or https:// and contain a valid hostname."}).encode('utf-8'))
                        return
                except Exception as e:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Failed to parse DefectDojo URL: {e}"}).encode('utf-8'))
                    return

                # Validate Engagement ID format
                try:
                    engagement_id_int = int(str(engagement_id).strip())
                    if engagement_id_int <= 0:
                        self.send_response(400)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Engagement ID must be a positive integer."}).encode('utf-8'))
                        return
                except ValueError:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Engagement ID must be a valid integer."}).encode('utf-8'))
                    return

                target_fingerprint = req_json.get('fingerprint')
                pushed_count = 0
                errors = []
                for f in scan_data.get('findings', []):
                    if target_fingerprint:
                        if f.get('fingerprint') != target_fingerprint:
                            continue
                    else:
                        if f.get('approval_state') != 'APPROVED':
                            continue
                            
                    sink_str = 'Unknown'
                    if f.get('sink') and f['sink'].get('file'):
                        sink_str = f"{f['sink']['file']}:{f['sink']['line']}"
                    elif f.get('instances') and len(f['instances']) > 0:
                        sink_str = f"{f['instances'][0].get('sink_file')}:{f['instances'][0].get('sink_line')}"
                        
                    # Backfill severity, priority, SLA if missing (for backwards compatibility with older results)
                    if "severity" not in f:
                        try:
                            from risk.priority_policy import determine_severity, get_priority, get_sla_days
                            f["severity"] = determine_severity(f)
                            f["priority"] = get_priority(f)
                            f["sla_days"] = get_sla_days(f["priority"])
                        except Exception:
                            pass
                            
                    sev = f.get('severity', 'Medium')
                    prio = f.get('priority', 'P3')
                    sla_val = f.get('sla_days', 14)
                    
                    desc = f"{f.get('category')} - {f.get('subtype')}\n\n"
                    desc += f"Severity: {sev}\n"
                    desc += f"Priority: {prio}\n"
                    desc += f"SLA Limit: {sla_val} days\n\n"
                    desc += f"Sink: {sink_str}\n\n"
                    desc += f"Reasoning:\n{f.get('reasoning') or f.get('llm_reasoning') or 'N/A'}"
                    
                    payload = {
                        "title": f.get('title') or f"Taintlace: {f.get('category')} - {f.get('subtype')}",
                        "description": desc,
                        "severity": sev,
                        "active": True,
                        "verified": True,
                        "engagement": engagement_id_int,
                        "scanner_type": "Taintlace SAST",
                        "vuln_id_from_tool": f.get('fingerprint'),
                        "tags": ["taintlace", f"priority-{prio.lower()}", f"sla-{sla_val}d"]
                    }
                    
                    try:
                        req = urllib.request.Request(f"{dd_url.rstrip('/')}/api/v2/findings/")
                        req.add_header('Authorization', f'Token {dd_token}')
                        req.add_header('Content-Type', 'application/json')
                        resp = urllib.request.urlopen(req, json.dumps(payload).encode('utf-8'))
                        pushed_count += 1
                    except urllib.error.URLError as e:
                        errors.append(f"Failed to push {f.get('fingerprint')}: {str(e)}")
                    except Exception as e:
                        errors.append(f"Failed to push {f.get('fingerprint')}: {str(e)}")
                        
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "pushed": pushed_count, "errors": errors}).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()
                
        # Suppress logging
        def log_message(self, format, *args):
            pass

    port = find_free_port(8081)
    handler = DashboardHandler
    
    print(f"[*] Starting Taintlace Dashboard on http://localhost:{port}")
    print(f"[*] Serving results from {json_path}")
    print("[*] Press Ctrl+C to stop the server.")
    
    httpd = HTTPServer(("", port), handler)
    
    def open_browser():
        time.sleep(0.5)
        webbrowser.open(f"http://localhost:{port}")
        
    browser_thread = Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down dashboard server.")
        httpd.server_close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dashboard.py <path_to_scan_json>")
        sys.exit(1)
    start_dashboard(sys.argv[1])
