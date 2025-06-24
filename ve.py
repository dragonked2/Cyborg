#Ali Essam - CyborgGui Version 5
import os
import re
import logging
import threading
import queue
import webbrowser
import datetime
import json
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, font
from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import sys
import hashlib
import copy
import time
from urllib.parse import quote_plus
from collections import defaultdict
from typing import List, Dict, Any, Set, Optional, Callable, Tuple, Generator

try:
    from ttkbootstrap import Style, Toplevel, Window
    from ttkbootstrap.constants import *
    from ttkbootstrap.scrolled import ScrolledText, ScrolledFrame
    from ttkbootstrap.tooltip import ToolTip
    from pygments import lex
    from pygments.lexers import PhpLexer
    from pygments.styles import get_style_by_name
    from pygments.token import Token
    import matplotlib
    matplotlib.use('TkAgg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except ImportError as e:
    _MISSING_DEPS = True
    _MISSING_MODULE = str(e).split("'")[1]
else:
    _MISSING_DEPS = False
    _MISSING_MODULE = None

APP_NAME = "Cyborg Scanner Pro (Helios Engine v5)"
APP_VERSION = "31.0.0"
LOG_FILE = "cyborg_scanner_pro.log"
CACHE_DIR = ".cyborg_cache"

DEFAULT_SETTINGS = {
    "poc_base_url": "http://localhost",
    "custom_sanitizers": ["intval", "floatval", "basename", "realpath", "filter_input", "filter_var", "escapeshellarg", "escapeshellcmd", "strip_tags", "mysqli_real_escape_string", "pg_escape_string", "json_encode"],
    "pygments_style": "one-dark",
    "use_caching": True,
}

DEFAULT_DETECTION_RULES = [
    {"id":"RCE001","enabled":True,"severity":"Critical","category":"Remote Code Execution","cwe":"CWE-94","sink_pattern":r"\b(eval|exec|system|shell_exec|popen|passthru|proc_open|pcntl_exec)\s*\(","description":"A sink function that executes code or system commands was found with tainted data.","remediation":"Never pass user-controlled data to execution sinks. Use a strict allow-list for commands or parameters. Escape all shell arguments using `escapeshellarg()` for arguments and `escapeshellcmd()` for the command string itself.","poc_payload":"id"},
    {"id":"CMD001","enabled":True,"severity":"Critical","category":"Command Injection","cwe":"CWE-78","sink_pattern":r"`(.+?)`","description":"The backtick operator (execution operator) is used to execute a shell command, and contains tainted data.","remediation":"Avoid using the backtick operator with user-controllable data. Refactor to use safer execution functions like `proc_open` with proper argument handling.","poc_payload":"; id"},
    {"id":"SQLI001","enabled":True,"severity":"Critical","category":"SQL Injection","cwe":"CWE-89","sink_pattern":r"\b(mysql_query|mysqli_query|pg_query|sqlite_query|query|execute|prepare)\s*\(","description":"An SQL query is being constructed by concatenating a variable directly, which can lead to SQL injection.","remediation":"Always use parameterized queries (prepared statements) to separate SQL logic from user-supplied data. This prevents the database from interpreting data as commands.","poc_payload":"' OR 1=1 -- "},
    {"id":"LFI001","enabled":True,"severity":"High","category":"File Inclusion","cwe":"CWE-22","sink_pattern":r"\b(include|require|include_once|require_once|file_get_contents|readfile|fopen)\s*\(","description":"A file path is being constructed using a tainted variable, which could lead to Local File Inclusion (LFI) or Path Traversal.","remediation":"Never include files based on user-controllable data. Use a strict allow-list of valid, full file paths that are permitted for inclusion.","poc_payload":"../../../../etc/passwd"},
    {"id":"XSS001","enabled":True,"severity":"High","category":"Cross-Site Scripting (XSS)","cwe":"CWE-79","sink_pattern":r"\b(echo|print|printf|vprintf)\s+","description":"User-controllable data is being printed directly to the HTML page without proper output encoding, leading to Reflected Cross-Site Scripting (XSS).","remediation":"Always encode output based on its context. For HTML body content, use `htmlspecialchars($data, ENT_QUOTES, 'UTF-8')` to prevent script execution.","poc_payload":"<script>alert('XSS-Cyborg')</script>"},
    {"id":"FUPL001","enabled":True,"severity":"Critical","category":"Insecure File Upload","cwe":"CWE-434","sink_pattern":r"\bmove_uploaded_file\s*\(\s*\$\w+\[['\"]tmp_name['\"]\]\s*,\s*(.*?)\)","description":"The destination path of a file upload appears to be constructed from tainted data, allowing an attacker to control the filename and potentially upload a web shell.","remediation":"Validate file extensions against a strict allow-list. Generate a new, random filename for the uploaded file. Store uploads in a directory outside of the web root and serve them via a secure script.","poc_payload":"shell.php"},
    {"id":"SSRF001","enabled":True,"severity":"High","category":"Server-Side Request Forgery","cwe":"CWE-918","sink_pattern":r"\b(curl_exec|file_get_contents|fsockopen)\s*\(","description":"Functions capable of making server-side requests are being called with user-controlled data, which could allow an attacker to probe internal networks or interact with internal services.","remediation":"Validate all URLs against a strict allow-list of domains and protocols. Disable redirects if not necessary. Avoid passing full user-controlled URLs to these functions.","poc_payload":"http://127.0.0.1:8080/internal-status"},
    {"id":"UNS001","enabled":True,"severity":"Critical","category":"Insecure Deserialization","cwe":"CWE-502","sink_pattern":r"\bunserialize\s*\(","description":"The `unserialize()` function is being called on user-controlled data. This can lead to object injection, which can be exploited for remote code execution if a suitable gadget chain exists in the application's class definitions.","remediation":"Avoid using `unserialize()` on untrusted data. Use a safe, standard data format like JSON (`json_decode`) for data interchange instead. If serialization is required, sign the data with a secret key to prevent tampering.","poc_payload":"O:8:\"EvilClass\":0:{}"}
]

def setup_logger():
    logger = logging.getLogger(APP_NAME)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    console_handler = logging.StreamHandler(sys.stdout)
    console_format = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    try:
        file_handler = logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8')
        file_format = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    except IOError:
        pass
    return logger

logger = setup_logger()

class DataManager:
    def __init__(self, file_path: str, default_data: Any):
        self.file_path = file_path
        self.default_data = default_data
        self._lock = threading.Lock()
    def load(self) -> Any:
        with self._lock:
            try:
                if os.path.exists(self.file_path):
                    with open(self.file_path, 'r', encoding='utf-8') as f:
                        return json.load(f)
            except (IOError, json.JSONDecodeError):
                pass
            return copy.deepcopy(self.default_data)
    def save(self, data: Any):
        with self._lock:
            try:
                os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
            except IOError:
                pass

class SettingsManager(DataManager):
    def __init__(self, file_path: str, defaults: Dict):
        super().__init__(file_path, defaults)
        self.settings = self.load()
        self._validate_settings()
    def _validate_settings(self):
        updated = False
        if not isinstance(self.settings, dict):
            self.settings = copy.deepcopy(self.default_data)
            updated = True
        for key, value in self.default_data.items():
            if key not in self.settings:
                self.settings[key] = value
                updated = True
        if updated:
            self.save(self.settings)
    def get(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)
    def set(self, key: str, value: Any):
        self.settings[key] = value
        self.save(self.settings)

class HeliosDataFlowEngine:
    SOURCE_PATTERN = re.compile(r"(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\[['\"]?(\w+)['\"]?\])")
    VAR_ASSIGNMENT_PATTERN = re.compile(r"(\$\w+)\s*[.&]?=\s*(.+)")
    def __init__(self, custom_sanitizers: List[str]):
        base_sanitizers = {"htmlspecialchars", "htmlentities", "intval", "floatval", "basename", "realpath", "filter_input", "filter_var", "escapeshellarg", "escapeshellcmd", "strip_tags", "mysqli_real_escape_string", "pg_escape_string", "json_encode"}
        self.sanitizer_functions = base_sanitizers.union(custom_sanitizers)
        self.sanitizer_pattern = re.compile(rf"(\$\w+)\s*=\s*({'|'.join(re.escape(s) for s in self.sanitizer_functions)})\s*\((.+)\)")
    def analyze_file_content(self, lines: List[str]) -> Dict[int, List[Dict]]:
        tainted_vars = {}
        taint_on_line = defaultdict(list)
        for line_num, line in enumerate(lines, 1):
            if (sanitizer_match := self.sanitizer_pattern.search(line)):
                reassigned_var, sanitizer_args = sanitizer_match.group(1), sanitizer_match.group(3)
                if reassigned_var in re.findall(r'(\$\w+)', sanitizer_args) and reassigned_var in tainted_vars:
                    del tainted_vars[reassigned_var]
            if (assignment_match := self.VAR_ASSIGNMENT_PATTERN.search(line)):
                left_var, right_expr = assignment_match.groups()
                if (source_match := self.SOURCE_PATTERN.search(right_expr)):
                    tainted_vars[left_var] = (source_match.group(1), [f"Line {line_num}: Tainted from source `{source_match.group(1)}`."])
                else:
                    for r_var in re.findall(r"(\$\w+)", right_expr):
                        if r_var in tainted_vars:
                            original_source, original_path = tainted_vars[r_var]
                            op = "." if "." in line.split("=")[0] else " "
                            assignment_type = "Concatenated" if op == "." else "Assigned"
                            tainted_vars[left_var] = (original_source, original_path + [f"Line {line_num}: {assignment_type} from `{r_var}`."])
                            break
            for var in set(re.findall(r'(\$\w+)', line)):
                if var in tainted_vars:
                    source, path = tainted_vars[var]
                    taint_on_line[line_num].append({'var': var, 'source': source, 'path': path, 'confidence': 100 - (len(path) * 5)})
        return taint_on_line

class Scanner:
    TRUSTED_PATHS = {"/vendor/", "/node_modules/", "/.git/", "/tests/", "/docs/"}
    SUPPORTED_EXTENSIONS = {".php", ".inc", ".phtml"}
    def __init__(self, result_queue: queue.Queue, config: Dict):
        self.result_queue = result_queue
        self.config = config
        self.active_rules = config.get("active_rules", [])
        self.ignored_hashes = config.get("ignored_hashes", set())
        self.settings = config.get("settings", {})
        self.use_caching = config.get("settings", {}).get("use_caching", True)
        self.is_running = threading.Event()
        self.taint_analyzer = HeliosDataFlowEngine(self.settings.get("custom_sanitizers", []))
        self.is_running.set()
        self.cache = self._load_cache()
    def stop(self):
        self.is_running.clear()
    def _get_file_hash(self, file_path: str) -> str:
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except IOError:
            return ""
    def _load_cache(self) -> Dict:
        if not self.use_caching:
            return {}
        rules_hash = hashlib.md5(str(sorted(r['id'] for r in self.active_rules)).encode()).hexdigest()
        cache_path = os.path.join(CACHE_DIR, f"findings_cache_{rules_hash}.json")
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except (IOError, json.JSONDecodeError):
                return {}
        return {}
    def _save_cache(self):
        if not self.use_caching:
            return
        rules_hash = hashlib.md5(str(sorted(r['id'] for r in self.active_rules)).encode()).hexdigest()
        cache_path = os.path.join(CACHE_DIR, f"findings_cache_{rules_hash}.json")
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(cache_path, 'w') as f:
                json.dump(self.cache, f)
        except IOError:
            pass
    def run(self, target_path: str):
        files_to_scan = list(self._discover_files(target_path))
        self.result_queue.put(("file_count", len(files_to_scan)))
        with ThreadPoolExecutor(max_workers=(os.cpu_count() or 1) * 2) as executor:
            futures = {executor.submit(self._scan_file, file_path, target_path) for file_path in files_to_scan}
            for future in as_completed(futures):
                if not self.is_running.is_set():
                    for f in futures:
                        f.cancel()
                    break
        self._save_cache()
        if self.is_running.is_set():
            self.result_queue.put(("done", None))
    def _discover_files(self, target_path: str) -> Generator[str, None, None]:
        if os.path.isfile(target_path):
            if os.path.splitext(target_path)[1].lower() in self.SUPPORTED_EXTENSIONS:
                yield target_path
        elif os.path.isdir(target_path):
            for root, dirs, files in os.walk(target_path, topdown=True):
                if not self.is_running.is_set():
                    return
                dirs[:] = [d for d in dirs if not any(trusted in os.path.join(root, d).replace("\\", "/") for trusted in self.TRUSTED_PATHS)]
                for f in files:
                    if os.path.splitext(f)[1].lower() in self.SUPPORTED_EXTENSIONS:
                        yield os.path.join(root, f)
    def _scan_file(self, file_path: str, base_path: str):
        if not self.is_running.is_set():
            return
        rel_path = os.path.relpath(file_path, base_path if os.path.isdir(base_path) else os.path.dirname(base_path))
        self.result_queue.put(("scan_status", f"Analyzing: {rel_path}"))
        try:
            file_hash = self._get_file_hash(file_path)
            if self.use_caching and file_hash and self.cache.get(file_path) == file_hash:
                self.result_queue.put(("progress", 1))
                return
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            if (taint_flows := self.taint_analyzer.analyze_file_content(lines)):
                self._find_vulnerabilities(lines, taint_flows, file_path, rel_path)
            if self.use_caching and file_hash:
                self.cache[file_path] = file_hash
        except Exception:
            pass
        finally:
            self.result_queue.put(("progress", 1))
    def _find_vulnerabilities(self, lines: List[str], taint_flows: Dict[int, List[Dict]], file_path: str, rel_path: str):
        for line_num, line_taints in taint_flows.items():
            if not self.is_running.is_set():
                return
            line_content = lines[line_num - 1].strip()
            for rule in self.active_rules:
                try:
                    if re.search(rule['sink_pattern'], line_content, re.IGNORECASE):
                        for taint in line_taints:
                            finding_hash = self._get_finding_hash(file_path, line_num, rule['id'], taint['source'])
                            if finding_hash in self.ignored_hashes:
                                continue
                            taint['path'].append(f"Line {line_num}: Reaches sink `{line_content}` matching pattern `{rule['sink_pattern']}`.")
                            self.result_queue.put(("finding", {**rule, "hash": finding_hash, "file": os.path.basename(file_path), "path": file_path, "line": line_num, "code": line_content, "full_code_context": "".join(lines), "tainted_source": taint['source'], "taint_path": taint['path'], "confidence": max(10, taint['confidence']), "generated_poc": self._generate_poc_url(rule, taint['source'], rel_path)}))
                            break
                except re.error:
                    rule['enabled'] = False
    def _get_finding_hash(self, fp: str, ln: int, rid: str, src: str) -> str:
        return hashlib.sha256(f"{fp}:{ln}:{rid}:{src}".encode()).hexdigest()
    def _generate_poc_url(self, rule: Dict, source_str: str, rel_path: str) -> Optional[str]:
        if not (param_match := re.search(r"\[['\"]?(\w+)['\"]?\]", source_str)):
            return None
        param_name, payload = param_match.group(1), rule.get("poc_payload", "")
        encoded_payload = quote_plus(payload)
        url_path = rel_path.replace("\\", "/")
        base_url = self.settings.get("poc_base_url", "http://localhost").rstrip('/')
        return f"{base_url}/{url_path}?{param_name}={encoded_payload}"

class AppController:
    def __init__(self, settings_path: str = "settings.json"):
        self.settings_manager = SettingsManager(settings_path, DEFAULT_SETTINGS)
        self.rule_manager = DataManager("rules.json", DEFAULT_DETECTION_RULES)
        self.ignore_manager = DataManager("ignored_findings.json", [])
        self.rules = self.rule_manager.load()
        self.ignored_hashes = set(self.ignore_manager.load())
        self.results = []
        self.scan_state = "idle"
        self.target_path = None
        self.scanner_instance = None
        self.scan_thread = None
        self.result_queue = queue.Queue()
    def start_scan(self, target_path: str):
        if self.scan_state == "scanning":
            return
        self.target_path = target_path
        self.results.clear()
        self.scan_state = "scanning"
        active_rules = [r for r in self.rules if r.get("enabled")]
        if not active_rules:
            self.result_queue.put(("error", "Please enable at least one rule to start a scan."))
            self.scan_state = "idle"
            return
        scanner_config = {"active_rules": active_rules, "ignored_hashes": self.ignored_hashes, "settings": self.settings_manager.settings}
        self.scanner_instance = Scanner(self.result_queue, scanner_config)
        self.scan_thread = threading.Thread(target=self.scanner_instance.run, args=(target_path,), daemon=True)
        self.scan_thread.start()
    def cancel_scan(self):
        if self.scan_state == "scanning" and self.scanner_instance:
            self.scanner_instance.stop()
            self.scan_state = "cancelled"
    def add_finding_to_ignore_list(self, finding_hash: str):
        self.ignored_hashes.add(finding_hash)
        self.results = [r for r in self.results if r['hash'] != finding_hash]
        self.ignore_manager.save(list(self.ignored_hashes))
    def clear_ignore_list(self):
        self.ignored_hashes.clear()
        self.ignore_manager.save([])

class ReportExporter:
    def __init__(self, results: List[Dict], target_path: str, settings: Dict):
        self.results = results
        self.target_path = target_path
        self.settings = settings
    def to_html(self, output_path: str):
        generate_html_report(self.results, self.target_path, self.settings, output_path)
    def to_json(self, output_path: str):
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({"scan_target": self.target_path, "findings": self.results}, f, indent=4)
    def to_csv(self, output_path: str):
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=['severity', 'category', 'id', 'file', 'path', 'line', 'code', 'description', 'remediation'])
            writer.writeheader()
            for res in self.results:
                writer.writerow({k: res.get(k, '') for k in writer.fieldnames})
    def to_sarif(self, output_path: str):
        runs = [{"tool": {"driver": {"name": APP_NAME, "version": APP_VERSION}}, "results": [self._convert_finding_to_sarif_result(r) for r in self.results]}]
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json", "version": "2.1.0", "runs": runs}, f, indent=4)
    def _convert_finding_to_sarif_result(self, finding: Dict) -> Dict:
        return {"ruleId": finding.get('id'), "message": {"text": finding.get('description')}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.get('path').replace("\\", "/")}, "region": {"startLine": finding.get('line')}}}], "level": {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}.get(finding.get('severity'), "note")}

def generate_html_report(results: List[Dict], target_path: str, settings: Dict, report_path: str):
    if not results:
        return
    severity_map = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    results.sort(key=lambda x: severity_map.get(x['severity'], 99))
    summary = defaultdict(int)
    for res in results:
        summary[res['severity']] += 1
    chart_data = {"labels": list(summary.keys()),"data": list(summary.values()), "colors": [{'Critical': '#d32f2f', 'High': '#f57c00', 'Medium': '#1976d2', 'Low': '#388e3c', 'Info': '#757575'}.get(sev, '#757575') for sev in summary.keys()]}
    findings_html = "".join([f"""<div class="finding severity-{res['severity']}"><div class="finding-header" onclick="toggleFinding(this)"><div><strong class="sev-label-{res['severity']}">{res['severity']}</strong>: {html.escape(res['category'])}<br><span class="file-path">{html.escape(res['file'])} (Line: {res['line']})</span></div><div class="toggle-icon"></div></div><div class="finding-body"><h3>Vulnerable Code</h3><div class="code-block">{html.escape(res['code'])}</div><h3>Taint Path</h3><div class="code-block">{"<br>".join([html.escape(line) for line in res.get('taint_path', [])])}</div><h3>Generated Proof of Concept (PoC)</h3><div>{f'<a href="{res["generated_poc"]}" target="_blank" class="poc-link">{html.escape(res["generated_poc"])}</a>' if res.get("generated_poc") else '<p>N/A</p>'}</div><h3>Description</h3><p>{html.escape(res['description'])}</p><h3>Remediation</h3><p>{html.escape(res['remediation'])}</p></div></div>""" for res in results])
    html_content=f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Cyborg Scanner Pro Report</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;background-color:#1a1a1a;color:#e0e0e0}}.container{{max-width:1300px;margin:20px auto;padding:20px;background-color:#2a2a2a;border-radius:8px}}h1,h2,h3{{color:#4fc3f7;border-bottom:1px solid #444;padding-bottom:10px}}h1{{text-align:center}}.summary-container{{display:flex;gap:20px;align-items:center;flex-wrap:wrap}}#summary-chart-container{{flex:1;min-width:250px;max-width:350px}}.summary-box{{flex:2;display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px}}.summary-card{{padding:20px;border-radius:8px;text-align:center;color:#fff}}.summary-card .count{{font-size:2.5em;font-weight:700}}.Critical{{background:linear-gradient(135deg,#d32f2f,#b71c1c)}}.High{{background:linear-gradient(135deg,#f57c00,#e65100)}}.Medium{{background:linear-gradient(135deg,#1976d2,#0d47a1)}}.Low{{background:linear-gradient(135deg,#388e3c,#1b5e20)}}.finding{{border:1px solid #444;border-left-width:5px;border-radius:5px;margin-bottom:20px;overflow:hidden;background-color:#303030}}.finding-header{{padding:15px;background-color:#383838;cursor:pointer;display:flex;justify-content:space-between;align-items:center}}.finding-body{{padding:20px;display:none}}.sev-label-Critical,.sev-label-High{{font-weight:700}}.severity-Critical{{border-left-color:#d32f2f}}.sev-label-Critical{{color:#d32f2f}}.severity-High{{border-left-color:#f57c00}}.sev-label-High{{color:#f57c00}}.severity-Medium{{border-left-color:#1976d2}}.sev-label-Medium{{color:#1976d2}}.severity-Low{{border-left-color:#388e3c}}.sev-label-Low{{color:#388e3c}}.code-block{{background-color:#212121;padding:15px;border-radius:5px;font-family:monospace;white-space:pre-wrap;word-wrap:break-word;max-height:400px;overflow-y:auto}}.poc-link{{color:#82b1ff;text-decoration:none;word-break:break-all}}.file-path{{font-family:monospace;color:#aaa}}.toggle-icon::after{{content:'▼';display:inline-block;transition:transform .2s}}.finding-header.open .toggle-icon::after{{transform:rotate(-180deg)}}</style></head><body><div class="container"><h1>Cyborg Scanner Pro Security Report</h1><div><strong>Target:</strong><span class="file-path">{html.escape(target_path)}</span> <strong>Scan Date:</strong>{datetime.datetime.now():%Y-%m-%d %H:%M:%S} <strong>Total Findings:</strong>{len(results)}</div><h2>Scan Summary</h2><div class="summary-container"><div id="summary-chart-container"><canvas id="summaryChart"></canvas></div><div class="summary-box"><div class="summary-card Critical"><div class="count">{summary['Critical']}</div><div class="label">Critical</div></div><div class="summary-card High"><div class="count">{summary['High']}</div><div class="label">High</div></div><div class="summary-card Medium"><div class="count">{summary['Medium']}</div><div class="label">Medium</div></div><div class="summary-card Low"><div class="count">{summary['Low']}</div><div class="label">Low</div></div></div></div><h2>Findings</h2><div id="findings-list">{findings_html}</div></div><script>function toggleFinding(e){{e.classList.toggle("open");e.nextElementSibling.style.display="block"===e.nextElementSibling.style.display?"none":"block"}}new Chart(document.getElementById("summaryChart").getContext("2d"),{{type:"doughnut",data:{{labels:{json.dumps(chart_data['labels'])},datasets:[{{data:{json.dumps(chart_data['data'])},backgroundColor:{json.dumps(chart_data['colors'])},borderColor:"#2a2a2a"}}]}},options:{{responsive:!0,plugins:{{legend:{{position:"top",labels:{{color:"#e0e0e0"}}}},title:{{display:!0,text:"Findings Distribution",color:"#e0e0e0"}}}}}}}});</script></body></html>"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

class SyntaxHighlightingText(tk.Text):
    def __init__(self, master=None, style_name='monokai', **kwargs):
        super().__init__(master, **kwargs)
        self.lexer = PhpLexer()
        self.tag_colors = {}
        self.set_style(style_name)
    def set_style(self, style_name: str):
        try:
            style = get_style_by_name(style_name)
        except:
            style = get_style_by_name('monokai')
        bg_color, default_fg = style.background_color, "#FFFFFF"
        for token, s in style:
            tag, fg, bg = str(token), f"#{s['color']}" if s['color'] else None, f"#{s['bgcolor']}" if s['bgcolor'] else None
            if tag == 'Token.Text':
                default_fg = fg or default_fg
            font_config = [k for k in ('bold', 'italic') if s.get(k)]
            self.tag_configure(tag, foreground=fg, background=bg)
            if font_config:
                current_font = font.Font(font=self['font'])
                current_font.configure(weight='bold' if s.get('bold') else 'normal', slant='italic' if s.get('italic') else 'roman')
                self.tag_configure(tag, font=current_font)
            if s.get('underline'):
                self.tag_configure(tag, underline=True)
        self.configure(background=bg_color, foreground=default_fg, selectbackground=style.highlight_color, insertbackground="white")
    def highlight(self, text=None):
        text = text or self.get("1.0", "end-1c")
        for tag in self.tag_names():
            if tag not in ("sel", "finding_line", "sink_pattern"):
                self.tag_remove(tag, "1.0", "end")
        self.mark_set("range_start", "1.0")
        for token, content in lex(text, self.lexer):
            self.mark_set("range_end", f"range_start + {len(content)}c")
            self.tag_add(str(token), "range_start", "range_end")
            self.mark_set("range_start", "range_end")
    def set_text(self, text: str, highlight_line: int = -1, pattern: Optional[str]=None):
        self.config(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", text)
        self.highlight()
        if highlight_line != -1:
            line_start, line_end = f"{highlight_line}.0", f"{highlight_line}.end"
            self.tag_add("finding_line", line_start, line_end)
            self.tag_configure("finding_line", background="#555522")
            self.see(line_start)
        if pattern and highlight_line != -1:
            try:
                for m in re.finditer(pattern, self.get(line_start, line_end), re.IGNORECASE):
                    self.tag_add("sink_pattern", f"{highlight_line}.{m.start()}", f"{highlight_line}.{m.end()}")
                    self.tag_configure("sink_pattern", background="red", foreground="white")
            except re.error:
                pass
        self.config(state=DISABLED)

class CyborgGUI(Window):
    def __init__(self, controller: AppController, splash: Toplevel):
        self.controller = controller
        super().__init__(themename="cyborg", title=APP_NAME)
        self.state("zoomed")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.withdraw()
        self.splash = splash
        self.total_files = 0
        self.processed_files = 0
        self.scan_start_time = 0.0
        self.sort_column = "severity"
        self.sort_reverse = False
        self.filter_after_id = None
        self.queue_after_id = None
        self.detail_font = font.Font(family="Consolas", size=11)
        self._create_menu()
        self._create_widgets()
        self.start_queue_processing()
        self.after(1000, self.main_app_ready)

    def main_app_ready(self):
        if self.splash and self.splash.winfo_exists():
            self.splash.destroy()
        self.deiconify()
        self._update_dashboard()

    def start_queue_processing(self):
        self._process_queue()
        self.queue_after_id = self.after(50, self.start_queue_processing)

    def _create_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Scan File...", command=lambda: self._start_scan("file"), accelerator="Ctrl+O")
        file_menu.add_command(label="Scan Directory...", command=lambda: self._start_scan("directory"), accelerator="Ctrl+Shift+O")
        file_menu.add_separator()
        self.export_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Export Results As", menu=self.export_menu, state=DISABLED)
        for fmt in ("html", "json", "csv", "sarif"):
            self.export_menu.add_command(label=f"{fmt.upper()}...", command=lambda f=fmt: self._export_data(f))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Manage Rules...", command=lambda: self.notebook.select(self.rules_tab))
        tools_menu.add_command(label="Manage Ignored Findings...", command=self._manage_ignored_findings)
        tools_menu.add_separator()
        tools_menu.add_command(label="Settings...", command=self._open_settings_dialog, accelerator="Ctrl+,")
        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about_dialog)
        self.bind_all("<Control-o>", lambda e: self._start_scan("file"))
        self.bind_all("<Control-Shift-O>", lambda e: self._start_scan("directory"))
        self.bind_all("<Control-,>", lambda e: self._open_settings_dialog())

    def _create_widgets(self):
        main_pane = ttk.PanedWindow(self, orient=HORIZONTAL)
        main_pane.pack(fill=BOTH, expand=YES, padx=10, pady=10)
        left_pane = ttk.Frame(main_pane, padding=5)
        self.notebook = ttk.Notebook(left_pane, bootstyle="dark")
        self.notebook.pack(fill=BOTH, expand=YES)
        self.dashboard_tab = self._create_dashboard_tab()
        self.rules_tab = self._create_rules_tab()
        self.log_tab = self._create_log_viewer_tab()
        main_pane.add(left_pane, weight=2)
        right_pane = ttk.Frame(main_pane, padding=5)
        self._create_results_display(right_pane)
        main_pane.add(right_pane, weight=5)
        status_frame = ttk.Frame(self, padding=(10, 5))
        status_frame.pack(fill=X, side=BOTTOM)
        self.status_label = ttk.Label(status_frame, text="Ready to scan.")
        self.status_label.pack(side=LEFT, fill=X, expand=YES)
        self.progress_bar = ttk.Progressbar(status_frame, mode=DETERMINATE)
        self.progress_bar.pack(side=RIGHT, ipadx=100)

    def _create_dashboard_tab(self):
        frame = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(frame, text=" Dashboard ")
        ttk.Label(frame, text=APP_NAME, font="-size 24 -weight bold").pack(pady=(0,5))
        ttk.Label(frame, text="Helios Engine v5 - PHP Static Analysis", bootstyle=SECONDARY, font="-size 10").pack()
        ttk.Separator(frame).pack(fill=X, pady=20)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=X, pady=10)
        self.scan_file_btn = ttk.Button(btn_frame, text="Scan File...", command=lambda: self._start_scan("file"), bootstyle="success")
        self.scan_file_btn.pack(fill=X, pady=3, ipady=5)
        self.scan_dir_btn = ttk.Button(btn_frame, text="Scan Directory...", command=lambda: self._start_scan("directory"), bootstyle="primary")
        self.scan_dir_btn.pack(fill=X, pady=3, ipady=5)
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel Scan", command=self._cancel_scan, state=DISABLED, bootstyle="danger-outline")
        self.cancel_btn.pack(fill=X, pady=(15,0), ipady=5)
        self.summary_frame = ttk.Labelframe(frame, text="Scan Summary", padding=15)
        self.summary_frame.pack(fill=BOTH, expand=YES, pady=20)
        self.fig, self.ax = plt.subplots(figsize=(5, 4), dpi=100)
        self.chart_canvas = FigureCanvasTkAgg(self.fig, master=self.summary_frame)
        self.chart_canvas.get_tk_widget().pack(side=TOP, fill=BOTH, expand=True)
        self.fig.canvas.mpl_connect('button_press_event', self._on_chart_click)
        return frame

    def _create_rules_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text=" Rule Management ")
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=X, pady=(5, 10))
        ttk.Button(btn_frame, text="Add", command=self._add_rule, bootstyle="success-outline").pack(side=LEFT, padx=2)
        self.edit_rule_btn = ttk.Button(btn_frame, text="Edit", command=self._edit_rule, bootstyle="info-outline", state=DISABLED)
        self.edit_rule_btn.pack(side=LEFT, padx=2)
        self.delete_rule_btn = ttk.Button(btn_frame, text="Delete", command=self._delete_rule, bootstyle="danger-outline", state=DISABLED)
        self.delete_rule_btn.pack(side=LEFT, padx=2)
        ttk.Button(btn_frame, text="Restore Defaults", command=self._restore_default_rules, bootstyle="warning-outline").pack(side=RIGHT, padx=2)
        cols = ("enabled", "id", "severity", "category", "cwe")
        self.rules_tree = ttk.Treeview(frame, columns=cols, show="headings", bootstyle=PRIMARY, selectmode="browse")
        self.rules_tree.pack(fill=BOTH, expand=YES, pady=5)
        for c in cols:
            self.rules_tree.heading(c, text=c.capitalize(), command=lambda col=c: self._sort_treeview(self.rules_tree, c, self._populate_rules_tree))
        self.rules_tree.column("enabled", width=60, anchor=CENTER)
        self.rules_tree.column("id", width=80)
        self.rules_tree.column("cwe", width=100)
        self.rules_tree.bind("<<TreeviewSelect>>", self._on_rule_select)
        self.rules_tree.bind("<Double-1>", lambda e: self._edit_rule())
        self._populate_rules_tree()
        return frame

    def _create_log_viewer_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text=" Log Viewer ")
        log_header = ttk.Frame(frame)
        log_header.pack(fill=X, pady=5)
        ttk.Label(log_header, text="Application Log", font="-size 12 -weight bold").pack(side=LEFT)
        refresh_log_btn = ttk.Button(log_header, text="Refresh", command=self._refresh_log_viewer, bootstyle="info-outline")
        refresh_log_btn.pack(side=RIGHT)
        ToolTip(refresh_log_btn, "Reload the log file from disk.")
        self.log_text = ScrolledText(frame, wrap=WORD, autohide=True, state=DISABLED)
        self.log_text.pack(fill=BOTH, expand=YES)
        self._refresh_log_viewer()
        return frame

    def _create_results_display(self, parent_frame: ttk.Frame):
        results_lf = ttk.Labelframe(parent_frame, text="Scan Findings", padding=10)
        results_lf.pack(fill=BOTH, expand=True, side=TOP)
        filter_frame = ttk.Frame(results_lf)
        filter_frame.pack(fill=X, pady=5)
        ttk.Label(filter_frame, text="Filter:", bootstyle="secondary").pack(side=LEFT, padx=(0,5))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self._on_filter_change)
        ttk.Entry(filter_frame, textvariable=self.filter_var).pack(fill=X, expand=YES, side=LEFT)
        results_cols = ("severity", "confidence", "category", "file", "line")
        self.results_tree = ttk.Treeview(results_lf, columns=results_cols, show="headings", bootstyle="primary", selectmode="browse")
        self.results_tree.pack(fill=BOTH, expand=YES, pady=5)
        self.results_tree.bind("<<TreeviewSelect>>", self._on_result_select)
        self.results_tree.bind("<Button-3>", self._on_result_right_click)
        for c in results_cols:
            self.results_tree.heading(c, text=c.capitalize(), command=lambda col=c: self._sort_treeview(self.results_tree, c, self._repopulate_results_tree))
        self.results_tree.column("severity", width=80, anchor=W)
        self.results_tree.column("confidence", width=80, anchor=CENTER)
        self.results_tree.column("category", width=180, anchor=W)
        self.results_tree.column("line", width=60, anchor=CENTER)
        details_lf = ttk.Labelframe(parent_frame, text="Finding Details", padding=10)
        details_lf.pack(fill=BOTH, expand=True, pady=(10,0))
        self.details_notebook = ttk.Notebook(details_lf, bootstyle="info")
        self.details_notebook.pack(fill=BOTH, expand=YES)
        self.overview_tab_frame = self._create_details_overview_tab()
        self.code_tab_frame = self._create_code_viewer_tab()
        self.taint_path_tab_frame = self._create_details_text_tab("Taint Path")
        self.remediation_tab_frame = self._create_details_text_tab("Remediation")
        self.details_notebook.add(self.overview_tab_frame, text="Overview", state=DISABLED)
        self.details_notebook.add(self.code_tab_frame, text="Vulnerable Code", state=DISABLED)
        self.details_notebook.add(self.taint_path_tab_frame, text="Taint Path", state=DISABLED)
        self.details_notebook.add(self.remediation_tab_frame, text="Remediation", state=DISABLED)

    def _create_details_overview_tab(self) -> ttk.Frame:
        return ttk.Frame(self.details_notebook, padding=15)
    def _create_code_viewer_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self.details_notebook)
        self.details_code = SyntaxHighlightingText(frame, wrap=NONE, state=DISABLED, font=self.detail_font, style_name=self.controller.settings_manager.get('pygments_style'))
        v_scroll = ttk.Scrollbar(frame, orient=VERTICAL, command=self.details_code.yview)
        h_scroll = ttk.Scrollbar(frame, orient=HORIZONTAL, command=self.details_code.xview)
        self.details_code.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        v_scroll.pack(side=RIGHT, fill=Y)
        h_scroll.pack(side=BOTTOM, fill=X)
        self.details_code.pack(fill=BOTH, expand=YES)
        return frame
    def _create_details_text_tab(self, name: str) -> ttk.Frame:
        frame = ttk.Frame(self.details_notebook)
        widget = ScrolledText(frame, wrap=WORD, autohide=True, state=DISABLED, padding=5, font=self.detail_font)
        widget.pack(fill=BOTH, expand=YES)
        if name == "Taint Path":
            self.details_path = widget
        elif name == "Remediation":
            self.details_remed = widget
        return frame

    def _on_result_select(self, event=None):
        if not self.results_tree.selection():
            return
        selection_id = self.results_tree.selection()[0]
        selected_result = next((r for r in self.controller.results if r['hash'] == selection_id), None)
        if not selected_result:
            return
        for tab in self.details_notebook.tabs():
            self.details_notebook.tab(tab, state=NORMAL)
        for w in self.overview_tab_frame.winfo_children():
            w.destroy()
        overview_fields = [("Severity", f"{selected_result['severity']} (Confidence: {selected_result['confidence']}%)"), ("Category", selected_result['category']), ("Rule ID", selected_result['id']), ("CWE", selected_result.get('cwe', 'N/A')), ("File", f"{selected_result['file']}:{selected_result['line']}"), ("Tainted Source", f"`{selected_result['tainted_source']}`"), ("Description", selected_result.get('description'))]
        for i, (label, value) in enumerate(overview_fields):
            ttk.Label(self.overview_tab_frame, text=f"{label}:", bootstyle="secondary", font="-weight bold").grid(row=i, column=0, sticky=W, padx=5, pady=3)
            ttk.Label(self.overview_tab_frame, text=value, wraplength=self.overview_tab_frame.winfo_width()-150).grid(row=i, column=1, sticky=W, padx=5, pady=3)
        ttk.Button(self.overview_tab_frame, text="Copy as Markdown", command=lambda: self._copy_finding_as_markdown(selected_result)).grid(row=len(overview_fields), column=0, columnspan=2, pady=15)
        self.details_code.set_text(selected_result.get("full_code_context", ""), highlight_line=selected_result.get("line", -1), pattern=selected_result.get('sink_pattern'))
        for widget, text in [(self.details_path.text, "\n".join(selected_result.get("taint_path", []))), (self.details_remed.text, selected_result.get('remediation', ''))]:
            widget.config(state=NORMAL)
            widget.delete("1.0", END)
            widget.insert("1.0", text or "")
            widget.config(state=DISABLED)
        self.details_notebook.select(self.overview_tab_frame)

    def _copy_finding_as_markdown(self, finding: Dict):
        md = f"""
### Cyborg Scanner Finding: {finding['category']}
**Severity:** {finding['severity']} (Confidence: {finding['confidence']}%)
**File:** `{finding['path']}` on line `{finding['line']}`
**CWE:** {finding.get('cwe', 'N/A')}
**Description:** {finding.get('description')}
#### Vulnerable Code:
```php
{finding.get('code')}
```
#### Taint Path:
```
{"\n".join(finding.get("taint_path", []))}
```
#### Remediation:
{finding.get('remediation')}
"""
        self.clipboard_clear()
        self.clipboard_append(md.strip())
        self.status_label.config(text="Finding details copied to clipboard as Markdown.")

    def _on_chart_click(self, event):
        if not self.controller.results or event.inaxes != self.ax:
            return
        self.filter_var.set("")
        visible_wedges = [w for w, l in zip(self.ax.patches, self.ax.texts) if l.get_visible()]
        for i, wedge in enumerate(visible_wedges):
            if wedge.contains_point([event.x, event.y]):
                label = self.ax.texts[i*2].get_text()
                self.filter_var.set(label)
                break

    def _start_scan(self, mode: str):
        path = filedialog.askopenfilename(title="Select File", filetypes=[("PHP", "*.php *.inc *.phtml")]) if mode == "file" else filedialog.askdirectory(title="Select Directory")
        if path:
            self._reset_ui_for_scan()
            self._set_ui_state("scanning")
            self.scan_start_time = time.monotonic()
            self.controller.start_scan(path)

    def _process_queue(self):
        try:
            findings_batch = []
            while not self.controller.result_queue.empty():
                msg, data = self.controller.result_queue.get_nowait()
                if msg == "finding":
                    findings_batch.append(data)
                elif msg == "file_count":
                    self.total_files = data
                    self.progress_bar.config(maximum=data if data > 0 else 1)
                elif msg == "progress":
                    self.processed_files += data
                    self.progress_bar['value'] = self.processed_files
                elif msg == "scan_status":
                    self.status_label.config(text=data)
                elif msg == "error":
                    messagebox.showerror("Scan Error", data, parent=self)
                    self._scan_finished()
                elif msg == "done":
                    self.controller.scan_state = "done"
                    self._scan_finished(findings_batch)
                    return
            if findings_batch:
                self.controller.results.extend(findings_batch)
                self._repopulate_results_tree()
                self._update_dashboard()
        except queue.Empty:
            pass
    
    def _scan_finished(self, final_batch: Optional[List[Dict]] = None):
        if final_batch:
            self.controller.results.extend(final_batch)
        status_text = f"Scan complete in {time.monotonic() - self.scan_start_time:.2f}s. Found {len(self.controller.results)} issues in {self.processed_files} files."
        self.status_label.config(text=status_text)
        self._set_ui_state("idle")
        self._repopulate_results_tree()
        self._update_dashboard()
        if self.controller.results:
            for i in range(self.export_menu.index('end') + 1):
                self.export_menu.entryconfig(i, state=NORMAL)
            if messagebox.askyesno("Scan Complete", f"Found {len(self.controller.results)} issues.\n\nGenerate and view an HTML report?"):
                self._generate_and_open_report()
        else:
            messagebox.showinfo("Scan Complete", "No vulnerabilities were found based on the active rules.")

    def _cancel_scan(self):
        self.controller.cancel_scan()
        self.status_label.config(text="Scan cancelled by user.")
        self._set_ui_state("idle")
        self.progress_bar['value'] = 0
    def _reset_ui_for_scan(self):
        self.controller.results.clear()
        self._repopulate_results_tree()
        self.total_files, self.processed_files = 0, 0
        self.progress_bar['value'] = 0
        self.status_label.config(text="Initializing scan...")
        for i in range(self.export_menu.index('end') + 1):
            self.export_menu.entryconfig(i, state=DISABLED)
        for tab in self.details_notebook.tabs():
            self.details_notebook.tab(tab, state=DISABLED)
        self.details_code.set_text("")
        for w in (self.details_path, self.details_remed):
            w.text.config(state=NORMAL)
            w.text.delete("1.0", END)
            w.text.config(state=DISABLED)
        self._update_dashboard()
    def _set_ui_state(self, state: str):
        is_scanning = (state == "scanning")
        self.cancel_btn.config(state=NORMAL if is_scanning else DISABLED)
        for btn in (self.scan_file_btn, self.scan_dir_btn):
            btn.config(state=DISABLED if is_scanning else NORMAL)
        self.progress_bar.config(bootstyle="info-striped" if is_scanning else "success")

    def _update_dashboard(self):
        self.ax.clear()
        theme_colors = self.style.colors
        self.fig.patch.set_facecolor(theme_colors.bg)
        self.ax.set_facecolor(theme_colors.bg)
        severity_counts = defaultdict(int)
        for res in self.controller.results:
            severity_counts[res.get('severity', 'Info')] += 1
        if not severity_counts:
            self.ax.text(0.5, 0.5, 'No Scan Data', ha='center', va='center', fontsize=12, color=theme_colors.secondary)
        else:
            labels, sizes, colors = list(severity_counts.keys()), list(severity_counts.values()), [{'Critical': theme_colors.danger, 'High': theme_colors.warning, 'Medium': theme_colors.info, 'Low': theme_colors.success}.get(l, theme_colors.secondary) for l in list(severity_counts.keys())]
            self.ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, wedgeprops={'edgecolor': theme_colors.bg, 'linewidth': 2}, textprops={'color': theme_colors.fg})
            self.ax.axis('equal')
        self.ax.set_title("Findings by Severity (Click to Filter)", color=theme_colors.fg)
        self.fig.tight_layout()
        self.chart_canvas.draw()
        
    def _on_filter_change(self, *args):
        if self.filter_after_id:
            self.after_cancel(self.filter_after_id)
        self.filter_after_id = self.after(300, self._repopulate_results_tree)
    def _repopulate_results_tree(self):
        if self.filter_after_id:
            self.after_cancel(self.filter_after_id)
        self.filter_after_id = None
        for i in self.results_tree.get_children():
            self.results_tree.delete(i)
        query = self.filter_var.get().lower()
        filtered_results = [r for r in self.controller.results if not query or query in f"{r['severity']} {r['category']} {r['file']} {r['code']} {r['id']}".lower()]
        severity_map = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        def get_sort_key(item):
            value = item.get(self.sort_column)
            return severity_map.get(value, 99) if self.sort_column == 'severity' else int(value) if self.sort_column in ('line', 'confidence') else str(value).lower()
        if self.sort_column:
            filtered_results.sort(key=get_sort_key, reverse=self.sort_reverse)
        for r in filtered_results:
            self.results_tree.insert("", END, values=(r["severity"], f"{r['confidence']}%", r["category"], r["file"], r["line"]), iid=r["hash"], tags=(r["severity"],))
        self.results_tree.tag_configure('Critical', background=self.style.colors.get('danger'))
        self.results_tree.tag_configure('High', background=self.style.colors.get('warning'))
        
    def _generate_and_open_report(self):
        if not (report_path := filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")], initialfile=f"cyborg_scan_report_{datetime.datetime.now():%Y%m%d}.html")):
            return
        try:
            ReportExporter(self.controller.results, self.controller.target_path, self.controller.settings_manager.settings).to_html(report_path)
            webbrowser.open(f"file://{os.path.realpath(report_path)}")
        except Exception:
            messagebox.showerror("Error", f"Could not open browser. Report at:\n{report_path}", parent=self)
    def _export_data(self, format_type: str):
        if not self.controller.results:
            return
        if not (path := filedialog.asksaveasfilename(defaultextension=f".{format_type}", filetypes=[(f"{format_type.upper()}", f"*.{format_type}")], initialfile=f"cyborg_scan_{datetime.datetime.now():%Y%m%d}")):
            return
        try:
            getattr(ReportExporter(self.controller.results, self.controller.target_path, self.controller.settings_manager.settings), f"to_{format_type}")(path)
            messagebox.showinfo("Success", f"Results exported to {path}", parent=self)
        except Exception:
            messagebox.showerror("Export Error", "Could not write to file", parent=self)
    def _sort_treeview(self, tree, col, repopulate_func):
        self.sort_reverse = not self.sort_reverse if self.sort_column == col else False
        self.sort_column = col
        repopulate_func()
    def _show_about_dialog(self):
        AboutDialog(self)
    def on_closing(self):
        if self.queue_after_id:
            self.after_cancel(self.queue_after_id)
        if self.controller.scan_state == "scanning":
            if not messagebox.askyesno("Scan in Progress", "A scan is running. Are you sure you want to exit?"):
                return
            self.controller.cancel_scan()
        self.destroy()
    def _populate_rules_tree(self):
        for i in self.rules_tree.get_children():
            self.rules_tree.delete(i)
        sorted_rules = sorted(self.controller.rules, key=lambda x: str(x.get(self.sort_column, '')).lower(), reverse=self.sort_reverse)
        for r in sorted_rules:
            self.rules_tree.insert("", END, values=("✓" if r.get('enabled') else "✗", r.get('id'), r.get('severity'), r.get('category'), r.get('cwe')), iid=r.get('id'))
    def _on_rule_select(self, event=None):
        state = NORMAL if self.rules_tree.selection() else DISABLED
        self.edit_rule_btn.config(state=state)
        self.delete_rule_btn.config(state=state)
    def _add_rule(self):
        RuleEditor(self, on_save_callback=self._save_rule)
    def _edit_rule(self):
        if (focus := self.rules_tree.focus()) and (rule := next((r for r in self.controller.rules if r['id'] == focus), None)):
            RuleEditor(self, rule=rule, on_save_callback=self._save_rule)
    def _delete_rule(self):
        if not (rule_id := self.rules_tree.focus()):
            return
        if messagebox.askyesno("Confirm Delete", f"Delete rule '{rule_id}'?", parent=self):
            self.controller.rules = [r for r in self.controller.rules if r['id'] != rule_id]
            self.controller.rule_manager.save(self.controller.rules)
            self._populate_rules_tree()
    def _save_rule(self, rule_data, is_new):
        if is_new and any(r['id'].lower() == rule_data['id'].lower() for r in self.controller.rules):
            messagebox.showerror("Duplicate ID", f"Rule ID '{rule_data['id']}' already exists.", parent=self)
            return False
        if is_new:
            self.controller.rules.append(rule_data)
        else:
            self.controller.rules = [rule_data if r['id'] == rule_data['id'] else r for r in self.controller.rules]
        self.controller.rule_manager.save(self.controller.rules)
        self._populate_rules_tree()
        return True
    def _restore_default_rules(self):
        if messagebox.askyesno("Confirm Restore", "This will replace all current rules with the built-in defaults."):
            self.controller.rules = copy.deepcopy(DEFAULT_DETECTION_RULES)
            self.controller.rule_manager.save(self.controller.rules)
            self._populate_rules_tree()
            messagebox.showinfo("Success", "Default rules restored.")
    def _refresh_log_viewer(self):
        self.log_text.text.config(state=NORMAL)
        self.log_text.text.delete("1.0", END)
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                self.log_text.text.insert("1.0", f.read())
        except Exception:
            self.log_text.text.insert("1.0", "Could not read log file.")
        self.log_text.text.config(state=DISABLED)
        self.log_text.text.yview_moveto(1.0)
    def _open_settings_dialog(self):
        SettingsDialog(self, settings_manager=self.controller.settings_manager, on_save_callback=self._on_settings_saved)
    def _on_settings_saved(self):
        self.details_code.set_style(self.controller.settings_manager.get('pygments_style'))
    def _on_result_right_click(self, event):
        if not (selection := self.results_tree.identify_row(event.y)):
            return
        self.results_tree.selection_set(selection)
        context_menu = tk.Menu(self, tearoff=0)
        context_menu.add_command(label="🙈 Ignore this Finding", command=self._ignore_selected_finding)
        context_menu.tk_popup(event.x_root, event.y_root)
    def _ignore_selected_finding(self):
        if (sel := self.results_tree.selection()):
            self.controller.add_finding_to_ignore_list(sel[0])
            self._repopulate_results_tree()
            self.status_label.config(text="Finding ignored.")
    def _manage_ignored_findings(self):
        if (count := len(self.controller.ignored_hashes)) == 0:
            messagebox.showinfo("Ignored Findings", "The ignore list is empty.", parent=self)
            return
        if messagebox.askyesno("Manage Ignored Findings", f"You have {count} ignored findings.\n\nClear the entire ignore list?"):
            self.controller.clear_ignore_list()
            messagebox.showinfo("Success", "Ignore list has been cleared.", parent=self)

class RuleEditor(Toplevel):
    def __init__(self, parent, on_save_callback, rule=None):
        super().__init__(parent)
        self.on_save = on_save_callback
        self.is_new = rule is None
        self.title("Add New Rule" if self.is_new else "Edit Rule")
        self.geometry("800x800")
        self.transient(parent)
        self.grab_set()
        self.vars = {}
        self._create_widgets()
        self.rule_data = rule or {k:'' for k in ('id', 'severity', 'category', 'cwe', 'sink_pattern', 'description', 'remediation', 'poc_payload')}
        self._load_rule_data()
        self.place_window_center()
    def _create_widgets(self):
        container = ScrolledFrame(self, autohide=True, padding=20)
        container.pack(fill=BOTH, expand=YES)
        frame = container.container
        frame.columnconfigure(1, weight=1)
        fields = [("ID", "id", "Entry"), ("Severity", "severity", "Combobox", ["Critical", "High", "Medium", "Low", "Info"]), ("Category", "category", "Entry"), ("CWE", "cwe", "Entry"), ("Sink Pattern (Regex)", "sink_pattern", "Entry"), ("PoC Payload", "poc_payload", "Entry"), ("Description", "description", "Text"), ("Remediation", "remediation", "Text")]
        for i, (label_text, key, widget_type, *options) in enumerate(fields):
            ttk.Label(frame, text=f"{label_text}:").grid(row=i, column=0, sticky=(W, N), pady=5, padx=(0, 10))
            if widget_type == "Entry":
                widget = ttk.Entry(frame)
                widget.grid(row=i, column=1, sticky=EW, pady=5)
            elif widget_type == "Combobox":
                widget = ttk.Combobox(frame, values=options[0], state="readonly")
                widget.grid(row=i, column=1, sticky=EW, pady=5)
            else:
                widget = ScrolledText(frame, wrap=WORD, height=5, autohide=True)
                widget.grid(row=i, column=1, sticky=NSEW, pady=5)
            self.vars[key] = widget
        self.vars['enabled'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Enabled", variable=self.vars['enabled']).grid(row=len(fields), column=1, sticky=W, pady=10)
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill=X, side=BOTTOM)
        ttk.Button(btn_frame, text="Save Rule", command=self._save_and_close, bootstyle=SUCCESS).pack(side=LEFT, padx=10, expand=True, fill=X)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy, bootstyle=DANGER).pack(side=LEFT, padx=10, expand=True, fill=X)
    def _load_rule_data(self):
        for key, widget in self.vars.items():
            value = self.rule_data.get(key, "")
            if isinstance(widget, ttk.Entry):
                widget.insert(0, str(value))
            elif isinstance(widget, ttk.Combobox):
                widget.set(str(value))
            elif isinstance(widget, ScrolledText):
                widget.text.insert("1.0", str(value))
            elif isinstance(widget, tk.BooleanVar):
                widget.set(bool(value))
        if not self.is_new:
            self.vars['id'].config(state=DISABLED)
    def _save_and_close(self):
        new_data = {k: (w.get() if isinstance(w,(ttk.Entry,ttk.Combobox,tk.BooleanVar)) else w.text.get("1.0",END).strip()) for k,w in self.vars.items()}
        if not self.is_new:
            new_data['id'] = self.rule_data['id']
        if not all(new_data.get(k) for k in ['id', 'category', 'sink_pattern', 'severity']):
            messagebox.showerror("Validation Error", "ID, Severity, Category, and Sink Pattern are required.", parent=self)
            return
        try:
            re.compile(new_data['sink_pattern'])
        except re.error as e:
            messagebox.showerror("Invalid Regex", f"The sink pattern is invalid:\n{e}", parent=self)
            return
        if self.on_save(new_data, self.is_new):
            self.destroy()

class SettingsDialog(Toplevel):
    def __init__(self, parent: CyborgGUI, settings_manager: SettingsManager, on_save_callback: Callable):
        super().__init__(parent)
        self.settings_manager = settings_manager
        self.on_save = on_save_callback
        self.title("Settings")
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()
        self.vars = {}
        self._create_widgets()
        self._load_settings()
        self.place_window_center()
    def _create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=BOTH, expand=YES)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="PoC Base URL:").grid(row=0, column=0, sticky=W, pady=5)
        self.vars['poc_base_url'] = tk.StringVar()
        ttk.Entry(frame, textvariable=self.vars['poc_base_url']).grid(row=0, column=1, sticky=EW, pady=5)
        ttk.Label(frame, text="Custom Sanitizers (CSV):").grid(row=1, column=0, sticky=(W, N), pady=5)
        self.sanitizers_text = ScrolledText(frame, height=5, wrap=WORD)
        self.sanitizers_text.grid(row=1, column=1, sticky=NSEW, pady=5)
        ttk.Label(frame, text="Code Theme:").grid(row=2, column=0, sticky=W, pady=5)
        self.vars['pygments_style'] = tk.StringVar()
        ttk.Combobox(frame, textvariable=self.vars['pygments_style'], values=sorted(list(get_style_by_name.__globals__['STYLES'].keys())), state='readonly').grid(row=2, column=1, sticky=EW, pady=5)
        self.vars['use_caching'] = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Enable scan caching (improves performance)", variable=self.vars['use_caching']).grid(row=3, column=1, sticky=W, pady=10)
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill=X, side=BOTTOM)
        ttk.Button(btn_frame, text="Save", command=self._save_and_close, bootstyle=SUCCESS).pack(side=LEFT, expand=True, fill=X, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy, bootstyle=DANGER).pack(side=LEFT, expand=True, fill=X, padx=5)
    def _load_settings(self):
        for key, var in self.vars.items():
            var.set(self.settings_manager.get(key))
        self.sanitizers_text.text.insert("1.0", ", ".join(self.settings_manager.get('custom_sanitizers', [])))
    def _save_and_close(self):
        for key, var in self.vars.items():
            self.settings_manager.set(key, var.get())
        self.settings_manager.set('custom_sanitizers', [s.strip() for s in self.sanitizers_text.text.get("1.0", END).split(',') if s.strip()])
        messagebox.showinfo("Settings Saved", "Settings have been saved.", parent=self)
        self.on_save()
        self.destroy()

class AboutDialog(Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title(f"About {APP_NAME}")
        self.geometry("500x300")
        self.transient(parent)
        self.grab_set()
        self.place_window_center()
        ttk.Label(self, text=APP_NAME, font="-size 20 -weight bold").pack(pady=(20, 10))
        ttk.Label(self, text=f"Version {APP_VERSION}").pack()
        ttk.Label(self, text="Advanced Static Analysis Security Testing (SAST) Engine.").pack(pady=5)
        ttk.Separator(self).pack(fill=X, padx=20, pady=10)
        ttk.Label(self, text="This tool performs flow-based taint analysis to identify\npotential security vulnerabilities in PHP source code.").pack(pady=5)
        ttk.Button(self, text="Close", command=self.destroy, bootstyle=PRIMARY).pack(pady=20, side=BOTTOM, ipadx=10)

def main():
    if _MISSING_DEPS:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Dependency Error", f"Error: Module '{_MISSING_MODULE}' is not installed.\nPlease install GUI dependencies:\npip install ttkbootstrap pygments matplotlib")
        sys.exit(1)
    controller = AppController()
    splash = Toplevel()
    splash.geometry("350x200")
    splash.overrideredirect(True)
    splash_style = Style(theme='cyborg')
    splash.place_window_center()
    splash.configure(bg=splash_style.colors.get('bg'))
    ttk.Label(splash, text="Cyborg Scanner", font="-size 24 -weight bold").pack(pady=(40, 10))
    ttk.Label(splash, text=f"Initializing {APP_NAME}...", font="-size 12").pack()
    splash_pbar = ttk.Progressbar(splash, mode='indeterminate', bootstyle='success-striped')
    splash_pbar.pack(pady=20, padx=30, fill=X)
    splash_pbar.start(10)
    app = CyborgGUI(controller, splash)
    app.mainloop()

if __name__ == "__main__":
    main()
