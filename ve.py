import os
import re
import logging
import datetime
import threading
from tkinter import filedialog, messagebox, Tk, ttk
from ttkbootstrap import Style
from concurrent.futures import ThreadPoolExecutor
import webbrowser

# Logging Configuration
LOG_FILE = "cyborg.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Default Detection Rules
DETECTION_RULES = [
    # Input Handling Vulnerabilities
    {"pattern": r"\$_GET\[", "severity": "Critical", "description": "Unsanitized input from $_GET detected. This can lead to injection attacks, such as SQL injection or XSS."},
    {"pattern": r"\$_POST\[", "severity": "Critical", "description": "Unsanitized input from $_POST detected. Validate and sanitize all incoming data to avoid injection risks."},
    {"pattern": r"\$_REQUEST\[", "severity": "Critical", "description": "Potential injection risk via $_REQUEST. Avoid using $_REQUEST; prefer $_GET or $_POST with proper sanitization."},
    {"pattern": r"\$_COOKIE\[", "severity": "High", "description": "Insecure handling of $_COOKIE data. Ensure cookies are validated and sanitized to prevent injection attacks."},
    {"pattern": r"\$_SERVER\[", "severity": "High", "description": "Unvalidated use of $_SERVER variables. These can be manipulated to disclose sensitive information or inject malicious data."},

    # Code Execution Vulnerabilities
    {"pattern": r"eval\s*\(", "severity": "Critical", "description": "Use of eval detected. This function executes arbitrary PHP code and poses a significant security risk."},
    {"pattern": r"exec\s*\(", "severity": "Critical", "description": "Use of exec detected. This function can execute shell commands and must be avoided or heavily restricted."},
    {"pattern": r"system\s*\(", "severity": "Critical", "description": "Use of system detected. This function executes shell commands, which can compromise system security."},
    {"pattern": r"shell_exec\s*\(", "severity": "Critical", "description": "Use of shell_exec detected. Avoid this function as it allows arbitrary shell command execution."},
    {"pattern": r"popen\s*\(", "severity": "Critical", "description": "Use of popen detected. This can lead to shell command execution and should be avoided unless absolutely necessary."},
    {"pattern": r"passthru\s*\(", "severity": "Critical", "description": "Use of passthru detected. It allows execution of shell commands and must be avoided."},

    # File Handling Vulnerabilities
    {"pattern": r"file_put_contents\s*\(", "severity": "High", "description": "Potentially risky file write operation detected. Validate file paths and permissions."},
    {"pattern": r"file_get_contents\s*\(", "severity": "High", "description": "Potentially unsafe file read operation detected. Ensure input is sanitized to prevent path traversal attacks."},
    {"pattern": r"fopen\s*\(", "severity": "High", "description": "Use of fopen detected. Validate file paths and permissions to prevent unauthorized access."},
    {"pattern": r"unlink\s*\(", "severity": "High", "description": "File deletion detected via unlink. Validate inputs to avoid arbitrary file deletion."},
    {"pattern": r"chmod\s*\(", "severity": "Medium", "description": "Changing file permissions detected. Ensure proper permission configurations to avoid privilege escalation."},

    # Serialization and Deserialization
    {"pattern": r"serialize\s*\(", "severity": "High", "description": "Serialization detected. Ensure objects are serialized securely to prevent tampering or deserialization attacks."},
    {"pattern": r"unserialize\s*\(", "severity": "Critical", "description": "Insecure deserialization detected. This can lead to remote code execution or arbitrary object injection."},

    # Cryptographic Issues
    {"pattern": r"md5\s*\(", "severity": "High", "description": "Use of weak MD5 hashing algorithm detected. Replace with a secure algorithm like SHA-256."},
    {"pattern": r"sha1\s*\(", "severity": "High", "description": "Use of weak SHA1 hashing algorithm detected. Replace with a secure algorithm like SHA-256."},
    {"pattern": r"base64_decode\s*\(", "severity": "Medium", "description": "Use of base64_decode detected. This can be used to obfuscate malicious code."},

    # Database Vulnerabilities
    {"pattern": r"mysql_query\s*\(", "severity": "Critical", "description": "Use of deprecated mysql_query detected. Use parameterized queries or prepared statements instead."},
    {"pattern": r"mysqli_query\s*\(", "severity": "High", "description": "Ensure mysqli_query inputs are sanitized and validated to prevent SQL injection."},
    {"pattern": r"pg_query\s*\(", "severity": "High", "description": "Ensure pg_query inputs are sanitized and validated to prevent SQL injection in PostgreSQL."},
    {"pattern": r"sqlite_query\s*\(", "severity": "High", "description": "Ensure sqlite_query inputs are sanitized and validated to prevent SQL injection in SQLite."},

    # XSS and Output Escaping
    {"pattern": r"echo\s+\$_(GET|POST|REQUEST|COOKIE)\[", "severity": "Critical", "description": "Unescaped output detected from user input. This can lead to cross-site scripting (XSS)."},
    {"pattern": r"print\s+\$_(GET|POST|REQUEST|COOKIE)\[", "severity": "Critical", "description": "Unescaped output detected from user input. This can lead to cross-site scripting (XSS)."},

    # Security Misconfigurations
    {"pattern": r"ini_set\s*\(.*'display_errors',\s*'1'\)", "severity": "High", "description": "Error display enabled in a production environment. Disable to prevent information leakage."},
    {"pattern": r"error_reporting\s*\(", "severity": "Medium", "description": "Check error reporting configuration to avoid excessive error information exposure."}
]


def is_false_positive(line, pattern, file_path):
    """
    Determine if a detected vulnerability is a false positive based on trusted patterns.

    Args:
        line (str): The line of code where the vulnerability is detected.
        pattern (str): The pattern that triggered the vulnerability detection.
        file_path (str): The file path where the vulnerability was found.

    Returns:
        bool: True if the vulnerability is considered a false positive, False otherwise.
    """
    # Comprehensive list of trusted patterns
    trusted_patterns = [
        # HTML and SQL escaping functions
        r"htmlspecialchars\s*\(",         # Escaping HTML special characters
        r"addslashes\s*\(",               # Escaping special characters with slashes
        r"htmlentities\s*\(",             # Convert all applicable characters to HTML entities
        r"strip_tags\s*\(",               # Strips HTML and PHP tags from a string
        r"mysqli_real_escape_string\s*\(", # Escaping strings for MySQL queries
        r"pg_escape_string\s*\(",         # Escaping strings for PostgreSQL queries
        r"sqlite3_escape_string\s*\(",    # Escaping strings for SQLite queries
        r"prepare\s*\(",                  # SQL statement preparation

        # JavaScript-safe functions
        r"\bdecodeURIComponent\s*\(",    # JavaScript URL decoding
        r"\bencodeURIComponent\s*\(",    # JavaScript URL encoding
        r"\bJSON\.stringify\s*\(",       # JavaScript object-to-string conversion
        r"\bJSON\.parse\s*\(",           # JavaScript string-to-object conversion

        # Validation and Sanitization
        r"filter_var\s*\(.*?,\s*FILTER_SANITIZE_",  # PHP filter functions for sanitizing inputs
        r"preg_match\s*\(",                        # Pattern matching to validate inputs
        r"ctype_\w+\s*\(",                         # PHP ctype functions (e.g., ctype_alpha)
        r"validate_input\s*\(",                    # Custom validation functions
        r"sanitize_input\s*\(",                    # Custom sanitization functions

        # Encoding and Decoding functions
        r"base64_encode\s*\(",                     # Encoding data
        r"base64_decode\s*\(",                     # Decoding data
        r"hex2bin\s*\(",                           # Hexadecimal to binary conversion
        r"bin2hex\s*\(",                           # Binary to hexadecimal conversion

        # Security Libraries or Wrappers
        r"esc_attr\s*\(",                          # WordPress escaping attributes
        r"esc_html\s*\(",                          # WordPress escaping HTML
        r"wp_kses\s*\(",                           # WordPress content sanitization
        r"secure_query\s*\(",                      # Hypothetical secure query wrapper
        r"safe_execute\s*\(",                      # Hypothetical safe execution wrapper
    ]

    # Combine trusted patterns for matching
    combined_pattern = "|".join(f"({trusted})" for trusted in trusted_patterns)

    # Check if any trusted pattern matches the given line
    is_trusted = bool(re.search(combined_pattern, line))

    # Debug or log information (if needed)
    # print(f"Line checked: {line}")
    # print(f"Trusted pattern matched: {is_trusted}")

    return is_trusted


def scan_file(file_path, progress_callback):
    """Scan a single file for vulnerabilities."""
    results = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i, line in enumerate(lines, start=1):
                for rule in DETECTION_RULES:
                    if re.search(rule["pattern"], line) and not is_false_positive(line, rule["pattern"], file_path):
                        results.append({
                            "file": file_path,
                            "line": i,
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "code": line.strip()
                        })
                progress_callback(int((i / len(lines)) * 100))
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
    return results

def scan_directory(directory, progress_callback):
    """Scan all eligible files in a directory for vulnerabilities."""
    results = []
    files_to_scan = [
        os.path.join(root, file)
        for root, _, files in os.walk(directory)
        for file in files if file.endswith((".php", ".html", ".py"))
    ]
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_file, file_path, progress_callback) for file_path in files_to_scan]
        for future in futures:
            results.extend(future.result())
    return results



def generate_html_report(results, output_path):
    """
    Generate a visually appealing HTML report with a severity chart and a detailed table.

    Args:
        results (list): A list of dictionaries containing scan results with keys:
                        'file', 'line', 'severity', 'description', and 'code'.
        output_path (str): The file path where the HTML report will be saved.

    Returns:
        str: The absolute path to the generated report.
    """
    # Count severity occurrences
    severity_counts = {severity: 0 for severity in ["Critical", "High", "Medium", "Low"]}
    for result in results:
        severity_counts[result["severity"]] += 1

    # Create table rows dynamically
    table_rows = "\n".join([
        f"""
        <tr>
            <td>{result['file']}</td>
            <td>{result['line']}</td>
            <td class="{result['severity'].lower()}">{result['severity']}</td>
            <td>{result['description']}</td>
            <td><pre>{result['code']}</pre></td>
        </tr>
        """ for result in results
    ])

    # HTML Template
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerability Scan Report</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            /* Base Styles */
            body {{
                font-family: 'Arial', sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(to bottom, #e0f7fa, #ffffff);
                color: #333;
            }}
            h1 {{
                text-align: center;
                font-size: 2.5em;
                margin-top: 20px;
                color: #00796b;
                text-shadow: 1px 1px 4px rgba(0, 0, 0, 0.1);
            }}
            .container {{
                width: 90%;
                margin: 0 auto;
            }}
            .chart-container {{
                margin: 20px auto;
                background-color: #fff;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                padding: 20px;
                text-align: center;
                width: 50%;
            }}
            canvas {{
                max-width: 300px;
                margin: 0 auto;
            }}
            /* Table Styles */
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background-color: #ffffff;
                box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
                border-radius: 8px;
                overflow: hidden;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #00796b;
                color: white;
                font-weight: bold;
                text-transform: uppercase;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            tr:hover {{
                background-color: #f1f1f1;
                cursor: pointer;
            }}
            /* Severity Colors */
            .critical {{
                color: #d32f2f;
                font-weight: bold;
            }}
            .high {{
                color: #ffa000;
                font-weight: bold;
            }}
            .medium {{
                color: #fbc02d;
                font-weight: bold;
            }}
            .low {{
                color: #388e3c;
                font-weight: bold;
            }}
            /* Responsive Styles */
            @media (max-width: 768px) {{
                h1 {{
                    font-size: 1.8em;
                }}
                .chart-container {{
                    width: 90%;
                }}
                table {{
                    font-size: 0.9em;
                }}
            }}
        </style>
    </head>
    <body>
        <h1>Vulnerability Scan Report</h1>
        <div class="container">
            <!-- Chart Section -->
            <div class="chart-container">
                <h2 style="color: #00796b; font-size: 1.5em; margin-bottom: 10px;">Severity Distribution</h2>
                <canvas id="severityChart"></canvas>
            </div>
            <!-- Table Section -->
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Line</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>Code</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
        <script>
            // Chart Configuration
            const ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        data: [
                            {severity_counts['Critical']}, 
                            {severity_counts['High']}, 
                            {severity_counts['Medium']}, 
                            {severity_counts['Low']}
                        ],
                        backgroundColor: ['#d32f2f', '#ffa000', '#fbc02d', '#388e3c'],
                        hoverOffset: 10
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                color: '#333',
                                font: {{
                                    size: 14
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """

    # Write the HTML report to the output path
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(html_template)

    # Return the absolute path of the report
    return os.path.abspath(output_path)



# GUI Functions
def start_scan(mode, progress_bar, root):
    """Initiate the scanning process for a file or directory."""
    def update_progress(percentage):
        progress_bar["value"] = percentage
        root.update_idletasks()

    def run_scan():
        results = []
        if mode == "file":
            file_path = filedialog.askopenfilename(filetypes=[("Code Files", "*.php *.html *.py")])
            if file_path:
                results = scan_file(file_path, update_progress)
        elif mode == "directory":
            directory = filedialog.askdirectory()
            if directory:
                results = scan_directory(directory, update_progress)

        if results:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            html_path = f"cyborg_results_{timestamp}.html"
            html_absolute_path = generate_html_report(results, html_path)
            webbrowser.open(f"file://{html_absolute_path}")
            messagebox.showinfo("Scan Complete", f"Results saved to:\n{html_absolute_path}")
        else:
            messagebox.showinfo("No Issues Found", "No vulnerabilities detected!")

    threading.Thread(target=run_scan).start()

def create_gui():
    """Create and display the graphical user interface."""
    root = Tk()
    style = Style("cyborg")
    root.title("Cyborg Vulnerability Scanner")
    root.geometry("1000x700")

    ttk.Label(root, text="Cyborg Vulnerability Scanner", font=("Helvetica", 28), bootstyle="primary").pack(pady=30)
    progress_bar = ttk.Progressbar(root, length=800, mode="determinate")
    progress_bar.pack(pady=20)

    ttk.Button(root, text="Scan Single File", command=lambda: start_scan("file", progress_bar, root), bootstyle="success").pack(pady=20)
    ttk.Button(root, text="Scan Directory", command=lambda: start_scan("directory", progress_bar, root), bootstyle="primary").pack(pady=20)
    ttk.Label(root, text="Secure your code effortlessly with Cyborg.", font=("Helvetica", 18)).pack(pady=30)
    ttk.Label(root, text="Powered By Ali Essam", font=("Helvetica", 18)).pack(pady=30)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
