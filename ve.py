import os
import re
import logging
from tqdm import tqdm
import datetime
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, Tk, ttk
from ttkbootstrap import Style
from concurrent.futures import ThreadPoolExecutor
import webbrowser

# Logging Configuration
LOG_FILE = "cyborg.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Default Detection Rules
DETECTION_RULES = [
    # Sensitive Information Leaks
    {
        "pattern": r"(?i)(api_key|aws_secret_access_key|private_key|password|secret|token|oauth_token|access_token|ssh_passphrase)\s*=\s*[\"']([^\"']+)[\"']",
        "severity": "Critical",
        "description": "Hardcoded sensitive information detected. Store in environment variables or a secure vault."
    },
    {
        "pattern": r"(?i)(db_name|db_user|db_pass|database|username|password)\s*=\s*[\"']([^\"']+)[\"']",
        "severity": "Critical",
        "description": "Hardcoded database credentials detected. Avoid embedding credentials in code."
    },
    {
        "pattern": r"(?i)(BEGIN|END)\s*(RSA|DSA|EC|OPENSSH|PGP)\s*PRIVATE\s*KEY",
        "severity": "Critical",
        "description": "Private key detected in source files. Use secure key management practices."
    },
    {
        "pattern": r"(?i)(aws_access_key_id|aws_secret_access_key|az_subscription_key|gcp_private_key)\s*=\s*[\"']([^\"']+)[\"']",
        "severity": "Critical",
        "description": "Cloud provider credentials detected. Use secure credential management practices."
    },

    # Input Handling Vulnerabilities
    {
        "pattern": r"(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)\[.*\]",
        "severity": "Critical",
        "description": "Unsanitized input detected. Validate and sanitize all external input to prevent injection attacks."
    },
    {
        "pattern": r"htmlspecialchars\s*\(",
        "severity": "High",
        "description": "Ensure correct use of htmlspecialchars to prevent XSS attacks. Check encoding context."
    },
    {
        "pattern": r"strip_tags\s*\(",
        "severity": "Medium",
        "description": "Ensure proper use of strip_tags to prevent XSS. Consider using a more robust sanitization library."
    },
    {
        "pattern": r"(preg_replace|ereg_replace|split|ereg)\s*\(.*?['\"].*e['\"].*?\)",
        "severity": "Critical",
        "description": "Insecure regular expression detected with 'e' modifier. This can lead to code execution."
    },
    {
        "pattern": r"(?i)(urldecode|rawurldecode)\s*\(",
        "severity": "High",
        "description": "Improper use of URL decoding can lead to injection attacks. Sanitize and validate inputs."
    },

    # Code Execution Vulnerabilities
    {
        "pattern": r"(eval|exec|system|shell_exec|popen|passthru|proc_open|pcntl_exec|os.system|subprocess\.run|subprocess\.call)\s*\(",
        "severity": "Critical",
        "description": "Detected unsafe code execution function. Avoid using unless necessary and validate all inputs."
    },
    {
        "pattern": r"assert\s*\(",
        "severity": "Critical",
        "description": "Use of assert detected, which can lead to arbitrary code execution."
    },
    {
        "pattern": r"create_function\s*\(",
        "severity": "High",
        "description": "Detected use of create_function. Replace with anonymous functions for better security."
    },

    # File Handling Vulnerabilities
    {
        "pattern": r"(file_put_contents|file_get_contents|fopen|unlink|chmod|chown|readfile|scandir|opendir|readdir|mkdir|rmdir)\s*\(",
        "severity": "High",
        "description": "Potentially unsafe file operations detected. Validate file paths and permissions."
    },
    {
        "pattern": r"(move_uploaded_file|copy|rename)\s*\(",
        "severity": "Critical",
        "description": "Detected potentially unsafe file handling. Check paths and ensure secure file storage."
    },
    {
        "pattern": r"tmpfile\s*\(",
        "severity": "Medium",
        "description": "Ensure secure handling of temporary files to prevent unauthorized access."
    },

    # Serialization and Deserialization
    {
        "pattern": r"(serialize|unserialize|json_decode|yaml_parse|pickle\.loads|pickle\.load|unmarshal)\s*\(",
        "severity": "Critical",
        "description": "Detected serialization/deserialization operation. Ensure data is validated to prevent injection or RCE."
    },

    # Cryptographic Issues
    {
        "pattern": r"(md5|sha1|crypt|hash\s*\(['\"]md5['\"]|hash\s*\(['\"]sha1['\"])\s*\(",
        "severity": "High",
        "description": "Detected weak hashing algorithm. Replace with stronger algorithms such as bcrypt, Argon2, or SHA-256."
    },
    {
        "pattern": r"(openssl_encrypt|openssl_decrypt|mcrypt_encrypt|mcrypt_decrypt)\s*\(",
        "severity": "High",
        "description": "Detected cryptographic operations. Ensure strong algorithms and configurations are used."
    },
    {
        "pattern": r"(rand|mt_rand|srand)\s*\(",
        "severity": "High",
        "description": "Insecure random number generation detected. Use cryptographically secure alternatives like random_bytes or SecureRandom."
    },

    # Database Vulnerabilities
    {
        "pattern": r"(mysql_query|mysqli_query|pg_query|sqlite_query|oci_parse|db2_exec)\s*\(",
        "severity": "Critical",
        "description": "Detected direct SQL queries. Use parameterized queries or prepared statements to prevent SQL injection."
    },
    {
        "pattern": r"(?i)select\s+\*\s+from",
        "severity": "High",
        "description": "Wildcard detected in SQL queries. Avoid selecting all columns unnecessarily."
    },

    # Debugging Functions (Advanced)
    {
        "pattern": r"(var_dump|print_r|echo|die|exit|debug_backtrace|debug_print_backtrace|console\.log|alert|debugger|printf|sprintf)\s*\(",
        "severity": "Medium",
        "description": "Detected debugging or development functions. Remove these before deploying to production."
    },

    # Security Misconfigurations
    {
        "pattern": r"ini_set\s*\(.*'display_errors',\s*'1'\)",
        "severity": "High",
        "description": "Detected enabled error display. Disable this in production environments."
    },
    {
        "pattern": r"(?i)allow_url_(include|fopen)\s*=\s*['\"]1['\"]",
        "severity": "Critical",
        "description": "Remote file inclusion detected. Disable this setting in production."
    },

    # Logging Sensitive Data
    {
        "pattern": r"(error_log|log_message|console\.log|logging\.(debug|info|warning|error))\s*\(.*['\"](password|key|secret)['\"].*\)",
        "severity": "Critical",
        "description": "Sensitive data detected in logging functions. Avoid logging sensitive information."
    },

    # Authentication and Session Management
    {
        "pattern": r"session_start\s*\(",
        "severity": "High",
        "description": "Detected session handling. Ensure secure session management practices, including HTTPS."
    },
    {
        "pattern": r"(?i)(csrf_token|xsrf_token|session_id|jwt)\s*=\s*[\"'].*[\"']",
        "severity": "High",
        "description": "Potential exposure of CSRF/XSRF/session tokens detected. Protect sensitive tokens."
    },
    {
        "pattern": r"(?i)setcookie\s*\(",
        "severity": "High",
        "description": "Detected cookie handling. Ensure secure and HttpOnly flags are set."
    },

    # Access Control Issues
    {
        "pattern": r"(?i)(admin|superuser|root)_access\s*=\s*['\"]1['\"]",
        "severity": "Critical",
        "description": "Hardcoded privileged access detected. Avoid hardcoding access control logic."
    },

    # Insecure Practices
    {
        "pattern": r"(?i)base64_(encode|decode)\s*\(",
        "severity": "Medium",
        "description": "Base64 detected. Avoid using Base64 for sensitive data storage or obfuscation."
    },
    {
        "pattern": r"(?i)(wget|curl|urllib\.request)\s*\(['\"]http",
        "severity": "High",
        "description": "Detected unvalidated URL handling. Sanitize and validate URLs."
    },

    # Other Vulnerabilities
    {
        "pattern": r"(?i)(os.system|subprocess.run|subprocess.call)\s*\(",
        "severity": "Critical",
        "description": "Detected system command execution. Validate inputs to prevent command injection."
    },
    {
        "pattern": r"(fs.writeFile|fs.readFile|fs.appendFile)\s*\(",
        "severity": "High",
        "description": "Detected insecure file operations in JavaScript/Node.js. Validate file paths and inputs."
    }
]







TRUSTED_PATTERNS = [
    # HTML and SQL escaping functions
    re.compile(r"htmlspecialchars\s*\("),
    re.compile(r"addslashes\s*\("),
    re.compile(r"htmlentities\s*\("),
    re.compile(r"strip_tags\s*\("),
    re.compile(r"mysqli_real_escape_string\s*\("),
    re.compile(r"pg_escape_string\s*\("),
    re.compile(r"sqlite3_escape_string\s*\("),
    re.compile(r"prepare\s*\("),

    # JavaScript-safe functions
    re.compile(r"\bdecodeURIComponent\s*\("),
    re.compile(r"\bencodeURIComponent\s*\("),
    re.compile(r"\bJSON\.stringify\s*\("),
    re.compile(r"\bJSON\.parse\s*\("),

    # Validation and Sanitization
    re.compile(r"filter_var\s*\(.*?,\s*FILTER_SANITIZE_"),
    re.compile(r"preg_match\s*\("),
    re.compile(r"ctype_\w+\s*\("),
    re.compile(r"validate_input\s*\("),
    re.compile(r"sanitize_input\s*\("),

    # Encoding and Decoding functions
    re.compile(r"base64_encode\s*\("),
    re.compile(r"base64_decode\s*\("),
    re.compile(r"hex2bin\s*\("),
    re.compile(r"bin2hex\s*\("),

    # Security Libraries or Wrappers
    re.compile(r"esc_attr\s*\("),
    re.compile(r"esc_html\s*\("),
    re.compile(r"wp_kses\s*\("),
    re.compile(r"secure_query\s*\("),
    re.compile(r"safe_execute\s*\("),
]

# Define trusted file paths or directories to exclude
TRUSTED_PATHS = [
    "vendor/",        # Common dependency directories
    "node_modules/",  # JavaScript dependencies
    "PHPMailer",      # Known safe libraries
]


def is_false_positive(line, pattern, file_path):
    """
    Determine if a detected vulnerability is a false positive based on trusted patterns or contexts.

    Args:
        line (str): The line of code where the vulnerability is detected.
        pattern (str): The pattern that triggered the vulnerability detection.
        file_path (str): The file path where the vulnerability was found.

    Returns:
        bool: True if the vulnerability is considered a false positive, False otherwise.
    """
    # Check if the file path matches a trusted path
    for trusted_path in TRUSTED_PATHS:
        if trusted_path.lower() in file_path.lower():
            logging.debug(f"False positive: Trusted file path matched: {file_path}")
            return True

    # Check against precompiled trusted patterns
    for trusted_pattern in TRUSTED_PATTERNS:
        if trusted_pattern.search(line):
            logging.debug(f"False positive: Trusted pattern matched in line: {line.strip()}")
            return True

    # Additional heuristic: Ignore empty or placeholder variable declarations
    placeholder_patterns = [
        re.compile(r"=\s*[\"']?[\"']?\s*;"),  # Match empty string assignments (e.g., `= "";`)
        re.compile(r"=\s*null\s*;?", re.IGNORECASE),  # Match null assignments
    ]
    for placeholder_pattern in placeholder_patterns:
        if placeholder_pattern.search(line):
            logging.debug(f"False positive: Placeholder assignment detected in line: {line.strip()}")
            return True

    # Check if the line is part of a comment
    if line.strip().startswith("//") or line.strip().startswith("#"):
        logging.debug(f"False positive: Line is a comment: {line.strip()}")
        return True

    # No trusted pattern matched; consider it a valid vulnerability
    logging.debug(f"Potential vulnerability detected: {line.strip()} (Pattern: {pattern})")
    return False


def scan_file(file_path, progress_callback=None):
    """
    Scan a single file for vulnerabilities using advanced detection rules.

    Args:
        file_path (str): Path to the file to be scanned.
        progress_callback (callable, optional): Function to report scan progress.

    Returns:
        list: A list of detected vulnerabilities.
    """
    results = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

        # Combine lines for multiline pattern matching
        file_content = "\n".join(lines)

        # Scan each detection rule
        for rule in DETECTION_RULES:
            matches = re.finditer(rule["pattern"], file_content, re.MULTILINE)
            for match in matches:
                # Get the line number from the match
                start_pos = match.start()
                line_number = file_content[:start_pos].count("\n") + 1
                
                # Avoid false positives
                if not is_false_positive(match.group(), rule["pattern"], file_path):
                    results.append({
                        "file": file_path,
                        "line": line_number,
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "code": match.group().strip()
                    })

        # Report progress using a smart callback or default to tqdm
        if progress_callback:
            progress_callback(100)
        else:
            tqdm.write(f"Scan complete for {file_path}")
    
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except UnicodeDecodeError:
        logging.error(f"File encoding error in {file_path}. Ensure the file is UTF-8 encoded.")
    except Exception as e:
        logging.error(f"Unexpected error while scanning file {file_path}: {e}")

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
    """
    Create and display the graphical user interface for the Cyborg Vulnerability Scanner.
    """
    # Initialize the root window with ttkbootstrap styling
    root = tk.Tk()
    style = Style("cyborg")
    root.title("Cyborg Vulnerability Scanner")
    root.geometry("1000x750")
    root.resizable(False, False)  # Fixed window size for consistent layout

    # Header Section
    header_frame = ttk.Frame(root)
    header_frame.pack(pady=20)
    ttk.Label(
        header_frame,
        text="Cyborg Vulnerability Scanner",
        font=("Helvetica", 28),
        bootstyle="primary-inverse"
    ).pack()
    ttk.Label(
        header_frame,
        text="Secure your code effortlessly. Detect vulnerabilities before they cause trouble.",
        font=("Helvetica", 14),
        bootstyle="secondary"
    ).pack(pady=10)

    # Main Content Section
    content_frame = ttk.Frame(root)
    content_frame.pack(pady=20)

    # Progress Bar Section
    progress_label = ttk.Label(content_frame, text="Scan Progress:", font=("Helvetica", 12))
    progress_label.pack(pady=5)
    progress_bar = ttk.Progressbar(content_frame, length=800, mode="determinate")
    progress_bar.pack()

    # Buttons Section
    button_frame = ttk.Frame(content_frame)
    button_frame.pack(pady=30)

    ttk.Button(
        button_frame,
        text="Scan Single File",
        command=lambda: start_scan("file", progress_bar, root),
        bootstyle="success-outline"
    ).pack(pady=10)

    ttk.Button(
        button_frame,
        text="Scan Directory",
        command=lambda: start_scan("directory", progress_bar, root),
        bootstyle="info-outline"
    ).pack(pady=10)

    ttk.Button(
        button_frame,
        text="View Help",
        command=lambda: show_help(),
        bootstyle="secondary-outline"
    ).pack(pady=10)

    ttk.Button(
        button_frame,
        text="Exit Application",
        command=root.quit,
        bootstyle="danger-outline"
    ).pack(pady=10)

    # Footer Section
    footer_frame = ttk.Frame(root)
    footer_frame.pack(side="bottom", pady=20)
    ttk.Label(
        footer_frame,
        text="Powered by Ali Essam | Cyborg Security Tools © 2024",
        font=("Helvetica", 10),
        bootstyle="light"
    ).pack()

    # Help Functionality
    def show_help():
        """Display a help message for the user."""
        help_message = (
            "Welcome to the Cyborg Vulnerability Scanner!\n\n"
            "Instructions:\n"
            "1. Use 'Scan Single File' to analyze a specific file for vulnerabilities.\n"
            "2. Use 'Scan Directory' to analyze all eligible files in a directory.\n"
            "3. Monitor the progress of your scan using the progress bar.\n"
            "4. Review detailed scan results in an automatically generated HTML report.\n\n"
            "Supported File Types:\n"
            "- PHP, HTML, Python\n"
            "\nFor further assistance, contact: support@cyborgtools.com"
        )
        messagebox.showinfo("Help - Cyborg Vulnerability Scanner", help_message)

    # Start Main Loop
    root.mainloop()

if __name__ == "__main__":
    create_gui()
