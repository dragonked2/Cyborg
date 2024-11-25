# Cyborg Vulnerability Scanner
![Screenshot 2024-11-24 at 13-58-53 Free Logo Maker - Get Custom Logo Designs in Minutes Looka](https://github.com/user-attachments/assets/71c26d6b-f522-4032-bd02-7c5ec5334ac9)

Cyborg Vulnerability Scanner is a **free, open-source tool** designed to analyze your code for potential vulnerabilities and generate visually appealing, detailed reports. It supports scanning single files or entire directories and helps developers identify and mitigate security risks effectively.

---

## 🚀 Features

- **Comprehensive Vulnerability Detection**:
  - Identifies critical issues like SQL injection, XSS, insecure deserialization, and insecure file handling.
  - Detects weak cryptographic algorithms such as MD5 and SHA1.

- **Multi-Language Support**:
  - Scans files written in PHP, HTML, and Python.

- **Detailed Reports**:
  - Generates an HTML report with a severity distribution chart and a table of detected vulnerabilities.

- **Fast and Efficient**:
  - Uses multithreading for fast directory scans.

- **Customizable Detection**:
  - Predefined detection rules that can be extended for specific use cases.

- **User-Friendly GUI**:
  - Built with `ttkbootstrap`, featuring a modern, responsive interface.

---

## 📸 Screenshots

### GUI
![image](https://github.com/user-attachments/assets/b5dbf4a7-323f-4210-85b3-ee78861d02bc)



### HTML Report
![Screenshot 2024-11-24 140105](https://github.com/user-attachments/assets/77f6e524-58d2-4625-aed4-7138053b3c17)


---

## 🔧 Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/dragonked2/Cyborg.git
   cd cyborg-vulnerability-scanner
   ```

2. **Install Dependencies**:
   Ensure Python 3.8+ is installed. Then, install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Scanner**:
   ```bash
   python ve.py
   ```

---

## 🖥️ How to Use

### GUI Mode:
1. Launch the application:
   ```bash
   python ve.py
   ```
2. Select either:
   - **Scan Single File**: Choose a specific file to scan.
   - **Scan Directory**: Select a folder to scan all files within it.
3. View the results in a detailed HTML report that opens automatically upon completion.

### Command-Line Mode (Planned Feature):
Future versions will support CLI commands for enhanced automation.

---

### 💡 How to Create an EXE File for Easy Usage

You can convert the Cyborg Vulnerability Scanner into an executable file using **PyInstaller**, allowing you to run the tool without needing Python installed.

#### 1. **Install PyInstaller**
Ensure you have PyInstaller installed. Run the following command:

```bash
pip install pyinstaller
```

#### 2. **Create the EXE File**
Use PyInstaller to compile the Python script into a standalone executable:

```bash
python -m PyInstaller --onefile --noconsole ve.py
```

- **`--onefile`**: Bundles everything into a single executable file.
- **`--noconsole`**: Hides the console window (useful for GUI applications).

#### 3. **Run the EXE**
Navigate to the `dist` folder where the EXE file is generated, and double-click `ve.exe` to launch the tool.

```plaintext
dist/
└── ve.exe
```

Enjoy a seamless experience with your standalone vulnerability scanner!

--- 

This version ensures clarity and highlights the simplicity of the process, making it easy for users to follow.
---

## 🛡️ Detection Rules

Cyborg Scanner uses a comprehensive set of detection rules to find vulnerabilities, including:

- **Input Handling**:
  - Unsanitized inputs (`$_GET`, `$_POST`, `$_REQUEST`).
  - Unsafe cookies (`$_COOKIE`).

- **Code Execution**:
  - Dangerous functions like `eval`, `exec`, `shell_exec`.

- **File Operations**:
  - Potentially risky operations (`file_put_contents`, `fopen`, `unlink`).

- **Cryptography**:
  - Weak algorithms (e.g., `md5`, `sha1`).

- **Output Escaping**:
  - Unescaped user inputs in `echo` or `print`.

---

## 📜 Example Output

Sample of detected vulnerabilities in the HTML report:

| File       | Line | Severity | Description                                | Code                     |
|------------|------|----------|--------------------------------------------|--------------------------|
| `index.php` | 15   | Critical | Unsanitized input from `$_GET`.            | `echo $_GET['user'];`    |
| `script.py` | 32   | High     | Weak hashing algorithm `md5` detected.    | `hashed = md5(password)` |

The HTML report also includes a **severity distribution chart** for quick visualization.

---

## 🛠️ Development

### Extend Detection Rules
You can add new detection rules in the `DETECTION_RULES` list within `ve.py`. Each rule must include:
- `pattern`: Regex pattern to detect the vulnerability.
- `severity`: Severity level (`Critical`, `High`, `Medium`, `Low`).
- `description`: Explanation of the vulnerability.

Example:
```python
{"pattern": r"unsafe_function\s*\(", "severity": "Critical", "description": "Unsafe function detected. Avoid usage."}
```

---

## 📥 Contributing

Contributions are welcome! Here’s how you can contribute:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Added new feature"
   ```
4. Push your branch and submit a pull request.

---

## 📧 Support

If you encounter issues or have suggestions, please create a GitHub issue or contact **[Ali Essam](https://linkedin.com/in/dragonked2)**.

---

## 🌟 Acknowledgments

Thanks to all open-source contributors who inspired this project!

---

## 🏆 Future Features

- **Command-Line Interface (CLI)**:
  - Support for automation and integration into CI/CD pipelines.(soon)

- **Custom Rules**:
  - Allow users to define their own detection rules.(soon)

- **Multi-Language Support**:
  - Add support for JavaScript, Java, and C++.(soon)

---

### **Star this repository** 🌟 if you find Cyborg Vulnerability Scanner helpful!
