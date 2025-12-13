# File Scanner - Dangerous Text String Detection

**Author:** cyb3rlop3
**Purpose:** Automated scanning of files for malicious code patterns, credential leaks, and security vulnerabilities

## Overview

This Python-based file scanner automates the process of reviewing files for dangerous text strings, suspicious code patterns, and sensitive data leaks. Instead of manually reviewing thousands of files, this tool acts as a high-speed scanner that can detect security issues across your codebase, repositories, or file systems.

## Practical Applications

### 1. Malware and Exploit Detection
Security professionals can verify if files contain code that resembles known exploits or malicious patterns.

- **Use Case:** Scan downloaded scripts, code repositories, or suspect files for malware indicators
- **Benefit:** Rapidly identify malicious code without manual inspection

### 2. Open Source Intelligence (OSINT) & Data Leakage
Find accidentally exposed credentials and sensitive data in code repositories.

- **Use Case:** "Dumpster diving" in GitHub repos to find leaked passwords, API keys, or tokens
- **Benefit:** Discover and revoke compromised credentials before they are exploited

### 3. Code Security Audits
Review code for common vulnerabilities like SQL injection, XSS, and insecure functions.

- **Use Case:** Automated security review during code audits or penetration tests
- **Benefit:** Quickly identify vulnerable code patterns across large codebases

### 4. Web Shell Detection
Identify backdoors and web shells on compromised servers.

- **Use Case:** Server security audit after suspected breach
- **Benefit:** Detect common web shell signatures and obfuscated malicious code

## Features

- **Multi-Category Detection:** Credentials, malicious code, SQL injection, web shells, and more
- **Customizable Indicators:** Load custom patterns from JSON configuration
- **Multiple Scan Modes:** Directory scanning, single file, GitHub repository files
- **Detailed Reporting:** Generate reports in text, JSON, or CSV formats
- **Smart File Filtering:** Skip binary files, filter by extension, exclude directories
- **Line Number Tracking:** Pinpoint exact locations of detected patterns
- **Statistics:** Track scanned files, matches, and error counts

## Installation

### Requirements
- Python 3.7 or higher
- No external dependencies required (uses standard library)

### Setup
```bash
# Clone or download the files
git clone https://github.com/spearsies/Pythonscripts.git
cd Pythonscripts

# No pip install needed - uses only Python standard library
```

## Quick Start

### Basic Usage

```python
from file_scanner import FileScanner

# Create scanner instance
scanner = FileScanner()

# Scan a directory
results = scanner.scan_directory(
    directory='./my_project',
    recursive=True,
    file_extensions=['.py', '.js', '.php']
)

# Generate report
scanner.generate_report(output_file='scan_report.txt', format='text')
```

### Command Line Usage

```bash
# Run the default scanner
python file_scanner.py

# This will:
# - Scan the current directory
# - Look for .py, .txt, .js, .sh, .bat files
# - Generate scan_report.txt and scan_report.json
```

## Usage Examples

### Example 1: Scan for Credentials

```python
from file_scanner import FileScanner

scanner = FileScanner()

# Scan for leaked credentials
results = scanner.scan_directory(
    directory='./source_code',
    recursive=True,
    file_extensions=['.py', '.env', '.config', '.json']
)

# Check results
print(f"Found {len(results)} potential credential leaks")
scanner.generate_report('credentials_report.txt', 'text')
```

### Example 2: Scan GitHub Repository

```python
from file_scanner import FileScanner

scanner = FileScanner()

# Scan a specific GitHub file
url = 'https://raw.githubusercontent.com/user/repo/main/config.py'
matches = scanner.scan_github_file(url)

if matches:
    print(f"Found {len(matches)} security issues in {url}")
```

### Example 3: Custom Indicators

```python
from file_scanner import FileScanner

# Load custom indicators from JSON file
scanner = FileScanner(indicators_file='indicators.json')

# Scan with custom patterns
results = scanner.scan_directory('.', recursive=True)
scanner.generate_report('custom_report.json', 'json')
```

### Example 4: Web Shell Detection

```python
from file_scanner import FileScanner

scanner = FileScanner()

# Configure for web shell detection
scanner.indicators = {
    'web_shells': [
        'c99', 'r57', 'wso', 'webshell',
        'eval(', 'base64_decode', 'shell_exec'
    ]
}

# Scan web directory
results = scanner.scan_directory(
    directory='/var/www/html',
    file_extensions=['.php', '.phtml']
)

if results:
    print("WARNING: Potential web shells detected!")
    scanner.generate_report('webshell_report.txt', 'text')
```

## Configuration

### Indicator Categories (Default)

The scanner comes with pre-configured detection patterns:

1. **Credentials:** Passwords, API keys, tokens, secrets
2. **Malicious Code:** eval(), exec(), system calls, dangerous functions
3. **Network Suspicious:** Reverse shells, netcat, suspicious network activity
4. **SQL Injection:** SQL injection patterns and exploits
5. **Data Exfiltration:** Suspicious network connections, file transfers
6. **Web Vulnerabilities:** XSS, innerHTML, dangerous DOM manipulation
7. **File Operations:** Risky file system operations
8. **Crypto Miners:** Cryptocurrency mining scripts
9. **Backdoors:** Known backdoor signatures
10. **Obfuscation:** Base64 encoding, compression, encoding tricks

### Custom Indicators File (indicators.json)

Create a JSON file with your own patterns:

```json
{
  "custom_category": [
    "pattern1",
    "pattern2",
    "dangerous_function("
  ],
  "credentials": [
    "password",
    "api_key",
    "secret"
  ]
}
```

Load it when creating the scanner:

```python
scanner = FileScanner(indicators_file='indicators.json')
```

## Report Formats

### Text Report
Human-readable format with file paths, categories, and line numbers.

```python
scanner.generate_report('report.txt', 'text')
```

### JSON Report
Structured data format for programmatic processing.

```python
scanner.generate_report('report.json', 'json')
```

### CSV Report
Spreadsheet-compatible format for analysis.

```python
scanner.generate_report('report.csv', 'csv')
```

## Advanced Features

### Exclude Directories

```python
results = scanner.scan_directory(
    directory='.',
    exclude_dirs=['.git', 'node_modules', 'venv', '__pycache__']
)
```

### Filter by File Extensions

```python
results = scanner.scan_directory(
    directory='.',
    file_extensions=['.py', '.js', '.php', '.rb']
)
```

### Case-Sensitive Scanning

```python
matches = scanner.scan_file('config.py', case_sensitive=True)
```

### Get Scan Statistics

```python
stats = scanner.get_summary()
print(f"Files scanned: {stats['files_scanned']}")
print(f"Matches found: {stats['total_matches']}")
```

## Real-World Scenarios

### Scenario 1: Penetration Testing
You've gained access to a client's codebase and need to find hardcoded credentials.

```python
scanner = FileScanner()
scanner.indicators = {'credentials': ['password', 'api_key', 'secret', 'token']}
results = scanner.scan_directory('/client/source', recursive=True)
scanner.generate_report('pentest_findings.txt', 'text')
```

### Scenario 2: Malware Analysis
Analyzing a suspicious script for malicious behavior.

```python
scanner = FileScanner()
results = scanner.scan_file('suspicious_script.py')

for match in results:
    print(f"ALERT: {match['category']} - {match['pattern']} at line {match['line_numbers']}")
```

### Scenario 3: GitHub OSINT
Searching public repositories for exposed secrets.

```python
scanner = FileScanner()

github_files = [
    'https://raw.githubusercontent.com/target/repo/main/.env',
    'https://raw.githubusercontent.com/target/repo/main/config.py',
]

for url in github_files:
    matches = scanner.scan_github_file(url)
    if matches:
        print(f"Credentials found in {url}")
```

### Scenario 4: Server Breach Investigation
Scanning a web server for backdoors after compromise.

```python
scanner = FileScanner()
results = scanner.scan_directory(
    directory='/var/www',
    file_extensions=['.php', '.phtml', '.php3'],
    recursive=True
)

if results:
    print("Web shells detected! Investigate immediately.")
    scanner.generate_report('breach_investigation.txt', 'text')
```

## How It Works

The scanner uses three core programming concepts:

1. **File I/O:** Opens and reads file contents into memory
2. **Iteration:** Loops through files and searches for patterns
3. **Conditionals:** Uses `if` statements to check for indicator matches

### Core Logic

```python
# Open file
with open(file_path, 'r') as f:
    content = f.read()

# Search for patterns
for pattern in dangerous_patterns:
    if pattern in content:  # Conditional check
        print(f"ALERT: Found {pattern}")
```

## Performance Considerations

- **Binary File Detection:** Automatically skips binary files to improve speed
- **Smart Filtering:** Exclude common directories (`.git`, `node_modules`) to reduce scan time
- **File Extension Filtering:** Focus on relevant file types
- **Progress Tracking:** Monitor scan statistics in real-time

## Security Best Practices

1. **Validate Findings:** Not all matches are true positives - review results manually
2. **Regular Scans:** Schedule periodic scans of your codebase
3. **Custom Patterns:** Tailor indicators to your specific environment
4. **Secure Reports:** Treat scan reports as sensitive data - they may contain secrets
5. **Version Control:** Never commit actual credentials; use `.env.example` files

## Troubleshooting

### Issue: Files not being scanned
- Check file extensions filter
- Verify directory is not in exclude list
- Ensure proper permissions to read files

### Issue: Too many false positives
- Refine your indicators to be more specific
- Use case-sensitive matching
- Add context to patterns (e.g., "password =" instead of just "password")

### Issue: Binary file errors
- The scanner automatically detects and skips binary files
- If errors persist, check file encoding

## Contributing

This tool is designed for security professionals and developers. Suggested improvements:

- Additional indicator categories
- Performance optimizations
- New report formats
- Integration with other security tools

## Legal and Ethical Use

**Important:** This tool is for authorized security testing only.

- ✅ Use on your own code and systems
- ✅ Use during authorized penetration tests
- ✅ Use for security research and education
- ❌ Do not use for unauthorized access
- ❌ Do not use to exploit vulnerabilities
- ❌ Do not scan systems without permission

## License

Free to use for security research, testing, and educational purposes.

## Contact

**Author:** cyb3rlop3
**Email:** stan.spears@outlook.com
**GitHub:** https://github.com/spearsies/Pythonscripts

## Changelog

### Version 1.0
- Initial release
- Multi-category indicator support
- Text, JSON, and CSV reporting
- Directory and GitHub scanning
- Custom indicator configuration

---

**Remember:** Use this tool responsibly and only on systems you own or have explicit permission to test.
