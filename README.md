# Python Scripts for SOC Analysts

A collection of Python-based security automation tools for SOC analysts, penetration testers, and security researchers. These scripts automate common security tasks including malware detection, credential leak scanning, and Active Directory user validation.

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/spearsies/Pythonscripts)

## Table of Contents

- [Overview](#overview)
- [Tools](#tools)
  - [File Scanner](#file-scanner)
  - [Active Directory User Check](#active-directory-user-check)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Use Cases](#use-cases)
- [Documentation](#documentation)
- [Legal & Ethical Use](#legal--ethical-use)
- [Contributing](#contributing)
- [Contact](#contact)

## Overview

This repository provides ready-to-use Python scripts designed for security operations:

- **File Scanner**: Detect malicious code patterns, credential leaks, and security vulnerabilities across codebases
- **AD User Check**: Validate Active Directory user accounts in bulk from CSV files

All tools are built with Python's standard library where possible, minimizing dependencies and maximizing portability.

## Tools

### File Scanner

**Automated security scanning for dangerous code patterns and credential leaks**

![File Scanner](https://img.shields.io/badge/status-production-success.svg)

A high-speed file scanner that searches for:
- Hardcoded credentials (passwords, API keys, tokens)
- Malicious code patterns (eval, exec, shell commands)
- SQL injection attempts
- Web shells and backdoors
- Network suspicious activity
- Data exfiltration indicators
- Crypto mining scripts
- Obfuscation techniques

**Key Features:**
- 10+ detection categories with customizable patterns
- Multiple output formats (Text, JSON, CSV)
- GitHub repository scanning support
- Line-by-line pattern tracking
- Binary file detection and filtering
- Recursive directory scanning

**Quick Example:**
```python
from file_scanner import FileScanner

scanner = FileScanner()
results = scanner.scan_directory('./my_project', recursive=True)
scanner.generate_report('security_scan.txt', 'text')
```

**Learn More:** [FILE_SCANNER_README.md](FILE_SCANNER_README.md)

### Active Directory User Check

**Bulk validation of Active Directory user accounts**

![AD Check](https://img.shields.io/badge/status-production-success.svg)

Quickly verify if users from a CSV file exist and are active in your Active Directory environment.

**Key Features:**
- CSV input/output for bulk processing
- LDAP/NTLM authentication
- User status detection (active/disabled)
- Email and display name retrieval
- Summary statistics and reporting

**Quick Example:**
```python
# Configure AD settings in script
python check_ad_users.py
# Input: usernames.csv
# Output: ad_check_results.csv
```

**Use Cases:**
- Security audits and access reviews
- User account validation
- Offboarding verification
- Compliance reporting

## Installation

### Requirements

- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/spearsies/Pythonscripts.git
cd Pythonscripts
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

**Note:** The File Scanner has no external dependencies and uses only Python's standard library.

## Quick Start

### Scan Files for Security Issues

```bash
# Scan current directory
python file_scanner.py

# Scan specific file types
python scanner_examples.py
```

### Check Active Directory Users

```bash
# 1. Edit check_ad_users.py with your AD configuration
# 2. Prepare usernames.csv with user list
# 3. Run the script
python check_ad_users.py

# 4. Review ad_check_results.csv for results
```

### Custom Security Indicators

Create a custom `indicators.json` file:

```json
{
  "custom_patterns": [
    "SECRET_KEY",
    "private_token",
    "admin_password"
  ],
  "malware_signatures": [
    "malicious_function",
    "backdoor_code"
  ]
}
```

Then load it:

```python
from file_scanner import FileScanner

scanner = FileScanner(indicators_file='indicators.json')
results = scanner.scan_directory('.')
scanner.generate_report('custom_report.json', 'json')
```

## Use Cases

### For SOC Analysts

- **Incident Response**: Quickly scan compromised systems for malware signatures
- **Threat Hunting**: Search codebases for indicators of compromise
- **Log Analysis**: Detect suspicious patterns in log files
- **User Account Audits**: Validate user access across AD environments

### For Penetration Testers

- **Credential Discovery**: Find hardcoded passwords and API keys in source code
- **Web Shell Detection**: Identify backdoors on compromised servers
- **Code Review**: Automate vulnerability detection in client applications
- **Reconnaissance**: Enumerate user accounts and status

### For Security Researchers

- **OSINT**: Scan public GitHub repositories for leaked credentials
- **Malware Analysis**: Identify malicious code patterns in suspicious files
- **Vulnerability Research**: Detect common security anti-patterns
- **Security Audits**: Automated code security reviews

### For Developers

- **Pre-commit Checks**: Scan code for secrets before committing
- **Security Testing**: Integrate into CI/CD pipelines
- **Code Quality**: Detect dangerous coding patterns
- **Compliance**: Ensure no sensitive data in repositories

## Documentation

### File Scanner Documentation

Comprehensive documentation available in [FILE_SCANNER_README.md](FILE_SCANNER_README.md):

- Detailed feature explanations
- Advanced usage examples
- Configuration options
- Report format specifications
- Performance optimization tips
- Troubleshooting guide

### Example Scripts

See [scanner_examples.py](scanner_examples.py) for practical examples:

- Scanning for specific credential types
- GitHub repository scanning
- Custom indicator usage
- Web shell detection
- Batch processing

### Configuration Files

- `indicators.json` - Custom security pattern definitions
- `requirements.txt` - Python package dependencies
- `usernames.csv` - Sample CSV format for AD user checks

## Legal & Ethical Use

**IMPORTANT:** These tools are for authorized security testing only.

### Authorized Use

- Your own code and systems
- Security audits with written authorization
- Penetration tests with explicit permission
- Educational and research purposes
- Defensive security operations

### Prohibited Use

- Unauthorized access to systems
- Scanning systems without permission
- Exploiting discovered vulnerabilities without authorization
- Violating privacy laws or regulations
- Malicious purposes of any kind

**By using these tools, you agree to use them responsibly and only on systems you own or have explicit permission to test.**

## Security Considerations

### File Scanner

- This is a **defensive security tool**, not malware
- Safe to run - only reads files, never modifies them
- Treat scan reports as sensitive (may contain discovered secrets)
- Validate findings manually - not all matches are true positives

### AD User Check

- Never commit actual AD credentials to version control
- Use environment variables or secure vaults for credentials
- Ensure LDAP connections are encrypted
- Handle user data per privacy policies and regulations

## Performance Tips

### File Scanner Optimization

```python
# Exclude large directories
results = scanner.scan_directory(
    '.',
    exclude_dirs=['.git', 'node_modules', 'venv', '__pycache__']
)

# Limit to specific file types
results = scanner.scan_directory(
    '.',
    file_extensions=['.py', '.js', '.php', '.env', '.config']
)
```

### AD User Check Optimization

- Process users in batches for large lists
- Cache connection objects for multiple queries
- Use service accounts with minimal required permissions

## Troubleshooting

### Common Issues

**File Scanner: Too many false positives**
- Refine indicators to be more specific
- Use case-sensitive matching
- Add context to patterns (e.g., `password =` instead of just `password`)

**File Scanner: Files not being scanned**
- Check file extension filter
- Verify directory not in exclude list
- Ensure proper read permissions

**AD Check: Connection failures**
- Verify AD server address and credentials
- Check network connectivity and firewall rules
- Ensure NTLM authentication is enabled

**AD Check: No users found**
- Verify LDAP search base DN is correct
- Check username format (sAMAccountName)
- Confirm account has proper search permissions

## Contributing

Contributions are welcome! Here are some ways you can help:

- Report bugs and suggest features via [Issues](https://github.com/spearsies/Pythonscripts/issues)
- Submit pull requests with improvements
- Add new detection patterns to indicators
- Improve documentation
- Share your use cases and examples

### Development Guidelines

1. Follow PEP 8 style guidelines
2. Add docstrings to all functions
3. Include usage examples for new features
4. Test thoroughly before submitting PRs
5. Update documentation as needed

## Roadmap

Future enhancements planned:

- [ ] Regex pattern support in file scanner
- [ ] Multi-threaded scanning for better performance
- [ ] SIEM integration capabilities
- [ ] Web-based dashboard for results
- [ ] Additional output formats (HTML, PDF)
- [ ] Real-time directory monitoring
- [ ] Azure AD support for user validation
- [ ] Integration with popular security tools

## Contact

**Author:** cyb3rlop3 (Stan Spears)
**Email:** stan.spears@outlook.com
**GitHub:** [@spearsies](https://github.com/spearsies)

## Acknowledgments

Built for the security community by security professionals. Special thanks to all SOC analysts and security researchers who inspire better tooling.

## License

Free to use for security research, testing, and educational purposes. See [LICENSE](LICENSE) for more details.

---

**Star this repository if you find it useful!** ⭐

**Remember:** Always use these tools responsibly and ethically. Security tools are powerful - use them wisely.
