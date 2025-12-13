# Pythonscripts 🐍

A curated collection of Python-based security automation tools for **cybersecurity professionals, SOC analysts, and penetration testers**. This repository reflects my transition from 23 years of honorable U.S. Army service into a career as a **Senior Cybersecurity Analyst**, blending **discipline, analytical skill, and creative problem-solving** into production-ready security tools.

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/spearsies/Pythonscripts)

---

## 🎯 Purpose

**For Recruiters and Hiring Managers:**
- **Cybersecurity-focused tools** demonstrating applied knowledge of threat detection, malware analysis, and security automation
- **Production-ready scripts** showcasing code quality, documentation, and professional development practices
- **Real-world applications** used in SOC operations, incident response, and penetration testing

**For Security Professionals:**
- Ready-to-use tools for malware detection, credential leak scanning, and Active Directory validation
- Customizable security patterns and indicators
- Multiple output formats for integration with existing workflows

Each tool is designed to be **clear, documented, and reusable**—mirroring the rigor I bring to professional environments.

---

## 🛡️ Cybersecurity Expertise

**Stanley Spears** - Senior Cybersecurity Analyst
- 🎖️ 23 years of honorable U.S. Army service
- 🔐 Certified Ethical Hacker (CEH), SSCP, Microsoft AZ-500 training
- 💼 Hands-on experience across healthcare, finance, government, and federal contracting
- 🛠️ Skilled in **incident response, SOC operations, and security automation**
- 📝 Creator of *Spears IT Services* cybersecurity blog and home lab for ongoing research

This repository demonstrates how I apply Python to **real-world cybersecurity challenges**—from automated threat detection to bulk user validation.

---

## 📋 Table of Contents

- [Tools Overview](#-tools-overview)
  - [File Scanner](#file-scanner)
  - [Active Directory User Check](#active-directory-user-check)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Use Cases](#-use-cases)
- [Documentation](#-documentation)
- [Legal & Ethical Use](#-legal--ethical-use)
- [Professional Value](#-professional-value)
- [Contributing](#-contributing)
- [Contact](#-contact)

---

## 🔧 Tools Overview

### File Scanner

**Automated security scanning for dangerous code patterns and credential leaks**

![File Scanner](https://img.shields.io/badge/status-production-success.svg)

A high-speed file scanner that automates the detection of security vulnerabilities across codebases. Instead of manually reviewing thousands of files, this tool rapidly identifies:

- **Credentials**: Hardcoded passwords, API keys, tokens, secrets
- **Malicious Code**: eval(), exec(), shell commands, dangerous functions
- **SQL Injection**: Injection patterns and exploits
- **Web Shells**: Backdoors and common web shell signatures
- **Network Activity**: Reverse shells, suspicious connections
- **Data Exfiltration**: Indicators of data theft
- **Crypto Miners**: Cryptocurrency mining scripts
- **Obfuscation**: Base64 encoding, compression tricks

**Key Features:**
- 10+ detection categories with customizable JSON patterns
- Multiple output formats (Text, JSON, CSV)
- GitHub repository scanning support
- Line-by-line pattern tracking for precise investigation
- Binary file detection and filtering
- Recursive directory scanning with smart exclusions

**Quick Example:**
```python
from file_scanner import FileScanner

scanner = FileScanner()
results = scanner.scan_directory('./my_project', recursive=True)
scanner.generate_report('security_scan.txt', 'text')
```

**Real-World Applications:**
- SOC analysts scanning incident artifacts for malware signatures
- Penetration testers finding hardcoded credentials in client code
- Security researchers conducting OSINT on public repositories
- Developers preventing credential leaks before deployment

**Learn More:** [FILE_SCANNER_README.md](FILE_SCANNER_README.md)

---

### Active Directory User Check

**Bulk validation of Active Directory user accounts from CSV files**

![AD Check](https://img.shields.io/badge/status-production-success.svg)

Quickly verify if users exist and are active in your Active Directory environment. Essential for security audits, access reviews, and compliance reporting.

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
# Input: usernames.csv → Output: ad_check_results.csv
```

**Real-World Applications:**
- Security audits and access reviews
- Offboarding verification
- Compliance reporting for SOX, HIPAA, etc.
- Incident response user enumeration

---

## 🚀 Installation

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

---

## ⚡ Quick Start

### Scan Files for Security Issues

```bash
# Scan current directory
python file_scanner.py

# View examples
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
scanner.generate_report('custom_scan.json', 'json')
```

---

## 💼 Use Cases

### For SOC Analysts

- **Incident Response**: Quickly scan compromised systems for malware signatures
- **Threat Hunting**: Search codebases for indicators of compromise (IOCs)
- **Log Analysis**: Detect suspicious patterns in application logs
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

### For IT Administrators

- **Pre-deployment Checks**: Scan code for secrets before production
- **Compliance**: Ensure no sensitive data in repositories
- **Access Reviews**: Bulk validate user account status
- **Audit Trail**: Document security scanning activities

---

## 📚 Documentation

### Comprehensive Guides

- **[FILE_SCANNER_README.md](FILE_SCANNER_README.md)** - Complete file scanner documentation
  - Detailed feature explanations
  - Advanced usage examples
  - Configuration options
  - Performance optimization
  - Troubleshooting guide

- **[scanner_examples.py](scanner_examples.py)** - Practical code examples
  - Scanning for specific credential types
  - GitHub repository scanning
  - Custom indicator usage
  - Web shell detection

- **[CLAUDE.MD](CLAUDE.MD)** - AI assistant context file
  - Repository structure
  - Development guidelines
  - Security considerations

### Configuration Files

- `indicators.json` - Custom security pattern definitions
- `requirements.txt` - Python package dependencies
- `usernames.csv` - Sample CSV format for AD user checks

---

## ⚖️ Legal & Ethical Use

**IMPORTANT:** These tools are for authorized security testing only.

### ✅ Authorized Use

- Your own code and systems
- Security audits with written authorization
- Penetration tests with explicit permission
- Educational and research purposes
- Defensive security operations

### ❌ Prohibited Use

- Unauthorized access to systems
- Scanning systems without permission
- Exploiting discovered vulnerabilities without authorization
- Violating privacy laws or regulations
- Malicious purposes of any kind

**By using these tools, you agree to use them responsibly and only on systems you own or have explicit permission to test.**

---

## ✨ Professional Value

This repository is more than code—it's a **portfolio of applied cybersecurity expertise**.

**What This Demonstrates:**

🎖️ **Strategic Thinking** - Military-honed problem-solving applied to security automation
🔐 **Technical Depth** - Production-ready tools used in real SOC operations
🛠️ **Code Quality** - Professional documentation, error handling, and maintainability
📊 **Practical Impact** - Tools that solve actual security challenges, not just academic exercises
🔄 **Continuous Learning** - Active development and improvement based on field experience

**Professional Development Practices:**
- Comprehensive documentation and code comments
- Modular, reusable code architecture
- Multiple output formats for workflow integration
- Error handling and input validation
- Performance optimization
- Security-first design principles

---

## 🤝 Contributing

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

---

## 🗺️ Roadmap

Future enhancements planned:

- [ ] Regex pattern support in file scanner
- [ ] Multi-threaded scanning for better performance
- [ ] SIEM integration capabilities (Splunk, ELK)
- [ ] Web-based dashboard for results
- [ ] Additional output formats (HTML, PDF)
- [ ] Real-time directory monitoring
- [ ] Azure AD support for user validation
- [ ] Integration with popular security tools (MISP, TheHive)

---

## 📜 License

Licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

Free to use for security research, testing, and educational purposes.

---

## 👤 Contact

**Stanley Spears** (cyb3rlop3)
Senior Cybersecurity Analyst

- **Email:** stan.spears@outlook.com
- **GitHub:** [@spearsies](https://github.com/spearsies)
- **Twitter:** [@spearsies](https://twitter.com/spearsies)
- **LinkedIn:** [Stanley Spears](https://linkedin.com/in/stanleyspears)

🎖️ Retired Army veteran | 🔐 CEH, SSCP, AZ-500 | 📈 Seeking opportunities as a Senior Cybersecurity Analyst with mission-driven organizations

---

## 🙏 Acknowledgments

Built for the security community by security professionals. Special thanks to all SOC analysts and security researchers who inspire better tooling.

---

**⭐ Star this repository if you find it useful!**

**Remember:** Always use these tools responsibly and ethically. Security tools are powerful - use them wisely.
