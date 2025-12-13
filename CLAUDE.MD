# Project Overview

**Repository:** Scripts Collection
**Author:** cyb3rlop3 (Stan Spears)
**Email:** stan.spears@outlook.com
**GitHub:** https://github.com/spearsies/Pythonscripts
**Purpose:** Security automation scripts for penetration testing, security auditing, and system administration

## Repository Structure

This repository contains Python-based security and administrative tools:

```
.
├── file_scanner.py          # Dangerous text string detection scanner
├── FILE_SCANNER_README.md   # Comprehensive documentation for file scanner
├── scanner_examples.py      # Usage examples for file scanner
├── check_ad_users.py        # Active Directory user validation script
├── indicators.json          # Custom security indicators for file scanner
├── usernames.csv           # Sample/input CSV for AD user checks
└── requirements.txt        # Python dependencies
```

## Scripts Description

### 1. File Scanner (`file_scanner.py`)

**Purpose:** Automated scanning of files for malicious code patterns, credential leaks, and security vulnerabilities

**Use Cases:**
- Malware and exploit detection
- Open Source Intelligence (OSINT) & data leakage prevention
- Code security audits
- Web shell detection
- Credential leak detection

**Key Features:**
- Multi-category detection (credentials, malicious code, SQL injection, web shells, etc.)
- Customizable indicators via JSON configuration
- Multiple scan modes (directory, single file, GitHub repository files)
- Report generation (text, JSON, CSV formats)
- Line number tracking for precise issue location
- Binary file detection and filtering
- Recursive directory scanning with exclusions

**Quick Usage:**
```python
from file_scanner import FileScanner

scanner = FileScanner()
results = scanner.scan_directory('.', recursive=True, file_extensions=['.py', '.js', '.php'])
scanner.generate_report('scan_report.txt', 'text')
```

**Detection Categories:**
- Credentials (passwords, API keys, tokens, secrets)
- Malicious code (eval, exec, system calls)
- Network suspicious activity (reverse shells, netcat)
- SQL injection patterns
- Data exfiltration indicators
- Web vulnerabilities (XSS, dangerous DOM manipulation)
- File operations (risky file system operations)
- Crypto miners
- Backdoors
- Obfuscation techniques

**Important:** This is a security research tool. Use only on authorized systems. The code itself is NOT malware - it's a defensive security tool for detecting malicious patterns.

### 2. Active Directory User Check (`check_ad_users.py`)

**Purpose:** Verify if users from a CSV file exist and are active in Active Directory

**Use Cases:**
- User account validation
- Security audits
- Access review automation
- Bulk user status checking

**Key Features:**
- CSV input/output
- LDAP/AD authentication
- User existence verification
- Active/disabled status detection
- Display name and email retrieval
- Summary statistics

**Dependencies:**
```
ldap3
```

**Configuration Required:**
- `AD_SERVER`: Your Active Directory server address
- `AD_DOMAIN`: Domain name
- `AD_USER`: Authentication username
- `AD_PASSWORD`: Authentication password (recommend using getpass in production)
- `AD_SEARCH_BASE`: LDAP search base (e.g., 'DC=domain,DC=com')

**Quick Usage:**
```python
# Update configuration variables in script
# Prepare usernames.csv with 'username' column
python check_ad_users.py
# Output: ad_check_results.csv
```

## Configuration Files

### `indicators.json`
Custom security indicators for the file scanner. Structure:
```json
{
  "category_name": [
    "pattern1",
    "pattern2"
  ]
}
```

### `usernames.csv`
Input file for AD user checking. Format:
```csv
username
user1
user2
```

### `requirements.txt`
Python package dependencies:
```
ldap3
```

## Development Guidelines

### When Modifying File Scanner

1. **DO NOT enhance malicious capabilities** - This is a defensive tool
2. **Test with sample data** - Use test files, not production data
3. **Validate detection accuracy** - Check for false positives/negatives
4. **Update documentation** - Keep FILE_SCANNER_README.md in sync
5. **Preserve line number tracking** - Essential for investigation
6. **Maintain report formats** - Text, JSON, and CSV outputs

### When Modifying AD User Check

1. **Protect credentials** - Never commit actual AD credentials
2. **Use environment variables** - For sensitive configuration
3. **Test connection handling** - Ensure proper error handling
4. **Validate CSV parsing** - Handle malformed input gracefully
5. **Respect LDAP limits** - Consider rate limiting for large batches

## Security Considerations

### File Scanner
- **Not malware:** This tool detects threats, it doesn't create them
- **Pattern matching:** Uses string searching, not code execution
- **Safe to run:** Does not modify files, only reads and reports
- **Report security:** Treat scan reports as sensitive (may contain discovered secrets)

### AD User Check
- **Credential protection:** Use secure credential storage (e.g., Azure Key Vault, environment variables)
- **Audit logging:** Track who runs user checks and when
- **Network security:** Use secure connections to AD servers
- **Data privacy:** Handle user information per privacy policies

## Legal and Ethical Use

**Authorized Use Only:**
- Your own code and systems
- Authorized penetration tests with written permission
- Security research and education
- Defensive security operations

**Prohibited:**
- Unauthorized access to systems
- Exploiting discovered vulnerabilities without authorization
- Scanning systems without permission
- Violating privacy laws or regulations

## Common Tasks

### Run File Scanner on Current Directory
```bash
python file_scanner.py
```

### Scan Specific File Types
```python
from file_scanner import FileScanner
scanner = FileScanner()
scanner.scan_directory('.', file_extensions=['.py', '.js', '.php', '.sh'])
scanner.generate_report('security_scan.txt', 'text')
```

### Check AD Users
```bash
# 1. Update AD_SERVER, AD_DOMAIN, AD_USER, AD_PASSWORD in check_ad_users.py
# 2. Prepare usernames.csv
# 3. Run script
python check_ad_users.py
# 4. Review ad_check_results.csv
```

### Custom Indicator Scanning
```python
from file_scanner import FileScanner
scanner = FileScanner(indicators_file='indicators.json')
results = scanner.scan_directory('.')
scanner.generate_report('custom_scan.json', 'json')
```

## Testing

### File Scanner Tests
```bash
# Run example scanner
python scanner_examples.py

# Scan with verbose output
python file_scanner.py
```

### AD User Check Tests
1. Create test CSV with known usernames
2. Update configuration with test AD server
3. Run script and verify output matches expected results

## Dependencies

### Python Version
- Python 3.7 or higher

### External Packages
- `ldap3` - For Active Directory authentication (check_ad_users.py only)

### Standard Library Packages (file_scanner.py)
- `os`, `re`, `json`, `csv`, `pathlib`, `datetime`, `typing`, `collections`, `urllib`

## Installation

```bash
# Clone repository
git clone https://github.com/spearsies/Pythonscripts.git
cd Pythonscripts

# Install dependencies (optional, only for AD script)
pip install -r requirements.txt

# File scanner has no external dependencies
python file_scanner.py
```

## Troubleshooting

### File Scanner Issues

**Binary file errors:**
- Scanner auto-detects and skips binary files
- Check file encoding if errors persist

**Too many false positives:**
- Refine indicators to be more specific
- Use case-sensitive matching
- Add context to patterns (e.g., "password =" vs "password")

**Files not scanned:**
- Check file extension filter
- Verify directory not in exclude list
- Ensure read permissions

### AD User Check Issues

**Connection failures:**
- Verify AD server address is correct
- Check network connectivity
- Validate credentials
- Ensure NTLM authentication is allowed

**No users found:**
- Verify search base DN is correct
- Check username format (sAMAccountName)
- Confirm user has search permissions

**CSV parsing errors:**
- Ensure CSV has header row
- Verify column name matches USERNAME_COLUMN
- Check file encoding (UTF-8)

## Performance Optimization

### File Scanner
- Use `file_extensions` parameter to limit scope
- Exclude large directories (node_modules, .git, venv)
- Binary file detection improves speed
- Process large repos in batches

### AD User Check
- Consider rate limiting for very large user lists
- Use connection pooling for repeated checks
- Cache results if checking same users multiple times

## Future Enhancements

Potential improvements:
- Regex pattern support in file scanner
- Parallel processing for large directory scans
- Integration with SIEM systems
- Real-time monitoring capabilities
- Advanced reporting dashboards
- Multi-threaded AD queries
- Integration with identity management systems

## Contact

**Author:** cyb3rlop3 (Stan Spears)
**Email:** stan.spears@outlook.com
**GitHub:** https://github.com/spearsies/Pythonscripts

## License

Free to use for security research, testing, and educational purposes.

## Changelog

### Current Version
- File scanner with multi-category detection
- Text, JSON, and CSV reporting
- Directory and GitHub scanning
- Custom indicator configuration
- Active Directory user validation script
- CSV input/output support

---

**Remember:** Always use these tools responsibly and only on systems you own or have explicit permission to test.
