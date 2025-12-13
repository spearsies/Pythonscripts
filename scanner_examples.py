"""
File Scanner - Usage Examples
Demonstrates various ways to use the file scanner for security analysis
"""

from file_scanner import FileScanner

def example_1_scan_directory():
    """
    Example 1: Scan a directory for malicious code patterns
    Use Case: Code review automation, malware detection
    """
    print("=" * 80)
    print("EXAMPLE 1: Scan Directory for Malicious Code")
    print("=" * 80)

    scanner = FileScanner()

    # Scan a specific directory for Python files only
    results = scanner.scan_directory(
        directory='./my_project',
        recursive=True,
        file_extensions=['.py'],
        exclude_dirs=['.git', '__pycache__', 'venv']
    )

    print(f"\nFound {len(results)} potential security issues in Python files")

    # Display results
    for result in results:
        print(f"\nFile: {result['file']}")
        print(f"  Category: {result['category']}")
        print(f"  Pattern: {result['pattern']}")
        print(f"  Lines: {result['line_numbers']}")

    # Generate detailed report
    scanner.generate_report(output_file='malware_scan_report.txt', format='text')
    scanner.generate_report(output_file='malware_scan_report.json', format='json')


def example_2_credential_scan():
    """
    Example 2: Scan for leaked credentials (OSINT / Data Leakage Detection)
    Use Case: Finding exposed passwords, API keys, tokens in code
    """
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Credential Leakage Detection")
    print("=" * 80)

    # Create scanner with only credential indicators
    scanner = FileScanner()
    scanner.indicators = {
        'credentials': [
            'password =',
            'passwd =',
            'api_key =',
            'secret =',
            'token =',
            'AWS_ACCESS_KEY',
            'AWS_SECRET_KEY',
            'PRIVATE_KEY',
            'CLIENT_SECRET'
        ]
    }

    # Scan configuration files and scripts
    results = scanner.scan_directory(
        directory='.',
        recursive=True,
        file_extensions=['.py', '.js', '.env', '.config', '.json', '.yaml', '.yml', '.txt'],
        exclude_dirs=['.git', 'node_modules']
    )

    print(f"\nFound {len(results)} potential credential leaks")

    if results:
        print("\nWARNING: Credentials found in the following files:")
        for result in results:
            print(f"  - {result['file']} (Line {result['line_numbers'][0]}): {result['pattern']}")

    scanner.generate_report(output_file='credential_leak_report.txt', format='text')


def example_3_github_scan():
    """
    Example 3: Scan GitHub repository files for sensitive data
    Use Case: OSINT, checking public repos for accidentally committed secrets
    """
    print("\n" + "=" * 80)
    print("EXAMPLE 3: GitHub Repository Scanning (OSINT)")
    print("=" * 80)

    scanner = FileScanner()

    # List of GitHub raw file URLs to scan
    github_files = [
        'https://raw.githubusercontent.com/username/repo/main/config.py',
        'https://raw.githubusercontent.com/username/repo/main/settings.json',
        'https://raw.githubusercontent.com/username/repo/main/.env.example'
    ]

    print(f"\nScanning {len(github_files)} files from GitHub...")

    for url in github_files:
        print(f"\nScanning: {url}")
        matches = scanner.scan_github_file(url)

        if matches:
            print(f"  ALERT: Found {len(matches)} potential issues!")
            for match in matches:
                print(f"    - {match['category']}: {match['pattern']}")
        else:
            print("  OK: No issues found")

    scanner.generate_report(output_file='github_scan_report.json', format='json')


def example_4_custom_indicators():
    """
    Example 4: Use custom indicators file
    Use Case: Tailored scanning for specific threats or patterns
    """
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Custom Indicators Scanning")
    print("=" * 80)

    # Load custom indicators from JSON file
    scanner = FileScanner(indicators_file='indicators.json')

    # Scan with custom indicators
    results = scanner.scan_directory(
        directory='.',
        recursive=True,
        file_extensions=['.php', '.py', '.js', '.sh']
    )

    print(f"\nScanned {scanner.stats['files_scanned']} files")
    print(f"Found issues in {scanner.stats['files_with_matches']} files")
    print(f"Total matches: {scanner.stats['total_matches']}")

    # Generate comprehensive report
    scanner.generate_report(output_file='custom_scan_report.txt', format='text')


def example_5_web_shell_detection():
    """
    Example 5: Detect web shells and backdoors
    Use Case: Server compromise detection, website security audit
    """
    print("\n" + "=" * 80)
    print("EXAMPLE 5: Web Shell and Backdoor Detection")
    print("=" * 80)

    scanner = FileScanner()

    # Focus on web shell indicators
    scanner.indicators = {
        'web_shells': [
            'c99',
            'r57',
            'wso',
            'b374k',
            'webshell',
            'shell_exec',
            'passthru',
            'system(',
            'eval(',
            'base64_decode',
            'gzinflate',
            'str_rot13',
            'assert(',
            'preg_replace.*\/e'
        ]
    }

    # Scan web directory for PHP files
    results = scanner.scan_directory(
        directory='./web',
        recursive=True,
        file_extensions=['.php', '.phtml', '.php3', '.php4', '.php5'],
        exclude_dirs=['cache', 'tmp']
    )

    if results:
        print(f"\nWARNING: Found {len(results)} potential web shells or backdoors!")
        scanner.generate_report(output_file='webshell_detection_report.txt', format='text')
    else:
        print("\nNo web shells detected. Server appears clean.")


def example_6_sql_injection_scan():
    """
    Example 6: Scan for SQL injection vulnerabilities in code
    Use Case: Code security audit, finding vulnerable database queries
    """
    print("\n" + "=" * 80)
    print("EXAMPLE 6: SQL Injection Vulnerability Detection")
    print("=" * 80)

    scanner = FileScanner()

    # Focus on SQL injection patterns
    scanner.indicators = {
        'sql_vulnerable': [
            'execute(',
            'query(',
            'SELECT * FROM',
            'WHERE.*=.*$',
            'WHERE.*=.*%s',
            'cursor.execute',
            'db.query',
            'mysql_query',
            'mysqli_query'
        ]
    }

    # Scan code files
    results = scanner.scan_directory(
        directory='.',
        recursive=True,
        file_extensions=['.py', '.php', '.java', '.cs', '.rb']
    )

    print(f"\nFound {len(results)} potential SQL injection vulnerabilities")
    scanner.generate_report(output_file='sql_injection_report.txt', format='text')


def example_7_batch_file_scan():
    """
    Example 7: Scan individual files from a list
    Use Case: Targeted scanning of specific files
    """
    print("\n" + "=" * 80)
    print("EXAMPLE 7: Batch File Scanning")
    print("=" * 80)

    scanner = FileScanner()

    # List of specific files to scan
    files_to_scan = [
        'config.py',
        'settings.py',
        'database.py',
        'api_keys.txt',
        'credentials.json'
    ]

    print(f"Scanning {len(files_to_scan)} specific files...\n")

    for file_path in files_to_scan:
        print(f"Scanning: {file_path}")
        matches = scanner.scan_file(file_path)

        if matches:
            print(f"  ALERT: Found {len(matches)} issues")
        else:
            print(f"  OK: Clean")

    print(f"\nSummary:")
    print(f"  Files scanned: {scanner.stats['files_scanned']}")
    print(f"  Issues found: {scanner.stats['total_matches']}")


def main():
    """
    Run all examples (comment out the ones you don't need)
    """
    print("FILE SCANNER - USAGE EXAMPLES")
    print("Author: cyb3rlop3\n")

    # Uncomment the examples you want to run:

    # example_1_scan_directory()
    # example_2_credential_scan()
    # example_3_github_scan()
    # example_4_custom_indicators()
    # example_5_web_shell_detection()
    # example_6_sql_injection_scan()
    # example_7_batch_file_scan()

    print("\n" + "=" * 80)
    print("To run examples, uncomment them in the main() function")
    print("=" * 80)


if __name__ == '__main__':
    main()
