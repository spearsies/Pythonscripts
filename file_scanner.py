"""
File Scanner for Dangerous Text Strings
Author: cyb3rlop3
Description: Scans files for malicious code patterns, sensitive data leaks, and suspicious strings.
Use Cases: Malware detection, OSINT, credential leakage detection, code review automation
"""

import os
import re
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Tuple
from collections import defaultdict

class FileScanner:
    """
    A high-speed file scanner that searches for dangerous text patterns.
    """

    def __init__(self, indicators_file: str = None):
        """
        Initialize the scanner with indicators to search for.

        Args:
            indicators_file: Path to JSON file containing indicators
        """
        self.indicators = self._load_indicators(indicators_file)
        self.results = []
        self.stats = {
            'files_scanned': 0,
            'files_with_matches': 0,
            'total_matches': 0,
            'errors': 0
        }

    def _load_indicators(self, indicators_file: str) -> Dict[str, List[str]]:
        """
        Load indicators from a JSON file or use defaults.

        Returns:
            Dictionary of indicator categories and their patterns
        """
        default_indicators = {
            'credentials': [
                'password',
                'passwd',
                'pwd',
                'api_key',
                'apikey',
                'secret',
                'token',
                'auth_token',
                'access_token',
                'private_key',
                'aws_access_key_id',
                'aws_secret_access_key'
            ],
            'malicious_code': [
                'eval(',
                'exec(',
                'system(',
                'shell_exec',
                'base64_decode',
                'passthru',
                '__import__',
                'subprocess.call',
                'os.system',
                'commands.getoutput'
            ],
            'network_suspicious': [
                'reverse_shell',
                'bind_shell',
                'nc -e',
                'netcat',
                '/bin/sh',
                '/bin/bash',
                'cmd.exe',
                'powershell.exe',
                'wget http',
                'curl http'
            ],
            'sql_injection': [
                'UNION SELECT',
                'DROP TABLE',
                'DELETE FROM',
                '-- ',
                'OR 1=1',
                "' OR '1'='1",
                'exec sp_',
                'xp_cmdshell'
            ],
            'data_exfiltration': [
                'requests.post',
                'urllib.request',
                'socket.connect',
                'ftp.login',
                'smtplib.SMTP',
                'paramiko.SSHClient'
            ]
        }

        if indicators_file and os.path.exists(indicators_file):
            try:
                with open(indicators_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading indicators file: {e}")
                print("Using default indicators...")
                return default_indicators

        return default_indicators

    def _is_binary_file(self, file_path: str) -> bool:
        """
        Check if a file is binary (skip binary files for text scanning).

        Args:
            file_path: Path to the file

        Returns:
            True if binary, False if text
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                # Check for null bytes (common in binary files)
                if b'\x00' in chunk:
                    return True
                # Check for high ratio of non-text bytes
                text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
                non_text = sum(1 for byte in chunk if byte not in text_chars)
                return non_text / len(chunk) > 0.3 if chunk else False
        except Exception:
            return True

    def scan_file(self, file_path: str, case_sensitive: bool = False) -> List[Dict]:
        """
        Scan a single file for dangerous indicators.

        Args:
            file_path: Path to the file to scan
            case_sensitive: Whether to perform case-sensitive search

        Returns:
            List of matches found in the file
        """
        matches = []

        # Skip binary files
        if self._is_binary_file(file_path):
            return matches

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Search for each indicator category
                for category, patterns in self.indicators.items():
                    for pattern in patterns:
                        # Perform search
                        if case_sensitive:
                            found = pattern in content
                        else:
                            found = pattern.lower() in content.lower()

                        if found:
                            # Find line number(s) where pattern appears
                            lines = content.split('\n')
                            line_numbers = []

                            for line_num, line in enumerate(lines, 1):
                                if case_sensitive:
                                    if pattern in line:
                                        line_numbers.append(line_num)
                                else:
                                    if pattern.lower() in line.lower():
                                        line_numbers.append(line_num)

                            matches.append({
                                'file': file_path,
                                'category': category,
                                'pattern': pattern,
                                'line_numbers': line_numbers,
                                'timestamp': datetime.now().isoformat()
                            })

                            self.stats['total_matches'] += 1

            self.stats['files_scanned'] += 1
            if matches:
                self.stats['files_with_matches'] += 1

        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            self.stats['errors'] += 1

        return matches

    def scan_directory(self, directory: str, recursive: bool = True,
                      file_extensions: List[str] = None,
                      exclude_dirs: List[str] = None) -> List[Dict]:
        """
        Scan all files in a directory for dangerous indicators.

        Args:
            directory: Path to directory to scan
            recursive: Whether to scan subdirectories
            file_extensions: List of file extensions to scan (e.g., ['.py', '.txt'])
            exclude_dirs: List of directory names to exclude (e.g., ['node_modules', '.git'])

        Returns:
            List of all matches found
        """
        if exclude_dirs is None:
            exclude_dirs = ['.git', 'node_modules', '__pycache__', 'venv', '.venv']

        all_matches = []

        if recursive:
            for root, dirs, files in os.walk(directory):
                # Remove excluded directories from search
                dirs[:] = [d for d in dirs if d not in exclude_dirs]

                for file in files:
                    file_path = os.path.join(root, file)

                    # Filter by file extension if specified
                    if file_extensions:
                        if not any(file.endswith(ext) for ext in file_extensions):
                            continue

                    matches = self.scan_file(file_path)
                    if matches:
                        all_matches.extend(matches)
                        self.results.extend(matches)
        else:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                if os.path.isfile(file_path):
                    # Filter by file extension if specified
                    if file_extensions:
                        if not any(file.endswith(ext) for ext in file_extensions):
                            continue

                    matches = self.scan_file(file_path)
                    if matches:
                        all_matches.extend(matches)
                        self.results.extend(matches)

        return all_matches

    def scan_github_file(self, github_url: str) -> List[Dict]:
        """
        Scan a file from GitHub repository (raw content).

        Args:
            github_url: URL to the GitHub file (will convert to raw URL)

        Returns:
            List of matches found
        """
        try:
            import urllib.request

            # Convert GitHub URL to raw URL if needed
            if 'github.com' in github_url and '/blob/' in github_url:
                raw_url = github_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            else:
                raw_url = github_url

            # Fetch file content
            with urllib.request.urlopen(raw_url) as response:
                content = response.read().decode('utf-8', errors='ignore')

            matches = []

            # Search for indicators
            for category, patterns in self.indicators.items():
                for pattern in patterns:
                    if pattern.lower() in content.lower():
                        # Find line numbers
                        lines = content.split('\n')
                        line_numbers = [i+1 for i, line in enumerate(lines)
                                      if pattern.lower() in line.lower()]

                        matches.append({
                            'file': github_url,
                            'category': category,
                            'pattern': pattern,
                            'line_numbers': line_numbers,
                            'timestamp': datetime.now().isoformat()
                        })

                        self.stats['total_matches'] += 1

            self.stats['files_scanned'] += 1
            if matches:
                self.stats['files_with_matches'] += 1
                self.results.extend(matches)

            return matches

        except Exception as e:
            print(f"Error scanning GitHub file {github_url}: {e}")
            self.stats['errors'] += 1
            return []

    def generate_report(self, output_file: str = None, format: str = 'text'):
        """
        Generate a report of scan results.

        Args:
            output_file: Path to output file (if None, prints to console)
            format: Report format ('text', 'json', 'csv')
        """
        if format == 'json':
            report_data = {
                'scan_timestamp': datetime.now().isoformat(),
                'statistics': self.stats,
                'findings': self.results
            }

            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2)
                print(f"JSON report saved to: {output_file}")
            else:
                print(json.dumps(report_data, indent=2))

        elif format == 'csv':
            if output_file:
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = ['file', 'category', 'pattern', 'line_numbers', 'timestamp']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.results)
                print(f"CSV report saved to: {output_file}")
            else:
                print("CSV format requires an output file.")

        else:  # text format
            report_lines = []
            report_lines.append("=" * 80)
            report_lines.append("FILE SCANNER REPORT")
            report_lines.append("=" * 80)
            report_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append("")
            report_lines.append("STATISTICS:")
            report_lines.append(f"  Files Scanned: {self.stats['files_scanned']}")
            report_lines.append(f"  Files with Matches: {self.stats['files_with_matches']}")
            report_lines.append(f"  Total Matches Found: {self.stats['total_matches']}")
            report_lines.append(f"  Errors: {self.stats['errors']}")
            report_lines.append("")
            report_lines.append("=" * 80)
            report_lines.append("FINDINGS:")
            report_lines.append("=" * 80)

            if self.results:
                # Group by file
                files_dict = defaultdict(list)
                for result in self.results:
                    files_dict[result['file']].append(result)

                for file_path, matches in files_dict.items():
                    report_lines.append("")
                    report_lines.append(f"FILE: {file_path}")
                    report_lines.append("-" * 80)

                    for match in matches:
                        report_lines.append(f"  [ALERT] Category: {match['category']}")
                        report_lines.append(f"          Pattern: {match['pattern']}")
                        report_lines.append(f"          Line(s): {', '.join(map(str, match['line_numbers']))}")
                        report_lines.append("")
            else:
                report_lines.append("\nNo dangerous patterns found. All clear!")

            report_lines.append("=" * 80)

            report_text = '\n'.join(report_lines)

            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                print(f"Report saved to: {output_file}")
            else:
                print(report_text)

    def get_summary(self) -> Dict:
        """
        Get a summary of scan statistics.

        Returns:
            Dictionary with scan statistics
        """
        return self.stats


def main():
    """
    Main function demonstrating basic usage.
    """
    print("=" * 80)
    print("FILE SCANNER - Dangerous Text String Detection")
    print("=" * 80)
    print()

    # Example 1: Scan a single directory
    print("Example: Scanning current directory...")
    scanner = FileScanner()

    # Scan current directory for Python files
    results = scanner.scan_directory(
        directory='.',
        recursive=True,
        file_extensions=['.py', '.txt', '.js', '.sh', '.bat'],
        exclude_dirs=['.git', 'node_modules', '__pycache__']
    )

    # Generate report
    scanner.generate_report(output_file='scan_report.txt', format='text')
    scanner.generate_report(output_file='scan_report.json', format='json')

    print(f"\nScan complete! Found {len(results)} potential issues.")
    print(f"Reports saved to scan_report.txt and scan_report.json")


if __name__ == '__main__':
    main()
