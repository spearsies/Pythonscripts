# Contributing to Pythonscripts

Thank you for your interest in contributing to this project! This repository welcomes contributions from security professionals, developers, and researchers who want to improve these security automation tools.

## 🎯 Ways to Contribute

### Report Bugs
- Use the [GitHub Issues](https://github.com/spearsies/Pythonscripts/issues) page
- Provide detailed information about the bug
- Include steps to reproduce
- Share your environment details (OS, Python version, etc.)

### Suggest Features
- Open an issue with the "enhancement" label
- Describe the feature and its use case
- Explain how it would benefit the security community

### Add Detection Patterns
- Contribute new security indicators to `indicators.json`
- Document the threat type and source
- Provide examples of what the pattern detects

### Improve Documentation
- Fix typos or clarify existing documentation
- Add usage examples
- Create tutorials or guides
- Translate documentation (if applicable)

### Submit Code
- Fix bugs
- Implement new features
- Optimize performance
- Add test coverage

## 📋 Contribution Guidelines

### Before You Start

1. **Check existing issues** to avoid duplicate work
2. **Open an issue** to discuss major changes before implementing
3. **Fork the repository** to your GitHub account
4. **Create a feature branch** from `master`

### Code Standards

#### Python Style
- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines
- Use meaningful variable and function names
- Maximum line length: 100 characters
- Use 4 spaces for indentation (no tabs)

#### Documentation
- Add docstrings to all functions and classes
- Use clear, concise comments for complex logic
- Update README.md if you add features
- Include usage examples for new functionality

#### Code Quality
```python
def scan_file(self, file_path: str, case_sensitive: bool = False) -> List[Dict]:
    """
    Scan a single file for dangerous indicators.

    Args:
        file_path: Path to the file to scan
        case_sensitive: Whether to perform case-sensitive search

    Returns:
        List of matches found in the file

    Example:
        >>> scanner = FileScanner()
        >>> results = scanner.scan_file('config.py')
        >>> print(f"Found {len(results)} issues")
    """
    # Implementation here
    pass
```

### Security Considerations

⚠️ **IMPORTANT**: These are security tools. Please ensure:

1. **No Malicious Code**: Never introduce actual malware or exploits
2. **Responsible Disclosure**: Report vulnerabilities privately first
3. **Ethical Use**: Contributions must support defensive security only
4. **No Credential Leaks**: Never commit API keys, passwords, or secrets
5. **Safe Defaults**: Default configurations should be secure

### Testing

- Test your changes thoroughly before submitting
- Ensure existing functionality still works
- Test on multiple Python versions if possible (3.7, 3.8, 3.9, 3.10+)
- Provide test files or examples with your PR

### Commit Messages

Use clear, descriptive commit messages:

```
Good:
- "Add regex pattern support for file scanner"
- "Fix false positives in credential detection"
- "Update documentation for AD user check script"

Avoid:
- "Update"
- "Fix stuff"
- "WIP"
```

### Pull Request Process

1. **Create a Pull Request** from your fork to the main repository
2. **Fill out the PR template** completely
3. **Reference related issues** (e.g., "Fixes #123")
4. **Wait for review** - be patient and responsive to feedback
5. **Make requested changes** if any
6. **Squash commits** if requested

#### PR Title Format
```
[Type] Short description

Examples:
[Feature] Add multi-threading support for directory scanning
[Fix] Resolve false positives in SQL injection detection
[Docs] Update installation instructions for Windows
[Security] Patch credential leak in logging
```

#### PR Description Template
```markdown
## Description
Brief description of what this PR does

## Related Issue
Fixes #(issue number)

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Testing
Describe how you tested your changes

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have tested that my changes work as expected
- [ ] Any dependent changes have been merged and published
```

## 🔒 Security Vulnerability Reporting

If you discover a security vulnerability, please **do NOT** open a public issue.

Instead:
1. Email: stan.spears@outlook.com
2. Subject: "SECURITY: [Brief description]"
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)

I will respond within 48 hours and work with you on a fix.

## 📜 Code of Conduct

### Our Standards

- **Be respectful** and professional in all interactions
- **Be constructive** with feedback and criticism
- **Be collaborative** and help others learn
- **Focus on what's best** for the security community

### Unacceptable Behavior

- Harassment, trolling, or personal attacks
- Publishing others' private information
- Promoting or demonstrating malicious hacking
- Any conduct that would be inappropriate in a professional setting

## 🏆 Recognition

Contributors will be recognized in:
- The project README.md
- Release notes for significant contributions
- The repository contributors list

## 📞 Questions?

- Open an issue for general questions
- Email stan.spears@outlook.com for private inquiries
- Check existing documentation first

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for helping make these security tools better for everyone!** 🙏

Together, we can build better defensive security capabilities for the entire community.
