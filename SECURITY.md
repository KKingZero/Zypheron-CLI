# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Zypheron, please report it to us responsibly:

1. **Email**: Send details to security@zypheron.io (or create a private security advisory on GitHub)
2. **Encrypted Communication**: For sensitive issues, you can use our PGP key (available on request)
3. **Do Not**: Do not publicly disclose the issue until we've had a chance to address it

### What to Include

Please include the following in your report:
- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment
- Any potential fixes you've identified

## Security Response Process

1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
2. **Initial Assessment**: We will conduct an initial assessment within 5 business days
3. **Status Updates**: We will keep you informed of our progress
4. **Fix Development**: We will work on a fix and prepare a security advisory
5. **Public Disclosure**: After the fix is released, we will credit you (unless you prefer to remain anonymous)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Features

### Input Validation & Sanitization

Zypheron implements comprehensive input validation to prevent injection attacks:

- **Command Injection Protection**: All user inputs are validated against allowlists
- **Target Validation**: IP addresses, domains, and CIDR ranges are strictly validated
- **Port Validation**: Port numbers and ranges are validated (1-65535)
- **Tool Name Allowlist**: Only approved security tools can be executed
- **File Path Sanitization**: Path traversal attempts are blocked

### Secure IPC Communication

The Go CLI and Python AI Engine communicate via Unix domain sockets with:

- **Authentication Tokens**: 64-character hex tokens (256-bit entropy)
- **Socket Permissions**: 0600 (owner read/write only)
- **Token Persistence**: Tokens stored in `~/.zypheron/ipc.token` with 0600 permissions
- **Token Verification**: Every IPC request requires valid authentication

### API Key Storage

API keys are stored securely using the operating system's credential storage:

- **Keyring Integration**: Uses system keyring (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows)
- **No Plain Text**: API keys are never stored in plain text files
- **Migration Support**: Automatic migration from .env files to keyring
- **Access Control**: Only the user who stored the key can retrieve it

### Safe Type Handling

All type assertions use safe patterns:

- **No Panic on Invalid Types**: Graceful degradation instead of crashes
- **Partial Results**: Returns valid data even when some entries are malformed
- **Error Logging**: Invalid data is logged for debugging

### Scan Data Storage

Scan results are stored securely:

- **Directory Permissions**: `~/.zypheron/scans/` has 0700 permissions
- **File Permissions**: Individual scan files have 0600 permissions
- **Sanitized Filenames**: Special characters removed from filenames

## Known Security Considerations

### Kali Tool Execution

Zypheron executes Kali Linux security tools with elevated privileges. Users should:

- Only run Zypheron on trusted systems
- Review scan targets before confirming execution
- Understand that some tools may generate network traffic
- Ensure proper authorization before scanning targets

### AI API Communication

The AI features communicate with external AI providers:

- API keys are transmitted over HTTPS
- No scan results are sent to AI providers without explicit --ai-analysis flag
- Users should review their AI provider's privacy policy
- Consider using local Ollama models for sensitive operations

### Network Exposure

- The IPC socket is local-only (Unix domain socket)
- No network ports are opened by default
- All communications are local to the machine

## Security Best Practices

### For Users

1. **Authorized Scanning Only**: Only scan systems you own or have explicit permission to test
2. **Keep Updated**: Regularly update Zypheron to get security patches
3. **Secure API Keys**: Use the keyring storage feature instead of .env files
4. **Review Scans**: Always review scan configurations before execution
5. **Audit Logs**: Regularly review scan history for unauthorized activity

### For Developers

1. **Input Validation**: Always validate and sanitize user inputs
2. **Least Privilege**: Run with minimum required permissions
3. **Secure Defaults**: Default configurations should be secure
4. **Code Review**: All PRs must pass security scanning (Gosec, Bandit)
5. **Dependency Updates**: Keep dependencies updated and monitor for vulnerabilities

## Security Testing

Zypheron includes:

- **Automated Security Scanning**: Gosec for Go, Bandit for Python
- **Dependency Audits**: `govulncheck` for Go, `safety` for Python
- **Input Validation Tests**: Comprehensive test suite for injection prevention
- **CI/CD Integration**: Security scans run on every PR

## Compliance

Zypheron is designed to support security compliance requirements:

- **Audit Logging**: All scans are logged with timestamps
- **Access Control**: Keyring-based authentication
- **Data Protection**: Encrypted API key storage
- **Transparency**: Open source for security auditing

## Updates and Patches

Security updates are released as:

- **Critical**: Immediate hotfix release
- **High**: Patch within 7 days
- **Medium**: Patch in next minor release
- **Low**: Patch in next major release

Subscribe to security advisories on GitHub to stay informed.

## Credits

We thank the following researchers for responsibly disclosing security issues:

- *[To be populated as issues are reported and resolved]*

## Contact

- **Security Issues**: security@zypheron.io
- **General Questions**: team@zypheron.io
- **GitHub**: https://github.com/KKingZero/Cobra-AI

---

**Last Updated**: 2025-01-28

