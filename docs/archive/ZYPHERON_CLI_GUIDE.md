# Zypheron CLI User Guide

## 📚 Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Commands](#core-commands)
- [Best Practices](#best-practices)
- [Advanced Usage](#advanced-usage)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Introduction

**Zypheron** is an AI-powered penetration testing platform that integrates with Kali Linux security tools. It combines the power of multiple AI providers (Claude, OpenAI, Gemini, DeepSeek, Grok, Ollama) with industry-standard security tools to provide intelligent, automated security assessments.

### Key Features
- 🤖 **Multi-AI Provider Support** - Leverage multiple AI engines for enhanced analysis
- 🛠️ **Kali Tools Integration** - Seamless integration with nmap, nikto, metasploit, and more
- 🔍 **Intelligent Scanning** - AI-powered vulnerability detection and analysis
- 📊 **Real-time Monitoring** - Live dashboard for scan progress and results
- 🎯 **Autonomous Agents** - Self-directed penetration testing capabilities
- 📝 **Advanced Reporting** - Comprehensive reports with AI-enriched findings

---

## 📦 Installation

### Prerequisites
- **Operating System**: Linux (Kali Linux recommended), macOS, or Windows (WSL2)
- **Go Version**: 1.21 or higher
- **Python**: 3.8+ (for AI engine)
- **Tools**: git, make

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/zypheron.git
cd zypheron/zypheron-go

# Build the CLI
make build

# Install system-wide (optional)
sudo make install
```

### Verify Installation

```bash
# Check version
./build/zypheron --version

# Run setup wizard
./build/zypheron setup
```

---

## 🚀 Quick Start

### 1. Initial Setup

```bash
# Run the interactive setup wizard
zypheron setup

# Configure AI provider (choose one or multiple)
zypheron config set ai-provider claude  # or openai, gemini, deepseek, etc.
zypheron config set api-key YOUR_API_KEY

# Verify AI engine
zypheron ai test
```

### 2. Check Available Tools

```bash
# Check installed Kali tools
zypheron tools check

# List all available tools
zypheron tools list

# Get info about a specific tool
zypheron tools info nmap
```

### 3. Run Your First Scan

```bash
# Basic network scan
zypheron scan 192.168.1.1

# Web application scan
zypheron scan https://example.com --web

# Fast scan
zypheron scan 192.168.1.0/24 --fast
```

---

## 🔧 Core Commands

### AI Management

```bash
# List available AI providers
zypheron ai providers

# Start AI engine
zypheron ai start --provider claude

# Test AI functionality
zypheron ai test --provider openai

# Check AI engine status
zypheron ai status

# Stop AI engine
zypheron ai stop
```

### Security Scanning

```bash
# Network scan with specific tool
zypheron scan TARGET --tool nmap

# Port scanning
zypheron scan TARGET --ports 80,443,8080

# Vulnerability scan
zypheron scan TARGET --vuln

# Aggressive scan (use with caution)
zypheron scan TARGET --aggressive

# Custom scan with specific options
zypheron scan TARGET --tool nikto --output results.json
```

### Tool Management

```bash
# Check tool status
zypheron tools check

# List tools by category
zypheron tools list --category web

# Show only installed tools
zypheron tools list --installed

# Show only missing tools
zypheron tools list --missing

# Get tool information
zypheron tools info metasploit

# Suggest best tool for a task
zypheron tools suggest scan

# Install a specific tool
zypheron tools install nuclei

# Install all missing critical tools
zypheron tools install-all --critical-only

# Install all high-priority tools
zypheron tools install-all --high-priority
```

### Tool Integrations

#### Burp Suite Professional

```bash
# Start a Burp scan and import findings
zypheron integrate burp \
  --target https://example.com \
  --host 127.0.0.1 \
  --port 1337 \
  --api-key $BURP_API_KEY \
  --spider \
  --active-scan \
  --import \
  --output burp-results.json
```

#### OWASP ZAP

```bash
# Run a ZAP scan and save results
zypheron integrate zap \
  --target https://example.com \
  --host 127.0.0.1 \
  --port 8080 \
  --spider \
  --ajax-spider \
  --active-scan \
  --output zap-results.json
```

### AI Chat Interface

```bash
# Start interactive chat
zypheron chat

# Chat with specific provider
zypheron chat --provider gemini

# Chat with temperature control
zypheron chat --temperature 0.7

# One-shot query
zypheron chat "What are the best practices for SQL injection testing?"
```

### History Management

```bash
# View scan history
zypheron history list

# View recent scans (default: 10)
zypheron history list --limit 20

# View detailed scan results
zypheron history show SCAN_ID

# Clear all history
zypheron history clear
```

### Configuration Management

```bash
# Show current configuration
zypheron config show

# Set configuration value
zypheron config set KEY VALUE

# Get specific config value
zypheron config get KEY

# List all config keys
zypheron config list

# Validate configuration
zypheron config validate
```

### Reporting

```bash
# Generate report from scan
zypheron report generate SCAN_ID

# Generate PDF report
zypheron report generate SCAN_ID --format pdf

# Generate HTML report
zypheron report generate SCAN_ID --format html

# Export to JSON
zypheron report export SCAN_ID --format json
```

---

## 🎯 Best Practices

### 1. Pre-Engagement

#### Always Get Authorization
```bash
# ⚠️ CRITICAL: Never scan systems without written permission
# Document authorization before starting
echo "Authorization: [Client Name] - [Date] - [Scope]" > authorization.txt
```

#### Define Scope Clearly
```bash
# Create a scope file
cat > scope.txt << EOF
In-Scope:
  - 192.168.1.0/24
  - example.com
  - *.example.com

Out-of-Scope:
  - 192.168.1.1 (router)
  - production.example.com
EOF
```

#### Tool Verification
```bash
# Always check tools before engagement
zypheron tools check

# Install missing critical tools
zypheron tools install-all --critical-only
```

### 2. Reconnaissance Phase

#### Start with Passive Reconnaissance
```bash
# Use OSINT tools first (less intrusive)
zypheron osint gather example.com

# Check publicly available information
zypheron recon passive example.com
```

#### Progress to Active Scanning
```bash
# Start with light scanning
zypheron scan TARGET --fast

# Gradually increase intensity if authorized
zypheron scan TARGET --ports 1-1000

# Full scan only when necessary
zypheron scan TARGET --full
```

### 3. Scanning Best Practices

#### Use Appropriate Scan Types
```bash
# Network Infrastructure
zypheron scan 192.168.1.0/24 --tool nmap --ports common

# Web Applications
zypheron scan https://example.com --web --tool nikto

# Wireless Networks
zypheron scan --wireless --interface wlan0

# API Endpoints
zypheron scan https://api.example.com --api
```

#### Rate Limiting and Stealth
```bash
# Use slower, stealthier scans for production systems
zypheron scan TARGET --delay 1000  # 1 second delay

# Limit concurrent connections
zypheron scan TARGET --max-connections 5

# Use random delays
zypheron scan TARGET --random-delay
```

#### Save and Document Results
```bash
# Always save scan results
zypheron scan TARGET --output scan-$(date +%Y%m%d-%H%M%S).json

# Generate immediate report
zypheron scan TARGET | tee scan.log
zypheron report generate SCAN_ID --format pdf
```

### 4. AI-Assisted Analysis

#### Leverage AI for Vulnerability Analysis
```bash
# Start AI chat for analysis
zypheron chat

# In chat:
# "Analyze the results from scan ID: abc123"
# "What are the critical vulnerabilities in these findings?"
# "Suggest remediation steps for CVE-2023-1234"
```

#### Use Multiple AI Providers
```bash
# Get diverse perspectives
zypheron ai test --provider claude
zypheron ai test --provider openai
zypheron ai test --provider gemini

# Compare AI recommendations
```

### 5. Documentation and Reporting

#### Comprehensive Reporting
```bash
# Generate detailed reports
zypheron report generate SCAN_ID \
  --format pdf \
  --include-screenshots \
  --include-remediation \
  --output final-report-$(date +%Y%m%d).pdf
```

#### Maintain Scan History
```bash
# Regular history reviews
zypheron history list --limit 50 > engagement-history.txt

# Export findings
zypheron history export --format json > findings.json
```

### 6. Security and Privacy

#### Secure Configuration
```bash
# Use environment variables for sensitive data
export ZYPHERON_API_KEY="your-api-key"
export ZYPHERON_PROVIDER="claude"

# Don't hardcode credentials in scripts
# Use configuration files with proper permissions
chmod 600 ~/.zypheron/config.yaml
```

#### Clean Up After Engagement
```bash
# Clear sensitive scan data
zypheron history clear --scan-id SCAN_ID

# Secure delete temporary files
shred -u temporary-scan-data.txt

# Clear AI chat history if it contains sensitive info
zypheron chat --clear-history
```

---

## 🚀 Advanced Usage

### 1. Automated Scanning Workflows

#### Scheduled Scans
```bash
#!/bin/bash
# scheduled-scan.sh

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="./scans/${TIMESTAMP}"

mkdir -p "${OUTPUT_DIR}"

# Phase 1: Reconnaissance
zypheron recon ${TARGET} --output "${OUTPUT_DIR}/recon.json"

# Phase 2: Network Scan
zypheron scan ${TARGET} --full --output "${OUTPUT_DIR}/netscan.json"

# Phase 3: Vulnerability Scan
zypheron scan ${TARGET} --vuln --output "${OUTPUT_DIR}/vulnscan.json"

# Phase 4: Generate Report
zypheron report generate --all --format pdf --output "${OUTPUT_DIR}/report.pdf"

# Phase 5: AI Analysis
zypheron chat "Analyze scans in ${OUTPUT_DIR} and provide risk assessment"
```

#### CI/CD Integration
```bash
# .gitlab-ci.yml or GitHub Actions
security-scan:
  script:
    - zypheron scan $STAGING_URL --web --fail-on critical
    - zypheron report generate --format json --output security-report.json
  artifacts:
    reports:
      security: security-report.json
```

### 2. Custom Tool Chains

```bash
# Combine multiple tools
zypheron scan TARGET --tool nmap,nikto,nuclei

# Sequential scanning
zypheron scan TARGET --tool nmap --output nmap.json
zypheron scan TARGET --tool nikto --input nmap.json --output nikto.json
zypheron scan TARGET --tool nuclei --input nikto.json --output final.json
```

### 3. AI-Powered Exploitation

```bash
# Start autonomous agent
zypheron exploit auto --target TARGET --safe-mode

# Guided exploitation with AI
zypheron exploit guided --target TARGET --vulnerability CVE-2023-1234

# AI-suggested exploitation paths
zypheron chat "What exploitation paths exist for findings in scan ID: abc123?"
```

### 4. Multi-Target Campaigns

```bash
# Scan multiple targets from file
cat targets.txt | while read target; do
  zypheron scan "$target" --output "scan-${target}.json"
done

# Parallel scanning (use carefully)
parallel -j 5 zypheron scan {} :::: targets.txt
```

---

## 🔒 Security Considerations

### 1. Legal and Ethical

- ⚠️ **Authorization is MANDATORY** - Never scan systems without explicit written permission
- 📄 **Document Everything** - Keep records of authorization, scope, and findings
- 🎯 **Stay in Scope** - Never deviate from agreed-upon targets
- ⚖️ **Follow Laws** - Comply with local and international cybersecurity laws
- 🤝 **Responsible Disclosure** - Report vulnerabilities responsibly

### 2. Operational Security

#### Network Safety
```bash
# Use VPN or authorized network
# Verify you're on the correct network before scanning
ip addr show

# Check routing
ip route show
```

#### Rate Limiting
```bash
# Don't overwhelm target systems
zypheron scan TARGET --max-rate 100  # packets per second
zypheron scan TARGET --delay 1000     # milliseconds between requests
```

#### Data Protection
```bash
# Encrypt sensitive scan results
gpg --encrypt --recipient your@email.com scan-results.json

# Secure file permissions
chmod 600 sensitive-data.json

# Use secure storage
mkdir -p ~/secure-scans
chmod 700 ~/secure-scans
```

### 3. API Key Security

```bash
# Never commit API keys to repositories
echo "ZYPHERON_API_KEY=*" >> .gitignore

# Use environment variables
export ZYPHERON_API_KEY=$(cat ~/.secrets/zypheron-key)

# Rotate keys regularly
zypheron config set api-key NEW_KEY
```

### 4. AI Data Privacy

- 🔒 **Sensitive Data** - Be aware that AI providers may see your queries
- 🏢 **Enterprise Mode** - Use local AI (Ollama) for highly sensitive assessments
- 🗑️ **Data Retention** - Clear chat history after engagements
- 📋 **Compliance** - Ensure AI usage complies with data protection regulations

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Command Not Found
```bash
# If 'zypheron' is not found, use full path
$(pwd)/zypheron-go/build/zypheron

# Or create an alias
alias zypheron='/path/to/zypheron'

# Or install system-wide
cd zypheron-go && sudo make install
```

#### 2. Permission Denied
```bash
# Make binary executable
chmod +x /path/to/zypheron

# For tool installation, use sudo
sudo zypheron tools install nmap
```

#### 3. AI Engine Connection Failed
```bash
# Check AI engine status
zypheron ai status

# Restart AI engine
zypheron ai stop
zypheron ai start

# Verify API key
zypheron config get api-key

# Test connection
zypheron ai test --verbose
```

#### 4. Tool Not Found
```bash
# Check if tool is installed
zypheron tools check

# Install missing tool
sudo zypheron tools install TOOL_NAME

# Update tool paths
zypheron config set tool-path-nmap /usr/bin/nmap
```

#### 5. Scan Fails
```bash
# Enable debug mode
zypheron scan TARGET --debug

# Check network connectivity
ping TARGET

# Verify permissions
sudo zypheron scan TARGET  # Some scans need root

# Check firewall
sudo iptables -L
```

### Debug Mode

```bash
# Enable global debug
zypheron --debug scan TARGET

# Verbose output
zypheron scan TARGET --verbose

# Check logs
tail -f ~/.zypheron/logs/zypheron.log
```

### Getting Help

```bash
# Command help
zypheron --help
zypheron scan --help
zypheron tools --help

# Version information
zypheron --version

# Configuration check
zypheron config validate
```

---

## 📚 Additional Resources

### Official Documentation
- [GitHub Repository](https://github.com/yourusername/zypheron)
- [Quick Start Guide](./zypheron-go/QUICK_START.md)
- [Migration Guide](./zypheron-go/MIGRATION_GUIDE.md)

### Community
- Report bugs via GitHub Issues
- Contribute via Pull Requests
- Join discussions in GitHub Discussions

### Further Reading
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

## 📝 Quick Reference Card

```bash
# Setup
zypheron setup                          # Initial configuration
zypheron config set ai-provider claude  # Set AI provider
zypheron tools check                    # Check installed tools

# Scanning
zypheron scan TARGET                    # Basic scan
zypheron scan TARGET --fast             # Quick scan
zypheron scan TARGET --web              # Web app scan
zypheron scan TARGET --vuln             # Vulnerability scan

# Tools
zypheron tools list                     # List all tools
zypheron tools info TOOL                # Tool information
zypheron tools install TOOL             # Install tool

# AI Interaction
zypheron ai providers                   # List AI providers
zypheron ai test                        # Test AI
zypheron chat                          # Interactive chat

# History & Reports
zypheron history list                   # View scan history
zypheron report generate SCAN_ID        # Generate report

# Help
zypheron --help                        # General help
zypheron COMMAND --help                # Command-specific help
```

---

## ⚠️ Important Reminders

1. **🔐 Authorization First** - Always obtain written permission before testing
2. **📊 Document Everything** - Keep detailed records of all activities
3. **🎯 Stay in Scope** - Only test authorized systems and networks
4. **🛡️ Be Responsible** - Report vulnerabilities through proper channels
5. **🔒 Protect Data** - Secure all scan results and findings
6. **⚖️ Follow Laws** - Comply with all applicable laws and regulations

---

**Happy (Authorized) Hacking! 🚀**

*Remember: With great power comes great responsibility. Use Zypheron ethically and legally.*

