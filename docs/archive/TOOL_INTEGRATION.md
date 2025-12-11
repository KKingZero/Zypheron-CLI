# 🔧 Tool Integration Guide

## Overview

Zypheron integrates with industry-standard penetration testing tools to leverage their strengths while providing unified reporting and AI-powered analysis.

## Supported Tools

### 1. Burp Suite Professional
- Web application security testing
- Advanced scanning engine
- HTTP proxy and history
- Extensions ecosystem

### 2. OWASP ZAP
- Free and open source
- Automated scanning
- AJAX spider for SPAs
- Active and passive scanning

### 3. Dependency Scanners
- Safety (Python)
- npm audit (Node.js)
- govulncheck (Go)
- OWASP Dependency-Check (multi-language)

### 4. Secret Scanners
- TruffleHog patterns
- detect-secrets
- Custom regex patterns

## Burp Suite Integration

### Setup

1. **Start Burp Suite Professional** with REST API enabled
2. **Configure API key** in Burp (User options → Misc → REST API)
3. **Note the port** (default: 1337)

### Usage

#### Quick Scan

```bash
zypheron integrate burp \
  --target https://example.com \
  --api-key your-burp-api-key \
  --spider \
  --active-scan
```

#### With Authentication

```bash
# First authenticate
zypheron auth-scan https://example.com \
  --username admin \
  --password pass123 \
  --session-file session.json

# Then run Burp with authenticated session
zypheron integrate burp \
  --target https://example.com \
  --session-id <session-id> \
  --import
```

#### Python API

```python
from integrations.burp import BurpAPI, BurpScanner, ScanConfig

# Initialize
api = BurpAPI()
scanner = BurpScanner(api)

# Check availability
if api.is_available():
    print("Burp Suite connected!")
    
# Run authenticated scan
config = ScanConfig(
    urls=["https://example.com"],
    scan_type="active",
    session_cookies={"sessionid": "abc123"}
)

task_id = await scanner.run_scan(config)

# Get results
issues = await scanner.get_results(task_id)
print(f"Found {len(issues)} issues")

# Import into Zypheron
from integrations.burp import BurpReporter

reporter = BurpReporter()
reporter.import_burp_issues(issues)

# Merge with Zypheron results
combined = reporter.merge_with_zypheron_results(existing_vulns)
```

### Features

- ✅ Automated scan orchestration
- ✅ Authentication context support
- ✅ Issue import and deduplication
- ✅ Proxy history retrieval
- ✅ Scope management

## OWASP ZAP Integration

### Setup

1. **Start ZAP** with API enabled
   ```bash
   zap.sh -daemon -config api.key=your-api-key -port 8080
   ```

2. **Verify connection**
   ```bash
   zypheron integrate zap --target https://example.com
   ```

### Usage

#### Quick Scan

```bash
zypheron integrate zap \
  --target https://example.com \
  --spider \
  --ajax-spider \
  --active-scan
```

#### Authenticated Scan

```bash
zypheron integrate zap \
  --target https://example.com \
  --session-id <authenticated-session> \
  --spider \
  --active-scan \
  -o zap-results.json
```

#### Python API

```python
from integrations.zap import ZAPAPI, ZAPScanner, ZAPScanConfig

# Initialize
api = ZAPAPI()
scanner = ZAPScanner(api)

# Check availability
if api.is_available():
    print("ZAP connected!")

# Configure scan
config = ZAPScanConfig(
    target_url="https://example.com",
    scan_type="both",  # spider + active
    use_ajax_spider=True,
    username="testuser",
    password="testpass"
)

# Run scan
results = await scanner.run_scan(config)

# Get high-risk alerts
high_risk = scanner.get_high_risk_alerts()
print(f"High risk alerts: {len(high_risk)}")

# Convert to Zypheron format
zypheron_vulns = scanner.convert_to_zypheron_format(results['alerts'])
```

### Features

- ✅ Traditional and AJAX spidering
- ✅ Active and passive scanning
- ✅ Authentication context
- ✅ Alert retrieval and conversion
- ✅ Report generation

## Secrets Scanning

### CLI Usage

```bash
# Scan current directory
zypheron secrets .

# Scan specific directory
zypheron secrets /path/to/code --recursive

# Filter by file extensions
zypheron secrets . -e .py,.js,.env,.yaml

# Custom entropy threshold
zypheron secrets . --min-entropy 5.0

# Save results
zypheron secrets . -o secrets-report.json
```

### Python API

```python
from secrets import SecretScanner

scanner = SecretScanner()

# Scan directory
findings = scanner.scan_directory(
    directory="./src",
    recursive=True,
    file_extensions=['.py', '.js', '.env']
)

# Get critical findings
critical = scanner.get_critical_findings()

for finding in critical:
    print(f"Found {finding.secret_type} in {finding.file_path}:{finding.line_number}")
    print(f"Redacted: {finding.to_dict()['matched_string']}")
```

### Detected Secret Types

- AWS Access Keys and Secret Keys
- GitHub Personal Access Tokens
- Slack Tokens
- Stripe API Keys
- Google API Keys
- OpenAI API Keys
- Anthropic (Claude) API Keys
- Private Keys (RSA, SSH, PGP)
- Database Connection Strings
- JWT Tokens
- Generic API keys, passwords, tokens
- High-entropy strings

### Custom Patterns

```python
from secrets import SecretPatterns

patterns = SecretPatterns()

# Add custom pattern
patterns.add_custom_pattern(
    name="company_api_key",
    regex=r"COMP-[A-Z0-9]{32}",
    secret_type="company_api_key",
    confidence="high",
    severity="critical"
)
```

## Dependency Scanning

### CLI Usage

```bash
# Scan current directory
zypheron deps .

# Scan specific manifest
zypheron deps . -m requirements.txt

# Generate SBOM
zypheron deps . --sbom --sbom-format cyclonedx

# Save results
zypheron deps . -o deps-report.json
```

### Python API

```python
from supply_chain import DependencyScanner, SBOMGenerator

# Scan dependencies
scanner = DependencyScanner()
vulns = scanner.scan_directory("./", recursive=True)

# Get critical vulnerabilities
critical = scanner.get_critical_vulnerabilities()

for vuln in critical:
    print(f"{vuln.package_name}@{vuln.installed_version}")
    print(f"CVE: {vuln.cve_id}")
    print(f"Fix: Upgrade to {vuln.fixed_version}")

# Generate SBOM
sbom = SBOMGenerator()
sbom.scan_python_requirements("requirements.txt")
sbom.scan_nodejs_package("package.json")

sbom.export_sbom("sbom.json", format="cyclonedx")
```

### Supported Ecosystems

- ✅ Python (pip, requirements.txt)
- ✅ Node.js (npm, package.json)
- ✅ Go (go.mod)
- ⚠️ Java (basic support)
- ⚠️ .NET (basic support)

## Workflow Examples

### Complete Security Assessment

```bash
#!/bin/bash
TARGET="https://example.com"

echo "=== Phase 1: Unauthenticated Scan ==="
zypheron scan $TARGET --web -o unauthenticated.json

echo "=== Phase 2: Secrets Scan ==="
zypheron secrets ./code -o secrets.json

echo "=== Phase 3: Dependency Scan ==="
zypheron deps ./code --sbom -o deps.json

echo "=== Phase 4: Authenticated Scan ==="
zypheron auth-scan $TARGET --test-account -o authenticated.json

echo "=== Phase 5: Burp Integration ==="
zypheron integrate burp --target $TARGET --import -o burp.json

echo "=== Phase 6: ZAP Integration ==="
zypheron integrate zap --target $TARGET --import -o zap.json

echo "=== Phase 7: Compliance Report ==="
zypheron compliance --framework pci-dss \
  --scan-results authenticated.json \
  -o compliance-report.html

echo "✓ Complete assessment finished!"
```

### Python Orchestration

```python
from orchestrator import TestOrchestrator

orchestrator = TestOrchestrator()

# Run complete assessment
results = await orchestrator.run_complete_assessment(
    target="https://example.com",
    authenticated=True,
    use_burp=True,
    use_zap=True,
    scan_secrets=True,
    scan_dependencies=True,
    generate_compliance=True
)

print(f"Total vulnerabilities: {results['total_vulnerabilities']}")
print(f"Risk level: {results['overall_risk']}")
```

## Performance Optimization

### Go vs Python

**Implemented in Go (fast):**
- CLI argument parsing
- User interaction
- Progress display
- File I/O
- Command orchestration

**Implemented in Python (flexible):**
- AI/ML analysis
- Complex parsing (HTML, JSON, XML)
- Tool integrations
- Vulnerability analysis
- Report generation

**Communication:**
- Unix socket IPC (< 1ms latency)
- JSON protocol
- Async/await for concurrency

### Optimization Tips

1. **Use distributed scanning** for large target lists
2. **Cache API results** (CVE data, AI analyses)
3. **Parallel testing** where safe
4. **Batch operations** for efficiency
5. **Stream results** for real-time feedback

## Troubleshooting

### Burp Suite Connection Issues

```bash
# Check if Burp is running
curl http://127.0.0.1:1337/burp/version

# Verify API key
zypheron integrate burp --target https://example.com --api-key YOUR_KEY
```

### ZAP Connection Issues

```bash
# Check if ZAP is running
curl http://127.0.0.1:8080/JSON/core/view/version/

# Start ZAP daemon
zap.sh -daemon -config api.key=zypheron123 -port 8080
```

### Secrets Scanner False Positives

```python
# Add exclusions
scanner.add_exclusion(r'test_data/')
scanner.add_exclusion(r'examples/')

# Adjust entropy threshold
scanner.min_entropy = 5.0  # Higher = fewer false positives
```

## Advanced Configuration

### Custom Tool Integration

```python
from integrations.base import ToolIntegration

class MyCustomTool(ToolIntegration):
    def scan(self, target):
        # Your tool logic
        pass
    
    def get_results(self):
        # Parse results
        pass
    
    def convert_to_zypheron_format(self, results):
        # Convert to standard format
        pass
```

---

**Next Steps:**
- Read `AUTHENTICATED_TESTING.md` for auth details
- Read `API_TESTING_GUIDE.md` for API testing
- Read `SECRETS_SCANNING.md` for secrets detection

