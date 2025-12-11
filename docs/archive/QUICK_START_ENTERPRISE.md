# 🚀 Zypheron Enterprise - Quick Start Guide

Get started with enterprise features in 5 minutes.

## Prerequisites

- Zypheron CLI installed
- Python 3.9+ with zypheron-ai
- API keys for AI providers (optional but recommended)

## Installation

```bash
# Navigate to AI engine
cd zypheron-ai

# Install with all dependencies
pip install -e ".[all]"

# Verify installation
python -c "from verification import ExploitVerifier; print('✓ Enterprise features ready')"
```

## 1️⃣ Exploit Verification (2 minutes)

### Safe Vulnerability Verification

```python
import asyncio
from verification import ExploitVerifier, VerificationMode

async def verify_vuln():
    verifier = ExploitVerifier()
    
    # Verify vulnerability exists (read-only, safe)
    result = await verifier.verify_exploit(
        target="test.example.com",
        vulnerability="SQL Injection",
        cve_id="CVE-2023-12345",
        mode=VerificationMode.READ_ONLY
    )
    
    print(f"Vulnerability: {result.vulnerability}")
    print(f"Success: {result.success}")
    print(f"Risk Score: {result.risk_score}/100")
    print(f"Evidence: {', '.join(result.evidence)}")
    
    # Automatic rollback (for SAFE_WRITE mode)
    if result.rolled_back:
        print("✓ All changes automatically rolled back")

asyncio.run(verify_vuln())
```

**Output:**
```
Vulnerability: SQL Injection
Success: True
Risk Score: 65/100
Evidence: Checked SQL Injection on test.example.com
✓ All changes automatically rolled back
```

## 2️⃣ Compliance Reporting (3 minutes)

### Generate PCI-DSS Report

```python
from compliance import ComplianceReporter, ComplianceFramework
from compliance.templates import PCIDSSTemplate

# Create reporter
reporter = ComplianceReporter()

# Create report
report = reporter.create_report(
    framework=ComplianceFramework.PCI_DSS,
    organization="Acme Corporation",
    scope="E-commerce payment system",
    assessor="Security Team"
)

# Load PCI-DSS controls
report.controls = PCIDSSTemplate.get_controls()

# Simulate assessment (normally from actual scans)
scan_results = {
    'vulnerabilities': [
        {'severity': 'high', 'type': 'outdated_software'},
        {'severity': 'medium', 'type': 'missing_header'}
    ]
}

# Assess compliance
import asyncio
asyncio.run(reporter.assess_scan_results(report, scan_results))

# View results
print(f"Compliance: {report.compliance_percentage:.1f}%")
print(f"Risk Level: {report.risk_level}")
print(f"Controls: {report.compliant_count}/{report.total_controls}")

# Export HTML report
reporter.export_report(
    report.report_id,
    format='html',
    output_file='pci-dss-report.html'
)
print("✓ Report saved to pci-dss-report.html")
```

**Output:**
```
Compliance: 87.5%
Risk Level: medium
Controls: 35/40
✓ Report saved to pci-dss-report.html
```

## 3️⃣ Distributed Scanning (5 minutes)

### Setup Coordinator

```python
# coordinator.py
import asyncio
from distributed import ScanCoordinator

async def run_coordinator():
    coordinator = ScanCoordinator()
    await coordinator.start()
    
    print("✓ Coordinator started")
    print("Waiting for agents to connect...")
    
    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        await coordinator.stop()

asyncio.run(run_coordinator())
```

### Setup Agent

```python
# agent.py
import asyncio
from distributed import ScanAgent, AgentConfig

async def run_agent():
    config = AgentConfig(
        coordinator_host="localhost",
        coordinator_port=8765,
        max_concurrent_tasks=3,
        supported_tools=["nmap", "nikto"]
    )
    
    agent = ScanAgent(config)
    await agent.start()
    
    print(f"✓ Agent {config.agent_id} started")
    print(f"Connected to coordinator at {config.coordinator_host}")
    
    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        await agent.stop()

asyncio.run(run_agent())
```

### Submit Scan Campaign

```python
# submit_scans.py
import asyncio
from distributed import ScanCoordinator

async def submit_campaign():
    coordinator = ScanCoordinator()
    
    # Submit 50 scans
    targets = [f"192.168.1.{i}" for i in range(1, 51)]
    
    task_ids = await coordinator.submit_campaign(
        targets=targets,
        scan_types=["nmap"],
        parameters={"ports": "1-1000"}
    )
    
    print(f"✓ Submitted {len(task_ids)} scan tasks")
    
    # Monitor progress
    while True:
        stats = coordinator.get_statistics()
        tasks = stats['tasks']
        print(f"Progress: {tasks['completed']}/{tasks['total']}")
        
        if tasks['completed'] == tasks['total']:
            break
        
        await asyncio.sleep(5)
    
    print("✓ All scans completed!")

asyncio.run(submit_campaign())
```

## 4️⃣ Automated Penetration Testing (5 minutes)

### Run Automated Pentest

```python
import asyncio
from datetime import datetime
from autopent import AutoPentEngine, PentestConfig

async def run_pentest():
    # Configure pentest
    config = PentestConfig(
        # Targets
        targets=["test.example.com"],
        scope=["test.example.com", "*.test.example.com"],
        exclusions=["prod.example.com"],
        
        # Authorization (REQUIRED - use real token)
        authorization_token="a" * 32,  # Replace with real token
        authorized_by="John Doe, CISO",
        authorization_date=datetime.now(),
        
        # Safety settings
        safe_mode=True,  # Recommended for first run
        avoid_dos=True,
        avoid_data_modification=True,
        max_exploitation_attempts=3,
        
        # Constraints
        max_duration=1800,  # 30 minutes
        rate_limit=100
    )
    
    # Start pentest
    print("Starting automated penetration test...")
    print("Target:", config.targets[0])
    print("Safe Mode:", config.safe_mode)
    
    engine = AutoPentEngine()
    result = await engine.start_pentest(config)
    
    # Results
    print("\n" + "="*50)
    print("PENETRATION TEST RESULTS")
    print("="*50)
    print(f"Status: {result.status.value}")
    print(f"Duration: {result.duration:.1f}s")
    print(f"Overall Risk: {result.overall_risk.upper()}")
    print(f"\nStatistics:")
    print(f"  Hosts Tested: {result.hosts_tested}")
    print(f"  Vulnerabilities: {result.vulnerabilities_found}")
    print(f"  Exploits Attempted: {result.exploits_attempted}")
    print(f"  Exploits Successful: {result.exploits_successful}")
    print(f"\nSafety:")
    print(f"  Operations Blocked: {len(result.safety_blocks)}")
    print(f"  Warnings: {len(result.warnings)}")
    print(f"\n{result.summary}")

asyncio.run(run_pentest())
```

**Output:**
```
Starting automated penetration test...
Target: test.example.com
Safe Mode: True

==================================================
PENETRATION TEST RESULTS
==================================================
Status: completed
Duration: 847.3s
Overall Risk: MEDIUM

Statistics:
  Hosts Tested: 1
  Vulnerabilities: 5
  Exploits Attempted: 2
  Exploits Successful: 1

Safety:
  Operations Blocked: 3
  Warnings: 2

Automated Penetration Test Summary

Test ID: pentest_a7f3c9d1
Duration: 847.3 seconds
Overall Risk: MEDIUM

Findings:
- Hosts Tested: 1
- Vulnerabilities Found: 5
- Exploits Attempted: 2
- Exploits Successful: 1
- Critical Issues: 1

Safety Controls:
- Safety Blocks: 3
- Warnings: 2
- Safe Mode: Enabled

Recommendation: Review and plan remediation
```

## 5️⃣ Complete Integration Example

Combine all features in a single workflow:

```python
import asyncio
from verification import ExploitVerifier, VerificationMode
from compliance import ComplianceReporter, ComplianceFramework
from compliance.templates import PCIDSSTemplate
from autopent import AutoPentEngine, PentestConfig
from datetime import datetime

async def complete_assessment():
    target = "test.example.com"
    
    print("═══════════════════════════════════════")
    print("  ZYPHERON ENTERPRISE ASSESSMENT")
    print("═══════════════════════════════════════\n")
    
    # Phase 1: Automated Pentest
    print("Phase 1: Automated Penetration Test")
    print("-" * 40)
    
    config = PentestConfig(
        targets=[target],
        scope=[target],
        authorization_token="a" * 32,
        safe_mode=True
    )
    
    engine = AutoPentEngine()
    pentest = await engine.start_pentest(config)
    print(f"✓ Pentest completed: {pentest.vulnerabilities_found} vulnerabilities\n")
    
    # Phase 2: Verify Critical Vulnerabilities
    print("Phase 2: Exploit Verification")
    print("-" * 40)
    
    verifier = ExploitVerifier()
    for vuln in pentest.vulnerabilities[:3]:  # Top 3
        result = await verifier.verify_exploit(
            target=target,
            vulnerability=vuln['type'],
            mode=VerificationMode.READ_ONLY
        )
        print(f"✓ Verified: {vuln['type']} - Risk: {result.risk_score:.0f}/100")
    
    print()
    
    # Phase 3: Compliance Assessment
    print("Phase 3: Compliance Reporting")
    print("-" * 40)
    
    reporter = ComplianceReporter()
    report = reporter.create_report(
        framework=ComplianceFramework.PCI_DSS,
        organization="Your Organization",
        scope=f"Assessment of {target}"
    )
    
    report.controls = PCIDSSTemplate.get_controls()
    
    scan_results = {
        'vulnerabilities': pentest.vulnerabilities
    }
    await reporter.assess_scan_results(report, scan_results)
    
    print(f"✓ Compliance: {report.compliance_percentage:.1f}%")
    print(f"✓ Risk Level: {report.risk_level}")
    
    # Export report
    reporter.export_report(
        report.report_id,
        format='html',
        output_file=f'assessment-{target}.html'
    )
    print(f"✓ Report saved: assessment-{target}.html\n")
    
    # Summary
    print("═══════════════════════════════════════")
    print("  ASSESSMENT COMPLETE")
    print("═══════════════════════════════════════")
    print(f"Target: {target}")
    print(f"Vulnerabilities: {pentest.vulnerabilities_found}")
    print(f"Compliance: {report.compliance_percentage:.1f}%")
    print(f"Overall Risk: {pentest.overall_risk.upper()}")

asyncio.run(complete_assessment())
```

## Next Steps

1. **Read Full Documentation**: [ENTERPRISE_FEATURES.md](ENTERPRISE_FEATURES.md)
2. **Configure AI Provider**: Add API keys to `.env`
3. **Run on Real Targets**: Get proper authorization first!
4. **Customize**: Extend with your own tools and checks
5. **Integrate**: Connect to your SIEM, ticketing systems

## Common Issues

### "ModuleNotFoundError: No module named 'verification'"

```bash
cd zypheron-ai
pip install -e .
```

### "Authorization required for this operation"

Provide a valid authorization token (32+ characters):

```python
authorization_token="your-secure-authorization-token-here-32chars"
```

### "Agent connection failed"

Ensure coordinator is running first, then start agents.

## Support

- **Documentation**: [ENTERPRISE_FEATURES.md](ENTERPRISE_FEATURES.md)
- **Issues**: GitHub Issues
- **Enterprise Support**: enterprise@zypheron.ai

---

**Happy (Authorized) Pentesting! 🚀**

