# Jinja2 Implementation Plan for Cobra-AI-Zypheron

## Executive Summary

Implement Jinja2 templating across Cobra-AI-Zypheron to improve maintainability, following the pattern used successfully by Strix. This will replace hardcoded string concatenation with clean, maintainable templates.

**Benefits:**
- 🧹 Cleaner code: Separate presentation from logic
- 🔧 Easier maintenance: Edit templates without touching Python
- 🎨 Better styling: Template inheritance and reusability
- 🤖 Modular AI prompts: Like Strix's approach
- 📊 Consistent reports: Shared base templates

---

## Phase 1: Foundation Setup

### 1.1 Audit Current Usage

**Goal:** Identify all locations using string concatenation for templates

**Actions:**
```bash
# Find all HTML generation in Python strings
grep -r "<!DOCTYPE html>" zypheron-ai/ --include="*.py"

# Find f-string report generation
grep -r "_generate.*report" zypheron-ai/ --include="*.py"

# Find AI prompt construction
grep -r "prompt = f\"\"\"" zypheron-ai/ --include="*.py"
```

**Files to review:**
- `zypheron-ai/compliance/compliance_reporter.py` (main target)
- `zypheron-ai/integrations/burp/burp_reporter.py`
- Any AI chat/prompt generation files

### 1.2 Directory Structure Design

**Create new structure:**
```
zypheron-ai/
├── templates/
│   ├── base/
│   │   ├── base.html.jinja          # Base HTML template
│   │   ├── email.html.jinja         # Email template base
│   │   └── styles.css               # Shared styles
│   ├── compliance/
│   │   ├── report.html.jinja        # Generic compliance report
│   │   ├── pci_dss.html.jinja       # PCI-DSS specific
│   │   ├── hipaa.html.jinja         # HIPAA specific
│   │   ├── soc2.html.jinja          # SOC2 specific
│   │   ├── iso27001.html.jinja      # ISO27001 specific
│   │   ├── report.md.jinja          # Markdown reports
│   │   └── executive_summary.jinja  # Summary section
│   ├── scan_reports/
│   │   ├── vulnerability.html.jinja
│   │   └── summary.md.jinja
│   └── emails/
│       ├── notification.html.jinja
│       └── alert.html.jinja
├── prompts/
│   ├── compliance/
│   │   ├── pci_dss_assessment.jinja
│   │   └── executive_summary.jinja
│   ├── vulnerabilities/
│   │   ├── sql_injection.jinja
│   │   ├── xss.jinja
│   │   ├── ssrf.jinja
│   │   └── rce.jinja
│   ├── frameworks/
│   │   ├── fastapi.jinja
│   │   ├── django.jinja
│   │   ├── flask.jinja
│   │   └── nodejs.jinja
│   └── analysis/
│       ├── code_review.jinja
│       └── threat_modeling.jinja
└── utils/
    └── template_loader.py            # Jinja2 environment setup
```

---

## Phase 2: Core Implementation

### 2.1 Create Template Loader Utility

**File:** `zypheron-ai/utils/template_loader.py`

```python
"""
Jinja2 Template Loader for Zypheron AI

Provides centralized template loading and rendering following
the Strix pattern for modular prompt templates.
"""

from pathlib import Path
from typing import Dict, List, Optional, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape, Template
import logging

logger = logging.getLogger(__name__)


class TemplateLoader:
    """Centralized template loader for Jinja2"""

    def __init__(self, base_path: Optional[Path] = None):
        """Initialize template loader

        Args:
            base_path: Base path for templates (defaults to zypheron-ai/)
        """
        if base_path is None:
            base_path = Path(__file__).parent.parent

        self.base_path = base_path
        self.templates_dir = base_path / "templates"
        self.prompts_dir = base_path / "prompts"

        # Create Jinja2 environments
        self.template_env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )

        self.prompt_env = Environment(
            loader=FileSystemLoader(self.prompts_dir),
            autoescape=False,  # Don't escape prompts
            trim_blocks=True,
            lstrip_blocks=True
        )

        # Add custom filters
        self._register_custom_filters()

    def _register_custom_filters(self):
        """Register custom Jinja2 filters"""

        def format_severity(severity: str) -> str:
            """Format severity with color codes"""
            colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745'
            }
            return colors.get(severity.lower(), '#6c757d')

        def format_timestamp(dt) -> str:
            """Format datetime for reports"""
            if dt is None:
                return "N/A"
            return dt.strftime('%Y-%m-%d %H:%M:%S')

        self.template_env.filters['severity_color'] = format_severity
        self.template_env.filters['timestamp'] = format_timestamp
        self.prompt_env.filters['timestamp'] = format_timestamp

    def render_template(
        self,
        template_name: str,
        context: Dict[str, Any]
    ) -> str:
        """Render a template from templates/ directory

        Args:
            template_name: Template filename (e.g., 'compliance/report.html.jinja')
            context: Dictionary of variables to pass to template

        Returns:
            Rendered template string
        """
        try:
            template = self.template_env.get_template(template_name)
            return template.render(**context)
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {e}")
            raise

    def render_prompt(
        self,
        prompt_name: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Render a prompt from prompts/ directory

        Args:
            prompt_name: Prompt filename (e.g., 'vulnerabilities/xss.jinja')
            context: Optional variables to pass to prompt

        Returns:
            Rendered prompt string
        """
        try:
            template = self.prompt_env.get_template(prompt_name)
            return template.render(**(context or {}))
        except Exception as e:
            logger.error(f"Failed to render prompt {prompt_name}: {e}")
            raise

    def load_prompt_modules(
        self,
        module_names: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """Load multiple prompt modules (Strix pattern)

        Args:
            module_names: List of module names (e.g., ['xss', 'sql_injection'])
            context: Optional context for rendering

        Returns:
            Dictionary mapping module name to rendered content
        """
        modules = {}
        available = self.get_available_prompt_modules()

        for module_name in module_names:
            try:
                # Find module path
                module_path = self._find_prompt_module(module_name, available)

                if module_path:
                    content = self.render_prompt(module_path, context)
                    var_name = module_name.split('/')[-1]
                    modules[var_name] = content
                    logger.info(f"Loaded prompt module: {module_name}")
                else:
                    logger.warning(f"Prompt module not found: {module_name}")

            except Exception as e:
                logger.warning(f"Failed to load module {module_name}: {e}")

        return modules

    def get_available_prompt_modules(self) -> Dict[str, List[str]]:
        """Get available prompt modules organized by category"""
        available = {}

        if not self.prompts_dir.exists():
            return available

        for category_dir in self.prompts_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith('__'):
                modules = [
                    f.stem for f in category_dir.glob('*.jinja')
                ]
                if modules:
                    available[category_dir.name] = sorted(modules)

        return available

    def _find_prompt_module(
        self,
        module_name: str,
        available: Dict[str, List[str]]
    ) -> Optional[str]:
        """Find full path for a prompt module"""

        # If already a path
        if '/' in module_name:
            candidate = f"{module_name}.jinja"
            if (self.prompts_dir / candidate).exists():
                return candidate

        # Search in categories
        for category, modules in available.items():
            if module_name in modules:
                return f"{category}/{module_name}.jinja"

        # Check root level
        candidate = f"{module_name}.jinja"
        if (self.prompts_dir / candidate).exists():
            return candidate

        return None


# Global singleton instance
_loader: Optional[TemplateLoader] = None


def get_template_loader() -> TemplateLoader:
    """Get global template loader instance"""
    global _loader
    if _loader is None:
        _loader = TemplateLoader()
    return _loader
```

### 2.2 Create Base Templates

**File:** `zypheron-ai/templates/base/base.html.jinja`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Zypheron Report{% endblock %}</title>
    <style>
        /* Base styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto',
                         'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .card {
            background: white;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }

        .metric {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }

        .metric-label {
            font-size: 0.9em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }

        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
        }

        /* Severity colors */
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }

        /* Status colors */
        .status-compliant { color: #28a745; }
        .status-non-compliant { color: #dc3545; }
        .status-partial { color: #ffc107; }
        .status-needs-review { color: #6c757d; }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        th {
            background: #2c3e50;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .footer {
            margin-top: 60px;
            padding-top: 20px;
            border-top: 2px solid #dee2e6;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }

        {% block extra_styles %}{% endblock %}
    </style>
</head>
<body>
    <div class="container">
        {% block header %}
        <div class="header">
            <h1>{% block header_title %}Zypheron Report{% endblock %}</h1>
            <div class="subtitle">{% block header_subtitle %}{% endblock %}</div>
        </div>
        {% endblock %}

        {% block content %}{% endblock %}

        {% block footer %}
        <div class="footer">
            <p>Generated by <strong>Zypheron AI</strong> on {{ generation_time | timestamp }}</p>
            <p>AI-Powered Penetration Testing Platform</p>
        </div>
        {% endblock %}
    </div>
</body>
</html>
```

---

## Phase 3: Compliance Report Migration

### 3.1 Create Compliance Report Template

**File:** `zypheron-ai/templates/compliance/report.html.jinja`

```html
{% extends "base/base.html.jinja" %}

{% block title %}{{ report.framework.value | upper }} Compliance Report - {{ report.organization }}{% endblock %}

{% block header_title %}{{ report.framework.value | upper }} Compliance Report{% endblock %}
{% block header_subtitle %}{{ report.organization }}{% endblock %}

{% block content %}
<!-- Executive Summary -->
<div class="card">
    <h2>Executive Summary</h2>
    <p style="white-space: pre-wrap; margin-top: 20px;">{{ report.executive_summary }}</p>

    <div class="metrics">
        <div class="metric">
            <div class="metric-label">Overall Compliance</div>
            <div class="metric-value severity-{{ report.risk_level }}">
                {{ "%.1f" | format(report.compliance_percentage) }}%
            </div>
        </div>
        <div class="metric">
            <div class="metric-label">Risk Level</div>
            <div class="metric-value severity-{{ report.risk_level }}">
                {{ report.risk_level | upper }}
            </div>
        </div>
        <div class="metric">
            <div class="metric-label">Controls Tested</div>
            <div class="metric-value">{{ report.total_controls }}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Compliant</div>
            <div class="metric-value status-compliant">{{ report.compliant_count }}</div>
        </div>
    </div>
</div>

<!-- Compliance Status Breakdown -->
<div class="card">
    <h2>Compliance Status</h2>
    <table>
        <tr>
            <th>Status</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
        <tr>
            <td class="status-compliant">Compliant</td>
            <td>{{ report.compliant_count }}</td>
            <td>{{ "%.1f" | format((report.compliant_count / report.total_controls * 100) if report.total_controls > 0 else 0) }}%</td>
        </tr>
        <tr>
            <td class="status-non-compliant">Non-Compliant</td>
            <td>{{ report.non_compliant_count }}</td>
            <td>{{ "%.1f" | format((report.non_compliant_count / report.total_controls * 100) if report.total_controls > 0 else 0) }}%</td>
        </tr>
        <tr>
            <td class="status-partial">Partial</td>
            <td>{{ report.partial_count }}</td>
            <td>{{ "%.1f" | format((report.partial_count / report.total_controls * 100) if report.total_controls > 0 else 0) }}%</td>
        </tr>
    </table>
</div>

<!-- Control Assessment -->
<div class="card">
    <h2>Control Assessment</h2>
    <table>
        <thead>
            <tr>
                <th>Control ID</th>
                <th>Name</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {% for control in report.controls %}
            <tr>
                <td><strong>{{ control.control_id }}</strong></td>
                <td>{{ control.name }}</td>
                <td>{{ control.category | replace('_', ' ') | title }}</td>
                <td class="severity-{{ control.severity }}">{{ control.severity | upper }}</td>
                <td class="status-{{ control.status.value | replace('_', '-') }}">
                    {{ control.status.value | replace('_', ' ') | title }}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<!-- Critical Findings -->
{% if report.critical_findings %}
<div class="card">
    <h2 style="color: #dc3545;">Critical Findings</h2>
    <ul style="line-height: 2;">
        {% for finding in report.critical_findings %}
        <li><strong>{{ finding }}</strong></li>
        {% endfor %}
    </ul>
</div>
{% endif %}

<!-- High Priority Findings -->
{% if report.high_findings %}
<div class="card">
    <h2 style="color: #fd7e14;">High Priority Findings</h2>
    <ul style="line-height: 2;">
        {% for finding in report.high_findings %}
        <li>{{ finding }}</li>
        {% endfor %}
    </ul>
</div>
{% endif %}

<!-- Recommendations -->
{% if report.recommendations %}
<div class="card">
    <h2>Recommendations</h2>
    <ol style="line-height: 2;">
        {% for rec in report.recommendations[:10] %}
        <li>{{ rec }}</li>
        {% endfor %}
    </ol>
</div>
{% endif %}

{% endblock %}
```

### 3.2 Update compliance_reporter.py

**Refactor:** `zypheron-ai/compliance/compliance_reporter.py`

```python
# At the top of the file
from utils.template_loader import get_template_loader
from datetime import datetime

class ComplianceReporter:
    def __init__(self, ai_provider=None):
        self.ai_provider = ai_provider
        self.reports: Dict[str, ComplianceReport] = {}
        self.template_loader = get_template_loader()

    def _generate_html_report(self, report: ComplianceReport) -> str:
        """Generate HTML report using Jinja2 template"""
        context = {
            'report': report,
            'generation_time': datetime.now()
        }

        # Try framework-specific template first, fall back to generic
        template_name = f'compliance/{report.framework.value}.html.jinja'
        try:
            return self.template_loader.render_template(template_name, context)
        except:
            # Fall back to generic template
            return self.template_loader.render_template(
                'compliance/report.html.jinja',
                context
            )

    def _generate_markdown_report(self, report: ComplianceReport) -> str:
        """Generate Markdown report using Jinja2 template"""
        context = {
            'report': report,
            'generation_time': datetime.now()
        }
        return self.template_loader.render_template(
            'compliance/report.md.jinja',
            context
        )

    async def _generate_executive_summary(self, report: ComplianceReport) -> None:
        """Generate AI-powered executive summary using prompt template"""
        if not self.ai_provider:
            report.executive_summary = self._generate_basic_summary(report)
            return

        try:
            # Load prompt template
            prompt = self.template_loader.render_prompt(
                'compliance/executive_summary.jinja',
                {'report': report}
            )

            summary = await self.ai_provider.chat(prompt)
            report.executive_summary = summary

        except Exception as e:
            logger.error(f"Failed to generate AI summary: {e}")
            report.executive_summary = self._generate_basic_summary(report)
```

---

## Phase 4: AI Prompt Templates

### 4.1 Create Executive Summary Prompt

**File:** `zypheron-ai/prompts/compliance/executive_summary.jinja`

```jinja
Generate an executive summary for this compliance assessment:

Framework: {{ report.framework.value | upper }}
Organization: {{ report.organization }}
Compliance: {{ "%.1f" | format(report.compliance_percentage) }}%
Status: {{ report.overall_status.value }}
Risk Level: {{ report.risk_level }}

Controls Tested: {{ report.total_controls }}
- Compliant: {{ report.compliant_count }}
- Non-Compliant: {{ report.non_compliant_count }}
- Partial: {{ report.partial_count }}

Critical Findings: {{ report.critical_findings | length }}
High Findings: {{ report.high_findings | length }}

Provide a concise executive summary (3-4 paragraphs) covering:
1. Overall compliance posture
2. Key risks and concerns
3. Priority recommendations
4. Business impact

Write in a professional tone suitable for executive leadership.
```

### 4.2 Create Vulnerability Testing Prompts

**File:** `zypheron-ai/prompts/vulnerabilities/sql_injection.jinja`

```jinja
<sql_injection_testing_guide>
<title>SQL INJECTION VULNERABILITY TESTING</title>

<critical>SQL injection remains prevalent due to dynamic query construction, ORM misuse, and insufficient input validation. Test systematically across query contexts and database engines.</critical>

<scope>
- Classic SQL injection (in-band)
- Blind SQL injection (boolean-based, time-based)
- Out-of-band SQL injection
- Second-order SQL injection
- NoSQL injection variants
</scope>

<methodology>
1. Identify injection points: parameters, headers, cookies, JSON fields
2. Test basic payloads: quotes, logical operators, comments
3. Fingerprint database: error messages, timing, behavior
4. Exploit confirmed vulnerabilities: data extraction, authentication bypass
5. Validate with proof-of-concept demonstrating data access
</methodology>

<test_payloads>
# Basic detection
' OR '1'='1
" OR "1"="1
' OR 1=1--
') OR ('1'='1

# Time-based blind
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
' AND BENCHMARK(5000000,MD5('A'))--

# Union-based
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--

# Boolean-based blind
' AND 1=1--  (true condition)
' AND 1=2--  (false condition)
</test_payloads>

<database_fingerprinting>
# MySQL
VERSION(), DATABASE(), USER()

# PostgreSQL
version(), current_database(), current_user

# MSSQL
@@VERSION, DB_NAME(), USER_NAME()

# Oracle
SELECT banner FROM v$version
</database_fingerprinting>

<validation>
Provide:
1. Exact injection point and payload
2. Database type and version
3. Proof of data extraction (sample row)
4. Impact assessment (data accessed, privilege level)
5. Remediation recommendation
</validation>

<remember>Always test with safe payloads first. Demonstrate read-only data access. Document exact reproduction steps.</remember>
</sql_injection_testing_guide>
```

**File:** `zypheron-ai/prompts/frameworks/fastapi.jinja`

```jinja
<fastapi_security_testing_guide>
<title>FASTAPI SECURITY TESTING PLAYBOOK</title>

<critical>FastAPI applications require testing across dependency injection, Pydantic validation, authentication middleware, and async contexts. Focus on authorization bypasses and data validation gaps.</critical>

<attack_surface>
- OpenAPI schema endpoints (/openapi.json, /docs, /redoc)
- Dependency injection security (OAuth2, JWT validation)
- Pydantic model validation and coercion
- Router-level vs route-level authentication
- CORS configuration
- WebSocket authentication
- Background task authorization
- File upload handling
</attack_surface>

<test_methodology>
1. Enumerate all endpoints from OpenAPI schema
2. Map authentication dependencies per route
3. Test authorization with different user roles/tenants
4. Validate input handling across content-types
5. Test WebSocket authentication if present
6. Check for IDOR vulnerabilities on resource IDs
7. Verify CORS policy enforcement
</test_methodology>

<key_vulnerabilities>
# Missing authentication on routes
GET /api/users/{user_id}  (no Depends() security)

# Weak JWT validation
Token decoded without signature verification
Missing audience/issuer validation

# IDOR in path parameters
GET /api/users/{user_id}/profile
Test: Can user 1 access user 2's data?

# Pydantic validation bypass
Send extra fields not in model
Type coercion exploitation

# CORS misconfiguration
Overly permissive allow_origins
Credentials allowed with wildcard origin
</key_vulnerabilities>

<testing_checklist>
- [ ] Fetch /openapi.json and enumerate all endpoints
- [ ] Identify endpoints missing security dependencies
- [ ] Test cross-tenant data access on all resource endpoints
- [ ] Verify JWT signature validation
- [ ] Test content-type switching (JSON ↔ multipart ↔ form)
- [ ] Check WebSocket authentication
- [ ] Test file upload path traversal
- [ ] Validate CORS with arbitrary origins
- [ ] Test background task authorization
</testing_checklist>

<remember>FastAPI's dependency system is powerful but easily misconfigured. Always test actual authorization logic, not just authentication token presence.</remember>
</fastapi_security_testing_guide>
```

---

## Phase 5: Testing & Validation

### 5.1 Create Test Script

**File:** `zypheron-ai/tests/test_templates.py`

```python
"""
Test suite for Jinja2 template rendering
"""

import pytest
from datetime import datetime
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.template_loader import TemplateLoader, get_template_loader
from compliance.compliance_reporter import (
    ComplianceReport, ComplianceControl, ComplianceFramework, ComplianceStatus
)


@pytest.fixture
def template_loader():
    """Get template loader instance"""
    return get_template_loader()


@pytest.fixture
def sample_report():
    """Create sample compliance report"""
    report = ComplianceReport(
        report_id="test_report_001",
        framework=ComplianceFramework.PCI_DSS,
        organization="Test Organization",
        scope="Web Application",
        assessment_date=datetime.now(),
        assessor="Test Assessor"
    )

    # Add sample controls
    report.controls = [
        ComplianceControl(
            control_id="PCI-1.1",
            name="Network Security Controls",
            description="Test control",
            framework=ComplianceFramework.PCI_DSS,
            requirement="Install network security controls",
            category="network_security",
            severity="critical",
            status=ComplianceStatus.COMPLIANT
        ),
        ComplianceControl(
            control_id="PCI-6.1",
            name="Security Updates",
            description="Vulnerability management",
            framework=ComplianceFramework.PCI_DSS,
            requirement="Identify security vulnerabilities",
            category="vulnerability_management",
            severity="critical",
            status=ComplianceStatus.NON_COMPLIANT
        )
    ]

    report.calculate_statistics()
    report.executive_summary = "This is a test executive summary."
    report.critical_findings = ["PCI-6.1: Security Updates"]

    return report


def test_template_loader_initialization(template_loader):
    """Test template loader initializes correctly"""
    assert template_loader is not None
    assert template_loader.templates_dir.exists()
    assert template_loader.prompts_dir.exists()


def test_html_report_generation(template_loader, sample_report):
    """Test HTML report generation"""
    context = {
        'report': sample_report,
        'generation_time': datetime.now()
    }

    html = template_loader.render_template('compliance/report.html.jinja', context)

    # Verify key elements
    assert '<!DOCTYPE html>' in html
    assert 'PCI-DSS Compliance Report' in html
    assert 'Test Organization' in html
    assert 'PCI-1.1' in html
    assert 'Network Security Controls' in html


def test_markdown_report_generation(template_loader, sample_report):
    """Test Markdown report generation"""
    context = {
        'report': sample_report,
        'generation_time': datetime.now()
    }

    md = template_loader.render_template('compliance/report.md.jinja', context)

    # Verify markdown structure
    assert '# PCI-DSS Compliance Report' in md
    assert '**Organization:**' in md
    assert '| Control ID |' in md


def test_prompt_module_loading(template_loader):
    """Test loading prompt modules"""
    available = template_loader.get_available_prompt_modules()

    # Should have categories
    assert isinstance(available, dict)
    assert len(available) > 0


def test_executive_summary_prompt(template_loader, sample_report):
    """Test executive summary prompt rendering"""
    context = {'report': sample_report}

    prompt = template_loader.render_prompt(
        'compliance/executive_summary.jinja',
        context
    )

    assert 'Framework: PCI-DSS' in prompt
    assert 'Test Organization' in prompt
    assert 'executive summary' in prompt.lower()


def test_sql_injection_prompt(template_loader):
    """Test SQL injection testing prompt"""
    prompt = template_loader.render_prompt('vulnerabilities/sql_injection.jinja')

    assert 'SQL INJECTION' in prompt
    assert 'UNION SELECT' in prompt
    assert 'methodology' in prompt.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
```

### 5.2 Manual Testing Checklist

```bash
# 1. Test template loader
cd zypheron-ai
python3 -c "from utils.template_loader import get_template_loader; loader = get_template_loader(); print(loader.get_available_prompt_modules())"

# 2. Generate sample HTML report
python3 -c "
from utils.template_loader import get_template_loader
from compliance.compliance_reporter import ComplianceReporter, ComplianceFramework
from datetime import datetime

reporter = ComplianceReporter()
report = reporter.create_report(
    ComplianceFramework.PCI_DSS,
    'Test Corp',
    'Production Environment',
    'Test User'
)
report.calculate_statistics()

html = reporter._generate_html_report(report)
with open('/tmp/test_report.html', 'w') as f:
    f.write(html)
print('Report saved to /tmp/test_report.html')
"

# 3. Open in browser
xdg-open /tmp/test_report.html  # Linux
# open /tmp/test_report.html     # macOS

# 4. Run test suite
cd tests
pytest test_templates.py -v
```

---

## Phase 6: Documentation

### 6.1 Template Usage Guide

**File:** `zypheron-ai/docs/TEMPLATES.md`

```markdown
# Jinja2 Templates Guide

## Overview

Zypheron uses Jinja2 templating for report generation and AI prompt management.

## Directory Structure

- `templates/` - HTML/Markdown report templates
- `prompts/` - AI prompt templates

## Using Templates

### Render a Report

```python
from utils.template_loader import get_template_loader

loader = get_template_loader()
html = loader.render_template('compliance/report.html.jinja', {
    'report': my_report,
    'generation_time': datetime.now()
})
```

### Load AI Prompts

```python
# Single prompt
prompt = loader.render_prompt('vulnerabilities/xss.jinja')

# Multiple modules
modules = loader.load_prompt_modules([
    'sql_injection',
    'xss',
    'fastapi'
])
```

## Creating New Templates

### Report Template

1. Create file in `templates/your_category/`
2. Extend `base/base.html.jinja`
3. Override blocks as needed

### Prompt Template

1. Create `.jinja` file in `prompts/category/`
2. Use variables with `{{ variable }}`
3. Test with template loader

## Custom Filters

- `severity_color` - Get color code for severity
- `timestamp` - Format datetime

## Best Practices

- Use template inheritance
- Keep logic minimal in templates
- Document variables in comments
- Test all templates
```

---

## Implementation Timeline

| Phase | Tasks | Estimated Time |
|-------|-------|----------------|
| **Phase 1** | Audit + Setup | 2-3 hours |
| **Phase 2** | Core Implementation | 4-6 hours |
| **Phase 3** | Compliance Migration | 3-4 hours |
| **Phase 4** | AI Prompts | 2-3 hours |
| **Phase 5** | Testing | 2-3 hours |
| **Phase 6** | Documentation | 1-2 hours |
| **Total** | | **14-21 hours** |

---

## Migration Checklist

### Pre-Migration
- [ ] Review current string concatenation code
- [ ] Backup existing reporters
- [ ] Create feature branch: `feature/jinja-templates`
- [ ] Set up test environment

### Implementation
- [ ] Create directory structure
- [ ] Implement TemplateLoader class
- [ ] Create base HTML template
- [ ] Create compliance report templates
- [ ] Migrate compliance_reporter.py
- [ ] Create AI prompt templates
- [ ] Create Markdown templates
- [ ] Add custom filters

### Testing
- [ ] Unit tests for template loader
- [ ] Integration tests for reporters
- [ ] Visual testing of HTML reports
- [ ] Prompt template validation
- [ ] Performance benchmarks

### Documentation
- [ ] Template usage guide
- [ ] Prompt authoring guide
- [ ] Migration notes
- [ ] Update main README

### Deployment
- [ ] Code review
- [ ] Merge to main
- [ ] Update dependencies
- [ ] Deploy to staging
- [ ] Production deployment

---

## Success Metrics

**Code Quality:**
- ✅ Remove 500+ lines of string concatenation
- ✅ Reduce complexity in reporter classes
- ✅ Improve test coverage to 80%+

**Maintainability:**
- ✅ Non-developers can edit templates
- ✅ Templates reusable across frameworks
- ✅ Clear separation of concerns

**Features:**
- ✅ Support 4+ compliance frameworks
- ✅ 10+ AI prompt modules
- ✅ Multiple output formats (HTML, MD, PDF)

---

## Future Enhancements

1. **PDF Generation**: Add weasyprint for PDF exports
2. **Email Templates**: Notification and alert emails
3. **Dashboard Templates**: Web UI for MCP interface
4. **Custom Themes**: Allow branding customization
5. **Template Marketplace**: Share community templates
6. **Internationalization**: Multi-language support

---

## Support & Resources

- **Jinja2 Docs**: https://jinja.palletsprojects.com/
- **Strix Reference**: `/home/zero/Downloads/strix-main/strix/prompts/`
- **Questions**: Open issue or ask in team chat

---

*Generated: {{ datetime.now().strftime('%Y-%m-%d') }}*
*Author: Zypheron Development Team*
