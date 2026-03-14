# Jinja2 Templates Usage Guide

## Overview

Zypheron now uses Jinja2 templating for:
- **Compliance reports** (HTML, Markdown) with automatic fallback to legacy generation
- **AI prompts** for vulnerability testing and security assessments

## Quick Start

### Using Compliance Reporter

```python
from compliance.compliance_reporter import ComplianceReporter, ComplianceFramework

# Create reporter (Jinja2 enabled by default)
reporter = ComplianceReporter()

# Create a report
report = reporter.create_report(
    framework=ComplianceFramework.PCI_DSS,
    organization="Your Company",
    scope="Production Environment"
)

# Add controls and calculate statistics
report.controls = [...]  # Your controls
report.calculate_statistics()

# Export with Jinja2 templates (automatic fallback if templates fail)
html = reporter.export_report(report.report_id, format='html')
markdown = reporter.export_report(report.report_id, format='markdown')
```

### Using AI Prompt Templates

```python
from utils.template_loader import get_template_loader

loader = get_template_loader()

# Load single prompt
sql_injection_prompt = loader.render_prompt('vulnerabilities/sql_injection.jinja')

# Load multiple prompts
prompts = loader.load_prompt_modules([
    'sql_injection',
    'xss',
    'api_security'
])

# Use with context variables
prompt = loader.render_prompt(
    'compliance/executive_summary.jinja',
    {'report': my_report}
)
```

## Available Templates

### Compliance Reports

Located in `templates/compliance/`:
- `base.html.jinja` - Generic compliance report (used by all frameworks)
- `pci_dss.html.jinja` - PCI-DSS specific
- `hipaa.html.jinja` - HIPAA specific
- `soc2.html.jinja` - SOC2 specific
- `iso27001.html.jinja` - ISO 27001 specific
- `report.md.jinja` - Markdown format

### AI Prompts

Located in `prompts/`:

**Vulnerabilities:**
- `vulnerabilities/sql_injection.jinja` - SQL injection testing guide
- `vulnerabilities/xss.jinja` - XSS testing guide

**Security:**
- `security/api_security.jinja` - API security testing (REST & GraphQL)
- `security/authn_authz.jinja` - Authentication/Authorization testing

**Compliance:**
- `compliance/executive_summary.jinja` - AI-powered executive summaries

## Fallback Mechanism

The system automatically falls back to legacy string generation if:
- Jinja2 is not installed
- Templates are missing or corrupted
- Template rendering fails

No code changes needed - it's completely automatic!

```python
# This will use Jinja2 if available, otherwise legacy
reporter = ComplianceReporter()  # use_jinja=True by default

# Force legacy mode
reporter = ComplianceReporter(use_jinja=False)
```

## Creating Custom Templates

### Adding a New Compliance Template

1. Create file in `templates/compliance/`:
```bash
templates/compliance/my_framework.html.jinja
```

2. Use the same structure as `base.html.jinja`

3. The reporter will automatically use it:
```python
report = reporter.create_report(
    framework=ComplianceFramework.MY_FRAMEWORK,
    ...
)
# Will use my_framework.html.jinja if it exists
```

### Adding a New AI Prompt

1. Create file in appropriate category:
```bash
prompts/vulnerabilities/csrf.jinja
prompts/security/ssrf.jinja
```

2. Load it:
```python
prompt = loader.render_prompt('vulnerabilities/csrf.jinja')
```

## Custom Filters

Available Jinja2 filters:

```jinja
{{ report.risk_level | severity_color }}  {# Returns hex color code #}
{{ report.assessment_date | timestamp }}   {# Formats datetime #}
{{ control.status.value | status_class }}  {# Converts to CSS class #}
```

## Testing

Run the test suite to verify everything works:

```bash
cd zypheron-ai
python3 test_jinja_implementation.py
```

This tests:
- All 4 compliance frameworks (PCI-DSS, HIPAA, SOC2, ISO 27001)
- HTML and Markdown generation with Jinja2 vs legacy
- AI prompt template loading
- Automatic fallback mechanism
- Visual comparison of outputs

Test outputs are saved to `test_output/` directory.

## Troubleshooting

### Templates Not Loading

**Problem:** "Template not found" error

**Solution:**
```bash
# Verify directory structure
ls -R templates/
ls -R prompts/

# Check templates_dir is correct
python3 -c "from utils.template_loader import get_template_loader; print(get_template_loader().templates_dir)"
```

### Jinja2 Syntax Errors

**Problem:** "unexpected char '$'" or similar

**Solution:** Wrap problematic content in `{% raw %}` blocks:
```jinja
{% raw %}${variable}{% endraw %}  {# For JavaScript template literals #}
{% raw %}{{expression}}{% endraw %} {# For literal double braces #}
```

### Always Using Legacy

**Problem:** Jinja2 never used, always falls back

**Solution:**
```python
# Check if Jinja2 is available
import logging
logging.basicConfig(level=logging.DEBUG)

reporter = ComplianceReporter()
# Check debug logs for "Jinja2 template loader initialized"
```

## Best Practices

1. **Keep templates simple** - Complex logic belongs in Python, not templates
2. **Test both paths** - Always verify Jinja2 AND legacy generation work
3. **Use inheritance** - Extend `base.html.jinja` for consistency
4. **Document variables** - Add comments listing required template variables
5. **Version control** - Commit templates alongside code
6. **Escape user input** - Templates auto-escape HTML, but verify sensitive content

## Examples

### Complete Compliance Report Example

```python
#!/usr/bin/env python3
from compliance.compliance_reporter import (
    ComplianceReporter,
    ComplianceFramework,
    ComplianceStatus
)
from compliance.templates import PCIDSSTemplate

# Initialize reporter
reporter = ComplianceReporter()

# Create report
report = reporter.create_report(
    framework=ComplianceFramework.PCI_DSS,
    organization="Acme Corp",
    scope="E-commerce Platform"
)

# Add controls
report.controls = PCIDSSTemplate.get_controls()

# Set sample statuses
for i, control in enumerate(report.controls[:5]):
    control.status = ComplianceStatus.COMPLIANT if i % 2 == 0 else ComplianceStatus.NON_COMPLIANT
    control.tested_at = datetime.now()

# Calculate statistics
report.calculate_statistics()

# Add executive summary
report.executive_summary = "Sample summary..."

# Generate reports
html = reporter.export_report(report.report_id, format='html', output_file='report.html')
md = reporter.export_report(report.report_id, format='markdown', output_file='report.md')

print(f"Generated HTML: {len(html)} bytes")
print(f"Generated Markdown: {len(md)} bytes")
```

### Loading Multiple AI Prompts

```python
from utils.template_loader import get_template_loader

loader = get_template_loader()

# Get available prompts
available = loader.get_available_prompt_modules()
print(f"Available categories: {list(available.keys())}")

# Load web vulnerability prompts
web_vuln_prompts = loader.load_prompt_modules([
    'sql_injection',
    'xss'
])

# Load API security prompts
api_prompts = loader.load_prompt_modules([
    'api_security',
    'authn_authz'
])

# Use in AI provider
for name, prompt_text in web_vuln_prompts.items():
    print(f"\n=== {name} ===")
    print(f"Prompt length: {len(prompt_text)} chars")
    # response = await ai_provider.chat(prompt_text)
```

## Migration Notes

### From Legacy to Jinja2

Existing code continues to work without changes! The system automatically uses Jinja2 when available.

**No breaking changes:**
- Old API remains unchanged
- Legacy fallback always available
- Same output format (HTML structure matched exactly)

**New capabilities:**
- Easy template customization
- Cleaner codebase
- Reusable prompt modules
- Better maintainability

## Support

- **Issues:** Report bugs in the main repository
- **Questions:** See main README.md or ask in discussions
- **Contributing:** Submit PRs with new templates or improvements

---

*Last updated: 2025-11-26*
*Zypheron AI Development Team*
