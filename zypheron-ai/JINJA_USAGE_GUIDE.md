# Jinja2 Templates Usage Guide

Zypheron uses Jinja2 for compliance reports (HTML, Markdown) and AI prompt templates, with automatic fallback to legacy generation.

## Compliance Reports

```python
from compliance.compliance_reporter import ComplianceReporter, ComplianceFramework

reporter = ComplianceReporter()  # Jinja2 enabled by default

report = reporter.create_report(
    framework=ComplianceFramework.PCI_DSS,
    organization="Your Company",
    scope="Production Environment"
)
report.controls = [...]
report.calculate_statistics()

html = reporter.export_report(report.report_id, format='html')
markdown = reporter.export_report(report.report_id, format='markdown')
```

Force legacy mode: `ComplianceReporter(use_jinja=False)`

## AI Prompt Templates

```python
from utils.template_loader import get_template_loader

loader = get_template_loader()

# Single prompt
prompt = loader.render_prompt('vulnerabilities/sql_injection.jinja')

# With context
prompt = loader.render_prompt('compliance/executive_summary.jinja', {'report': my_report})

# Multiple prompts
prompts = loader.load_prompt_modules(['sql_injection', 'xss', 'api_security'])
```

## Available Templates

**Compliance** (`templates/compliance/`): `base.html.jinja`, `pci_dss.html.jinja`, `hipaa.html.jinja`, `soc2.html.jinja`, `iso27001.html.jinja`, `report.md.jinja`

**AI Prompts** (`prompts/`):
- `vulnerabilities/sql_injection.jinja`, `vulnerabilities/xss.jinja`
- `security/api_security.jinja`, `security/authn_authz.jinja`
- `compliance/executive_summary.jinja`

## Custom Filters

```jinja
{{ report.risk_level | severity_color }}   {# Hex color code #}
{{ report.assessment_date | timestamp }}    {# Formatted datetime #}
{{ control.status.value | status_class }}   {# CSS class #}
```

## Adding Templates

**Compliance**: Create `templates/compliance/my_framework.html.jinja` extending `base.html.jinja`.

**AI Prompts**: Create `prompts/<category>/<name>.jinja`, then load with `loader.render_prompt('<category>/<name>.jinja')`.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Template not found | Check `ls -R templates/ prompts/` |
| Syntax error with `$` or `{{` | Wrap in `{% raw %}...{% endraw %}` |
| Always using legacy | Check `import logging; logging.basicConfig(level=logging.DEBUG)` for init messages |

## Testing

```bash
cd zypheron-ai
python3 test_jinja_implementation.py
```

Tests all 4 frameworks, HTML/Markdown generation, prompt loading, and fallback. Output saved to `test_output/`.
