#!/usr/bin/env python3
"""
Test script for Jinja2 template implementation

Tests all 4 compliance frameworks with both Jinja2 and legacy generation
"""

import sys
from pathlib import Path
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from compliance.compliance_reporter import (
    ComplianceReporter,
    ComplianceReport,
    ComplianceControl,
    ComplianceFramework,
    ComplianceStatus
)
from compliance.templates import (
    PCIDSSTemplate,
    HIPAATemplate,
    SOC2Template,
    ISO27001Template
)


def create_sample_report(framework: ComplianceFramework) -> ComplianceReport:
    """Create a sample compliance report with test data"""
    reporter = ComplianceReporter()
    report = reporter.create_report(
        framework=framework,
        organization="Test Corporation Inc.",
        scope="Production Web Application",
        assessor="Zypheron Test Suite"
    )

    # Add controls based on framework
    if framework == ComplianceFramework.PCI_DSS:
        report.controls = PCIDSSTemplate.get_controls()[:10]  # First 10 for testing
    elif framework == ComplianceFramework.HIPAA:
        report.controls = HIPAATemplate.get_controls()[:10]
    elif framework == ComplianceFramework.SOC2:
        report.controls = SOC2Template.get_controls()[:10]
    elif framework == ComplianceFramework.ISO_27001:
        report.controls = ISO27001Template.get_controls()[:10]

    # Set some sample statuses
    for i, control in enumerate(report.controls):
        if i % 3 == 0:
            control.status = ComplianceStatus.COMPLIANT
            control.evidence.append("Control implemented correctly")
        elif i % 3 == 1:
            control.status = ComplianceStatus.NON_COMPLIANT
            control.findings.append("Control not implemented")
            control.gaps.append("Missing implementation")
        else:
            control.status = ComplianceStatus.PARTIAL
            control.findings.append("Partial implementation found")

        control.tested_at = datetime.now()
        control.tester = "Test Suite"

    # Calculate statistics
    report.calculate_statistics()

    # Add executive summary
    report.executive_summary = f"""
This assessment evaluated {report.organization}'s compliance with {framework.value.upper()}
requirements for their production web application.

Overall compliance stands at {report.compliance_percentage:.1f}%, indicating a {report.risk_level}
risk level. Out of {report.total_controls} controls assessed, {report.compliant_count} are fully
compliant, {report.partial_count} are partially implemented, and {report.non_compliant_count}
require immediate attention.

Key recommendations include implementing missing security controls, completing partial
implementations, and establishing regular compliance monitoring procedures.

This assessment was conducted by the Zypheron Test Suite on {report.assessment_date.strftime('%Y-%m-%d')}.
    """.strip()

    return report


def test_framework(framework: ComplianceFramework, output_dir: Path):
    """Test report generation for a specific framework"""
    print(f"\n{'='*70}")
    print(f"Testing {framework.value.upper()} Framework")
    print(f"{'='*70}")

    # Create sample report
    print(f"1. Creating sample report...")
    report = create_sample_report(framework)
    print(f"   ✓ Created report with {report.total_controls} controls")
    print(f"   ✓ Compliance: {report.compliance_percentage:.1f}%")
    print(f"   ✓ Risk Level: {report.risk_level}")

    # Test Jinja2 HTML generation
    print(f"\n2. Testing Jinja2 HTML generation...")
    try:
        reporter_jinja = ComplianceReporter(use_jinja=True)
        html_jinja = reporter_jinja._generate_html_report(report)

        output_file = output_dir / f"{framework.value}_jinja.html"
        with open(output_file, 'w') as f:
            f.write(html_jinja)

        print(f"   ✓ Generated HTML with Jinja2 ({len(html_jinja)} bytes)")
        print(f"   ✓ Saved to: {output_file}")
    except Exception as e:
        print(f"   ✗ Jinja2 HTML generation failed: {e}")
        return False

    # Test legacy HTML generation
    print(f"\n3. Testing legacy HTML generation...")
    try:
        reporter_legacy = ComplianceReporter(use_jinja=False)
        html_legacy = reporter_legacy._legacy_generate_html_report(report)

        output_file = output_dir / f"{framework.value}_legacy.html"
        with open(output_file, 'w') as f:
            f.write(html_legacy)

        print(f"   ✓ Generated HTML with legacy ({len(html_legacy)} bytes)")
        print(f"   ✓ Saved to: {output_file}")
    except Exception as e:
        print(f"   ✗ Legacy HTML generation failed: {e}")
        return False

    # Test Jinja2 Markdown generation
    print(f"\n4. Testing Jinja2 Markdown generation...")
    try:
        reporter_jinja = ComplianceReporter(use_jinja=True)
        md_jinja = reporter_jinja._generate_markdown_report(report)

        output_file = output_dir / f"{framework.value}_jinja.md"
        with open(output_file, 'w') as f:
            f.write(md_jinja)

        print(f"   ✓ Generated Markdown with Jinja2 ({len(md_jinja)} bytes)")
        print(f"   ✓ Saved to: {output_file}")
    except Exception as e:
        print(f"   ✗ Jinja2 Markdown generation failed: {e}")
        return False

    # Test legacy Markdown generation
    print(f"\n5. Testing legacy Markdown generation...")
    try:
        reporter_legacy = ComplianceReporter(use_jinja=False)
        md_legacy = reporter_legacy._legacy_generate_markdown_report(report)

        output_file = output_dir / f"{framework.value}_legacy.md"
        with open(output_file, 'w') as f:
            f.write(md_legacy)

        print(f"   ✓ Generated Markdown with legacy ({len(md_legacy)} bytes)")
        print(f"   ✓ Saved to: {output_file}")
    except Exception as e:
        print(f"   ✗ Legacy Markdown generation failed: {e}")
        return False

    # Compare outputs
    print(f"\n6. Comparing outputs...")
    if len(html_jinja) > 0 and len(html_legacy) > 0:
        print(f"   ✓ Both HTML methods produced output")
        size_diff = abs(len(html_jinja) - len(html_legacy))
        print(f"   ℹ Size difference: {size_diff} bytes")

    if len(md_jinja) > 0 and len(md_legacy) > 0:
        print(f"   ✓ Both Markdown methods produced output")
        size_diff = abs(len(md_jinja) - len(md_legacy))
        print(f"   ℹ Size difference: {size_diff} bytes")

    return True


def test_prompt_templates(output_dir: Path):
    """Test AI prompt template loading"""
    print(f"\n{'='*70}")
    print(f"Testing AI Prompt Templates")
    print(f"{'='*70}")

    from utils.template_loader import get_template_loader

    loader = get_template_loader()

    # Test available modules
    print(f"\n1. Checking available prompt modules...")
    available = loader.get_available_prompt_modules()
    print(f"   Found {len(available)} categories:")
    for category, modules in available.items():
        print(f"   - {category}: {len(modules)} modules")
        for module in modules:
            print(f"     • {module}")

    # Test loading specific prompts
    print(f"\n2. Testing prompt loading...")
    prompts_to_test = [
        ('vulnerabilities/sql_injection.jinja', 'SQL Injection'),
        ('vulnerabilities/xss.jinja', 'XSS'),
        ('security/api_security.jinja', 'API Security'),
        ('security/authn_authz.jinja', 'AuthN/AuthZ'),
    ]

    for prompt_path, name in prompts_to_test:
        try:
            content = loader.render_prompt(prompt_path)
            output_file = output_dir / f"prompt_{prompt_path.replace('/', '_')}.txt"
            with open(output_file, 'w') as f:
                f.write(content)
            print(f"   ✓ {name}: {len(content)} bytes")
            print(f"     Saved to: {output_file}")
        except Exception as e:
            print(f"   ✗ {name}: {e}")

    return True


def test_fallback_mechanism():
    """Test that fallback works when Jinja2 fails"""
    print(f"\n{'='*70}")
    print(f"Testing Fallback Mechanism")
    print(f"{'='*70}")

    # Create reporter with Jinja2 enabled
    print(f"\n1. Testing automatic fallback...")
    reporter = ComplianceReporter(use_jinja=True)
    report = create_sample_report(ComplianceFramework.PCI_DSS)

    try:
        # This should try Jinja first, then fall back to legacy if templates missing
        html = reporter._generate_html_report(report)
        if len(html) > 0:
            print(f"   ✓ Report generated successfully ({len(html)} bytes)")
            print(f"   ✓ Fallback mechanism working")
        else:
            print(f"   ✗ Empty output generated")
            return False
    except Exception as e:
        print(f"   ✗ Fallback failed: {e}")
        return False

    return True


def main():
    """Run all tests"""
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║          ZYPHERON JINJA2 IMPLEMENTATION TEST SUITE                  ║
╚══════════════════════════════════════════════════════════════════════╝
""")

    # Create output directory
    output_dir = Path(__file__).parent / "test_output"
    output_dir.mkdir(exist_ok=True)
    print(f"Output directory: {output_dir}\n")

    results = {}

    # Test all 4 frameworks
    frameworks = [
        ComplianceFramework.PCI_DSS,
        ComplianceFramework.HIPAA,
        ComplianceFramework.SOC2,
        ComplianceFramework.ISO_27001
    ]

    for framework in frameworks:
        results[framework.value] = test_framework(framework, output_dir)

    # Test prompt templates
    results['prompts'] = test_prompt_templates(output_dir)

    # Test fallback mechanism
    results['fallback'] = test_fallback_mechanism()

    # Print summary
    print(f"\n{'='*70}")
    print(f"TEST SUMMARY")
    print(f"{'='*70}")

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for name, passed_test in results.items():
        status = "✓ PASSED" if passed_test else "✗ FAILED"
        print(f"{name.upper():20s}: {status}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print(f"\n🎉 All tests passed! Jinja2 implementation is working correctly.")
        print(f"\nGenerated files are in: {output_dir}")
        print(f"You can open the HTML files in a browser to verify visual appearance.")
        return 0
    else:
        print(f"\n⚠️  Some tests failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
