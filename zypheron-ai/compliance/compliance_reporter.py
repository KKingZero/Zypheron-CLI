"""
Compliance Reporting Engine
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import json

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"
    NIST = "nist"


class ComplianceStatus(Enum):
    """Compliance status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NEEDS_REVIEW = "needs_review"


@dataclass
class ComplianceControl:
    """Individual compliance control"""
    control_id: str
    name: str
    description: str
    framework: ComplianceFramework
    
    # Requirements
    requirement: str
    category: str
    severity: str  # critical, high, medium, low
    
    # Assessment
    status: ComplianceStatus = ComplianceStatus.NEEDS_REVIEW
    findings: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    
    # Remediation
    remediation_steps: List[str] = field(default_factory=list)
    remediation_priority: str = "medium"
    estimated_effort: str = ""
    
    # Metadata
    tested_at: Optional[datetime] = None
    tester: str = ""
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'control_id': self.control_id,
            'name': self.name,
            'description': self.description,
            'framework': self.framework.value,
            'requirement': self.requirement,
            'category': self.category,
            'severity': self.severity,
            'status': self.status.value,
            'findings': self.findings,
            'evidence': self.evidence,
            'gaps': self.gaps,
            'remediation_steps': self.remediation_steps,
            'remediation_priority': self.remediation_priority,
            'estimated_effort': self.estimated_effort,
            'tested_at': self.tested_at.isoformat() if self.tested_at else None,
            'tester': self.tester,
            'notes': self.notes
        }


@dataclass
class ComplianceReport:
    """Complete compliance assessment report"""
    report_id: str
    framework: ComplianceFramework
    organization: str
    scope: str
    
    # Assessment details
    assessment_date: datetime
    assessor: str
    controls: List[ComplianceControl] = field(default_factory=list)
    
    # Summary statistics
    total_controls: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    partial_count: int = 0
    not_applicable_count: int = 0
    
    # Overall assessment
    overall_status: ComplianceStatus = ComplianceStatus.NEEDS_REVIEW
    compliance_percentage: float = 0.0
    risk_level: str = "unknown"  # low, medium, high, critical
    
    # Findings
    critical_findings: List[str] = field(default_factory=list)
    high_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Executive summary
    executive_summary: str = ""
    
    def calculate_statistics(self):
        """Calculate compliance statistics"""
        self.total_controls = len(self.controls)
        
        if self.total_controls == 0:
            return
        
        self.compliant_count = sum(
            1 for c in self.controls
            if c.status == ComplianceStatus.COMPLIANT
        )
        self.non_compliant_count = sum(
            1 for c in self.controls
            if c.status == ComplianceStatus.NON_COMPLIANT
        )
        self.partial_count = sum(
            1 for c in self.controls
            if c.status == ComplianceStatus.PARTIAL
        )
        self.not_applicable_count = sum(
            1 for c in self.controls
            if c.status == ComplianceStatus.NOT_APPLICABLE
        )
        
        # Calculate compliance percentage (excluding N/A)
        applicable_controls = self.total_controls - self.not_applicable_count
        if applicable_controls > 0:
            compliant_controls = self.compliant_count + (self.partial_count * 0.5)
            self.compliance_percentage = (compliant_controls / applicable_controls) * 100
        
        # Determine overall status
        if self.compliance_percentage >= 95:
            self.overall_status = ComplianceStatus.COMPLIANT
        elif self.compliance_percentage >= 70:
            self.overall_status = ComplianceStatus.PARTIAL
        else:
            self.overall_status = ComplianceStatus.NON_COMPLIANT
        
        # Determine risk level
        if self.compliance_percentage >= 90:
            self.risk_level = "low"
        elif self.compliance_percentage >= 75:
            self.risk_level = "medium"
        elif self.compliance_percentage >= 50:
            self.risk_level = "high"
        else:
            self.risk_level = "critical"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'framework': self.framework.value,
            'organization': self.organization,
            'scope': self.scope,
            'assessment_date': self.assessment_date.isoformat(),
            'assessor': self.assessor,
            'controls': [c.to_dict() for c in self.controls],
            'total_controls': self.total_controls,
            'compliant_count': self.compliant_count,
            'non_compliant_count': self.non_compliant_count,
            'partial_count': self.partial_count,
            'not_applicable_count': self.not_applicable_count,
            'overall_status': self.overall_status.value,
            'compliance_percentage': round(self.compliance_percentage, 2),
            'risk_level': self.risk_level,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'recommendations': self.recommendations,
            'executive_summary': self.executive_summary
        }


class ComplianceReporter:
    """
    Generate compliance reports for various frameworks
    
    Features:
    - Multiple framework support
    - Automated control testing
    - Gap analysis
    - Remediation recommendations
    - Executive summaries
    - Export to multiple formats (JSON, HTML, PDF)
    """
    
    def __init__(self, ai_provider=None):
        self.ai_provider = ai_provider
        self.reports: Dict[str, ComplianceReport] = {}
    
    def create_report(
        self,
        framework: ComplianceFramework,
        organization: str,
        scope: str,
        assessor: str = "Zypheron AI"
    ) -> ComplianceReport:
        """Create a new compliance report"""
        report_id = f"compliance_{framework.value}_{int(datetime.now().timestamp())}"
        
        report = ComplianceReport(
            report_id=report_id,
            framework=framework,
            organization=organization,
            scope=scope,
            assessment_date=datetime.now(),
            assessor=assessor
        )
        
        self.reports[report_id] = report
        logger.info(f"Created compliance report: {report_id}")
        
        return report
    
    async def assess_scan_results(
        self,
        report: ComplianceReport,
        scan_results: Dict[str, Any]
    ) -> None:
        """
        Assess scan results against compliance controls
        
        Args:
            report: Compliance report to update
            scan_results: Security scan results
        """
        logger.info(f"Assessing scan results for {report.framework.value}")
        
        # Map scan findings to compliance controls
        for control in report.controls:
            await self._assess_control(control, scan_results)
        
        # Update statistics
        report.calculate_statistics()
        
        # Generate findings
        await self._generate_findings(report)
        
        # Generate executive summary
        if self.ai_provider:
            await self._generate_executive_summary(report)
    
    async def _assess_control(
        self,
        control: ComplianceControl,
        scan_results: Dict[str, Any]
    ) -> None:
        """Assess individual control against scan results"""
        control.tested_at = datetime.now()
        
        # Example assessment logic (customize per framework)
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Check for critical vulnerabilities
        critical_vulns = [
            v for v in vulnerabilities
            if v.get('severity') == 'critical'
        ]
        
        if control.category == 'vulnerability_management':
            if critical_vulns:
                control.status = ComplianceStatus.NON_COMPLIANT
                control.findings.append(
                    f"Found {len(critical_vulns)} critical vulnerabilities"
                )
                control.gaps.append("Critical vulnerabilities must be remediated")
            else:
                control.status = ComplianceStatus.COMPLIANT
                control.evidence.append("No critical vulnerabilities found")
        
        # Add more assessment logic for other categories
        # This would be customized based on the specific control
    
    async def _generate_findings(self, report: ComplianceReport) -> None:
        """Generate critical and high findings"""
        for control in report.controls:
            if control.status == ComplianceStatus.NON_COMPLIANT:
                finding = f"{control.control_id}: {control.name}"
                
                if control.severity == 'critical':
                    report.critical_findings.append(finding)
                elif control.severity == 'high':
                    report.high_findings.append(finding)
                
                # Add remediation recommendations
                if control.remediation_steps:
                    report.recommendations.extend(control.remediation_steps)
    
    async def _generate_executive_summary(self, report: ComplianceReport) -> None:
        """Generate AI-powered executive summary"""
        if not self.ai_provider:
            report.executive_summary = self._generate_basic_summary(report)
            return
        
        try:
            prompt = f"""
            Generate an executive summary for this compliance assessment:
            
            Framework: {report.framework.value.upper()}
            Organization: {report.organization}
            Compliance: {report.compliance_percentage:.1f}%
            Status: {report.overall_status.value}
            Risk Level: {report.risk_level}
            
            Controls Tested: {report.total_controls}
            - Compliant: {report.compliant_count}
            - Non-Compliant: {report.non_compliant_count}
            - Partial: {report.partial_count}
            
            Critical Findings: {len(report.critical_findings)}
            High Findings: {len(report.high_findings)}
            
            Provide a concise executive summary (3-4 paragraphs) covering:
            1. Overall compliance posture
            2. Key risks and concerns
            3. Priority recommendations
            4. Business impact
            """
            
            summary = await self.ai_provider.chat(prompt)
            report.executive_summary = summary
            
        except Exception as e:
            logger.error(f"Failed to generate AI summary: {e}")
            report.executive_summary = self._generate_basic_summary(report)
    
    def _generate_basic_summary(self, report: ComplianceReport) -> str:
        """Generate basic text summary"""
        return f"""
Compliance Assessment Summary

Framework: {report.framework.value.upper()}
Organization: {report.organization}
Assessment Date: {report.assessment_date.strftime('%Y-%m-%d')}
Assessor: {report.assessor}

Overall Compliance: {report.compliance_percentage:.1f}%
Status: {report.overall_status.value}
Risk Level: {report.risk_level.upper()}

Controls Assessed: {report.total_controls}
- Compliant: {report.compliant_count}
- Non-Compliant: {report.non_compliant_count}
- Partial: {report.partial_count}
- Not Applicable: {report.not_applicable_count}

Critical Findings: {len(report.critical_findings)}
High Priority Findings: {len(report.high_findings)}

{"This organization demonstrates strong compliance posture." if report.compliance_percentage >= 90 else "Significant compliance gaps identified requiring immediate attention."}
        """.strip()
    
    def export_report(
        self,
        report_id: str,
        format: str = 'json',
        output_file: Optional[str] = None
    ) -> Optional[str]:
        """
        Export report to file
        
        Args:
            report_id: Report ID
            format: Output format (json, html, markdown)
            output_file: Output file path
            
        Returns:
            Report content as string
        """
        report = self.reports.get(report_id)
        if not report:
            logger.error(f"Report not found: {report_id}")
            return None
        
        if format == 'json':
            content = json.dumps(report.to_dict(), indent=2)
        elif format == 'html':
            content = self._generate_html_report(report)
        elif format == 'markdown':
            content = self._generate_markdown_report(report)
        else:
            logger.error(f"Unsupported format: {format}")
            return None
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(content)
                logger.info(f"Exported report to {output_file}")
            except Exception as e:
                logger.error(f"Failed to export report: {e}")
                return None
        
        return content
    
    def _generate_html_report(self, report: ComplianceReport) -> str:
        """Generate HTML report"""
        # Calculate status colors
        status_color = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        }
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{report.framework.value.upper()} Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; }}
        .metric {{ display: inline-block; margin: 10px 20px; }}
        .metric-label {{ font-size: 12px; color: #7f8c8d; }}
        .metric-value {{ font-size: 24px; font-weight: bold; }}
        .status-{report.risk_level} {{ color: {status_color.get(report.risk_level, '#000')}; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
        .compliant {{ color: #28a745; }}
        .non-compliant {{ color: #dc3545; }}
        .partial {{ color: #ffc107; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report.framework.value.upper()} Compliance Report</h1>
        <p>{report.organization}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>{report.executive_summary}</p>
        
        <div class="metrics">
            <div class="metric">
                <div class="metric-label">Overall Compliance</div>
                <div class="metric-value status-{report.risk_level}">
                    {report.compliance_percentage:.1f}%
                </div>
            </div>
            <div class="metric">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value status-{report.risk_level}">
                    {report.risk_level.upper()}
                </div>
            </div>
            <div class="metric">
                <div class="metric-label">Controls Tested</div>
                <div class="metric-value">{report.total_controls}</div>
            </div>
        </div>
    </div>
    
    <h2>Control Assessment</h2>
    <table>
        <tr>
            <th>Control ID</th>
            <th>Name</th>
            <th>Category</th>
            <th>Severity</th>
            <th>Status</th>
        </tr>
"""
        
        for control in report.controls:
            status_class = control.status.value.replace('_', '-')
            html += f"""
        <tr>
            <td>{control.control_id}</td>
            <td>{control.name}</td>
            <td>{control.category}</td>
            <td>{control.severity}</td>
            <td class="{status_class}">{control.status.value.replace('_', ' ').title()}</td>
        </tr>
"""
        
        html += """
    </table>
    
    <h2>Key Findings</h2>
"""
        
        if report.critical_findings:
            html += "<h3>Critical</h3><ul>"
            for finding in report.critical_findings:
                html += f"<li>{finding}</li>"
            html += "</ul>"
        
        if report.high_findings:
            html += "<h3>High</h3><ul>"
            for finding in report.high_findings:
                html += f"<li>{finding}</li>"
            html += "</ul>"
        
        html += f"""
    <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #ddd;">
        <p><small>Generated by Zypheron AI on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_markdown_report(self, report: ComplianceReport) -> str:
        """Generate Markdown report"""
        md = f"""# {report.framework.value.upper()} Compliance Report

**Organization:** {report.organization}  
**Assessment Date:** {report.assessment_date.strftime('%Y-%m-%d')}  
**Assessor:** {report.assessor}

## Executive Summary

{report.executive_summary}

## Compliance Overview

| Metric | Value |
|--------|-------|
| Overall Compliance | {report.compliance_percentage:.1f}% |
| Risk Level | {report.risk_level.upper()} |
| Controls Tested | {report.total_controls} |
| Compliant | {report.compliant_count} |
| Non-Compliant | {report.non_compliant_count} |
| Partial | {report.partial_count} |

## Control Assessment

| Control ID | Name | Category | Severity | Status |
|------------|------|----------|----------|--------|
"""
        
        for control in report.controls:
            status = control.status.value.replace('_', ' ').title()
            md += f"| {control.control_id} | {control.name} | {control.category} | {control.severity} | {status} |\n"
        
        if report.critical_findings:
            md += "\n## Critical Findings\n\n"
            for finding in report.critical_findings:
                md += f"- {finding}\n"
        
        if report.high_findings:
            md += "\n## High Priority Findings\n\n"
            for finding in report.high_findings:
                md += f"- {finding}\n"
        
        if report.recommendations:
            md += "\n## Recommendations\n\n"
            for rec in report.recommendations[:10]:  # Top 10
                md += f"- {rec}\n"
        
        md += f"\n---\n*Generated by Zypheron AI on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
        
        return md
    
    def get_report(self, report_id: str) -> Optional[ComplianceReport]:
        """Get report by ID"""
        return self.reports.get(report_id)
    
    def list_reports(self) -> List[ComplianceReport]:
        """List all reports"""
        return list(self.reports.values())

