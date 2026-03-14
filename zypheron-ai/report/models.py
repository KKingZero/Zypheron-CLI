"""
Data models for professional pentest reports.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_CVSS_RANGES = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.1, 3.9),
    Severity.INFO: (0.0, 0.0),
}


@dataclass
class Vulnerability:
    """A single vulnerability finding with CVSS scoring."""
    vuln_id: str
    title: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    affected_target: str = ""
    affected_component: str = ""
    description: str = ""
    evidence: str = ""
    tool_output: str = ""
    tool_name: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    status: str = "confirmed"


@dataclass
class Finding:
    """A general finding (not necessarily a vulnerability)."""
    finding_id: str
    title: str
    category: str  # ports, services, creds, web, cloud, ad, etc.
    detail: str = ""
    evidence: str = ""
    tool_name: str = ""
    target: str = ""


@dataclass
class HostInfo:
    """Information about a discovered host."""
    ip: str
    hostname: str = ""
    os_guess: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)


@dataclass
class SeveritySummary:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


@dataclass
class PentestReport:
    """Complete professional penetration test report."""
    # Metadata
    report_id: str = ""
    title: str = "Penetration Test Report"
    client_name: str = ""
    assessor: str = "Zypheron AI"
    target: str = ""
    scope: str = ""
    start_date: str = ""
    end_date: str = ""
    report_date: str = ""
    classification: str = "Confidential"
    session_id: str = ""

    # Executive Summary (AI-generated)
    executive_summary: str = ""
    methodology: str = ""
    overall_risk_rating: str = ""

    # Findings
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    hosts: List[HostInfo] = field(default_factory=list)

    # Summary stats
    severity_summary: SeveritySummary = field(default_factory=SeveritySummary)

    # Tool chain
    tools_used: List[str] = field(default_factory=list)
    ai_provider: str = ""
    ai_model: str = ""

    # MITRE ATT&CK coverage
    mitre_techniques_observed: List[str] = field(default_factory=list)

    def compute_severity_summary(self) -> None:
        """Recompute severity counts from vulnerabilities list."""
        self.severity_summary = SeveritySummary()
        for v in self.vulnerabilities:
            match v.severity:
                case Severity.CRITICAL:
                    self.severity_summary.critical += 1
                case Severity.HIGH:
                    self.severity_summary.high += 1
                case Severity.MEDIUM:
                    self.severity_summary.medium += 1
                case Severity.LOW:
                    self.severity_summary.low += 1
                case Severity.INFO:
                    self.severity_summary.info += 1
