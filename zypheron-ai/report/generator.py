"""
Zypheron Professional Report Generator

Reads loot directory data, applies CVSS scoring, generates AI narrative,
and renders Jinja2 templates to Markdown (and optionally PDF).

Usage from CLI (Go → Python bridge):
    zypheron report --session <id> --format pdf|md --output report.pdf
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger

from .cvss_lookup import CVSSLookup
from .models import (
    Finding,
    HostInfo,
    PentestReport,
    Severity,
    Vulnerability,
)
from core.loot import LootManager, base_loot_dir


TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generate professional pentest reports from session loot."""

    def __init__(self, session_id: str, ai_provider=None):
        self.session_id = session_id
        self.loot = LootManager(session_id)
        self.ai_provider = ai_provider
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(default=False),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.report = PentestReport(session_id=session_id)

    def load_session(self) -> None:
        """Load session metadata and loot data."""
        meta = LootManager.load_session_meta(self.session_id)
        if meta:
            self.report.target = meta.get("target", "")
            self.report.start_date = meta.get("started_at", "")
            self.report.end_date = meta.get("finished_at", "")
            self.report.ai_provider = meta.get("provider", "")
            self.report.ai_model = meta.get("model", "")
        self.report.report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Load vulnerabilities from loot/vulns/
        self._load_vulns()
        # Load findings from loot/findings/
        self._load_findings()
        # Load hosts from loot/hosts/
        self._load_hosts()
        # Compute summary
        self.report.compute_severity_summary()

    def _load_vulns(self) -> None:
        """Load vulnerability JSON files from the vulns/ loot directory."""
        vulns_dir = self.loot.get_path("vulns")
        if not vulns_dir.exists():
            return
        for f in sorted(vulns_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                vuln = self._parse_vuln(data)
                if vuln:
                    self.report.vulnerabilities.append(vuln)
            except Exception as e:
                logger.warning(f"Failed to load vuln file {f}: {e}")

    def _load_findings(self) -> None:
        """Load finding JSON files from the findings/ loot directory."""
        findings_dir = self.loot.get_path("findings")
        if not findings_dir.exists():
            return
        for f in sorted(findings_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                finding = Finding(
                    finding_id=data.get("finding_id", f.stem),
                    title=data.get("title", f.stem),
                    category=data.get("category", "general"),
                    detail=data.get("detail", ""),
                    evidence=data.get("evidence", ""),
                    tool_name=data.get("tool_name", ""),
                    target=data.get("target", ""),
                )
                self.report.findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to load finding {f}: {e}")

    def _load_hosts(self) -> None:
        """Load host data from the hosts/ loot directory."""
        hosts_dir = self.loot.get_path("hosts")
        if not hosts_dir.exists():
            return
        for f in sorted(hosts_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                host = HostInfo(
                    ip=data.get("ip", ""),
                    hostname=data.get("hostname", ""),
                    os_guess=data.get("os_guess", ""),
                    open_ports=data.get("open_ports", []),
                    services=data.get("services", []),
                )
                self.report.hosts.append(host)
            except Exception as e:
                logger.warning(f"Failed to load host {f}: {e}")

    def _parse_vuln(self, data: Dict) -> Optional[Vulnerability]:
        """Parse a vulnerability dict, applying CVSS lookup."""
        severity_str = data.get("severity", "info").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        # CVSS scoring: use provided score, then lookup, then tool severity
        cvss_score = data.get("cvss_score", 0.0)
        cvss_vector = data.get("cvss_vector", "")

        if not cvss_score:
            vuln_type = data.get("vuln_type", data.get("title", ""))
            lookup_result = CVSSLookup.lookup(vuln_type)
            if lookup_result:
                cvss_score, cvss_vector = lookup_result
            else:
                cvss_score = CVSSLookup.from_tool_severity(
                    data.get("tool_name", ""), severity_str
                )

        return Vulnerability(
            vuln_id=data.get("vuln_id", data.get("id", "")),
            title=data.get("title", "Unknown Vulnerability"),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cve_ids=data.get("cve_ids", []),
            cwe_ids=data.get("cwe_ids", []),
            affected_target=data.get("affected_target", data.get("target", "")),
            affected_component=data.get("affected_component", ""),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            tool_output=data.get("tool_output", ""),
            tool_name=data.get("tool_name", ""),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            mitre_techniques=data.get("mitre_techniques", []),
            status=data.get("status", "confirmed"),
        )

    async def generate_ai_narrative(self) -> None:
        """Use AI to generate executive summary and remediation text."""
        if not self.ai_provider:
            logger.info("No AI provider — skipping narrative generation")
            return

        from providers.base import AIMessage

        vuln_summary = "\n".join(
            f"- {v.title} ({v.severity.value}, CVSS {v.cvss_score})"
            for v in self.report.vulnerabilities[:20]
        )

        prompt = (
            f"You are writing the executive summary for a professional penetration test report.\n"
            f"Target: {self.report.target}\n"
            f"Findings:\n{vuln_summary}\n\n"
            f"Write a concise executive summary (3-5 paragraphs) covering:\n"
            f"1. Scope and approach\n"
            f"2. Key risk areas\n"
            f"3. Critical findings requiring immediate attention\n"
            f"4. Overall risk rating (Critical/High/Medium/Low)\n"
            f"5. Top recommendations\n\n"
            f"Be direct and professional. No marketing language."
        )

        try:
            response = await self.ai_provider.chat(
                messages=[AIMessage(role="user", content=prompt)],
                temperature=0.3,
                max_tokens=2000,
            )
            self.report.executive_summary = response.content
            # Extract risk rating from the response
            for rating in ["Critical", "High", "Medium", "Low"]:
                if rating.lower() in response.content.lower():
                    self.report.overall_risk_rating = rating
                    break
        except Exception as e:
            logger.error(f"AI narrative generation failed: {e}")

    def render_markdown(self, template_name: str = "pentest_report.md.j2") -> str:
        """Render the report to Markdown using Jinja2."""
        template = self.env.get_template(template_name)
        return template.render(report=self.report)

    def render_bug_bounty(self, vuln_index: int = 0) -> str:
        """Render a single vulnerability as a bug bounty submission."""
        if vuln_index >= len(self.report.vulnerabilities):
            return "No vulnerability at that index."
        template = self.env.get_template("bug_bounty_submission.md.j2")
        return template.render(vuln=self.report.vulnerabilities[vuln_index])

    def render_executive_summary(self) -> str:
        """Render just the executive summary."""
        template = self.env.get_template("executive_summary.md.j2")
        return template.render(report=self.report)

    def save(
        self,
        output_path: Optional[str] = None,
        fmt: str = "md",
        template_name: str = "pentest_report.md.j2",
    ) -> Path:
        """
        Save the report to disk.

        Args:
            output_path: Output file path. If None, saves to loot/reports/
            fmt: "md" or "json"
            template_name: Jinja2 template to use
        """
        if fmt == "json":
            content = json.dumps(asdict(self.report), indent=2, default=str)
            ext = ".json"
        else:
            content = self.render_markdown(template_name)
            ext = ".md"

        if not output_path:
            output_path = str(
                self.loot.get_path(
                    "reports",
                    f"report_{self.session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}",
                )
            )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content)
        logger.info(f"Report saved: {out}")
        return out
