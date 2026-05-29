"""
Zypheron Bug Bounty Engine

Orchestrates bounty-mode scanning:
  1. Parse and validate scope
  2. Run recon + AutoPent on in-scope targets
  3. Score findings by bounty impact
  4. Generate platform-specific submission drafts (H1/Bugcrowd)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader
from loguru import logger

from contracts.runtime import PolicyMode
from core.query_engine import QueryRequest, query_engine
from providers.base import AIMessage
from core.loot import LootManager
from report.models import Vulnerability, Severity


TEMPLATE_DIR = Path(__file__).parent.parent / "report" / "templates"


@dataclass
class ScopeEntry:
    target: str
    in_scope: bool = True
    notes: str = ""


@dataclass
class BountySubmission:
    """A draft submission ready for H1/Bugcrowd."""
    platform: str
    program: str
    vulnerability: Vulnerability
    submission_text: str = ""
    estimated_severity: str = ""
    estimated_bounty_range: str = ""


# Rough bounty ranges by severity (H1 averages)
BOUNTY_ESTIMATES = {
    "critical": "$5,000 - $50,000+",
    "high": "$2,000 - $10,000",
    "medium": "$500 - $3,000",
    "low": "$100 - $500",
    "info": "N/A (informational)",
}


class BountyEngine:
    """Orchestrate bounty-mode operations."""

    def __init__(
        self,
        session_id: str,
        targets: List[str],
        out_of_scope: Optional[List[str]] = None,
        platform: str = "hackerone",
        program: str = "",
        ai_provider=None,
    ):
        self.session_id = session_id
        self.targets = targets
        self.out_of_scope = out_of_scope or []
        self.platform = platform.lower()
        self.program = program
        self.ai_provider = ai_provider
        self.loot = LootManager(session_id)
        self.findings: List[Vulnerability] = []
        self.submissions: List[BountySubmission] = []

        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    # TODO: Add API-based scope fetching
    # async def fetch_scope_from_api(self, api_token: str) -> List[ScopeEntry]:
    #     """Fetch program scope from HackerOne/Bugcrowd API."""
    #     if self.platform == "hackerone":
    #         # GET https://api.hackerone.com/v1/hackers/programs/{program}/structured_scopes
    #         pass
    #     elif self.platform == "bugcrowd":
    #         # GET https://api.bugcrowd.com/programs/{program}/target_groups
    #         pass
    #     return []

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within the defined scope."""
        target = target.lower().strip()
        # Check exclusions first
        for excl in self.out_of_scope:
            excl = excl.lower().strip()
            if excl.startswith("*."):
                if target.endswith(excl[1:]) or target == excl[2:]:
                    return False
            elif target == excl:
                return False

        # Check inclusions
        for scope in self.targets:
            scope = scope.lower().strip()
            if scope.startswith("*."):
                if target.endswith(scope[1:]) or target == scope[2:]:
                    return True
            elif target == scope:
                return True
            # CIDR check would go here for IP ranges

        return False

    async def analyze_target(self, target: str) -> Dict[str, Any]:
        """Run the canonical runtime assessment against a single target."""
        prompt = (
            f"Run bug bounty web assessment for {target}. "
            "Use httpx, ffuf, nuclei, nikto, and sqlmap where applicable. "
            "Only return evidence from real tool execution."
        )
        response = await query_engine.execute(
            QueryRequest(
                messages=[AIMessage(role="user", content=prompt)],
                provider="zypheron-query-engine",
                model="runtime-bounty",
                session_id=self.session_id,
                policy_mode=PolicyMode.AUTONOMOUS_LAB,
            )
        )
        return response.to_result()

    def _severity_from_text(self, value: str) -> Severity:
        normalized = str(value or "").strip().lower()
        try:
            return Severity(normalized)
        except ValueError:
            return Severity.MEDIUM

    def _materialize_findings(self, target: str, runtime_result: Dict[str, Any]) -> List[Vulnerability]:
        """Convert runtime evidence into submission-eligible findings."""
        vulnerabilities: List[Vulnerability] = []
        tool_results = runtime_result.get("tool_results", [])

        for tool_result in tool_results:
            evidence = (tool_result.get("data") or {}).get("evidence", {})
            findings = evidence.get("findings", [])
            for finding in findings:
                severity = self._severity_from_text(finding.get("severity", "medium"))
                title = finding.get("title") or f"{tool_result.get('tool_name', 'runtime')} finding"
                vuln = Vulnerability(
                    vuln_id=f"{tool_result.get('tool_name', 'finding')}_{len(self.findings) + len(vulnerabilities)}",
                    title=title[:180],
                    severity=severity,
                    affected_target=target,
                    affected_component=evidence.get("target", target),
                    description=finding.get("description") or title,
                    evidence=finding.get("evidence") or evidence.get("summary", ""),
                    tool_output=tool_result.get("content", ""),
                    tool_name=tool_result.get("tool_name", "runtime"),
                    remediation=finding.get("remediation", ""),
                    cwe_ids=[finding.get("cwe_id")] if finding.get("cwe_id") else [],
                    references=[finding.get("url")] if finding.get("url") else [],
                )
                vulnerabilities.append(vuln)
        return vulnerabilities

    def generate_submission(self, vuln: Vulnerability) -> BountySubmission:
        """Generate a platform-specific submission draft."""
        template = self.env.get_template("bug_bounty_submission.md.j2")
        text = template.render(vuln=vuln)

        severity_str = vuln.severity.value if isinstance(vuln.severity, Severity) else str(vuln.severity)
        bounty_range = BOUNTY_ESTIMATES.get(severity_str, "Unknown")

        submission = BountySubmission(
            platform=self.platform,
            program=self.program,
            vulnerability=vuln,
            submission_text=text,
            estimated_severity=severity_str,
            estimated_bounty_range=bounty_range,
        )
        self.submissions.append(submission)
        return submission

    def save_submissions(self) -> List[Path]:
        """Save all submission drafts to the loot directory."""
        paths = []
        for i, sub in enumerate(self.submissions):
            filename = f"submission_{i+1}_{sub.vulnerability.vuln_id}.md"
            path = self.loot.save_loot("reports", filename, sub.submission_text)
            paths.append(path)
            logger.info(f"Submission draft saved: {path}")
        return paths

    async def run(self) -> Dict[str, Any]:
        """Execute the full bounty workflow."""
        logger.info(f"Starting bounty mode: {len(self.targets)} targets, platform={self.platform}")

        self.loot.log_timeline("bounty", "bounty_start",
                                tool="zypheron",
                                detail=f"{len(self.targets)} targets")

        results = {
            "session_id": self.session_id,
            "platform": self.platform,
            "program": self.program,
            "targets_analyzed": [],
            "submissions": [],
        }

        for target in self.targets:
            if not self.is_in_scope(target):
                logger.warning(f"Skipping out-of-scope target: {target}")
                continue

            self.loot.log_timeline("bounty", "target_start",
                                    tool="analyze", detail=target)

            runtime_result = await self.analyze_target(target)
            target_findings = self._materialize_findings(target, runtime_result)
            self.findings.extend(target_findings)

            results["targets_analyzed"].append({
                "target": target,
                "runtime_result": runtime_result,
                "validated_findings": [
                    {
                        "vuln_id": vuln.vuln_id,
                        "title": vuln.title,
                        "severity": vuln.severity.value if isinstance(vuln.severity, Severity) else str(vuln.severity),
                        "tool_name": vuln.tool_name,
                    }
                    for vuln in target_findings
                ],
            })

        # Generate submissions for any findings
        for vuln in self.findings:
            sub = self.generate_submission(vuln)
            results["submissions"].append({
                "vuln_id": vuln.vuln_id,
                "title": vuln.title,
                "severity": vuln.severity.value if isinstance(vuln.severity, Severity) else str(vuln.severity),
                "estimated_bounty": sub.estimated_bounty_range,
            })

        self.save_submissions()

        self.loot.log_timeline("bounty", "bounty_complete",
                                tool="zypheron",
                                detail=f"{len(results['submissions'])} submissions generated")

        return results
