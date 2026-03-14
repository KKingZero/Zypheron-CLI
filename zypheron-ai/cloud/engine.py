"""
Zypheron Cloud Security Engine

AI-orchestrated cloud security scanning across AWS, Azure, GCP, K8s.
Wraps: Prowler, Pacu, ScoutSuite, CloudBrute, AADInternals, Trivy, kube-hunter, Checkov.

Architecture:
  Go CLI (cloud.go) -> socket bridge -> this engine -> tool execution -> loot
"""

import asyncio
import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from loguru import logger

from ad.engine import redact_command
from core.loot import LootManager


@dataclass
class CloudToolDef:
    name: str
    command: str
    provider: str  # aws, azure, gcp, k8s, all
    phase: str  # recon, audit, exploit, posture
    purpose: str
    run_template: str  # Command template with {target}, {profile} placeholders


# Tool definitions per provider
CLOUD_TOOLS: List[CloudToolDef] = [
    # AWS
    CloudToolDef("prowler", "prowler", "aws", "posture",
                 "Security posture & compliance (500+ checks)",
                 "prowler aws --profile {profile} --output-formats json --output-directory {output}"),
    CloudToolDef("pacu", "pacu", "aws", "exploit",
                 "AWS exploitation framework (36 attack modules)",
                 "pacu --module-args '--regions us-east-1'"),
    CloudToolDef("scoutsuite", "scout", "aws", "audit",
                 "Multi-cloud passive security audit",
                 "scout aws --profile {profile} --report-dir {output}"),
    CloudToolDef("cloudbrute", "cloudbrute", "aws", "recon",
                 "Cloud asset discovery & brute-force",
                 "cloudbrute -d {target} -k {target} -w /usr/share/wordlists/cloud.txt"),

    # Azure
    CloudToolDef("scoutsuite", "scout", "azure", "audit",
                 "Multi-cloud passive security audit",
                 "scout azure --report-dir {output}"),
    CloudToolDef("roadtools", "roadrecon", "azure", "recon",
                 "Azure AD enumeration & graph analysis",
                 "roadrecon gather --access-token {token}"),
    CloudToolDef("cloudbrute", "cloudbrute", "azure", "recon",
                 "Cloud asset discovery",
                 "cloudbrute -d {target} -k {target}"),

    # GCP
    CloudToolDef("scoutsuite", "scout", "gcp", "audit",
                 "Multi-cloud passive security audit",
                 "scout gcp --report-dir {output}"),

    # K8s
    CloudToolDef("trivy", "trivy", "k8s", "posture",
                 "Container & image vulnerability scanning",
                 "trivy k8s --report summary --output {output}/trivy_k8s.json --format json"),
    CloudToolDef("kube-hunter", "kube-hunter", "k8s", "exploit",
                 "K8s cluster penetration testing",
                 "kube-hunter --remote {target} --report json > {output}/kube_hunter.json"),
    CloudToolDef("checkov", "checkov", "k8s", "posture",
                 "IaC misconfiguration scanner",
                 "checkov -d . --output json > {output}/checkov.json"),
]


class CloudEngine:
    """Orchestrate cloud security assessments with AI guidance."""

    def __init__(
        self,
        session_id: str,
        provider: str,
        target: str,
        mode: str = "audit",
        profile: str = "",
        available_tools: Optional[List[str]] = None,
        ai_provider=None,
    ):
        self.session_id = session_id
        self.provider = provider.lower()
        self.target = target
        self.mode = mode
        self.profile = profile or "default"
        self.available_tools = available_tools or []
        self.ai_provider = ai_provider
        self.loot = LootManager(session_id)

    def get_tools_for_provider(self) -> List[CloudToolDef]:
        """Get tools applicable to the selected cloud provider."""
        return [
            t for t in CLOUD_TOOLS
            if t.provider == self.provider or t.provider == "all"
        ]

    def get_available_tools(self) -> List[CloudToolDef]:
        """Get tools that are both applicable and installed."""
        tools = self.get_tools_for_provider()
        if self.available_tools:
            return [t for t in tools if t.name in self.available_tools]
        return [t for t in tools if shutil.which(t.command)]

    async def plan_scan(self) -> List[Dict[str, Any]]:
        """Use AI to plan the cloud scan chain."""
        tools = self.get_available_tools()
        if not tools:
            return []

        if self.ai_provider:
            from providers.base import AIMessage
            tool_list = "\n".join(f"- {t.name}: {t.purpose} (phase: {t.phase})" for t in tools)
            prompt = (
                f"Plan a cloud security assessment for {self.provider.upper()} target: {self.target}\n"
                f"Mode: {self.mode}\n"
                f"Available tools:\n{tool_list}\n\n"
                f"Return a JSON array of steps: "
                f'[{{"tool": "name", "phase": "...", "args": "...", "reason": "..."}}]\n'
                f"Order tools optimally: recon -> audit -> exploit (if mode allows)."
            )
            try:
                response = await self.ai_provider.chat(
                    messages=[AIMessage(role="user", content=prompt)],
                    temperature=0.2,
                    max_tokens=1500,
                )
                plan = json.loads(response.content)
                self.loot.save_loot_json("cloud", "scan_plan.json", plan)
                return plan
            except Exception as e:
                logger.warning(f"AI planning failed, using default order: {e}")

        # Default: run tools in phase order
        phase_order = {"recon": 0, "posture": 1, "audit": 2, "exploit": 3}
        tools.sort(key=lambda t: phase_order.get(t.phase, 99))

        plan = []
        for t in tools:
            if self.mode == "audit" and t.phase == "exploit":
                continue
            plan.append({
                "tool": t.name,
                "phase": t.phase,
                "args": "",
                "reason": t.purpose,
            })
        return plan

    async def run_tool(self, tool_def: CloudToolDef, extra_args: str = "") -> Dict[str, Any]:
        """Execute a single cloud tool and capture output."""
        output_dir = str(self.loot.get_path("cloud"))
        cmd = tool_def.run_template.format(
            target=self.target,
            profile=self.profile,
            output=output_dir,
            token="<token>",
        )
        if extra_args:
            cmd += f" {extra_args}"

        self.loot.log_timeline("cloud", "tool_start",
                                tool=tool_def.name,
                                detail=f"{tool_def.provider}: {redact_command(cmd)}")

        logger.info(f"Running: {redact_command(cmd)}")
        try:
            result = subprocess.run(
                shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=600,
            )
            output = result.stdout + result.stderr
            self.loot.save_loot("raw", f"{tool_def.name}_output.txt", output)

            status = "ok" if result.returncode == 0 else "error"
            self.loot.log_timeline("cloud", "tool_complete",
                                    tool=tool_def.name,
                                    detail=f"exit={result.returncode}", status=status)

            return {
                "tool": tool_def.name,
                "exit_code": result.returncode,
                "output_length": len(output),
                "status": status,
            }
        except subprocess.TimeoutExpired:
            self.loot.log_timeline("cloud", "tool_timeout", tool=tool_def.name, status="error")
            return {"tool": tool_def.name, "status": "timeout"}
        except Exception as e:
            self.loot.log_timeline("cloud", "tool_error",
                                    tool=tool_def.name, detail=str(e), status="error")
            return {"tool": tool_def.name, "status": "error", "error": str(e)}

    async def run(self) -> Dict[str, Any]:
        """Execute the full cloud security scan."""
        logger.info(f"Cloud scan: provider={self.provider}, target={self.target}, mode={self.mode}")

        self.loot.log_timeline("cloud", "cloud_scan_start",
                                tool="zypheron",
                                detail=f"{self.provider}:{self.target}")

        plan = await self.plan_scan()
        if not plan:
            return {"status": "no_tools", "message": "No cloud tools available"}

        results = {"plan": plan, "tool_results": [], "provider": self.provider}

        tool_map = {t.name: t for t in self.get_tools_for_provider()}
        for step in plan:
            tool_name = step.get("tool", "")
            tool_def = tool_map.get(tool_name)
            if not tool_def:
                continue
            result = await self.run_tool(tool_def, step.get("args", ""))
            results["tool_results"].append(result)

        self.loot.save_loot_json("cloud", "scan_results.json", results)
        self.loot.log_timeline("cloud", "cloud_scan_complete",
                                tool="zypheron",
                                detail=f"{len(results['tool_results'])} tools executed")

        return results
