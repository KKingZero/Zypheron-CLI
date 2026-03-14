"""
Zypheron MITRE ATT&CK Engine

Stores ATT&CK data locally, supports user-driven objective selection,
maps objectives to techniques, selects tools, and integrates with report.

Data source: MITRE ATT&CK STIX JSON (enterprise-attack.json)
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from core.loot import LootManager


DATA_DIR = Path.home() / ".zypheron" / "data" / "mitre"
ATTACK_DATA_FILE = DATA_DIR / "enterprise-attack.json"
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


# Built-in tactic definitions (always available even without downloaded data)
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "shortname": "reconnaissance"},
    {"id": "TA0042", "name": "Resource Development", "shortname": "resource-development"},
    {"id": "TA0001", "name": "Initial Access", "shortname": "initial-access"},
    {"id": "TA0002", "name": "Execution", "shortname": "execution"},
    {"id": "TA0003", "name": "Persistence", "shortname": "persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "shortname": "privilege-escalation"},
    {"id": "TA0005", "name": "Defense Evasion", "shortname": "defense-evasion"},
    {"id": "TA0006", "name": "Credential Access", "shortname": "credential-access"},
    {"id": "TA0007", "name": "Discovery", "shortname": "discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "shortname": "lateral-movement"},
    {"id": "TA0009", "name": "Collection", "shortname": "collection"},
    {"id": "TA0011", "name": "Command and Control", "shortname": "command-and-control"},
    {"id": "TA0010", "name": "Exfiltration", "shortname": "exfiltration"},
    {"id": "TA0040", "name": "Impact", "shortname": "impact"},
]

# Mapping: tactic -> Zypheron tools that implement techniques for it
TACTIC_TOOL_MAP: Dict[str, List[Dict[str, str]]] = {
    "reconnaissance": [
        {"technique": "T1595", "name": "Active Scanning", "tools": ["nmap", "masscan"]},
        {"technique": "T1592", "name": "Gather Victim Host Info", "tools": ["nmap", "whatweb"]},
        {"technique": "T1589", "name": "Gather Victim Identity Info", "tools": ["theharvester", "amass"]},
        {"technique": "T1593", "name": "Search Open Websites", "tools": ["subfinder", "gau", "waybackurls"]},
    ],
    "initial-access": [
        {"technique": "T1190", "name": "Exploit Public-Facing App", "tools": ["nuclei", "sqlmap", "nikto"]},
        {"technique": "T1566", "name": "Phishing", "tools": ["evilginx3"]},
        {"technique": "T1078", "name": "Valid Accounts", "tools": ["hydra", "netexec"]},
    ],
    "execution": [
        {"technique": "T1059", "name": "Command and Scripting Interpreter", "tools": ["metasploit"]},
        {"technique": "T1203", "name": "Exploitation for Client Execution", "tools": ["metasploit"]},
    ],
    "persistence": [
        {"technique": "T1136", "name": "Create Account", "tools": ["netexec", "impacket"]},
        {"technique": "T1053", "name": "Scheduled Task/Job", "tools": ["impacket"]},
    ],
    "privilege-escalation": [
        {"technique": "T1068", "name": "Exploitation for Privilege Escalation", "tools": ["metasploit"]},
        {"technique": "T1548", "name": "Abuse Elevation Control", "tools": ["PEASS-ng"]},
        {"technique": "T1649", "name": "Steal/Forge Auth Certificates", "tools": ["certipy"]},
    ],
    "defense-evasion": [
        {"technique": "T1027", "name": "Obfuscated Files", "tools": ["scarecrow"]},
        {"technique": "T1562", "name": "Impair Defenses", "tools": ["scarecrow", "havoc"]},
    ],
    "credential-access": [
        {"technique": "T1558.003", "name": "Kerberoasting", "tools": ["impacket-GetUserSPNs"]},
        {"technique": "T1558.004", "name": "AS-REP Roasting", "tools": ["impacket-GetNPUsers"]},
        {"technique": "T1003.001", "name": "LSASS Memory", "tools": ["lsassy", "mimikatz"]},
        {"technique": "T1557.001", "name": "LLMNR/NBT-NS Poisoning", "tools": ["responder"]},
        {"technique": "T1110", "name": "Brute Force", "tools": ["hydra", "john", "hashcat"]},
    ],
    "discovery": [
        {"technique": "T1087.002", "name": "Domain Account Discovery", "tools": ["bloodhound-python", "ldapdomaindump"]},
        {"technique": "T1046", "name": "Network Service Discovery", "tools": ["nmap", "masscan"]},
        {"technique": "T1135", "name": "Network Share Discovery", "tools": ["snaffler", "netexec"]},
    ],
    "lateral-movement": [
        {"technique": "T1021.002", "name": "SMB/Admin Shares", "tools": ["netexec", "impacket-psexec"]},
        {"technique": "T1021.006", "name": "WinRM", "tools": ["netexec"]},
        {"technique": "T1550.002", "name": "Pass the Hash", "tools": ["netexec", "impacket"]},
    ],
    "collection": [
        {"technique": "T1039", "name": "Data from Network Shared Drive", "tools": ["snaffler"]},
        {"technique": "T1005", "name": "Data from Local System", "tools": ["netexec"]},
    ],
    "command-and-control": [
        {"technique": "T1071", "name": "Application Layer Protocol", "tools": ["sliver", "havoc"]},
        {"technique": "T1572", "name": "Protocol Tunneling", "tools": ["ligolo-ng"]},
        {"technique": "T1573", "name": "Encrypted Channel", "tools": ["sliver", "havoc"]},
        {"technique": "T1105", "name": "Ingress Tool Transfer", "tools": ["sliver", "havoc"]},
    ],
    "exfiltration": [
        {"technique": "T1041", "name": "Exfiltration Over C2", "tools": ["sliver", "havoc"]},
    ],
    "impact": [
        {"technique": "T1486", "name": "Data Encrypted for Impact", "tools": []},
    ],
}


class MitreEngine:
    """MITRE ATT&CK engine for objective-driven attack execution."""

    def __init__(self, ai_provider=None):
        self.ai_provider = ai_provider
        self._stix_data = None

    async def update_data(self) -> Dict[str, Any]:
        """Download latest ATT&CK STIX data."""
        import aiohttp

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading ATT&CK data from {STIX_URL}...")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(STIX_URL, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                    if resp.status != 200:
                        return {"status": "error", "message": f"HTTP {resp.status}"}
                    data = await resp.read()
                    ATTACK_DATA_FILE.write_bytes(data)
                    size_mb = len(data) / (1024 * 1024)
                    logger.info(f"ATT&CK data saved: {ATTACK_DATA_FILE} ({size_mb:.1f} MB)")
                    return {
                        "status": "ok",
                        "message": f"ATT&CK Enterprise data updated ({size_mb:.1f} MB)",
                        "path": str(ATTACK_DATA_FILE),
                    }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def load_stix_data(self) -> Optional[Dict]:
        """Load cached STIX data."""
        if self._stix_data:
            return self._stix_data
        if ATTACK_DATA_FILE.exists():
            try:
                self._stix_data = json.loads(ATTACK_DATA_FILE.read_text())
                return self._stix_data
            except Exception as e:
                logger.warning(f"Failed to load ATT&CK data: {e}")
        return None

    def list_tactics(self) -> List[Dict]:
        """List all ATT&CK Enterprise tactics."""
        return TACTICS

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Get details for a specific technique from STIX data."""
        stix = self.load_stix_data()
        if not stix:
            # Fallback: check built-in map
            for tactic_tools in TACTIC_TOOL_MAP.values():
                for entry in tactic_tools:
                    if entry["technique"] == technique_id:
                        return entry
            return None

        # Search STIX objects
        for obj in stix.get("objects", []):
            if obj.get("type") == "attack-pattern":
                refs = obj.get("external_references", [])
                for ref in refs:
                    if ref.get("external_id") == technique_id:
                        return {
                            "id": technique_id,
                            "name": obj.get("name", ""),
                            "description": obj.get("description", "")[:500],
                            "platforms": obj.get("x_mitre_platforms", []),
                            "kill_chain_phases": [
                                p.get("phase_name") for p in obj.get("kill_chain_phases", [])
                            ],
                        }
        return None

    def resolve_objective(self, objective: str) -> List[Dict]:
        """
        Map a user objective to ATT&CK techniques and tools.

        Accepts both tactic names and natural language.
        """
        objective_lower = objective.lower().strip()

        # Direct tactic match
        for tactic in TACTICS:
            if (objective_lower == tactic["name"].lower()
                    or objective_lower == tactic["shortname"]
                    or objective_lower == tactic["id"].lower()):
                tools = TACTIC_TOOL_MAP.get(tactic["shortname"], [])
                return [{
                    "tactic": tactic["name"],
                    "tactic_id": tactic["id"],
                    **entry,
                } for entry in tools]

        # Fuzzy match: check if objective contains a tactic name
        for tactic in TACTICS:
            if tactic["name"].lower() in objective_lower or tactic["shortname"].replace("-", " ") in objective_lower:
                tools = TACTIC_TOOL_MAP.get(tactic["shortname"], [])
                return [{
                    "tactic": tactic["name"],
                    "tactic_id": tactic["id"],
                    **entry,
                } for entry in tools]

        return []

    async def run_objective(
        self,
        objective: str,
        target: str,
        session_id: str,
    ) -> Dict[str, Any]:
        """Execute an objective-driven attack."""
        loot_mgr = LootManager(session_id)

        techniques = self.resolve_objective(objective)

        # If no static match, use AI
        if not techniques and self.ai_provider:
            techniques = await self._ai_resolve_objective(objective)

        if not techniques:
            return {
                "status": "no_match",
                "message": f"Could not map objective '{objective}' to ATT&CK techniques",
                "hint": "Try: Initial Access, Credential Access, Lateral Movement, etc.",
            }

        loot_mgr.log_timeline("mitre", "zypheron", "objective_mapped",
                               detail=f"{objective} -> {len(techniques)} techniques")

        result = {
            "objective": objective,
            "target": target,
            "techniques": techniques,
            "execution_plan": [],
        }

        # Build execution plan
        for tech in techniques:
            tools = tech.get("tools", [])
            result["execution_plan"].append({
                "technique": tech.get("technique", ""),
                "name": tech.get("name", ""),
                "tools": tools,
                "tactic": tech.get("tactic", ""),
            })

        loot_mgr.save_loot_json("attack", "mitre_plan.json", result)
        return result

    async def _ai_resolve_objective(self, objective: str) -> List[Dict]:
        """Use AI to map a natural language objective to techniques."""
        if not self.ai_provider:
            return []

        from providers.base import AIMessage
        prompt = (
            f"Map this penetration test objective to MITRE ATT&CK Enterprise techniques:\n"
            f"Objective: {objective}\n\n"
            f"Return JSON array: [{{\"technique\": \"T1234\", \"name\": \"...\", "
            f"\"tactic\": \"...\", \"tools\": [\"tool1\", \"tool2\"]}}]\n"
            f"Include 3-5 most relevant techniques."
        )

        try:
            response = await self.ai_provider.chat(
                messages=[AIMessage(role="user", content=prompt)],
                temperature=0.2,
                max_tokens=1000,
            )
            return json.loads(response.content)
        except Exception as e:
            logger.warning(f"AI ATT&CK resolution failed: {e}")
            return []

    def generate_heatmap_data(self, observed_techniques: List[str]) -> Dict[str, Any]:
        """Generate ATT&CK coverage heatmap data for reports."""
        coverage = {}
        for tactic in TACTICS:
            shortname = tactic["shortname"]
            tactic_techniques = TACTIC_TOOL_MAP.get(shortname, [])
            total = len(tactic_techniques)
            covered = sum(
                1 for t in tactic_techniques
                if t["technique"] in observed_techniques
            )
            coverage[tactic["name"]] = {
                "id": tactic["id"],
                "total_techniques": total,
                "covered": covered,
                "percentage": round(covered / total * 100) if total > 0 else 0,
            }
        return coverage
