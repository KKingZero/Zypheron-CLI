"""
CVSS Score Lookup

Priority: static lookup table -> AI fallback
Maps common vulnerability types / tool severity to CVSS scores.
"""

from typing import Optional, Tuple
from loguru import logger


# Static CVSS lookup: (base_score, vector_string)
# Maps common vuln patterns from tool output to CVSS 3.1 scores
CVSS_TABLE: dict[str, Tuple[float, str]] = {
    # Critical
    "remote_code_execution": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "rce": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "sql_injection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "sqli": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "command_injection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "authentication_bypass": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "deserialization": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "default_credentials": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssti": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssrf_internal": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    # High
    "xss_stored": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
    "xxe": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L"),
    "idor": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "lfi": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "path_traversal": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "broken_access_control": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "jwt_none_algorithm": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "weak_password": (7.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "kerberoasting": (7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "asrep_roasting": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "ntlm_relay": (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "pass_the_hash": (7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "smb_signing_disabled": (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    # Medium
    "xss_reflected": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "csrf": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    "cors_misconfiguration": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "open_redirect": (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"),
    "clickjacking": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "directory_listing": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "ssl_weak_cipher": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "missing_security_headers": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "ssrf_blind": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # Low
    "information_disclosure": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "version_disclosure": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "cookie_no_httponly": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "cookie_no_secure": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "dns_zone_transfer": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

# Nuclei severity → CVSS range midpoints
NUCLEI_SEVERITY_MAP = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}


class CVSSLookup:
    """Resolve CVSS scores from vulnerability data."""

    @staticmethod
    def lookup(vuln_type: str) -> Optional[Tuple[float, str]]:
        """Look up CVSS score by vulnerability type key."""
        key = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")
        return CVSS_TABLE.get(key)

    @staticmethod
    def from_nuclei_severity(severity: str) -> float:
        """Convert Nuclei severity string to CVSS score midpoint."""
        return NUCLEI_SEVERITY_MAP.get(severity.lower(), 0.0)

    @staticmethod
    def from_tool_severity(tool: str, severity: str) -> float:
        """Convert a generic tool severity to a CVSS score."""
        severity = severity.lower()
        if severity in NUCLEI_SEVERITY_MAP:
            return NUCLEI_SEVERITY_MAP[severity]
        return 0.0

    @staticmethod
    def severity_from_score(score: float) -> str:
        """Get severity label from CVSS score."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0.0:
            return "low"
        return "info"

    @staticmethod
    async def ai_fallback(vuln_title: str, vuln_description: str, ai_provider=None) -> Optional[Tuple[float, str]]:
        """
        Use AI to estimate CVSS score when static lookup fails.
        Returns (score, reasoning) or None.
        """
        if not ai_provider:
            return None

        prompt = (
            f"Estimate the CVSS 3.1 base score for this vulnerability.\n"
            f"Title: {vuln_title}\n"
            f"Description: {vuln_description}\n\n"
            f"Respond with ONLY a JSON object: {{\"score\": 7.5, \"vector\": \"CVSS:3.1/AV:N/AC:L/...\"}}"
        )

        try:
            from providers.base import AIMessage
            response = await ai_provider.chat(
                messages=[AIMessage(role="user", content=prompt)],
                temperature=0.1,
                max_tokens=200,
            )
            import json
            data = json.loads(response.content.strip())
            score = float(data.get("score", 0))
            vector = data.get("vector", "")
            logger.info(f"AI CVSS estimate for '{vuln_title}': {score}")
            return (score, vector)
        except Exception as e:
            logger.warning(f"AI CVSS fallback failed: {e}")
            return None
