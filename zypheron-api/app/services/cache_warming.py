"""Cache warming service for pre-populating common vulnerability data.

Warms the cache with frequently requested CVEs and security information
to improve response times and reduce API costs.
"""

import asyncio
import structlog
from typing import Any

from app.services.cache import get_cache_service

logger = structlog.get_logger()

# Common CVEs that are frequently requested
# These are high-impact vulnerabilities that users commonly ask about
COMMON_CVES = [
    # 2024 Critical CVEs
    "CVE-2024-3094",   # XZ Utils backdoor
    "CVE-2024-21762",  # Fortinet FortiOS RCE
    "CVE-2024-1709",   # ConnectWise ScreenConnect bypass
    "CVE-2024-27198",  # JetBrains TeamCity auth bypass
    "CVE-2024-20353",  # Cisco ASA DoS

    # 2023 Critical CVEs
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2023-4966",   # Citrix Bleed
    "CVE-2023-46747",  # F5 BIG-IP RCE
    "CVE-2023-22515",  # Atlassian Confluence RCE
    "CVE-2023-34362",  # MOVEit Transfer SQLi

    # Historic high-impact CVEs
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",  # Log4j follow-up
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2021-26855",  # ProxyLogon (Exchange)
    "CVE-2021-27065",  # ProxyLogon (Exchange)
    "CVE-2020-1472",   # Zerologon
    "CVE-2019-0708",   # BlueKeep
    "CVE-2017-5754",   # Meltdown
    "CVE-2017-5753",   # Spectre v1
    "CVE-2017-0144",   # EternalBlue
    "CVE-2014-0160",   # Heartbleed
    "CVE-2014-6271",   # Shellshock
]

# Common security topics with pre-defined responses
COMMON_SECURITY_TOPICS = {
    "sql_injection": {
        "topic": "SQL Injection",
        "summary": "SQL injection is a code injection technique that exploits security vulnerabilities in an application's database layer.",
        "prevention": [
            "Use parameterized queries (prepared statements)",
            "Use stored procedures",
            "Validate and sanitize all user input",
            "Use ORM frameworks",
            "Apply principle of least privilege to database accounts",
        ],
        "testing": [
            "Try single quote (') in input fields",
            "Use SQLMap for automated testing",
            "Test with UNION-based payloads",
            "Check for error-based SQLi",
            "Test time-based blind SQLi",
        ],
    },
    "xss": {
        "topic": "Cross-Site Scripting (XSS)",
        "summary": "XSS attacks inject malicious scripts into web pages viewed by other users.",
        "types": ["Stored XSS", "Reflected XSS", "DOM-based XSS"],
        "prevention": [
            "Encode output (HTML entity encoding)",
            "Use Content Security Policy (CSP)",
            "Validate and sanitize input",
            "Use HTTPOnly and Secure cookie flags",
            "Use modern frameworks with auto-escaping",
        ],
    },
    "csrf": {
        "topic": "Cross-Site Request Forgery (CSRF)",
        "summary": "CSRF tricks users into executing unwanted actions on authenticated web applications.",
        "prevention": [
            "Use anti-CSRF tokens",
            "Validate Origin/Referer headers",
            "Use SameSite cookie attribute",
            "Require re-authentication for sensitive actions",
        ],
    },
}


async def warm_cache_entry(cache_key: str, data: dict[str, Any], ttl: int) -> bool:
    """Warm a single cache entry.

    Args:
        cache_key: Cache key
        data: Data to cache
        ttl: Time-to-live in seconds

    Returns:
        True if successful, False otherwise
    """
    try:
        cache_service = get_cache_service()
        import json
        await cache_service.backend.set(cache_key, json.dumps(data), ttl)
        return True
    except Exception as e:
        logger.error(f"Failed to warm cache for {cache_key}: {e}")
        return False


async def warm_security_topics() -> int:
    """Warm cache with common security topic information.

    Returns:
        Number of entries warmed
    """
    from app.core.config import get_settings
    settings = get_settings()

    warmed = 0
    for topic_key, topic_data in COMMON_SECURITY_TOPICS.items():
        cache_key = f"security_topic:{topic_key}"
        if await warm_cache_entry(cache_key, topic_data, settings.cache_ttl_general):
            warmed += 1

    logger.info(f"Warmed {warmed} security topic entries")
    return warmed


async def warm_cve_placeholders() -> int:
    """Create placeholder entries for common CVEs.

    These placeholders indicate that the CVE is known and should be
    looked up, improving user experience by reducing cold starts.

    Returns:
        Number of entries warmed
    """
    from app.core.config import get_settings
    settings = get_settings()

    warmed = 0
    for cve_id in COMMON_CVES:
        # Create a minimal placeholder indicating this is a known CVE
        placeholder = {
            "cve_id": cve_id,
            "status": "known",
            "priority": "high",
            "message": f"{cve_id} is a critical vulnerability. Full details available on request.",
        }
        cache_key = f"cve_known:{cve_id}"
        if await warm_cache_entry(cache_key, placeholder, settings.cache_ttl_vuln_desc):
            warmed += 1

    logger.info(f"Warmed {warmed} CVE placeholder entries")
    return warmed


async def warm_cache() -> dict[str, int]:
    """Run full cache warming process.

    Returns:
        Dictionary with counts of warmed entries by category
    """
    logger.info("Starting cache warming...")

    results = {
        "security_topics": await warm_security_topics(),
        "cve_placeholders": await warm_cve_placeholders(),
    }

    total = sum(results.values())
    logger.info(f"Cache warming complete. Warmed {total} entries total.")

    return results


async def schedule_cache_warming(interval_hours: int = 6):
    """Schedule periodic cache warming.

    Args:
        interval_hours: Hours between warming cycles
    """
    while True:
        try:
            await warm_cache()
        except Exception as e:
            logger.error(f"Cache warming failed: {e}")

        await asyncio.sleep(interval_hours * 3600)


def start_cache_warming_background():
    """Start cache warming in background task."""
    async def run():
        # Initial warm on startup (with small delay)
        await asyncio.sleep(5)
        await warm_cache()
        # Then schedule periodic warming
        await schedule_cache_warming(interval_hours=6)

    asyncio.create_task(run())
    logger.info("Cache warming background task started")
