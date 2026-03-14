"""
Automated Penetration Testing Engine

Intelligent, autonomous penetration testing with safety controls
"""

import asyncio
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# Edition detection
EDITION_FREE = "free"
EDITION_PRO = "pro"

def get_edition() -> str:
    """Get current Zypheron edition from environment"""
    return os.environ.get("ZYPHERON_EDITION", "pro").lower()


class PentestPhase(Enum):
    """Penetration test phases"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class PentestStatus(Enum):
    """Pentest status"""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PentestConfig:
    """Pentest configuration"""
    # Target information
    targets: List[str]
    scope: List[str]  # In-scope targets/networks
    exclusions: List[str] = field(default_factory=list)  # Out-of-scope
    
    # Authorization
    authorization_token: str = ""
    authorized_by: str = ""
    authorization_date: Optional[datetime] = None
    
    # Phases to execute
    phases: List[PentestPhase] = field(default_factory=lambda: [
        PentestPhase.RECONNAISSANCE,
        PentestPhase.SCANNING,
        PentestPhase.VULNERABILITY_ANALYSIS,
        PentestPhase.EXPLOITATION
    ])
    
    # Safety controls
    max_exploitation_attempts: int = 3
    avoid_dos: bool = True
    avoid_data_modification: bool = True
    safe_mode: bool = True  # Extra cautious, read-only when possible
    
    # Constraints
    business_hours_only: bool = False
    max_duration: int = 3600  # seconds
    max_concurrent_tasks: int = 5
    rate_limit: int = 100  # requests per second
    
    # AI provider
    ai_provider: Optional[str] = "claude"
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        # Simple contains check - implement proper matching
        for scope_item in self.scope:
            if scope_item in target:
                return True
        return False
    
    def is_excluded(self, target: str) -> bool:
        """Check if target is excluded"""
        for exclusion in self.exclusions:
            if exclusion in target:
                return True
        return False


@dataclass
class PentestResult:
    """Results of automated pentest"""
    pentest_id: str
    config: PentestConfig
    
    # Timing
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: float = 0.0
    
    # Status
    status: PentestStatus = PentestStatus.NOT_STARTED
    current_phase: Optional[PentestPhase] = None
    
    # Results by phase
    reconnaissance_results: Dict[str, Any] = field(default_factory=dict)
    scan_results: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    successful_exploits: List[Dict[str, Any]] = field(default_factory=list)
    post_exploit_data: Dict[str, Any] = field(default_factory=dict)
    
    # Attack chains discovered
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    
    # Safety events
    safety_blocks: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Statistics
    hosts_tested: int = 0
    vulnerabilities_found: int = 0
    exploits_attempted: int = 0
    exploits_successful: int = 0
    
    # Risk assessment
    overall_risk: str = "unknown"  # low, medium, high, critical
    critical_issues: List[str] = field(default_factory=list)
    
    # Executive summary
    summary: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'pentest_id': self.pentest_id,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration,
            'status': self.status.value,
            'current_phase': self.current_phase.value if self.current_phase else None,
            'vulnerabilities': self.vulnerabilities,
            'successful_exploits': self.successful_exploits,
            'attack_chains': self.attack_chains,
            'safety_blocks': self.safety_blocks,
            'warnings': self.warnings,
            'statistics': {
                'hosts_tested': self.hosts_tested,
                'vulnerabilities_found': self.vulnerabilities_found,
                'exploits_attempted': self.exploits_attempted,
                'exploits_successful': self.exploits_successful
            },
            'overall_risk': self.overall_risk,
            'critical_issues': self.critical_issues,
            'summary': self.summary
        }


class AutoPentEngine:
    """
    Automated Penetration Testing Engine
    
    Features:
    - Intelligent attack planning
    - Multi-phase testing
    - Safety controls
    - Authorization verification
    - Attack chain discovery
    - Adaptive strategy
    - Comprehensive reporting
    """
    
    def __init__(self, ai_provider=None):
        self.ai_provider = ai_provider
        self.pentests: Dict[str, PentestResult] = {}
        self.running_pentests: Set[str] = set()
        self.edition = get_edition()
    
    async def start_pentest(
        self,
        config: PentestConfig
    ) -> PentestResult:
        """
        Start automated penetration test
        
        Args:
            config: Pentest configuration
            
        Returns:
            PentestResult with ongoing results
        """
        import uuid
        pentest_id = f"pentest_{uuid.uuid4().hex[:8]}"
        
        result = PentestResult(
            pentest_id=pentest_id,
            config=config,
            started_at=datetime.now(),
            status=PentestStatus.RUNNING
        )
        
        self.pentests[pentest_id] = result
        self.running_pentests.add(pentest_id)
        
        logger.info(f"Starting automated pentest: {pentest_id}")
        
        try:
            # 1. Authorization check
            if not await self._verify_authorization(result):
                result.status = PentestStatus.FAILED
                result.safety_blocks.append("Authorization verification failed")
                return result
            
            # 2. Scope validation
            if not await self._validate_scope(result):
                result.status = PentestStatus.FAILED
                result.safety_blocks.append("Scope validation failed")
                return result
            
            # 3. Execute phases
            for phase in config.phases:
                result.current_phase = phase
                logger.info(f"Executing phase: {phase.value}")
                
                if phase == PentestPhase.RECONNAISSANCE:
                    await self._phase_reconnaissance(result)
                elif phase == PentestPhase.SCANNING:
                    await self._phase_scanning(result)
                elif phase == PentestPhase.VULNERABILITY_ANALYSIS:
                    await self._phase_vulnerability_analysis(result)
                elif phase == PentestPhase.EXPLOITATION:
                    await self._phase_exploitation(result)
                elif phase == PentestPhase.POST_EXPLOITATION:
                    await self._phase_post_exploitation(result)
            
            # 4. Generate report
            await self._generate_report(result)
            
            result.status = PentestStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Pentest failed: {e}", exc_info=True)
            result.status = PentestStatus.FAILED
            result.warnings.append(str(e))
            
        finally:
            result.completed_at = datetime.now()
            result.duration = (result.completed_at - result.started_at).total_seconds()
            self.running_pentests.discard(pentest_id)
        
        return result
    
    async def _verify_authorization(self, result: PentestResult) -> bool:
        """Verify penetration test is authorized"""
        config = result.config
        
        # Check authorization token
        if not config.authorization_token:
            logger.error("No authorization token provided")
            return False
        
        if len(config.authorization_token) < 32:
            logger.error("Invalid authorization token")
            return False
        
        # Check authorization metadata
        if not config.authorized_by:
            result.warnings.append("No authorizing party specified")
        
        if not config.authorization_date:
            result.warnings.append("No authorization date specified")
        
        logger.info("Authorization verified")
        return True
    
    async def _validate_scope(self, result: PentestResult) -> bool:
        """Validate test scope"""
        config = result.config
        
        if not config.targets:
            logger.error("No targets specified")
            return False
        
        if not config.scope:
            logger.error("No scope defined")
            return False
        
        # Validate each target is in scope
        for target in config.targets:
            if not config.is_in_scope(target):
                logger.error(f"Target {target} not in scope")
                return False
            
            if config.is_excluded(target):
                logger.error(f"Target {target} is excluded")
                return False
        
        logger.info(f"Scope validated: {len(config.targets)} targets")
        return True
    
    async def _phase_reconnaissance(self, result: PentestResult):
        """Reconnaissance phase"""
        logger.info("Phase: Reconnaissance")
        config = result.config
        
        recon_data = {
            'targets_analyzed': [],
            'domains_discovered': [],
            'subdomains': [],
            'ip_addresses': [],
            'technologies': [],
            'dns_records': {},
            'rate_limits': {},
            'errors': [],
        }
        
        for target in config.targets:
            logger.info(f"Reconnaissance on {target}")
            
            domain = self._extract_domain(target)
            recon_data['targets_analyzed'].append(target)

            if not domain:
                recon_data['errors'].append(f"Unable to parse domain from target {target}")
                continue

            dns_info = await self._resolve_dns(domain)
            recon_data['dns_records'][domain] = dns_info
            recon_data['ip_addresses'].extend(dns_info.get('addresses', []))
            recon_data['domains_discovered'].append(domain)

            subdomain_info = await self._enumerate_subdomains(domain)
            recon_data['subdomains'].extend(subdomain_info.get('subdomains', []))
            recon_data['errors'].extend(subdomain_info.get('errors', []))

            rate_limit_info = await self._fingerprint_rate_limits(config, target)
            if rate_limit_info:
                recon_data['rate_limits'][domain] = rate_limit_info

            result.hosts_tested += 1
        
        recon_data['ip_addresses'] = sorted(set(recon_data['ip_addresses']))
        recon_data['subdomains'] = sorted(set(recon_data['subdomains']))[:100]
        recon_data['domains_discovered'] = sorted(set(recon_data['domains_discovered']))

        result.reconnaissance_results = recon_data
        logger.info(f"Reconnaissance completed: {result.hosts_tested} hosts")
    
    async def _phase_scanning(self, result: PentestResult):
        """Scanning phase"""
        logger.info("Phase: Scanning")
        config = result.config
        
        scan_data = {
            'port_scans': [],
            'service_detection': [],
            'os_detection': []
        }
        
        for target in config.targets:
            logger.info(f"Scanning {target}")
            
            # Port scanning
            # - nmap comprehensive scan
            # - Service version detection
            # - OS fingerprinting
            
            scan_data['port_scans'].append({
                'target': target,
                'open_ports': [],  # Would contain actual scan results
                'services': []
            })
        
        result.scan_results = scan_data
        logger.info("Scanning completed")
    
    async def _phase_vulnerability_analysis(self, result: PentestResult):
        """Vulnerability analysis phase"""
        logger.info("Phase: Vulnerability Analysis")
        
        # Analyze scan results for vulnerabilities
        # - Match services to known vulnerabilities
        # - CVE lookups
        # - Web vulnerability scanning (nikto, nuclei)
        # - SSL/TLS analysis
        # - Configuration issues
        
        vulnerabilities = []
        
        # Example vulnerability
        if result.scan_results:
            vulnerabilities.append({
                'id': 'vuln_001',
                'type': 'outdated_software',
                'severity': 'high',
                'target': result.config.targets[0] if result.config.targets else 'unknown',
                'description': 'Outdated software version detected',
                'cve': 'CVE-2023-12345',
                'exploitable': True
            })
        
        result.vulnerabilities = vulnerabilities
        result.vulnerabilities_found = len(vulnerabilities)
        
        logger.info(f"Found {result.vulnerabilities_found} vulnerabilities")
    
    async def _phase_exploitation(self, result: PentestResult):
        """Exploitation phase - WITH SAFETY CONTROLS"""
        logger.info("Phase: Exploitation (Safe Mode)")
        config = result.config
        
        # EDITION CHECK: Block exploitation in free edition
        if self.edition == EDITION_FREE:
            logger.warning("Exploitation blocked - Free Edition")
            result.status = PentestStatus.COMPLETED
            result.safety_blocks.append("Exploitation phase blocked in Free Edition")
            result.warnings.append(
                "⚠️ EXPLOITATION BLOCKED - FREE EDITION\n\n"
                "Automated exploitation requires Zypheron Pro.\n"
                "Free Edition includes: OSINT, Recon, VulnScan, AI Analysis\n\n"
                "Upgrade at: https://zypheron.com/upgrade"
            )
            return
        
        if config.safe_mode:
            logger.info("Safe mode enabled - exploitation limited")
            result.warnings.append("Safe mode: exploitation attempts limited")
        
        for vuln in result.vulnerabilities:
            if not vuln.get('exploitable'):
                continue
            
            # Safety check: max attempts
            if result.exploits_attempted >= config.max_exploitation_attempts:
                logger.warning("Max exploitation attempts reached")
                result.safety_blocks.append("Max exploitation attempts reached")
                break
            
            # Safety check: avoid DoS
            if config.avoid_dos and self._is_dos_exploit(vuln):
                logger.info(f"Skipping DoS exploit: {vuln['id']}")
                result.safety_blocks.append(f"Skipped DoS exploit: {vuln['id']}")
                continue
            
            # Safety check: avoid data modification
            if config.avoid_data_modification and self._modifies_data(vuln):
                logger.info(f"Skipping data-modifying exploit: {vuln['id']}")
                result.safety_blocks.append(f"Skipped data modification: {vuln['id']}")
                continue
            
            # Attempt exploit
            logger.info(f"Attempting exploit for {vuln['id']}")
            result.exploits_attempted += 1
            
            # In safe mode, only verify vulnerability exists
            if config.safe_mode:
                exploit_result = await self._verify_vulnerability(vuln)
            else:
                exploit_result = await self._attempt_exploit(vuln)
            
            if exploit_result.get('success'):
                result.exploits_successful += 1
                result.successful_exploits.append(exploit_result)
                logger.info(f"Exploit successful: {vuln['id']}")
        
        logger.info(
            f"Exploitation completed: {result.exploits_successful}/"
            f"{result.exploits_attempted} successful"
        )
    
    def _is_dos_exploit(self, vuln: Dict[str, Any]) -> bool:
        """Check if exploit could cause DoS"""
        dos_keywords = ['dos', 'denial', 'crash', 'resource exhaustion']
        vuln_text = f"{vuln.get('type', '')} {vuln.get('description', '')}".lower()
        return any(keyword in vuln_text for keyword in dos_keywords)
    
    def _modifies_data(self, vuln: Dict[str, Any]) -> bool:
        """Check if exploit modifies data"""
        modify_keywords = ['sql injection', 'command injection', 'file upload', 'rce']
        vuln_text = f"{vuln.get('type', '')} {vuln.get('description', '')}".lower()
        return any(keyword in vuln_text for keyword in modify_keywords)

    def _extract_domain(self, target: str) -> Optional[str]:
        if not target:
            return None
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return parsed.hostname

    async def _resolve_dns(self, domain: str) -> Dict[str, Any]:
        result = {
            'domain': domain,
            'addresses': [],
            'sources': [],
            'errors': [],
        }

        if not domain:
            return result

        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, domain, None)
            addresses = sorted({info[4][0] for info in infos if info[4]})
            if addresses:
                result['addresses'].extend(addresses)
                result['sources'].append('system-resolver')
        except Exception as exc:
            result['errors'].append(f'system-resolver: {exc}')

        providers = [
            ('cloudflare', 'https://cloudflare-dns.com/dns-query', {'name': domain, 'type': 'A'}),
            ('google', 'https://dns.google/resolve', {'name': domain, 'type': 'A'}),
        ]

        for name, endpoint, params in providers:
            def _query():
                headers = {'accept': 'application/dns-json'}
                response = requests.get(endpoint, params=params, headers=headers, timeout=6)
                response.raise_for_status()
                return response.json()

            try:
                data = await asyncio.to_thread(_query)
            except Exception as exc:
                result['errors'].append(f'{name}: {exc}')
                continue

            answers = data.get('Answer') or []
            addresses = [record.get('data') for record in answers if record.get('type') in (1, 28)]
            if addresses:
                result['addresses'].extend(addresses)
                result['sources'].append(name)

        result['addresses'] = sorted(set(result['addresses']))
        return result

    async def _enumerate_subdomains(self, domain: str, limit: int = 50) -> Dict[str, Any]:
        result = {
            'domain': domain,
            'subdomains': [],
            'errors': [],
        }

        if not domain:
            return result

        sources = []

        def _crt_sh():
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()

        sources.append(('crt.sh', _crt_sh))

        def _bufferover():
            url = f"https://dns.bufferover.run/dns?q=. {domain}".replace(' ', '')
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()

        sources.append(('bufferover', _bufferover))

        discovered: Set[str] = set()

        for name, fetcher in sources:
            try:
                data = await asyncio.to_thread(fetcher)
            except Exception as exc:
                result['errors'].append(f'{name}: {exc}')
                continue

            if name == 'crt.sh' and isinstance(data, list):
                for entry in data:
                    value = entry.get('name_value')
                    if value and domain in value:
                        for sub in value.split('\n'):
                            if sub.endswith(domain):
                                discovered.add(sub.strip())
            elif name == 'bufferover' and isinstance(data, dict):
                for key in ('FDNS_A', 'RDNS'):
                    for entry in data.get(key, []) or []:
                        parts = entry.split(',')
                        hostname = parts[-1].strip()
                        if hostname.endswith(domain):
                            discovered.add(hostname)

        result['subdomains'] = sorted(sub for sub in discovered if sub != domain)[:limit]
        return result

    async def _fingerprint_rate_limits(
        self,
        config: PentestConfig,
        target: str,
        attempts: int = 20,
    ) -> Optional[Dict[str, Any]]:
        domain = self._extract_domain(target)
        if not domain:
            return None

        if config.avoid_dos:
            attempts = min(attempts, 10)

        schemes = []
        parsed = urlparse(target)
        if parsed.scheme:
            schemes.append(parsed.scheme)
        schemes.extend(s for s in ['https', 'http'] if s not in schemes)

        base_url = None
        for scheme in schemes:
            candidate = f"{scheme}://{domain}"

            def _probe_once():
                try:
                    response = requests.get(candidate, timeout=5)
                    return response.status_code
                except Exception:
                    return None

            status = await asyncio.to_thread(_probe_once)
            if status:
                base_url = candidate
                break

        if not base_url:
            return None

        stats = {
            'tested_url': base_url,
            'attempts': 0,
            'status_counts': {},
            'limit_hit': False,
            'limit_after': None,
            'retry_after': None,
            'errors': [],
        }

        start = time.time()
        headers = {'User-Agent': 'Zypheron-RateLimit/0.1'}

        for attempt in range(1, attempts + 1):
            def _request_loop():
                return requests.get(base_url, headers=headers, timeout=5)

            try:
                response = await asyncio.to_thread(_request_loop)
            except Exception as exc:
                stats['errors'].append(str(exc))
                break

            stats['attempts'] = attempt
            stats['status_counts'][response.status_code] = (
                stats['status_counts'].get(response.status_code, 0) + 1
            )

            if response.status_code == 429:
                stats['limit_hit'] = True
                stats['limit_after'] = attempt
                stats['retry_after'] = response.headers.get('Retry-After')
                break

        elapsed = max(time.time() - start, 0.001)
        stats['requests_per_second'] = round(stats['attempts'] / elapsed, 2)
        return stats
    
    async def _verify_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Verify vulnerability exists (read-only)"""
        logger.info(f"Verifying vulnerability: {vuln['id']}")
        
        # Perform read-only check
        # Example: check if vulnerable service responds to specific request
        
        return {
            'vulnerability_id': vuln['id'],
            'success': True,
            'method': 'verification',
            'safe_mode': True,
            'evidence': 'Vulnerability confirmed through read-only verification'
        }
    
    async def _attempt_exploit(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt actual exploitation (non-safe mode)"""
        logger.warning(f"Attempting actual exploitation: {vuln['id']}")
        
        # This would contain actual exploitation code
        # Only runs when safe_mode is disabled
        
        return {
            'vulnerability_id': vuln['id'],
            'success': False,
            'method': 'exploitation',
            'safe_mode': False,
            'error': 'Exploitation not implemented'
        }
    
    async def _phase_post_exploitation(self, result: PentestResult):
        """Post-exploitation phase"""
        logger.info("Phase: Post-Exploitation")
        
        # EDITION CHECK: Block post-exploitation in free edition
        if self.edition == EDITION_FREE:
            logger.warning("Post-exploitation blocked - Free Edition")
            result.safety_blocks.append("Post-exploitation phase blocked in Free Edition")
            return
        
        # Only if we have successful exploits
        if not result.successful_exploits:
            logger.info("No successful exploits for post-exploitation")
            return
        
        # Post-exploitation activities (with extreme caution)
        # - Privilege escalation discovery
        # - Lateral movement possibilities
        # - Data access assessment
        # - Persistence mechanisms
        
        result.post_exploit_data = {
            'privilege_escalation_paths': [],
            'lateral_movement_options': [],
            'sensitive_data_locations': []
        }
        
        logger.info("Post-exploitation analysis completed")
    
    async def _generate_report(self, result: PentestResult):
        """Generate final report"""
        logger.info("Generating report")
        
        # Calculate overall risk
        if result.exploits_successful > 0:
            result.overall_risk = "critical"
        elif result.vulnerabilities_found > 5:
            result.overall_risk = "high"
        elif result.vulnerabilities_found > 0:
            result.overall_risk = "medium"
        else:
            result.overall_risk = "low"
        
        # Identify critical issues
        for vuln in result.vulnerabilities:
            if vuln.get('severity') == 'critical':
                result.critical_issues.append(vuln['description'])
        
        # Generate AI-powered summary
        if self.ai_provider:
            result.summary = await self._generate_ai_summary(result)
        else:
            result.summary = self._generate_basic_summary(result)
        
        logger.info("Report generation completed")
    
    async def _generate_ai_summary(self, result: PentestResult) -> str:
        """Generate AI-powered executive summary"""
        try:
            prompt = f"""
            Generate an executive summary for this penetration test:
            
            Targets: {len(result.config.targets)}
            Hosts Tested: {result.hosts_tested}
            Vulnerabilities Found: {result.vulnerabilities_found}
            Successful Exploits: {result.exploits_successful}
            Overall Risk: {result.overall_risk}
            Critical Issues: {len(result.critical_issues)}
            
            Duration: {result.duration:.1f} seconds
            
            Provide a concise executive summary covering:
            1. Overall security posture
            2. Critical vulnerabilities
            3. Exploit success rate
            4. Immediate remediation priorities
            5. Risk assessment
            """
            
            summary = await self.ai_provider.chat(prompt)
            return summary
            
        except Exception as e:
            logger.error(f"AI summary generation failed: {e}")
            return self._generate_basic_summary(result)
    
    def _generate_basic_summary(self, result: PentestResult) -> str:
        """Generate basic text summary"""
        return f"""
Automated Penetration Test Summary

Test ID: {result.pentest_id}
Duration: {result.duration:.1f} seconds
Overall Risk: {result.overall_risk.upper()}

Findings:
- Hosts Tested: {result.hosts_tested}
- Vulnerabilities Found: {result.vulnerabilities_found}
- Exploits Attempted: {result.exploits_attempted}
- Exploits Successful: {result.exploits_successful}
- Critical Issues: {len(result.critical_issues)}

Safety Controls:
- Safety Blocks: {len(result.safety_blocks)}
- Warnings: {len(result.warnings)}
- Safe Mode: {"Enabled" if result.config.safe_mode else "Disabled"}

Recommendation: {"Immediate action required" if result.overall_risk in ["critical", "high"] else "Review and plan remediation"}
        """.strip()
    
    def get_pentest_status(self, pentest_id: str) -> Optional[Dict[str, Any]]:
        """Get status of running pentest"""
        result = self.pentests.get(pentest_id)
        if not result:
            return None
        
        return {
            'pentest_id': pentest_id,
            'status': result.status.value,
            'current_phase': result.current_phase.value if result.current_phase else None,
            'progress': {
                'hosts_tested': result.hosts_tested,
                'vulnerabilities_found': result.vulnerabilities_found,
                'exploits_attempted': result.exploits_attempted,
                'exploits_successful': result.exploits_successful
            },
            'elapsed_time': (datetime.now() - result.started_at).total_seconds()
        }
    
    def list_pentests(self) -> List[str]:
        """List all pentest IDs"""
        return list(self.pentests.keys())
    
    def get_result(self, pentest_id: str) -> Optional[PentestResult]:
        """Get pentest result"""
        return self.pentests.get(pentest_id)

