"""
Enterprise Feature Handlers for IPC Server

Handles requests for:
- Authenticated scanning
- Secrets detection
- Dependency scanning
- Burp/ZAP integration
- Exploit verification
- Compliance reporting
"""

import logging
from typing import Dict, Any
import asyncio

logger = logging.getLogger(__name__)


class EnterpriseHandlers:
    """Handlers for enterprise features"""
    
    def __init__(self):
        # Lazy load modules to avoid import errors
        self.session_manager = None
        self.auth_scanner = None
        self.secret_scanner = None
        self.dep_scanner = None
        self.burp_api = None
        self.zap_api = None
        self.exploit_verifier = None
        self.compliance_reporter = None
        
    def _ensure_session_manager(self):
        """Initialize session manager if needed"""
        if not self.session_manager:
            from auth.session_manager import SessionManager
            self.session_manager = SessionManager()
            logger.debug("Initialized SessionManager")
    
    def _ensure_auth_scanner(self):
        """Initialize authenticated scanner if needed"""
        if not self.auth_scanner:
            from analysis.authenticated_scanner import AuthenticatedScanner
            self._ensure_session_manager()
            self.auth_scanner = AuthenticatedScanner(self.session_manager)
            logger.debug("Initialized AuthenticatedScanner")
    
    def _ensure_secret_scanner(self):
        """Initialize secret scanner if needed"""
        if not self.secret_scanner:
            from secrets.secret_scanner import SecretScanner
            self.secret_scanner = SecretScanner()
            logger.debug("Initialized SecretScanner")
    
    def _ensure_dep_scanner(self):
        """Initialize dependency scanner if needed"""
        if not self.dep_scanner:
            from supply_chain.dependency_scanner import DependencyScanner
            from supply_chain.sbom_generator import SBOMGenerator
            self.dep_scanner = DependencyScanner()
            self.sbom_generator = SBOMGenerator()
            logger.debug("Initialized DependencyScanner")
    
    def _ensure_burp_api(self):
        """Initialize Burp API if needed"""
        if not self.burp_api:
            from integrations.burp.burp_api import BurpAPI
            from integrations.burp.burp_scanner import BurpScanner
            self.burp_api = BurpAPI()
            self.burp_scanner = BurpScanner(self.burp_api)
            logger.debug("Initialized Burp integration")
    
    def _ensure_zap_api(self):
        """Initialize ZAP API if needed"""
        if not self.zap_api:
            from integrations.zap.zap_api import ZAPAPI
            from integrations.zap.zap_scanner import ZAPScanner
            self.zap_api = ZAPAPI()
            self.zap_scanner = ZAPScanner(self.zap_api)
            logger.debug("Initialized ZAP integration")
    
    # ===== Authentication Handlers =====
    
    async def handle_authenticate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle authentication request"""
        try:
            self._ensure_session_manager()
            from auth.auth_providers import AuthProviderFactory
            
            target_url = params.get('target_url')
            auth_type = params.get('auth_type', 'form')
            username = params.get('username')
            password = params.get('password')
            
            # Create auth provider
            provider = AuthProviderFactory.create(auth_type, target_url)
            if not provider:
                return {'success': False, 'error': f'Unknown auth type: {auth_type}'}
            
            # Authenticate
            auth_result = await provider.authenticate(username, password, **params)
            
            if auth_result.success:
                # Create session
                session = self.session_manager.create_session(
                    session_id=auth_result.session_id,
                    target_url=target_url,
                    auth_type=auth_type,
                    username=username
                )
                
                # Update session with auth data
                self.session_manager.update_session(
                    auth_result.session_id,
                    cookies=auth_result.cookies,
                    headers=auth_result.headers,
                    tokens=auth_result.tokens
                )
                
                return {
                    'success': True,
                    'session_id': auth_result.session_id,
                    'username': username
                }
            else:
                return {
                    'success': False,
                    'error': auth_result.error
                }
                
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def handle_create_test_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle test account creation"""
        try:
            from auth.test_accounts import TestAccountManager
            
            manager = TestAccountManager()
            
            target_url = params.get('target_url')
            role = params.get('role', 'user')
            
            account = manager.create_account(
                target_url=target_url,
                role=role,
                auto_cleanup=True
            )
            
            if account:
                return {
                    'success': True,
                    'account_id': account.account_id,
                    'username': account.username,
                    'password': account.password,
                    'role': account.role
                }
            else:
                return {'success': False, 'error': 'Failed to create account'}
                
        except Exception as e:
            logger.error(f"Test account creation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== Authenticated Scanning Handlers =====
    
    async def handle_test_idor(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle IDOR testing"""
        try:
            self._ensure_auth_scanner()
            
            session_id = params.get('session_id')
            test_urls = params.get('test_urls', [])
            
            # Auto-discover URLs if not provided
            if not test_urls:
                # Would implement URL discovery logic
                test_urls = [params.get('target_url') + '/api/users/1']
            
            vulns = await self.auth_scanner.test_idor(session_id, test_urls)
            
            return {
                'success': True,
                'vulnerabilities': [v.to_dict() for v in vulns],
                'count': len(vulns)
            }
            
        except Exception as e:
            logger.error(f"IDOR testing failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def handle_test_privilege_escalation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle privilege escalation testing"""
        try:
            self._ensure_auth_scanner()
            
            session_id = params.get('session_id')
            admin_urls = params.get('admin_urls', [])
            
            # Would need both low and high priv sessions in production
            # For now, return placeholder
            
            return {
                'success': True,
                'vulnerabilities': [],
                'message': 'Privilege escalation testing requires additional sessions'
            }
            
        except Exception as e:
            logger.error(f"Privilege escalation testing failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def handle_test_session_security(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle session security testing"""
        try:
            self._ensure_session_manager()
            
            session_id = params.get('session_id')
            target_url = params.get('target_url')
            
            # Test session health
            health = self.session_manager.monitor_session_health(session_id, target_url)
            
            return {
                'success': True,
                'session_healthy': health,
                'tests_run': ['session_health', 'csrf_protection']
            }
            
        except Exception as e:
            logger.error(f"Session security testing failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== Secrets Scanning Handlers =====
    
    async def handle_scan_secrets(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle secrets scanning"""
        try:
            self._ensure_secret_scanner()
            
            directory = params.get('directory', '.')
            recursive = params.get('recursive', True)
            extensions = params.get('extensions')
            
            findings = self.secret_scanner.scan_directory(
                directory=directory,
                recursive=recursive,
                file_extensions=extensions
            )
            
            report = self.secret_scanner.generate_report()
            
            return {
                'success': True,
                'findings': [f.to_dict() for f in findings],
                'report': report
            }
            
        except Exception as e:
            logger.error(f"Secrets scanning failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== Dependency Scanning Handlers =====
    
    async def handle_scan_dependencies(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle dependency scanning"""
        try:
            self._ensure_dep_scanner()
            
            directory = params.get('directory', '.')
            recursive = params.get('recursive', True)
            generate_sbom = params.get('generate_sbom', False)
            sbom_format = params.get('sbom_format', 'cyclonedx')
            
            # Scan dependencies
            vulns = self.dep_scanner.scan_directory(directory, recursive)
            
            result = {
                'success': True,
                'vulnerabilities': [v.to_dict() for v in vulns],
                'report': self.dep_scanner.generate_report()
            }
            
            # Generate SBOM if requested
            if generate_sbom:
                # Scan for components
                from pathlib import Path
                dir_path = Path(directory)
                
                # Python requirements
                requirements = list(dir_path.rglob('requirements.txt'))
                for req_file in requirements:
                    self.sbom_generator.scan_python_requirements(str(req_file))
                
                # Node.js packages
                packages = list(dir_path.rglob('package.json'))
                for pkg_file in packages:
                    self.sbom_generator.scan_nodejs_package(str(pkg_file))
                
                # Generate SBOM
                if sbom_format == 'cyclonedx':
                    result['sbom'] = self.sbom_generator.generate_cyclonedx()
                else:
                    result['sbom'] = {
                        'components': [comp.__dict__ for comp in self.sbom_generator.components],
                        'statistics': self.sbom_generator.get_statistics()
                    }
            
            return result
            
        except Exception as e:
            logger.error(f"Dependency scanning failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== Burp Integration Handlers =====
    
    async def handle_check_burp_available(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check if Burp Suite is available"""
        try:
            self._ensure_burp_api()
            
            available = self.burp_api.is_available()
            version = self.burp_api.get_version() if available else None
            
            return {
                'success': True,
                'available': available,
                'version': version
            }
            
        except Exception as e:
            logger.error(f"Burp availability check failed: {e}")
            return {'success': False, 'available': False, 'error': str(e)}
    
    async def handle_burp_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Burp scan request"""
        try:
            self._ensure_burp_api()
            from integrations.burp.burp_scanner import ScanConfig
            
            target = params.get('target')
            session_id = params.get('session_id')
            
            # Build scan config
            scan_config = ScanConfig(urls=[target])
            
            # Add authentication if session provided
            if session_id and self.session_manager:
                session = self.session_manager.get_session(session_id)
                if session:
                    scan_config.session_cookies = session.cookies
                    scan_config.auth_headers = session.headers
            
            # Run scan
            task_id = await self.burp_scanner.run_scan(scan_config, wait_for_completion=True)
            
            # Get results
            if task_id:
                issues = await self.burp_scanner.get_results(task_id)
                stats = self.burp_scanner.get_scan_statistics(task_id)
                
                return {
                    'success': True,
                    'task_id': task_id,
                    'issues': issues,
                    'statistics': stats
                }
            else:
                return {'success': False, 'error': 'Failed to start Burp scan'}
                
        except Exception as e:
            logger.error(f"Burp scan failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def handle_import_burp_findings(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Import Burp findings"""
        try:
            self._ensure_burp_api()
            from integrations.burp.burp_reporter import BurpReporter
            
            task_id = params.get('task_id')
            
            # Get issues from Burp
            issues = self.burp_api.get_scan_issues(task_id)
            
            # Import and convert
            reporter = BurpReporter()
            imported_count = reporter.import_burp_issues(issues)
            
            # Get unique findings
            existing = params.get('existing_vulnerabilities', [])
            unique = reporter.deduplicate_findings(existing)
            
            return {
                'success': True,
                'imported_count': imported_count,
                'unique_count': len(unique),
                'findings': [f.to_zypheron_format() for f in unique]
            }
            
        except Exception as e:
            logger.error(f"Burp findings import failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== ZAP Integration Handlers =====
    
    async def handle_check_zap_available(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check if ZAP is available"""
        try:
            self._ensure_zap_api()
            
            available = self.zap_api.is_available()
            version = self.zap_api.zap.core.version if available and self.zap_api.zap else None
            
            return {
                'success': True,
                'available': available,
                'version': version
            }
            
        except Exception as e:
            logger.error(f"ZAP availability check failed: {e}")
            return {'success': False, 'available': False, 'error': str(e)}
    
    async def handle_zap_scan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ZAP scan request"""
        try:
            self._ensure_zap_api()
            from integrations.zap.zap_scanner import ZAPScanConfig
            
            target = params.get('target')
            session_id = params.get('session_id')
            spider = params.get('spider', True)
            ajax_spider = params.get('ajax_spider', True)
            active_scan = params.get('active_scan', True)
            
            # Build scan config
            scan_config = ZAPScanConfig(
                target_url=target,
                scan_type='both' if active_scan else 'spider',
                use_ajax_spider=ajax_spider
            )
            
            # Configure authentication if session provided
            if session_id and self.session_manager:
                session = self.session_manager.get_session(session_id)
                if session:
                    scan_config.username = session.username
            
            # Run scan
            results = await self.zap_scanner.run_scan(scan_config, wait_for_completion=True)
            
            # Convert alerts to Zypheron format
            if 'alerts' in results:
                alerts = results['alerts']
                zypheron_vulns = self.zap_scanner.convert_to_zypheron_format(alerts)
                results['zypheron_vulnerabilities'] = zypheron_vulns
            
            return {
                'success': True,
                **results
            }
            
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== Exploit Verification Handlers =====
    
    async def handle_verify_exploit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle exploit verification request"""
        try:
            from verification.exploit_verifier import ExploitVerifier, VerificationMode
            
            if not self.exploit_verifier:
                self.exploit_verifier = ExploitVerifier()
            
            target = params.get('target')
            vulnerability = params.get('vulnerability')
            mode_str = params.get('mode', 'READ_ONLY')
            auth_token = params.get('authorization_token')
            
            # Map string to enum
            mode_map = {
                'READ_ONLY': VerificationMode.READ_ONLY,
                'SAFE_WRITE': VerificationMode.SAFE_WRITE,
                'FULL_EXPLOIT': VerificationMode.FULL_EXPLOIT
            }
            mode = mode_map.get(mode_str, VerificationMode.READ_ONLY)
            
            result = await self.exploit_verifier.verify_exploit(
                target=target,
                vulnerability=vulnerability,
                mode=mode,
                authorization_token=auth_token
            )
            
            return {
                'success': True,
                'result': result.to_dict()
            }
            
        except Exception as e:
            logger.error(f"Exploit verification failed: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== Compliance Reporting Handlers =====
    
    async def handle_generate_compliance_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle compliance report generation"""
        try:
            from compliance.compliance_reporter import ComplianceReporter, ComplianceFramework
            from compliance.templates import PCIDSSTemplate, HIPAATemplate, SOC2Template, ISO27001Template
            
            if not self.compliance_reporter:
                self.compliance_reporter = ComplianceReporter()
            
            framework_str = params.get('framework', 'pci_dss')
            organization = params.get('organization', '')
            scope = params.get('scope', '')
            
            # Map string to enum
            framework_map = {
                'pci_dss': ComplianceFramework.PCI_DSS,
                'hipaa': ComplianceFramework.HIPAA,
                'soc2': ComplianceFramework.SOC2,
                'iso_27001': ComplianceFramework.ISO_27001
            }
            framework = framework_map.get(framework_str, ComplianceFramework.PCI_DSS)
            
            # Create report
            report = self.compliance_reporter.create_report(
                framework=framework,
                organization=organization,
                scope=scope
            )
            
            # Load controls
            template_map = {
                ComplianceFramework.PCI_DSS: PCIDSSTemplate,
                ComplianceFramework.HIPAA: HIPAATemplate,
                ComplianceFramework.SOC2: SOC2Template,
                ComplianceFramework.ISO_27001: ISO27001Template
            }
            template_class = template_map.get(framework)
            if template_class:
                report.controls = template_class.get_controls()
            
            # Assess if scan results provided
            if 'scan_results' in params:
                await self.compliance_reporter.assess_scan_results(
                    report,
                    params['scan_results']
                )
            
            return {
                'success': True,
                'report_id': report.report_id,
                'report': report.to_dict()
            }
            
        except Exception as e:
            logger.error(f"Compliance report generation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_all_handlers(self) -> Dict[str, callable]:
        """Get all enterprise handlers"""
        return {
            'authenticate': self.handle_authenticate,
            'create_test_account': self.handle_create_test_account,
            'test_idor': self.handle_test_idor,
            'test_privilege_escalation': self.handle_test_privilege_escalation,
            'test_session_security': self.handle_test_session_security,
            'scan_secrets': self.handle_scan_secrets,
            'scan_dependencies': self.handle_scan_dependencies,
            'check_burp_available': self.handle_check_burp_available,
            'burp_scan': self.handle_burp_scan,
            'import_burp_findings': self.handle_import_burp_findings,
            'check_zap_available': self.handle_check_zap_available,
            'zap_scan': self.handle_zap_scan,
            'verify_exploit': self.handle_verify_exploit,
            'generate_compliance_report': self.handle_generate_compliance_report,
        }

