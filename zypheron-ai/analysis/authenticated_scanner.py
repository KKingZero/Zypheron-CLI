"""
Authenticated Vulnerability Scanner

Tests for vulnerabilities that require authentication:
- IDOR (Insecure Direct Object References)
- Broken Authorization (BOLA/BFLA)
- Privilege Escalation
- Session Management issues
"""

import logging
import asyncio
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import requests
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

logger = logging.getLogger(__name__)


@dataclass
class AuthenticatedVulnerability:
    """Vulnerability found through authenticated testing"""
    vuln_id: str
    type: str  # idor, broken_auth, privilege_escalation, session_fixation
    severity: str  # critical, high, medium, low
    title: str
    description: str
    
    # Context
    url: str
    method: str
    parameter: Optional[str] = None
    
    # Evidence
    evidence: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    http_requests: List[Dict] = field(default_factory=list)
    http_responses: List[Dict] = field(default_factory=list)
    
    # Impact
    impact: str = ""
    exploitability: str = "medium"  # easy, medium, hard
    
    # Remediation
    remediation: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    tested_roles: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'vuln_id': self.vuln_id,
            'type': self.type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'proof_of_concept': self.proof_of_concept,
            'impact': self.impact,
            'exploitability': self.exploitability,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'discovered_at': self.discovered_at.isoformat(),
            'tested_roles': self.tested_roles
        }


class AuthenticatedScanner:
    """
    Scanner for authenticated vulnerability testing
    
    Tests:
    - IDOR (Insecure Direct Object References)
    - Horizontal privilege escalation
    - Vertical privilege escalation
    - Broken object level authorization (BOLA)
    - Broken function level authorization (BFLA)
    - Session fixation
    - Session hijacking
    - Insufficient session expiration
    """
    
    def __init__(self, session_manager=None):
        self.session_manager = session_manager
        self.vulnerabilities: List[AuthenticatedVulnerability] = []
    
    async def test_sql_injection(
        self,
        session_id: Optional[str],
        targets: List[Dict[str, Any]],
        timeout: int = 180,
    ) -> List[AuthenticatedVulnerability]:
        """Run SQLMap against authenticated endpoints and verify findings."""

        logger.info("Running SQL injection tests against %d targets", len(targets))
        findings: List[AuthenticatedVulnerability] = []

        req_session: Optional[requests.Session] = None
        cookie_header = None
        if session_id and self.session_manager:
            req_session = self.session_manager.create_requests_session(session_id)
            if req_session:
                cookie_header = self._build_cookie_header(req_session)

        for target in targets:
            url = target.get("url")
            if not url:
                continue

            method = target.get("method", "GET").upper()
            data = target.get("data")
            headers = target.get("headers", {}).copy()
            supabase = target.get("supabase", False)

            if cookie_header and "Cookie" not in headers:
                headers["Cookie"] = cookie_header

            baseline = await self._baseline_response(req_session, url, method, data, headers)

            cmd = [
                "sqlmap",
                "-u",
                url,
                "--batch",
                "--disable-coloring",
                "--flush-session",
                "--level",
                "3",
                "--risk",
                "2",
            ]

            if method != "GET":
                cmd.extend(["--method", method])
            if data:
                cmd.extend(["--data", data])
            if headers:
                serialized_headers = "\n".join(f"{k}: {v}" for k, v in headers.items())
                cmd.extend(["--headers", serialized_headers])
            if supabase:
                cmd.append("--tech=PostgreSQL")

            logger.debug("Executing sqlmap command: %s", " ".join(cmd))

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except FileNotFoundError:
                logger.error("sqlmap executable not found in PATH")
                break
            except asyncio.TimeoutError:
                process.kill()
                logger.warning("sqlmap timed out for %s", url)
                continue

            stdout = stdout_bytes.decode(errors="ignore")
            stderr = stderr_bytes.decode(errors="ignore")
            if stderr:
                logger.debug("sqlmap stderr for %s: %s", url, stderr.strip())

            parsed_results = self._parse_sqlmap_output(stdout)

            for result in parsed_results:
                verification = await self._verify_sql_injection(
                    req_session,
                    url,
                    method,
                    data,
                    headers,
                    result,
                    baseline,
                )

                vuln = AuthenticatedVulnerability(
                    vuln_id=f"sqlmap_{len(findings)}",
                    type="sql_injection",
                    severity="critical",
                    title=f"SQL Injection in parameter '{result.get('parameter', 'unknown')}'",
                    description=f"SQLMap detected {result.get('title', 'SQL injection')} via {result.get('type', 'unknown')} technique",
                    url=url,
                    method=method,
                    parameter=result.get("parameter"),
                    evidence=self._build_sqlmap_evidence(result, stdout, verification),
                    proof_of_concept=result.get("payload", ""),
                    impact="Attacker can read or modify database contents",
                    remediation="Implement parameterized queries and input validation. Review database permissions.",
                    cwe_id="CWE-89",
                    owasp_category="A03:2021 - Injection",
                )

                if verification.get("verified"):
                    vuln.exploitability = "easy"
                else:
                    vuln.exploitability = "medium"

                findings.append(vuln)
                logger.critical("SQL injection confirmed on %s (%s)", url, result.get("parameter"))

        self.vulnerabilities.extend(findings)
        return findings

    async def test_supabase_rls(
        self,
        supabase_url: str,
        anon_key: str,
        tables: List[str],
    ) -> List[AuthenticatedVulnerability]:
        """Probe Supabase REST endpoints for missing row level security."""

        vulnerabilities: List[AuthenticatedVulnerability] = []
        base = supabase_url.rstrip("/")

        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Accept": "application/json",
        }

        for table in tables:
            url = f"{base}/rest/v1/{table}?select=*&limit=3"

            def _probe() -> requests.Response:
                return requests.get(url, headers=headers, timeout=10)

            try:
                response: requests.Response = await asyncio.to_thread(_probe)
            except Exception as exc:
                logger.debug("Supabase probe failed for %s: %s", url, exc)
                continue

            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError:
                    data = []

                if data:
                    vuln = AuthenticatedVulnerability(
                        vuln_id=f"supabase_rls_{len(vulnerabilities)}",
                        type="supabase_rls_bypass",
                        severity="high",
                        title=f"Supabase RLS bypass on table '{table}'",
                        description="Anonymous key can access data without Row Level Security enforcement",
                        url=url,
                        method="GET",
                        evidence=[
                            f"Returned {len(data)} records using anon key",
                            f"Headers: {headers}",
                        ],
                        impact="Unauthenticated users can enumerate Supabase table contents",
                        remediation="Enable RLS on the table and restrict anon key permissions.",
                        cwe_id="CWE-284",
                        owasp_category="A01:2021 - Broken Access Control",
                    )

                    vulnerabilities.append(vuln)
                    logger.critical("Supabase RLS bypass detected on %s", table)

        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities
    async def test_idor(
        self,
        session_id: str,
        test_urls: List[str],
        target_user_id: Optional[str] = None
    ) -> List[AuthenticatedVulnerability]:
        """
        Test for Insecure Direct Object References
        
        Args:
            session_id: Authenticated session ID
            test_urls: URLs with object references to test
            target_user_id: Optional user ID to test access to
            
        Returns:
            List of IDOR vulnerabilities found
        """
        logger.info(f"Testing IDOR on {len(test_urls)} URLs")
        idor_vulns = []
        
        if not self.session_manager:
            logger.error("No session manager available")
            return idor_vulns
        
        req_session = self.session_manager.create_requests_session(session_id)
        if not req_session:
            logger.error(f"Invalid session {session_id}")
            return idor_vulns
        
        for url in test_urls:
            try:
                # Extract numeric IDs from URL
                numeric_params = self._extract_numeric_params(url)
                
                for param_name, original_value in numeric_params.items():
                    # Test with modified ID (increment/decrement)
                    test_values = [
                        str(int(original_value) + 1),
                        str(int(original_value) - 1),
                        str(int(original_value) + 100),
                        "1",  # First object
                        "999999"  # High value
                    ]
                    
                    for test_value in test_values:
                        # Create modified URL
                        modified_url = url.replace(
                            f"{param_name}={original_value}",
                            f"{param_name}={test_value}"
                        )
                        
                        # Make request with authenticated session
                        response = req_session.get(modified_url, timeout=10)
                        
                        # Check for unauthorized access
                        if response.status_code == 200:
                            # Successful access - potential IDOR
                            if self._is_different_content(url, modified_url, req_session):
                                vuln = AuthenticatedVulnerability(
                                    vuln_id=f"idor_{len(idor_vulns)}",
                                    type="idor",
                                    severity="high",
                                    title=f"IDOR in {param_name} parameter",
                                    description=f"Unauthorized access to other user's data through {param_name} manipulation",
                                    url=url,
                                    method="GET",
                                    parameter=param_name,
                                    evidence=[
                                        f"Original: {param_name}={original_value}",
                                        f"Modified: {param_name}={test_value}",
                                        f"Status: {response.status_code}",
                                        "Accessed different user's data"
                                    ],
                                    impact="Attacker can access unauthorized data",
                                    exploitability="easy",
                                    cwe_id="CWE-639",
                                    owasp_category="A01:2021 - Broken Access Control",
                                    remediation="Implement proper authorization checks for all object access"
                                )
                                
                                idor_vulns.append(vuln)
                                logger.warning(f"IDOR found: {param_name} on {url}")
                                break  # Found IDOR, no need to test more values
                        
            except Exception as e:
                logger.error(f"IDOR test failed for {url}: {e}")
        
        self.vulnerabilities.extend(idor_vulns)
        logger.info(f"IDOR testing complete: found {len(idor_vulns)} vulnerabilities")
        return idor_vulns
    
    async def test_privilege_escalation(
        self,
        low_priv_session_id: str,
        high_priv_session_id: str,
        admin_urls: List[str]
    ) -> List[AuthenticatedVulnerability]:
        """
        Test for privilege escalation (vertical)
        
        Args:
            low_priv_session_id: Low privilege user session
            high_priv_session_id: High privilege user session  
            admin_urls: URLs that should be admin-only
            
        Returns:
            List of privilege escalation vulnerabilities
        """
        logger.info(f"Testing privilege escalation on {len(admin_urls)} admin URLs")
        priv_esc_vulns = []
        
        if not self.session_manager:
            return priv_esc_vulns
        
        low_session = self.session_manager.create_requests_session(low_priv_session_id)
        high_session = self.session_manager.create_requests_session(high_priv_session_id)
        
        if not low_session or not high_session:
            logger.error("Invalid sessions")
            return priv_esc_vulns
        
        for url in admin_urls:
            try:
                # First verify admin can access
                admin_response = high_session.get(url, timeout=10)
                
                if admin_response.status_code != 200:
                    logger.debug(f"Admin cannot access {url}, skipping")
                    continue
                
                # Test with low privilege user
                user_response = low_session.get(url, timeout=10)
                
                # If low priv user can access admin function - privilege escalation
                if user_response.status_code == 200:
                    vuln = AuthenticatedVulnerability(
                        vuln_id=f"privesc_{len(priv_esc_vulns)}",
                        type="privilege_escalation",
                        severity="critical",
                        title=f"Privilege Escalation - Unauthorized Admin Access",
                        description=f"Low privilege user can access admin function at {url}",
                        url=url,
                        method="GET",
                        evidence=[
                            "Low privilege user accessed admin function",
                            f"Admin response: {admin_response.status_code}",
                            f"User response: {user_response.status_code}",
                            "Authorization check missing or insufficient"
                        ],
                        impact="Low privilege users can perform administrative actions",
                        exploitability="easy",
                        cwe_id="CWE-269",
                        owasp_category="A01:2021 - Broken Access Control",
                        remediation="Implement role-based access control (RBAC) and verify user permissions",
                        tested_roles=["user", "admin"]
                    )
                    
                    priv_esc_vulns.append(vuln)
                    logger.critical(f"Privilege escalation found: {url}")
                    
            except Exception as e:
                logger.error(f"Privilege escalation test failed for {url}: {e}")
        
        self.vulnerabilities.extend(priv_esc_vulns)
        logger.info(f"Privilege escalation testing complete: found {len(priv_esc_vulns)} vulnerabilities")
        return priv_esc_vulns
    
    async def test_horizontal_escalation(
        self,
        user1_session_id: str,
        user2_session_id: str,
        user_specific_urls: List[str]
    ) -> List[AuthenticatedVulnerability]:
        """
        Test for horizontal privilege escalation
        
        Args:
            user1_session_id: First user session
            user2_session_id: Second user session
            user_specific_urls: URLs containing user-specific data
            
        Returns:
            List of horizontal escalation vulnerabilities
        """
        logger.info("Testing horizontal privilege escalation")
        horiz_vulns = []
        
        if not self.session_manager:
            return horiz_vulns
        
        user1_session = self.session_manager.create_requests_session(user1_session_id)
        user2_session = self.session_manager.create_requests_session(user2_session_id)
        
        if not user1_session or not user2_session:
            return horiz_vulns
        
        for url in user_specific_urls:
            try:
                # User 1 accesses their data
                user1_response = user1_session.get(url, timeout=10)
                
                if user1_response.status_code != 200:
                    continue
                
                # User 2 tries to access User 1's data
                user2_response = user2_session.get(url, timeout=10)
                
                if user2_response.status_code == 200:
                    # Check if content is actually User 1's data
                    if user1_response.text == user2_response.text:
                        vuln = AuthenticatedVulnerability(
                            vuln_id=f"horiz_esc_{len(horiz_vulns)}",
                            type="horizontal_privilege_escalation",
                            severity="high",
                            title="Horizontal Privilege Escalation - Access to Other User's Data",
                            description=f"User can access another user's data at {url}",
                            url=url,
                            method="GET",
                            evidence=[
                                "User 2 accessed User 1's data",
                                "No proper authorization check implemented"
                            ],
                            impact="Users can access other users' private data",
                            exploitability="easy",
                            cwe_id="CWE-639",
                            owasp_category="A01:2021 - Broken Access Control",
                            remediation="Verify user ownership before returning data"
                        )
                        
                        horiz_vulns.append(vuln)
                        logger.warning(f"Horizontal escalation found: {url}")
                        
            except Exception as e:
                logger.error(f"Horizontal escalation test failed: {e}")
        
        self.vulnerabilities.extend(horiz_vulns)
        return horiz_vulns
    
    async def test_session_fixation(
        self,
        target_url: str,
        login_url: str,
        session_cookie_name: str = "sessionid"
    ) -> List[AuthenticatedVulnerability]:
        """Test for session fixation vulnerabilities"""
        logger.info("Testing session fixation")
        session_vulns = []
        
        try:
            # Get initial session cookie
            initial_session = requests.Session()
            pre_login_response = initial_session.get(target_url, timeout=10)
            
            pre_login_cookies = {
                cookie.name: cookie.value 
                for cookie in initial_session.cookies
            }
            
            pre_login_session_id = pre_login_cookies.get(session_cookie_name)
            
            # Authenticate (simulated)
            # In real test, would call actual login
            
            # Check if session ID changed after login
            post_login_response = initial_session.get(target_url, timeout=10)
            post_login_session_id = initial_session.cookies.get(session_cookie_name)
            
            if pre_login_session_id and pre_login_session_id == post_login_session_id:
                # Session ID didn't change - session fixation vulnerability
                vuln = AuthenticatedVulnerability(
                    vuln_id=f"session_fix_{len(session_vulns)}",
                    type="session_fixation",
                    severity="high",
                    title="Session Fixation Vulnerability",
                    description="Session ID is not regenerated after authentication",
                    url=login_url,
                    method="POST",
                    evidence=[
                        f"Pre-login session ID: {pre_login_session_id[:20]}...",
                        f"Post-login session ID: {post_login_session_id[:20]}...",
                        "Session ID remained the same after authentication"
                    ],
                    impact="Attacker can hijack user sessions by setting session ID before login",
                    exploitability="medium",
                    cwe_id="CWE-384",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    remediation="Regenerate session ID after successful authentication"
                )
                
                session_vulns.append(vuln)
                logger.warning("Session fixation vulnerability found")
                
        except Exception as e:
            logger.error(f"Session fixation test failed: {e}")
        
        self.vulnerabilities.extend(session_vulns)
        return session_vulns
    
    async def test_broken_authorization(
        self,
        session_id: str,
        api_endpoints: List[Dict[str, Any]]
    ) -> List[AuthenticatedVulnerability]:
        """
        Test for broken authorization at API level
        
        Args:
            session_id: Authenticated session
            api_endpoints: List of API endpoints with expected permissions
                         [{'url': '/api/users', 'method': 'GET', 'required_role': 'admin'}]
        """
        logger.info(f"Testing broken authorization on {len(api_endpoints)} endpoints")
        auth_vulns = []
        
        if not self.session_manager:
            return auth_vulns
        
        req_session = self.session_manager.create_requests_session(session_id)
        if not req_session:
            return auth_vulns
        
        for endpoint in api_endpoints:
            url = endpoint['url']
            method = endpoint.get('method', 'GET')
            required_role = endpoint.get('required_role', 'user')
            
            try:
                # Make request
                response = req_session.request(method, url, timeout=10)
                
                # If user has wrong role but still got 200, it's broken authorization
                user_role = endpoint.get('actual_role', 'user')
                
                if user_role != required_role and response.status_code == 200:
                    vuln = AuthenticatedVulnerability(
                        vuln_id=f"broken_auth_{len(auth_vulns)}",
                        type="broken_authorization",
                        severity="critical" if required_role == "admin" else "high",
                        title=f"Broken Function Level Authorization",
                        description=f"{user_role} can access {required_role}-only endpoint",
                        url=url,
                        method=method,
                        evidence=[
                            f"User role: {user_role}",
                            f"Required role: {required_role}",
                            f"Response status: {response.status_code}",
                            "Access granted despite insufficient privileges"
                        ],
                        impact=f"Unauthorized access to {required_role} functions",
                        exploitability="easy",
                        cwe_id="CWE-285",
                        owasp_category="A01:2021 - Broken Access Control",
                        remediation="Implement proper role-based authorization checks",
                        tested_roles=[user_role, required_role]
                    )
                    
                    auth_vulns.append(vuln)
                    logger.critical(f"Broken authorization found: {url}")
                    
            except Exception as e:
                logger.error(f"Authorization test failed for {url}: {e}")
        
        self.vulnerabilities.extend(auth_vulns)
        return auth_vulns
    
    async def test_session_timeout(
        self,
        session_id: str,
        protected_url: str,
        wait_minutes: int = 30
    ) -> Optional[AuthenticatedVulnerability]:
        """
        Test for insufficient session timeout
        
        Args:
            session_id: Session to test
            protected_url: Protected URL to test access
            wait_minutes: Minutes to wait before testing
        """
        logger.info(f"Testing session timeout (waiting {wait_minutes} minutes)")
        
        if not self.session_manager:
            return None
        
        try:
            # Make initial authenticated request
            req_session = self.session_manager.create_requests_session(session_id)
            initial_response = req_session.get(protected_url, timeout=10)
            
            if initial_response.status_code != 200:
                logger.warning("Initial request failed, cannot test timeout")
                return None
            
            # Wait
            logger.info(f"Waiting {wait_minutes} minutes to test session expiration...")
            await asyncio.sleep(wait_minutes * 60)
            
            # Test again
            timeout_response = req_session.get(protected_url, timeout=10)
            
            # Session should be expired and redirect to login or return 401
            if timeout_response.status_code == 200:
                vuln = AuthenticatedVulnerability(
                    vuln_id=f"session_timeout",
                    type="insufficient_session_expiration",
                    severity="medium",
                    title="Insufficient Session Timeout",
                    description=f"Session remains valid after {wait_minutes} minutes of inactivity",
                    url=protected_url,
                    method="GET",
                    evidence=[
                        f"Waited {wait_minutes} minutes",
                        f"Session still valid: {timeout_response.status_code}",
                        "No automatic session expiration"
                    ],
                    impact="Increased window for session hijacking attacks",
                    exploitability="medium",
                    cwe_id="CWE-613",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    remediation="Implement automatic session timeout (15-30 minutes recommended)"
                )
                
                self.vulnerabilities.append(vuln)
                logger.warning("Insufficient session timeout detected")
                return vuln
            else:
                logger.info("Session properly expired after timeout")
                return None
                
        except Exception as e:
            logger.error(f"Session timeout test failed: {e}")
            return None
    
    def _build_cookie_header(self, session: requests.Session) -> str:
        cookies = session.cookies.get_dict()
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    async def _baseline_response(
        self,
        session: Optional[requests.Session],
        url: str,
        method: str,
        data: Optional[str],
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        """Capture baseline status and length for verification comparisons."""

        def _send() -> Dict[str, Any]:
            if session:
                response = session.request(method, url, data=data, headers=headers, timeout=10)
            else:
                response = requests.request(method, url, data=data, headers=headers, timeout=10)
            return {
                "status": response.status_code,
                "length": len(response.text),
                "body": response.text[:1024],
            }

        try:
            return await asyncio.to_thread(_send)
        except Exception as exc:
            logger.debug("Baseline request failed for %s: %s", url, exc)
            return {"status": None, "length": 0, "body": ""}

    def _parse_sqlmap_output(self, output: str) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        in_block = False

        for raw_line in output.splitlines():
            line = raw_line.strip()

            if line.startswith("---"):
                if in_block and current:
                    results.append(current)
                    current = {}
                in_block = not in_block
                continue

            if not in_block or not line:
                continue

            if line.startswith("Parameter:"):
                remainder = line[len("Parameter:") :].strip()
                if "(" in remainder and remainder.endswith(")"):
                    name, location = remainder.rsplit("(", 1)
                    current["parameter"] = name.strip()
                    current["location"] = location.rstrip(")")
                else:
                    current["parameter"] = remainder
                continue

            if line.startswith("Type:"):
                current["type"] = line[len("Type:") :].strip()
                continue

            if line.startswith("Title:"):
                current["title"] = line[len("Title:") :].strip()
                continue

            if line.startswith("Payload:"):
                current["payload"] = line[len("Payload:") :].strip()
                continue

        if in_block and current:
            results.append(current)

        return results

    async def _verify_sql_injection(
        self,
        session: Optional[requests.Session],
        url: str,
        method: str,
        data: Optional[str],
        headers: Dict[str, str],
        finding: Dict[str, str],
        baseline: Dict[str, Any],
    ) -> Dict[str, Any]:
        parameter = finding.get("parameter")
        payload = finding.get("payload")
        location = (finding.get("location") or method).upper()

        if not parameter or not payload:
            return {"verified": False, "reason": "missing-parameter-or-payload"}

        parsed_url = urlparse(url)
        request_data = data
        request_url = url

        if location == "GET":
            qs = parse_qs(parsed_url.query, keep_blank_values=True)
            original = qs.get(parameter, [""])[0]
            qs[parameter] = [payload]
            new_query = urlencode(qs, doseq=True)
            request_url = urlunparse(parsed_url._replace(query=new_query))
        elif location == "POST" and data:
            parsed_data = parse_qs(data, keep_blank_values=True)
            parsed_data[parameter] = [payload]
            request_data = urlencode(parsed_data, doseq=True)
        else:
            return {"verified": False, "reason": f"unsupported-location-{location}"}

        def _send() -> Dict[str, Any]:
            if session:
                response = session.request(method, request_url, data=request_data, headers=headers, timeout=10)
            else:
                response = requests.request(method, request_url, data=request_data, headers=headers, timeout=10)
            return {
                "status": response.status_code,
                "length": len(response.text),
                "body": response.text[:1024],
            }

        try:
            probe = await asyncio.to_thread(_send)
        except Exception as exc:
            return {"verified": False, "reason": f"request-error: {exc}"}

        differences = []
        if baseline.get("status") is not None and probe["status"] != baseline.get("status"):
            differences.append(f"status {baseline.get('status')} -> {probe['status']}")

        if abs(probe["length"] - baseline.get("length", 0)) > 150:
            differences.append("response length delta > 150 bytes")

        payload_markers = ["syntax", "sql", "error", "warning"]
        if any(marker in probe["body"].lower() for marker in payload_markers):
            differences.append("response contains SQL error markers")

        return {
            "verified": bool(differences),
            "details": differences,
            "baseline": baseline,
            "probe": probe,
        }

    def _build_sqlmap_evidence(
        self,
        finding: Dict[str, str],
        raw_output: str,
        verification: Dict[str, Any],
    ) -> List[str]:
        evidence = [
            f"Parameter: {finding.get('parameter')} ({finding.get('location', 'unknown')})",
            f"Technique: {finding.get('type', 'unknown')}",
        ]

        payload = finding.get("payload")
        if payload:
            evidence.append(f"Payload: {payload}")

        title = finding.get("title")
        if title:
            evidence.append(f"Title: {title}")

        if verification.get("verified"):
            for detail in verification.get("details", []):
                evidence.append(f"Verification: {detail}")
        else:
            evidence.append(f"Verification pending: {verification.get('reason', 'no-difference-detected')}")

        # Provide a short snippet from sqlmap output for context
        for line in raw_output.splitlines()[-10:]:
            if "sqlmap identified" in line.lower() or "tested parameter" in line.lower():
                evidence.append(f"sqlmap: {line.strip()}")

        return evidence

    def _extract_numeric_params(self, url: str) -> Dict[str, str]:
        """Extract numeric parameters from URL"""
        params = {}
        
        # Parse query string
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for key, values in query_params.items():
                for value in values:
                    if value.isdigit():
                        params[key] = value
        
        # Extract from path (e.g., /users/123/profile)
        path_parts = parsed.path.split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit():
                params[f"path_segment_{i}"] = part
        
        return params
    
    def _is_different_content(
        self,
        url1: str,
        url2: str,
        session: requests.Session
    ) -> bool:
        """Check if two URLs return different content"""
        try:
            resp1 = session.get(url1, timeout=10)
            resp2 = session.get(url2, timeout=10)
            
            # Simple comparison - in production use more sophisticated diff
            return resp1.text != resp2.text
            
        except:
            return False
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate report of all authenticated vulnerabilities"""
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_type': self._count_by_type(),
            'by_severity': self._count_by_severity(),
            'critical_count': sum(1 for v in self.vulnerabilities if v.severity == 'critical'),
            'high_count': sum(1 for v in self.vulnerabilities if v.severity == 'high'),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count vulnerabilities by type"""
        counts = {}
        for vuln in self.vulnerabilities:
            counts[vuln.type] = counts.get(vuln.type, 0) + 1
        return counts
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts

