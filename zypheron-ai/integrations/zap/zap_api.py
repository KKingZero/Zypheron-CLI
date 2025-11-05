"""
OWASP ZAP REST API Client
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import time

logger = logging.getLogger(__name__)


@dataclass
class ZAPConfig:
    """ZAP configuration"""
    host: str = "127.0.0.1"
    port: int = 8080
    api_key: Optional[str] = None
    proxy_port: int = 8080
    
    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
    
    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self.proxy_port}"


class ZAPAPI:
    """
    OWASP ZAP API Client
    
    Features:
    - Spider (traditional and AJAX)
    - Active scanning
    - Passive scanning
    - Authentication
    - Context management
    - Alert retrieval
    
    Requires: OWASP ZAP running with API enabled
    """
    
    def __init__(self, config: Optional[ZAPConfig] = None):
        self.config = config or ZAPConfig()
        
        try:
            from zapv2 import ZAPv2
            self.zap = ZAPv2(
                apikey=self.config.api_key,
                proxies={
                    'http': self.config.proxy_url,
                    'https': self.config.proxy_url
                }
            )
        except ImportError:
            logger.error("python-owasp-zap-v2.4 not installed")
            self.zap = None
    
    def is_available(self) -> bool:
        """Check if ZAP is running"""
        if not self.zap:
            return False
        
        try:
            version = self.zap.core.version
            logger.info(f"ZAP {version} available")
            return True
        except Exception as e:
            logger.debug(f"ZAP not available: {e}")
            return False
    
    def spider(
        self,
        url: str,
        max_depth: int = 5,
        max_children: int = 0
    ) -> Optional[str]:
        """
        Start traditional spider scan
        
        Args:
            url: Target URL
            max_depth: Maximum spider depth
            max_children: Maximum children to spider (0 = unlimited)
            
        Returns:
            Scan ID
        """
        if not self.zap:
            return None
        
        try:
            scan_id = self.zap.spider.scan(
                url=url,
                maxdepth=max_depth,
                maxchildren=max_children
            )
            
            logger.info(f"Started ZAP spider: {scan_id}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start ZAP spider: {e}")
            return None
    
    def ajax_spider(
        self,
        url: str,
        in_scope: bool = True
    ) -> Optional[str]:
        """
        Start AJAX spider for JavaScript-heavy applications
        
        Args:
            url: Target URL
            in_scope: Only spider in-scope URLs
            
        Returns:
            Scan ID
        """
        if not self.zap:
            return None
        
        try:
            scan_id = self.zap.ajaxSpider.scan(
                url=url,
                inscope=in_scope
            )
            
            logger.info(f"Started ZAP AJAX spider: {scan_id}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start AJAX spider: {e}")
            return None
    
    def active_scan(
        self,
        url: str,
        recurse: bool = True,
        in_scope_only: bool = True
    ) -> Optional[str]:
        """
        Start active scan
        
        Args:
            url: Target URL
            recurse: Scan descendants
            in_scope_only: Only scan in-scope URLs
            
        Returns:
            Scan ID
        """
        if not self.zap:
            return None
        
        try:
            scan_id = self.zap.ascan.scan(
                url=url,
                recurse=recurse,
                inscope=in_scope_only
            )
            
            logger.info(f"Started ZAP active scan: {scan_id}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to start active scan: {e}")
            return None
    
    def get_spider_status(self, scan_id: str) -> int:
        """Get spider progress (0-100)"""
        if not self.zap:
            return -1
        
        try:
            status = int(self.zap.spider.status(scan_id))
            return status
        except Exception as e:
            logger.error(f"Failed to get spider status: {e}")
            return -1
    
    def get_scan_status(self, scan_id: str) -> int:
        """Get active scan progress (0-100)"""
        if not self.zap:
            return -1
        
        try:
            status = int(self.zap.ascan.status(scan_id))
            return status
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            return -1
    
    def get_alerts(
        self,
        base_url: Optional[str] = None,
        risk: Optional[str] = None
    ) -> List[Dict]:
        """
        Get all alerts/issues
        
        Args:
            base_url: Filter by base URL
            risk: Filter by risk level (High, Medium, Low, Informational)
            
        Returns:
            List of alerts
        """
        if not self.zap:
            return []
        
        try:
            if base_url:
                alerts = self.zap.core.alerts(baseurl=base_url, risk=risk)
            else:
                alerts = self.zap.core.alerts(risk=risk)
            
            logger.info(f"Retrieved {len(alerts)} ZAP alerts")
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to get ZAP alerts: {e}")
            return []
    
    def set_authentication(
        self,
        context_name: str,
        login_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str
    ) -> bool:
        """Configure form-based authentication"""
        if not self.zap:
            return False
        
        try:
            # Create context
            context_id = self.zap.context.new_context(context_name)
            
            # Set login URL
            self.zap.authentication.set_logged_in_indicator(
                contextid=context_id,
                loggedinindicatorregex='\\Qlogout\\E'
            )
            
            # Set authentication method
            login_request_data = f"{username_field}={username}&{password_field}={password}"
            
            self.zap.authentication.set_authentication_method(
                contextid=context_id,
                authmethodname='formBasedAuthentication',
                authmethodconfigparams=f'loginUrl={login_url}&loginRequestData={login_request_data}'
            )
            
            # Create user
            user_id = self.zap.users.new_user(context_id, username)
            self.zap.users.set_authentication_credentials(
                contextid=context_id,
                userid=user_id,
                authcredentialsconfigparams=f"username={username}&password={password}"
            )
            
            logger.info(f"Configured ZAP authentication for {context_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure authentication: {e}")
            return False
    
    def add_to_scope(self, url: str) -> bool:
        """Add URL to scope"""
        if not self.zap:
            return False
        
        try:
            self.zap.core.include_in_context('Default', url)
            logger.info(f"Added {url} to ZAP scope")
            return True
        except Exception as e:
            logger.error(f"Failed to add to scope: {e}")
            return False
    
    def generate_report(
        self,
        title: str,
        template: str = 'traditional-html',
        output_file: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate ZAP report
        
        Args:
            title: Report title
            template: Report template
            output_file: Optional output file path
            
        Returns:
            Report content
        """
        if not self.zap:
            return None
        
        try:
            report = self.zap.core.htmlreport()
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(report)
                logger.info(f"Generated ZAP report: {output_file}")
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate ZAP report: {e}")
            return None
    
    def clear_session(self) -> bool:
        """Clear ZAP session data"""
        if not self.zap:
            return False
        
        try:
            self.zap.core.new_session()
            logger.info("Cleared ZAP session")
            return True
        except Exception as e:
            logger.error(f"Failed to clear ZAP session: {e}")
            return False

