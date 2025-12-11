"""
ZAP Scanner Orchestration
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from .zap_api import ZAPAPI, ZAPConfig

logger = logging.getLogger(__name__)


@dataclass
class ZAPScanConfig:
    """ZAP scan configuration"""
    target_url: str
    scan_type: str = "both"  # spider, active, passive, both
    
    # Spider options
    use_ajax_spider: bool = True
    max_depth: int = 5
    
    # Active scan options
    scan_policy: str = "default"
    recurse: bool = True
    
    # Authentication
    auth_context: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Scope
    in_scope_only: bool = True
    exclude_patterns: List[str] = field(default_factory=list)
    
    # Performance
    max_duration_minutes: int = 60
    thread_count: int = 5


class ZAPScanner:
    """
    ZAP Scanner Orchestration
    
    Features:
    - Traditional and AJAX spidering
    - Active and passive scanning  
    - Authentication context management
    - Result processing
    """
    
    def __init__(self, zap_api: Optional[ZAPAPI] = None):
        self.api = zap_api or ZAPAPI()
        self.scan_results: Dict[str, Dict] = {}
    
    async def run_scan(
        self,
        config: ZAPScanConfig,
        wait_for_completion: bool = True
    ) -> Dict[str, Any]:
        """
        Run comprehensive ZAP scan
        
        Args:
            config: Scan configuration
            wait_for_completion: Wait for scan to complete
            
        Returns:
            Scan results
        """
        logger.info(f"Starting ZAP scan for {config.target_url}")
        
        if not self.api.is_available():
            logger.error("ZAP is not running")
            return {'error': 'ZAP not available'}
        
        scan_id = f"zap_{int(time.time())}"
        results = {
            'scan_id': scan_id,
            'target': config.target_url,
            'spider_scan_id': None,
            'active_scan_id': None,
            'alerts': []
        }
        
        try:
            # Add to scope
            self.api.add_to_scope(config.target_url)
            
            # Configure authentication if provided
            if config.username and config.password:
                self.api.set_authentication(
                    context_name=config.auth_context or "Default",
                    login_url=f"{config.target_url}/login",
                    username_field="username",
                    password_field="password",
                    username=config.username,
                    password=config.password
                )
            
            # Spider phase
            if config.scan_type in ['spider', 'both']:
                logger.info("Starting spider phase")
                
                if config.use_ajax_spider:
                    ajax_id = self.api.ajax_spider(config.target_url)
                    if ajax_id and wait_for_completion:
                        await self._wait_for_ajax_spider(ajax_id)
                
                spider_id = self.api.spider(config.target_url, max_depth=config.max_depth)
                results['spider_scan_id'] = spider_id
                
                if spider_id and wait_for_completion:
                    await self._wait_for_spider(spider_id)
            
            # Active scan phase
            if config.scan_type in ['active', 'both']:
                logger.info("Starting active scan phase")
                
                active_id = self.api.active_scan(
                    config.target_url,
                    recurse=config.recurse,
                    in_scope_only=config.in_scope_only
                )
                results['active_scan_id'] = active_id
                
                if active_id and wait_for_completion:
                    await self._wait_for_active_scan(active_id, config.max_duration_minutes)
            
            # Get alerts
            alerts = self.api.get_alerts(base_url=config.target_url)
            results['alerts'] = alerts
            results['total_alerts'] = len(alerts)
            
            # Store results
            self.scan_results[scan_id] = results
            
            logger.info(f"ZAP scan completed: {len(alerts)} alerts found")
            return results
            
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            results['error'] = str(e)
            return results
    
    async def _wait_for_spider(self, scan_id: str):
        """Wait for spider to complete"""
        logger.info(f"Waiting for spider {scan_id}")
        
        while True:
            status = self.api.get_spider_status(scan_id)
            
            if status < 0:
                logger.error("Failed to get spider status")
                break
            
            if status >= 100:
                logger.info("Spider completed")
                break
            
            logger.debug(f"Spider progress: {status}%")
            await asyncio.sleep(2)
    
    async def _wait_for_ajax_spider(self, scan_id: str):
        """Wait for AJAX spider to complete"""
        logger.info(f"Waiting for AJAX spider {scan_id}")
        
        # AJAX spider doesn't have numeric progress
        # Wait for it to finish
        while True:
            try:
                status = self.api.zap.ajaxSpider.status
                if status == 'stopped':
                    logger.info("AJAX spider completed")
                    break
                await asyncio.sleep(3)
            except:
                break
    
    async def _wait_for_active_scan(
        self,
        scan_id: str,
        max_duration_minutes: int
    ):
        """Wait for active scan to complete"""
        logger.info(f"Waiting for active scan {scan_id}")
        
        start_time = time.time()
        max_duration = max_duration_minutes * 60
        
        while True:
            # Check timeout
            if time.time() - start_time > max_duration:
                logger.warning(f"Active scan timeout after {max_duration_minutes}m")
                break
            
            status = self.api.get_scan_status(scan_id)
            
            if status < 0:
                logger.error("Failed to get scan status")
                break
            
            if status >= 100:
                logger.info("Active scan completed")
                break
            
            logger.debug(f"Active scan progress: {status}%")
            await asyncio.sleep(5)
    
    def get_high_risk_alerts(self, scan_id: Optional[str] = None) -> List[Dict]:
        """Get high risk alerts"""
        if scan_id and scan_id in self.scan_results:
            alerts = self.scan_results[scan_id].get('alerts', [])
        else:
            alerts = self.api.get_alerts(risk='High')
        
        return [a for a in alerts if a.get('risk', '').lower() == 'high']
    
    def convert_to_zypheron_format(self, alerts: List[Dict]) -> List[Dict]:
        """Convert ZAP alerts to Zypheron vulnerability format"""
        vulnerabilities = []
        
        # Map ZAP risk to Zypheron severity
        risk_map = {
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'informational': 'info'
        }
        
        for alert in alerts:
            vuln = {
                'id': f"zap_{alert.get('id', hash(str(alert)))}",
                'title': alert.get('name', 'Unknown'),
                'description': alert.get('description', ''),
                'severity': risk_map.get(alert.get('risk', '').lower(), 'medium'),
                'url': alert.get('url', ''),
                'parameter': alert.get('param', ''),
                'attack': alert.get('attack', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'cwe_id': f"CWE-{alert.get('cweid')}" if alert.get('cweid') else None,
                'wasc_id': alert.get('wascid'),
                'source': 'owasp_zap',
                'confidence': alert.get('confidence', 'Medium')
            }
            
            vulnerabilities.append(vuln)
        
        logger.info(f"Converted {len(vulnerabilities)} ZAP alerts to Zypheron format")
        return vulnerabilities

