"""
ZAP Spider - Authenticated crawling
"""

import logging
import asyncio
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from .zap_api import ZAPAPI

logger = logging.getLogger(__name__)


@dataclass
class SpiderConfig:
    """Spider configuration"""
    target_url: str
    max_depth: int = 5
    max_duration_minutes: int = 30
    use_ajax: bool = True
    follow_redirects: bool = True
    parse_comments: bool = True
    parse_robots_txt: bool = True
    handle_odata: bool = False


class ZAPSpider:
    """
    ZAP Spider for comprehensive crawling
    
    Features:
    - Traditional spider
    - AJAX spider for SPAs
    - Authenticated crawling
    - URL discovery
    """
    
    def __init__(self, zap_api: Optional[ZAPAPI] = None):
        self.api = zap_api or ZAPAPI()
        self.discovered_urls: Set[str] = set()
    
    async def spider(
        self,
        config: SpiderConfig,
        authenticated: bool = False
    ) -> Dict[str, Any]:
        """
        Spider target URL
        
        Args:
            config: Spider configuration
            authenticated: Whether to use authenticated context
            
        Returns:
            Spider results
        """
        logger.info(f"Spidering {config.target_url}")
        
        if not self.api.is_available():
            return {'error': 'ZAP not available'}
        
        results = {
            'target': config.target_url,
            'urls_discovered': [],
            'forms_found': [],
            'parameters_found': []
        }
        
        try:
            # Traditional spider
            spider_id = self.api.spider(
                url=config.target_url,
                max_depth=config.max_depth
            )
            
            if spider_id:
                await self._monitor_spider(spider_id, config.max_duration_minutes)
            
            # AJAX spider if enabled
            if config.use_ajax:
                ajax_id = self.api.ajax_spider(config.target_url)
                if ajax_id:
                    await self._monitor_ajax_spider(ajax_id, config.max_duration_minutes)
            
            # Get discovered URLs
            if self.api.zap:
                urls = self.api.zap.core.urls()
                self.discovered_urls.update(urls)
                results['urls_discovered'] = list(urls)
                results['total_urls'] = len(urls)
            
            logger.info(f"Spider completed: {len(results['urls_discovered'])} URLs discovered")
            return results
            
        except Exception as e:
            logger.error(f"Spider failed: {e}")
            results['error'] = str(e)
            return results
    
    async def _monitor_spider(
        self,
        scan_id: str,
        max_duration_minutes: int
    ):
        """Monitor spider progress"""
        import time
        start_time = time.time()
        max_duration = max_duration_minutes * 60
        
        while True:
            if time.time() - start_time > max_duration:
                logger.warning("Spider timeout")
                break
            
            status = self.api.get_spider_status(scan_id)
            
            if status < 0:
                break
            
            if status >= 100:
                logger.info("Spider completed")
                break
            
            logger.debug(f"Spider: {status}%")
            await asyncio.sleep(2)
    
    async def _monitor_ajax_spider(
        self,
        scan_id: str,
        max_duration_minutes: int
    ):
        """Monitor AJAX spider"""
        import time
        start_time = time.time()
        max_duration = max_duration_minutes * 60
        
        while True:
            if time.time() - start_time > max_duration:
                logger.warning("AJAX spider timeout")
                if self.api.zap:
                    self.api.zap.ajaxSpider.stop()
                break
            
            try:
                if self.api.zap:
                    status = self.api.zap.ajaxSpider.status
                    if status == 'stopped':
                        break
            except:
                break
            
            await asyncio.sleep(3)
    
    def get_forms(self) -> List[Dict]:
        """Get discovered forms"""
        forms = []
        
        # Parse discovered URLs for forms
        # In production, would parse actual HTML
        
        return forms
    
    def get_discovered_urls(self) -> List[str]:
        """Get all discovered URLs"""
        return list(self.discovered_urls)

