"""
Burp Suite REST API Client

Provides programmatic access to Burp Suite Professional features.
"""

import logging
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import time
import json

logger = logging.getLogger(__name__)


@dataclass
class BurpConfig:
    """Burp Suite configuration"""
    host: str = "127.0.0.1"
    port: int = 1337  # Burp REST API default port
    api_key: Optional[str] = None
    use_ssl: bool = False
    
    @property
    def base_url(self) -> str:
        protocol = "https" if self.use_ssl else "http"
        return f"{protocol}://{self.host}:{self.port}"


class BurpAPI:
    """
    Burp Suite REST API Client
    
    Features:
    - Project management
    - Scan orchestration
    - Issue retrieval
    - Proxy configuration
    - Extension management
    
    Requires: Burp Suite Professional with REST API enabled
    """
    
    def __init__(self, config: Optional[BurpConfig] = None):
        self.config = config or BurpConfig()
        self.session = requests.Session()
        
        if self.config.api_key:
            self.session.headers['X-Burp-API-Key'] = self.config.api_key
    
    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> requests.Response:
        """Make API request to Burp"""
        url = f"{self.config.base_url}{endpoint}"
        
        try:
            response = self.session.request(
                method,
                url,
                timeout=30,
                **kwargs
            )
            response.raise_for_status()
            return response
        except Exception as e:
            logger.error(f"Burp API request failed: {e}")
            raise
    
    def get_version(self) -> Optional[Dict]:
        """Get Burp Suite version"""
        try:
            response = self._request('GET', '/burp/version')
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get Burp version: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if Burp Suite is running and accessible"""
        try:
            version = self.get_version()
            if version:
                logger.info(f"Burp Suite {version.get('burp_version')} available")
                return True
            return False
        except:
            return False
    
    def create_task(
        self,
        urls: List[str],
        scan_configurations: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Create a new scan task
        
        Args:
            urls: URLs to scan
            scan_configurations: Scan configuration names
            
        Returns:
            Task ID
        """
        try:
            payload = {
                'urls': urls
            }
            
            if scan_configurations:
                payload['scan_configurations'] = scan_configurations
            
            response = self._request('POST', '/burp/scanner/scans', json=payload)
            
            if response.status_code == 201:
                task_id = response.headers.get('Location', '').split('/')[-1]
                logger.info(f"Created Burp scan task: {task_id}")
                return task_id
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to create Burp scan: {e}")
            return None
    
    def get_scan_status(self, task_id: str) -> Optional[Dict]:
        """Get scan status"""
        try:
            response = self._request('GET', f'/burp/scanner/scans/{task_id}')
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            return None
    
    def get_scan_issues(self, task_id: Optional[str] = None) -> List[Dict]:
        """
        Get scan issues
        
        Args:
            task_id: Optional task ID to filter issues
            
        Returns:
            List of issues
        """
        try:
            endpoint = '/burp/scanner/issues'
            if task_id:
                endpoint += f'?task_id={task_id}'
            
            response = self._request('GET', endpoint)
            issues = response.json().get('issues', [])
            
            logger.info(f"Retrieved {len(issues)} issues from Burp")
            return issues
            
        except Exception as e:
            logger.error(f"Failed to get Burp issues: {e}")
            return []
    
    def send_to_scanner(
        self,
        url: str,
        method: str = 'GET',
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> bool:
        """Send individual request to scanner"""
        try:
            payload = {
                'url': url,
                'method': method
            }
            
            if data:
                payload['data'] = data
            if headers:
                payload['headers'] = headers
            
            response = self._request('POST', '/burp/scanner/send_to_scanner', json=payload)
            
            logger.info(f"Sent {url} to Burp scanner")
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Failed to send to scanner: {e}")
            return False
    
    def get_proxy_history(
        self,
        filter_url: Optional[str] = None
    ) -> List[Dict]:
        """Get HTTP proxy history"""
        try:
            endpoint = '/burp/proxy/history'
            
            response = self._request('GET', endpoint)
            history = response.json().get('items', [])
            
            if filter_url:
                history = [
                    item for item in history
                    if filter_url in item.get('url', '')
                ]
            
            logger.info(f"Retrieved {len(history)} proxy history items")
            return history
            
        except Exception as e:
            logger.error(f"Failed to get proxy history: {e}")
            return []
    
    def export_state(self, output_file: str) -> bool:
        """Export Burp Suite state"""
        try:
            response = self._request('GET', '/burp/target/scope')
            
            with open(output_file, 'w') as f:
                json.dump(response.json(), f, indent=2)
            
            logger.info(f"Exported Burp state to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export Burp state: {e}")
            return False
    
    def add_to_scope(self, urls: List[str]) -> bool:
        """Add URLs to Burp scope"""
        try:
            for url in urls:
                payload = {'url': url}
                self._request('POST', '/burp/target/scope', json=payload)
            
            logger.info(f"Added {len(urls)} URLs to Burp scope")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add to scope: {e}")
            return False
    
    def clear_issues(self) -> bool:
        """Clear all scanner issues"""
        try:
            self._request('DELETE', '/burp/scanner/issues')
            logger.info("Cleared all Burp scanner issues")
            return True
        except Exception as e:
            logger.error(f"Failed to clear issues: {e}")
            return False

