"""
Burp Suite Scanner Orchestration

High-level interface for running Burp scans
"""

import logging
import asyncio
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from .burp_api import BurpAPI, BurpConfig

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Burp scan configuration"""
    urls: List[str]
    scan_type: str = "active"  # active, passive, both
    
    # Scan configurations (Burp named configs)
    configurations: List[str] = field(default_factory=lambda: ["default"])
    
    # Authentication
    session_cookies: Optional[Dict[str, str]] = None
    auth_headers: Optional[Dict[str, str]] = None
    
    # Scope
    in_scope_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    
    # Performance
    max_crawl_depth: int = 5
    max_duration_minutes: int = 60
    thread_count: int = 10
    
    # Options
    follow_redirects: bool = True
    test_cookies: bool = True
    test_headers: bool = True


class BurpScanner:
    """
    Burp Suite Scanner Orchestration
    
    Features:
    - Automated scan execution
    - Authentication context management
    - Scan monitoring and progress tracking
    - Result retrieval and processing
    """
    
    def __init__(self, burp_api: Optional[BurpAPI] = None):
        self.api = burp_api or BurpAPI()
        self.active_scans: Dict[str, Dict] = {}
    
    async def run_scan(
        self,
        config: ScanConfig,
        wait_for_completion: bool = True
    ) -> Optional[str]:
        """
        Run Burp scan
        
        Args:
            config: Scan configuration
            wait_for_completion: Wait for scan to complete
            
        Returns:
            Task ID
        """
        logger.info(f"Starting Burp scan for {len(config.urls)} URLs")
        
        # Check if Burp is available
        if not self.api.is_available():
            logger.error("Burp Suite is not running or accessible")
            return None
        
        try:
            # Add to scope
            if config.in_scope_patterns:
                self.api.add_to_scope(config.in_scope_patterns)
            
            # Create scan task
            task_id = self.api.create_task(
                urls=config.urls,
                scan_configurations=config.configurations
            )
            
            if not task_id:
                logger.error("Failed to create Burp scan task")
                return None
            
            # Track scan
            self.active_scans[task_id] = {
                'config': config,
                'started_at': datetime.now(),
                'status': 'running'
            }
            
            logger.info(f"Burp scan started: {task_id}")
            
            # Wait for completion if requested
            if wait_for_completion:
                await self._wait_for_completion(task_id, config.max_duration_minutes)
            
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to run Burp scan: {e}")
            return None
    
    async def _wait_for_completion(
        self,
        task_id: str,
        max_duration_minutes: int
    ):
        """Wait for scan to complete"""
        logger.info(f"Waiting for Burp scan {task_id} to complete (max {max_duration_minutes}m)")
        
        start_time = time.time()
        max_duration_seconds = max_duration_minutes * 60
        
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > max_duration_seconds:
                logger.warning(f"Burp scan {task_id} timeout after {max_duration_minutes}m")
                break
            
            # Get scan status
            status = self.api.get_scan_status(task_id)
            
            if not status:
                logger.error("Failed to get scan status")
                break
            
            scan_state = status.get('scan_status', 'unknown')
            
            if scan_state in ['succeeded', 'failed']:
                logger.info(f"Burp scan {task_id} {scan_state}")
                self.active_scans[task_id]['status'] = scan_state
                break
            
            # Log progress
            progress = status.get('progress', 0)
            logger.info(f"Scan progress: {progress}%")
            
            # Wait before next check
            await asyncio.sleep(10)
        
        # Update completion time
        self.active_scans[task_id]['completed_at'] = datetime.now()
    
    async def get_results(
        self,
        task_id: Optional[str] = None,
        severity_filter: Optional[List[str]] = None
    ) -> List[Dict]:
        """
        Get scan results
        
        Args:
            task_id: Optional task ID to filter results
            severity_filter: Filter by severity (high, medium, low)
            
        Returns:
            List of Burp issues
        """
        logger.info(f"Retrieving Burp scan results")
        
        issues = self.api.get_scan_issues(task_id)
        
        # Filter by severity
        if severity_filter:
            issues = [
                issue for issue in issues
                if issue.get('severity', '').lower() in [s.lower() for s in severity_filter]
            ]
        
        logger.info(f"Retrieved {len(issues)} Burp issues")
        return issues
    
    async def scan_with_authentication(
        self,
        urls: List[str],
        session_cookies: Dict[str, str],
        auth_headers: Optional[Dict[str, str]] = None
    ) -> Optional[str]:
        """
        Run authenticated Burp scan
        
        Args:
            urls: URLs to scan
            session_cookies: Session cookies for authentication
            auth_headers: Optional authentication headers
            
        Returns:
            Task ID
        """
        config = ScanConfig(
            urls=urls,
            session_cookies=session_cookies,
            auth_headers=auth_headers,
            scan_type="active"
        )
        
        return await self.run_scan(config)
    
    def get_proxy_history(
        self,
        target_filter: Optional[str] = None
    ) -> List[Dict]:
        """Get HTTP proxy history"""
        history = self.api.get_proxy_history(filter_url=target_filter)
        
        logger.info(f"Retrieved {len(history)} proxy history items")
        return history
    
    def export_scan_data(
        self,
        task_id: str,
        output_file: str
    ) -> bool:
        """Export scan data to file"""
        try:
            issues = self.api.get_scan_issues(task_id)
            
            import json
            with open(output_file, 'w') as f:
                json.dump({
                    'task_id': task_id,
                    'scan_info': self.active_scans.get(task_id, {}),
                    'issues': issues
                }, f, indent=2, default=str)
            
            logger.info(f"Exported Burp scan data to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export scan data: {e}")
            return False
    
    def get_scan_statistics(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """Get scan statistics"""
        issues = self.api.get_scan_issues(task_id)
        
        severity_counts = {}
        type_counts = {}
        
        for issue in issues:
            severity = issue.get('severity', 'unknown').lower()
            issue_type = issue.get('type', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
        
        return {
            'total_issues': len(issues),
            'by_severity': severity_counts,
            'by_type': type_counts,
            'high_critical_count': severity_counts.get('high', 0) + severity_counts.get('critical', 0)
        }

