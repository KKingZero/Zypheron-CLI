"""
CVE Matcher - Match dependencies to known CVEs
"""

import logging
from typing import Dict, List, Optional
import requests

logger = logging.getLogger(__name__)


class CVEMatcher:
    """
    Match dependencies to known CVEs
    
    Uses:
    - NVD API
    - OSV (Open Source Vulnerabilities) database
    - GitHub Advisory Database
    """
    
    def __init__(self):
        self.nvd_api_key = None
        self.cache: Dict[str, List[Dict]] = {}
    
    def search_cves(
        self,
        package_name: str,
        version: str,
        ecosystem: str
    ) -> List[Dict]:
        """
        Search for CVEs affecting a package
        
        Args:
            package_name: Package name
            version: Package version
            ecosystem: Ecosystem (npm, pypi, etc.)
            
        Returns:
            List of CVEs
        """
        cache_key = f"{ecosystem}:{package_name}:{version}"
        
        # Check cache
        if cache_key in self.cache:
            logger.debug(f"Using cached CVEs for {cache_key}")
            return self.cache[cache_key]
        
        cves = []
        
        # Try OSV database first (free, no rate limits)
        osv_cves = self._search_osv(package_name, version, ecosystem)
        cves.extend(osv_cves)
        
        # Cache results
        self.cache[cache_key] = cves
        
        return cves
    
    def _search_osv(
        self,
        package_name: str,
        version: str,
        ecosystem: str
    ) -> List[Dict]:
        """Search OSV database"""
        cves = []
        
        try:
            # Map ecosystem to OSV ecosystem name
            ecosystem_map = {
                'python': 'PyPI',
                'nodejs': 'npm',
                'go': 'Go',
                'java': 'Maven',
                'dotnet': 'NuGet'
            }
            
            osv_ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem)
            
            # Query OSV API
            url = "https://api.osv.dev/v1/query"
            payload = {
                'package': {
                    'name': package_name,
                    'ecosystem': osv_ecosystem
                },
                'version': version
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulns', [])
                
                for vuln in vulns:
                    cve = {
                        'id': vuln.get('id'),
                        'summary': vuln.get('summary', ''),
                        'details': vuln.get('details', ''),
                        'severity': self._parse_osv_severity(vuln),
                        'references': vuln.get('references', []),
                        'published': vuln.get('published', ''),
                        'modified': vuln.get('modified', '')
                    }
                    cves.append(cve)
                
                logger.info(f"Found {len(cves)} CVEs for {package_name}@{version}")
                
        except Exception as e:
            logger.error(f"OSV search failed: {e}")
        
        return cves
    
    def _parse_osv_severity(self, vuln: Dict) -> str:
        """Parse severity from OSV vulnerability"""
        # Check for CVSS score
        severity = vuln.get('database_specific', {}).get('severity', 'UNKNOWN')
        
        if severity == 'CRITICAL':
            return 'critical'
        elif severity == 'HIGH':
            return 'high'
        elif severity == 'MODERATE' or severity == 'MEDIUM':
            return 'medium'
        elif severity == 'LOW':
            return 'low'
        
        return 'unknown'
    
    def verify_cve(self, cve_id: str) -> Optional[Dict]:
        """Get detailed CVE information"""
        try:
            # Use NVD API
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return data
            
        except Exception as e:
            logger.error(f"CVE verification failed for {cve_id}: {e}")
        
        return None

