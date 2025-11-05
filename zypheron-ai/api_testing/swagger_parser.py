"""
Swagger/OpenAPI Parser - Parse and test OpenAPI specifications
"""

import logging
import json
import yaml
from typing import Dict, List, Optional, Any
import requests

logger = logging.getLogger(__name__)


class SwaggerParser:
    """Parse Swagger 2.0 specifications"""
    
    def __init__(self, spec_url_or_file: str):
        self.spec = self._load_spec(spec_url_or_file)
        self.endpoints: List[Dict] = []
        
        if self.spec:
            self._parse_endpoints()
    
    def _load_spec(self, source: str) -> Optional[Dict]:
        """Load spec from URL or file"""
        try:
            if source.startswith('http'):
                response = requests.get(source, timeout=10)
                return response.json()
            else:
                with open(source, 'r') as f:
                    if source.endswith('.json'):
                        return json.load(f)
                    else:
                        return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load Swagger spec: {e}")
            return None
    
    def _parse_endpoints(self):
        """Parse endpoints from spec"""
        if not self.spec:
            return
        
        base_path = self.spec.get('basePath', '')
        paths = self.spec.get('paths', {})
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    continue
                
                endpoint = {
                    'path': base_path + path,
                    'method': method.upper(),
                    'summary': details.get('summary', ''),
                    'parameters': details.get('parameters', []),
                    'security': details.get('security', []),
                    'responses': details.get('responses', {})
                }
                
                self.endpoints.append(endpoint)
        
        logger.info(f"Parsed {len(self.endpoints)} endpoints from Swagger spec")
    
    def get_endpoints(self) -> List[Dict]:
        """Get all endpoints"""
        return self.endpoints
    
    def get_authenticated_endpoints(self) -> List[Dict]:
        """Get endpoints requiring authentication"""
        return [ep for ep in self.endpoints if ep.get('security')]
    
    def get_endpoints_with_parameters(self) -> List[Dict]:
        """Get endpoints with parameters"""
        return [ep for ep in self.endpoints if ep.get('parameters')]


class OpenAPIParser(SwaggerParser):
    """Parse OpenAPI 3.x specifications (extends Swagger parser)"""
    
    def _parse_endpoints(self):
        """Parse OpenAPI 3.x endpoints"""
        if not self.spec:
            return
        
        servers = self.spec.get('servers', [])
        base_url = servers[0].get('url') if servers else ''
        
        paths = self.spec.get('paths', {})
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                    continue
                
                endpoint = {
                    'path': base_url + path,
                    'method': method.upper(),
                    'summary': details.get('summary', ''),
                    'description': details.get('description', ''),
                    'parameters': details.get('parameters', []),
                    'security': details.get('security', []),
                    'requestBody': details.get('requestBody', {}),
                    'responses': details.get('responses', {})
                }
                
                self.endpoints.append(endpoint)
        
        logger.info(f"Parsed {len(self.endpoints)} endpoints from OpenAPI spec")

