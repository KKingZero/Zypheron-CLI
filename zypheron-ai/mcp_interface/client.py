"""
Zypheron Backend Communication Module

Provides HTTP interface for communicating with Zypheron backend services
and orchestrating security tool execution via REST API.
"""

import requests
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import json

from mcp_interface.colors import ZypheronColors, colorize

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_SERVER_URL = "http://localhost:8080"
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes for long-running security tools


class ZypheronClient:
    """HTTP client for communicating with Zypheron backend services"""

    def __init__(self, server_url: str = DEFAULT_SERVER_URL, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize Zypheron client.
        
        Args:
            server_url: Base URL of Zypheron backend server
            timeout: Request timeout in seconds (default: 300)
        """
        self.server_url = server_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        
        # Load authentication token if available
        self.auth_token = self._load_auth_token()
        if self.auth_token:
            self.session.headers.update({'Authorization': f'Bearer {self.auth_token}'})
        
        logger.info(colorize(f"Zypheron interface connected: {self.server_url}", ZypheronColors.INFO))

    def _load_auth_token(self) -> Optional[str]:
        """Load authentication token from Zypheron config"""
        token_file = Path.home() / ".zypheron" / "ipc.token"
        
        if token_file.exists():
            try:
                token = token_file.read_text().strip()
                logger.debug("Loaded Zypheron auth token")
                return token
            except Exception as e:
                logger.warning(f"Failed to load auth token: {e}")
        
        return None

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform safe GET request with error handling.
        
        Args:
            endpoint: API endpoint path
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        
        try:
            logger.debug(f"GET {url}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json()
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {url}")
            return {"error": "Request timeout", "success": False}
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error: {url}")
            return {"error": "Failed to connect to Zypheron backend", "success": False}
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error {e.response.status_code}: {url}")
            return {"error": f"HTTP {e.response.status_code}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {"error": str(e), "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform safe POST request with error handling.
        
        Args:
            endpoint: API endpoint path
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint.lstrip('/')}"
        
        try:
            logger.debug(f"POST {url}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json()
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {url}")
            return {"error": "Request timeout", "success": False}
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error: {url}")
            return {"error": "Failed to connect to Zypheron backend", "success": False}
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error {e.response.status_code}: {url}")
            try:
                error_detail = e.response.json()
                return {"error": error_detail, "success": False}
            except:
                return {"error": f"HTTP {e.response.status_code}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {"error": str(e), "success": False}

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute arbitrary security tool command.
        
        Args:
            command: Shell command to execute
            use_cache: Whether to use cached results if available
            
        Returns:
            Command execution results
        """
        return self.safe_post('api/command', {
            'command': command,
            'use_cache': use_cache
        })

    def check_health(self) -> Dict[str, Any]:
        """
        Check backend server health.
        
        Returns:
            Health check status
        """
        return self.safe_get('health')

    def get_tool_status(self, tool_name: str) -> Dict[str, Any]:
        """
        Get status of a specific tool.
        
        Args:
            tool_name: Name of the security tool
            
        Returns:
            Tool status information
        """
        return self.safe_get(f'api/tools/{tool_name}/status')

    def list_available_tools(self) -> Dict[str, Any]:
        """
        List all available security tools.
        
        Returns:
            List of available tools
        """
        return self.safe_get('api/tools/list')

