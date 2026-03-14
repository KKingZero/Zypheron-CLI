"""
Authentication Providers - Support multiple auth types
"""

import logging
import base64
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any, Tuple
from dataclasses import dataclass
import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re

logger = logging.getLogger(__name__)


@dataclass
class AuthResult:
    """Result of authentication attempt"""
    success: bool
    session_id: Optional[str] = None
    cookies: Dict[str, str] = None
    headers: Dict[str, str] = None
    tokens: Dict[str, str] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.cookies is None:
            self.cookies = {}
        if self.headers is None:
            self.headers = {}
        if self.tokens is None:
            self.tokens = {}


class AuthProvider(ABC):
    """Base class for authentication providers"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
    
    @abstractmethod
    async def authenticate(
        self,
        username: str,
        password: str,
        **kwargs
    ) -> AuthResult:
        """Authenticate and return session data"""
        pass
    
    @abstractmethod
    def get_auth_type(self) -> str:
        """Return authentication type"""
        pass
    
    def _make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            full_url = urljoin(self.base_url, url)
            response = requests.request(method, full_url, timeout=30, **kwargs)
            return response
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise


class BasicAuthProvider(AuthProvider):
    """HTTP Basic Authentication"""
    
    def get_auth_type(self) -> str:
        return "basic"
    
    async def authenticate(
        self,
        username: str,
        password: str,
        **kwargs
    ) -> AuthResult:
        """Authenticate using HTTP Basic Auth"""
        try:
            # Create Authorization header
            credentials = f"{username}:{password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            auth_header = f"Basic {encoded}"
            
            # Test authentication
            test_url = kwargs.get('test_url', '/')
            response = self._make_request(
                'GET',
                test_url,
                headers={'Authorization': auth_header}
            )
            
            if response.status_code == 200:
                return AuthResult(
                    success=True,
                    headers={'Authorization': auth_header},
                    session_id=f"basic_{username}_{int(time.time())}"
                )
            else:
                return AuthResult(
                    success=False,
                    error=f"Authentication failed: {response.status_code}"
                )
                
        except Exception as e:
            logger.error(f"Basic auth failed: {e}")
            return AuthResult(success=False, error=str(e))


class BearerAuthProvider(AuthProvider):
    """Bearer Token Authentication"""
    
    def get_auth_type(self) -> str:
        return "bearer"
    
    async def authenticate(
        self,
        username: str,
        password: str,
        **kwargs
    ) -> AuthResult:
        """Authenticate and get bearer token"""
        try:
            # Get token endpoint
            token_url = kwargs.get('token_url', '/api/auth/token')
            
            # Request token
            response = self._make_request(
                'POST',
                token_url,
                json={'username': username, 'password': password}
            )
            
            if response.status_code not in [200, 201]:
                return AuthResult(
                    success=False,
                    error=f"Token request failed: {response.status_code}"
                )
            
            # Extract token
            data = response.json()
            token = data.get('token') or data.get('access_token') or data.get('bearer_token')
            
            if not token:
                return AuthResult(
                    success=False,
                    error="No token in response"
                )
            
            return AuthResult(
                success=True,
                headers={'Authorization': f'Bearer {token}'},
                tokens={'bearer_token': token},
                session_id=f"bearer_{username}_{int(time.time())}"
            )
            
        except Exception as e:
            logger.error(f"Bearer auth failed: {e}")
            return AuthResult(success=False, error=str(e))


class FormAuthProvider(AuthProvider):
    """Form-based Authentication"""
    
    def get_auth_type(self) -> str:
        return "form"
    
    async def authenticate(
        self,
        username: str,
        password: str,
        **kwargs
    ) -> AuthResult:
        """Authenticate using login form"""
        try:
            import time
            from bs4 import BeautifulSoup
            
            login_url = kwargs.get('login_url', '/login')
            username_field = kwargs.get('username_field', 'username')
            password_field = kwargs.get('password_field', 'password')
            
            # Create session to maintain cookies
            session = requests.Session()
            
            # Get login page to extract CSRF token if present
            login_page = session.get(urljoin(self.base_url, login_url), timeout=10)
            
            # Extract CSRF token
            csrf_token = None
            soup = BeautifulSoup(login_page.text, 'html.parser')
            
            # Look for common CSRF token patterns
            csrf_inputs = soup.find_all('input', {'name': re.compile(r'csrf|token', re.I)})
            if csrf_inputs:
                csrf_token = csrf_inputs[0].get('value')
                csrf_field_name = csrf_inputs[0].get('name')
            
            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }
            
            if csrf_token:
                login_data[csrf_field_name] = csrf_token
            
            # Add any additional fields
            extra_fields = kwargs.get('extra_fields', {})
            login_data.update(extra_fields)
            
            # Submit login form
            response = session.post(
                urljoin(self.base_url, login_url),
                data=login_data,
                allow_redirects=True,
                timeout=10
            )
            
            # Check for successful login
            # Common indicators: redirect to dashboard, no "login" in URL, specific cookies
            success_indicators = [
                response.status_code == 200,
                'login' not in response.url.lower() or 'dashboard' in response.url.lower(),
                len(session.cookies) > 0
            ]
            
            # Check for failure indicators in response
            failure_keywords = ['invalid', 'incorrect', 'failed', 'error']
            has_error = any(keyword in response.text.lower() for keyword in failure_keywords)
            
            if all(success_indicators) and not has_error:
                return AuthResult(
                    success=True,
                    cookies={cookie.name: cookie.value for cookie in session.cookies},
                    session_id=f"form_{username}_{int(time.time())}"
                )
            else:
                return AuthResult(
                    success=False,
                    error="Login form submission failed"
                )
                
        except Exception as e:
            logger.error(f"Form auth failed: {e}")
            return AuthResult(success=False, error=str(e))


class CookieAuthProvider(AuthProvider):
    """Cookie-based Authentication (import existing cookies)"""
    
    def get_auth_type(self) -> str:
        return "cookie"
    
    async def authenticate(
        self,
        username: str,
        password: str,
        **kwargs
    ) -> AuthResult:
        """Use provided cookies for authentication"""
        try:
            import time
            
            # Get cookies from kwargs
            cookies = kwargs.get('cookies', {})
            
            if not cookies:
                return AuthResult(
                    success=False,
                    error="No cookies provided"
                )
            
            # Test cookies
            test_url = kwargs.get('test_url', '/')
            session = requests.Session()
            
            for name, value in cookies.items():
                session.cookies.set(name, value)
            
            response = session.get(urljoin(self.base_url, test_url), timeout=10)
            
            # Check if cookies are valid
            if response.status_code == 200 and 'login' not in response.url.lower():
                return AuthResult(
                    success=True,
                    cookies=cookies,
                    session_id=f"cookie_{username}_{int(time.time())}"
                )
            else:
                return AuthResult(
                    success=False,
                    error="Cookie authentication failed"
                )
                
        except Exception as e:
            logger.error(f"Cookie auth failed: {e}")
            return AuthResult(success=False, error=str(e))


class OAuth2Provider(AuthProvider):
    """OAuth 2.0 Authentication"""
    
    def get_auth_type(self) -> str:
        return "oauth2"
    
    async def authenticate(
        self,
        username: str,
        password: str,
        **kwargs
    ) -> AuthResult:
        """Authenticate using OAuth 2.0 flow"""
        try:
            import time
            
            # OAuth2 endpoints
            auth_url = kwargs.get('auth_url', '/oauth/authorize')
            token_url = kwargs.get('token_url', '/oauth/token')
            client_id = kwargs.get('client_id')
            client_secret = kwargs.get('client_secret')
            redirect_uri = kwargs.get('redirect_uri', 'http://localhost:8080/callback')
            scope = kwargs.get('scope', 'read write')
            
            if not client_id or not client_secret:
                return AuthResult(
                    success=False,
                    error="Client ID and secret required for OAuth2"
                )
            
            # For password grant type (Resource Owner Password Credentials)
            token_data = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': scope
            }
            
            response = self._make_request(
                'POST',
                token_url,
                data=token_data
            )
            
            if response.status_code not in [200, 201]:
                return AuthResult(
                    success=False,
                    error=f"OAuth2 token request failed: {response.status_code}"
                )
            
            # Extract tokens
            data = response.json()
            access_token = data.get('access_token')
            refresh_token = data.get('refresh_token')
            token_type = data.get('token_type', 'Bearer')
            
            if not access_token:
                return AuthResult(
                    success=False,
                    error="No access token in response"
                )
            
            return AuthResult(
                success=True,
                headers={'Authorization': f'{token_type} {access_token}'},
                tokens={
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'token_type': token_type
                },
                session_id=f"oauth2_{username}_{int(time.time())}"
            )
            
        except Exception as e:
            logger.error(f"OAuth2 auth failed: {e}")
            return AuthResult(success=False, error=str(e))


class APIKeyAuthProvider(AuthProvider):
    """API Key Authentication"""
    
    def get_auth_type(self) -> str:
        return "apikey"
    
    async def authenticate(
        self,
        username: str,
        password: str,
        **kwargs
    ) -> AuthResult:
        """Authenticate using API key"""
        try:
            import time
            
            # API key can be in password field or kwargs
            api_key = password or kwargs.get('api_key')
            
            if not api_key:
                return AuthResult(
                    success=False,
                    error="No API key provided"
                )
            
            # API key location
            key_location = kwargs.get('key_location', 'header')  # header, query, cookie
            key_name = kwargs.get('key_name', 'X-API-Key')
            
            # Test API key
            test_url = kwargs.get('test_url', '/api/v1/status')
            
            if key_location == 'header':
                response = self._make_request(
                    'GET',
                    test_url,
                    headers={key_name: api_key}
                )
                
                if response.status_code == 200:
                    return AuthResult(
                        success=True,
                        headers={key_name: api_key},
                        tokens={'api_key': api_key},
                        session_id=f"apikey_{username}_{int(time.time())}"
                    )
                    
            elif key_location == 'query':
                response = self._make_request(
                    'GET',
                    test_url,
                    params={key_name: api_key}
                )
                
                if response.status_code == 200:
                    return AuthResult(
                        success=True,
                        tokens={'api_key': api_key, 'key_param': key_name},
                        session_id=f"apikey_{username}_{int(time.time())}"
                    )
            
            return AuthResult(
                success=False,
                error="API key authentication failed"
            )
            
        except Exception as e:
            logger.error(f"API key auth failed: {e}")
            return AuthResult(success=False, error=str(e))


class AuthProviderFactory:
    """Factory for creating authentication providers"""
    
    _providers = {
        'basic': BasicAuthProvider,
        'bearer': BearerAuthProvider,
        'form': FormAuthProvider,
        'cookie': CookieAuthProvider,
        'oauth2': OAuth2Provider,
        'apikey': APIKeyAuthProvider
    }
    
    @classmethod
    def create(cls, auth_type: str, base_url: str) -> Optional[AuthProvider]:
        """Create authentication provider"""
        provider_class = cls._providers.get(auth_type.lower())
        
        if not provider_class:
            logger.error(f"Unknown auth type: {auth_type}")
            return None
        
        return provider_class(base_url)
    
    @classmethod
    def list_providers(cls) -> list:
        """List available authentication types"""
        return list(cls._providers.keys())
    
    @classmethod
    def auto_detect(cls, url: str) -> Optional[str]:
        """Auto-detect authentication type from URL/response"""
        try:
            import time
            
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            # Check for WWW-Authenticate header
            if 'WWW-Authenticate' in response.headers:
                auth_header = response.headers['WWW-Authenticate'].lower()
                if 'basic' in auth_header:
                    return 'basic'
                elif 'bearer' in auth_header:
                    return 'bearer'
            
            # Check for login form
            if 'login' in response.url.lower() or '<form' in response.text.lower():
                if 'password' in response.text.lower():
                    return 'form'
            
            # Check for OAuth2 indicators
            if 'oauth' in response.text.lower() or 'authorize' in response.url.lower():
                return 'oauth2'
            
            # Default to form-based
            return 'form'
            
        except Exception as e:
            logger.error(f"Auto-detection failed: {e}")
            return None


# Add missing import
import time

