"""
Session Manager - Handle authenticated sessions across scan runs
"""

import logging
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import requests

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """Authenticated session state"""
    session_id: str
    target_url: str
    auth_type: str
    
    # Session data
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    # State
    is_valid: bool = True
    username: Optional[str] = None
    user_role: Optional[str] = None
    
    # CSRF protection
    csrf_token: Optional[str] = None
    csrf_header: str = "X-CSRF-Token"
    
    def is_expired(self) -> bool:
        """Check if session has expired"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    def needs_renewal(self, threshold_minutes: int = 5) -> bool:
        """Check if session needs renewal"""
        if not self.expires_at:
            return False
        threshold = datetime.now() + timedelta(minutes=threshold_minutes)
        return threshold > self.expires_at
    
    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO format
        data['created_at'] = self.created_at.isoformat()
        data['last_used'] = self.last_used.isoformat()
        data['expires_at'] = self.expires_at.isoformat() if self.expires_at else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        """Create session from dictionary"""
        # Convert ISO format back to datetime
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'last_used' in data and isinstance(data['last_used'], str):
            data['last_used'] = datetime.fromisoformat(data['last_used'])
        if 'expires_at' in data and data['expires_at']:
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)


class SessionManager:
    """
    Manage authenticated sessions for penetration testing
    
    Features:
    - Session persistence across scan runs
    - Automatic session renewal
    - CSRF token handling
    - Cookie and header management
    - Session health monitoring
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = Path.home() / '.zypheron' / 'sessions'
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.sessions: Dict[str, Session] = {}
        self._load_sessions()
    
    def create_session(
        self,
        session_id: str,
        target_url: str,
        auth_type: str,
        username: Optional[str] = None,
        expires_in_seconds: Optional[int] = None
    ) -> Session:
        """Create a new session"""
        expires_at = None
        if expires_in_seconds:
            expires_at = datetime.now() + timedelta(seconds=expires_in_seconds)
        
        session = Session(
            session_id=session_id,
            target_url=target_url,
            auth_type=auth_type,
            username=username,
            expires_at=expires_at
        )
        
        self.sessions[session_id] = session
        self._save_session(session)
        
        logger.info(f"Created session {session_id} for {target_url}")
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        session = self.sessions.get(session_id)
        
        if not session:
            return None
        
        # Check if expired
        if session.is_expired():
            logger.warning(f"Session {session_id} has expired")
            session.is_valid = False
            return session
        
        session.update_last_used()
        self._save_session(session)
        
        return session
    
    def update_session(
        self,
        session_id: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        tokens: Optional[Dict[str, str]] = None,
        csrf_token: Optional[str] = None
    ) -> bool:
        """Update session data"""
        session = self.sessions.get(session_id)
        if not session:
            logger.error(f"Session {session_id} not found")
            return False
        
        if cookies:
            session.cookies.update(cookies)
        if headers:
            session.headers.update(headers)
        if tokens:
            session.tokens.update(tokens)
        if csrf_token:
            session.csrf_token = csrf_token
        
        session.update_last_used()
        self._save_session(session)
        
        logger.debug(f"Updated session {session_id}")
        return True
    
    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        session.is_valid = False
        self._save_session(session)
        
        logger.info(f"Invalidated session {session_id}")
        return True
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        if session_id not in self.sessions:
            return False
        
        del self.sessions[session_id]
        
        # Delete file
        session_file = self.storage_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()
        
        logger.info(f"Deleted session {session_id}")
        return True
    
    def get_active_sessions(self, target_url: Optional[str] = None) -> list:
        """Get all active (non-expired, valid) sessions"""
        active = []
        for session in self.sessions.values():
            if not session.is_valid or session.is_expired():
                continue
            
            if target_url and session.target_url != target_url:
                continue
            
            active.append(session)
        
        return active
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions"""
        expired_ids = [
            sid for sid, session in self.sessions.items()
            if session.is_expired()
        ]
        
        for session_id in expired_ids:
            self.delete_session(session_id)
        
        logger.info(f"Cleaned up {len(expired_ids)} expired sessions")
        return len(expired_ids)
    
    def create_requests_session(self, session_id: str) -> Optional[requests.Session]:
        """Create a requests.Session with authentication"""
        session = self.get_session(session_id)
        if not session or not session.is_valid:
            return None
        
        req_session = requests.Session()
        
        # Add cookies
        for name, value in session.cookies.items():
            req_session.cookies.set(name, value)
        
        # Add headers
        req_session.headers.update(session.headers)
        
        # Add CSRF token if present
        if session.csrf_token:
            req_session.headers[session.csrf_header] = session.csrf_token
        
        logger.debug(f"Created requests.Session for {session_id}")
        return req_session
    
    def monitor_session_health(self, session_id: str, health_check_url: str) -> bool:
        """Check if session is still valid by making a request"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        req_session = self.create_requests_session(session_id)
        if not req_session:
            return False
        
        try:
            response = req_session.get(health_check_url, timeout=10)
            
            # Check if we got redirected to login (common sign of expired session)
            if 'login' in response.url.lower() and 'login' not in health_check_url.lower():
                logger.warning(f"Session {session_id} appears expired (redirected to login)")
                self.invalidate_session(session_id)
                return False
            
            # Check for common expired session indicators
            if response.status_code in [401, 403]:
                logger.warning(f"Session {session_id} unauthorized (status {response.status_code})")
                self.invalidate_session(session_id)
                return False
            
            logger.debug(f"Session {session_id} health check passed")
            return True
            
        except Exception as e:
            logger.error(f"Health check failed for session {session_id}: {e}")
            return False
    
    def extract_csrf_token(
        self,
        session_id: str,
        url: str,
        token_name: str = 'csrf_token',
        meta_name: Optional[str] = None
    ) -> Optional[str]:
        """Extract CSRF token from a page"""
        session = self.get_session(session_id)
        if not session:
            return None
        
        req_session = self.create_requests_session(session_id)
        if not req_session:
            return None
        
        try:
            from bs4 import BeautifulSoup
            
            response = req_session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try to find in input field
            csrf_input = soup.find('input', {'name': token_name})
            if csrf_input and csrf_input.get('value'):
                csrf_token = csrf_input['value']
                self.update_session(session_id, csrf_token=csrf_token)
                logger.info(f"Extracted CSRF token from input field")
                return csrf_token
            
            # Try to find in meta tag
            if meta_name:
                csrf_meta = soup.find('meta', {'name': meta_name})
                if csrf_meta and csrf_meta.get('content'):
                    csrf_token = csrf_meta['content']
                    self.update_session(session_id, csrf_token=csrf_token)
                    logger.info(f"Extracted CSRF token from meta tag")
                    return csrf_token
            
            logger.warning(f"Could not find CSRF token in {url}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract CSRF token: {e}")
            return None
    
    def _save_session(self, session: Session):
        """Save session to disk"""
        session_file = self.storage_dir / f"{session.session_id}.json"
        
        try:
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
            
            # Secure file permissions
            session_file.chmod(0o600)
            
        except Exception as e:
            logger.error(f"Failed to save session {session.session_id}: {e}")
    
    def _load_sessions(self):
        """Load sessions from disk"""
        if not self.storage_dir.exists():
            return
        
        for session_file in self.storage_dir.glob('*.json'):
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)
                
                session = Session.from_dict(data)
                self.sessions[session.session_id] = session
                
                logger.debug(f"Loaded session {session.session_id}")
                
            except Exception as e:
                logger.error(f"Failed to load session from {session_file}: {e}")
        
        logger.info(f"Loaded {len(self.sessions)} sessions")
    
    def export_session(self, session_id: str, output_file: str) -> bool:
        """Export session to file"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        try:
            with open(output_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
            
            logger.info(f"Exported session {session_id} to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export session: {e}")
            return False
    
    def import_session(self, input_file: str) -> Optional[Session]:
        """Import session from file"""
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
            
            session = Session.from_dict(data)
            self.sessions[session.session_id] = session
            self._save_session(session)
            
            logger.info(f"Imported session {session.session_id}")
            return session
            
        except Exception as e:
            logger.error(f"Failed to import session: {e}")
            return None

