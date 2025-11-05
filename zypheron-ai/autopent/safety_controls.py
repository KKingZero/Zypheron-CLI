"""
Safety Controls - Authorization and safety management for automated pentesting
"""

import logging
import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class Authorization:
    """Penetration test authorization"""
    authorization_id: str
    token: str  # Secret authorization token
    
    # Authorization details
    authorized_by: str  # Person granting authorization
    organization: str
    contact_email: str
    
    # Scope
    targets: List[str]
    scope: List[str]
    exclusions: List[str]
    
    # Constraints
    start_date: datetime
    end_date: datetime
    business_hours_only: bool = False
    
    # Approval
    approval_document: str = ""  # Path to signed authorization
    approved_at: datetime = None
    
    def is_valid(self) -> bool:
        """Check if authorization is valid"""
        now = datetime.now()
        return self.start_date <= now <= self.end_date
    
    def is_target_authorized(self, target: str) -> bool:
        """Check if specific target is authorized"""
        # Check exclusions first
        for exclusion in self.exclusions:
            if exclusion in target:
                return False
        
        # Check scope
        for scope_item in self.scope:
            if scope_item in target:
                return True
        
        return False


class AuthorizationManager:
    """
    Manage penetration test authorizations
    
    Features:
    - Create and validate authorizations
    - Token generation
    - Scope verification
    - Time-based restrictions
    """
    
    def __init__(self):
        self.authorizations: Dict[str, Authorization] = {}
    
    def create_authorization(
        self,
        authorized_by: str,
        organization: str,
        contact_email: str,
        targets: List[str],
        scope: List[str],
        duration_days: int = 7,
        exclusions: Optional[List[str]] = None,
        business_hours_only: bool = False
    ) -> Authorization:
        """
        Create new authorization
        
        Args:
            authorized_by: Name of authorizing person
            organization: Organization name
            contact_email: Contact email
            targets: List of targets
            scope: Scope definition
            duration_days: Duration in days
            exclusions: Excluded targets
            business_hours_only: Restrict to business hours
            
        Returns:
            Authorization object
        """
        # Generate secure token
        token = secrets.token_urlsafe(32)
        auth_id = hashlib.sha256(token.encode()).hexdigest()[:16]
        
        now = datetime.now()
        end_date = now + timedelta(days=duration_days)
        
        authorization = Authorization(
            authorization_id=auth_id,
            token=token,
            authorized_by=authorized_by,
            organization=organization,
            contact_email=contact_email,
            targets=targets,
            scope=scope,
            exclusions=exclusions or [],
            start_date=now,
            end_date=end_date,
            business_hours_only=business_hours_only,
            approved_at=now
        )
        
        self.authorizations[auth_id] = authorization
        
        logger.info(f"Created authorization {auth_id} for {organization}")
        logger.info(f"Valid until: {end_date}")
        logger.info(f"Scope: {scope}")
        
        return authorization
    
    def validate_authorization(self, token: str, target: Optional[str] = None) -> bool:
        """
        Validate authorization token
        
        Args:
            token: Authorization token
            target: Optional specific target to check
            
        Returns:
            True if valid
        """
        # Find authorization by token
        authorization = None
        for auth in self.authorizations.values():
            if auth.token == token:
                authorization = auth
                break
        
        if not authorization:
            logger.warning("Authorization token not found")
            return False
        
        # Check if still valid
        if not authorization.is_valid():
            logger.warning(f"Authorization {authorization.authorization_id} expired")
            return False
        
        # Check business hours if required
        if authorization.business_hours_only:
            if not self._is_business_hours():
                logger.warning("Outside business hours")
                return False
        
        # Check specific target if provided
        if target and not authorization.is_target_authorized(target):
            logger.warning(f"Target {target} not authorized")
            return False
        
        logger.info(f"Authorization validated: {authorization.authorization_id}")
        return True
    
    def _is_business_hours(self) -> bool:
        """Check if current time is within business hours"""
        now = datetime.now()
        # Business hours: Monday-Friday, 9 AM - 5 PM
        if now.weekday() >= 5:  # Weekend
            return False
        if now.hour < 9 or now.hour >= 17:
            return False
        return True
    
    def get_authorization(self, token: str) -> Optional[Authorization]:
        """Get authorization by token"""
        for auth in self.authorizations.values():
            if auth.token == token:
                return auth
        return None
    
    def list_authorizations(self) -> List[Authorization]:
        """List all authorizations"""
        return list(self.authorizations.values())


class SafetyController:
    """
    Safety controls for automated penetration testing
    
    Features:
    - Rate limiting
    - Scope enforcement
    - Attack type restrictions
    - Emergency stop
    """
    
    def __init__(self):
        self.blocked_operations: Set[str] = set()
        self.rate_limits: Dict[str, int] = {}
        self.request_counts: Dict[str, int] = {}
        self.emergency_stop = False
    
    def block_operation(self, operation: str):
        """Block a specific operation type"""
        self.blocked_operations.add(operation)
        logger.warning(f"Blocked operation: {operation}")
    
    def is_operation_allowed(self, operation: str) -> bool:
        """Check if operation is allowed"""
        if self.emergency_stop:
            logger.error("Emergency stop activated - all operations blocked")
            return False
        
        if operation in self.blocked_operations:
            logger.warning(f"Operation blocked: {operation}")
            return False
        
        return True
    
    def set_rate_limit(self, operation: str, max_per_minute: int):
        """Set rate limit for operation"""
        self.rate_limits[operation] = max_per_minute
        logger.info(f"Rate limit set: {operation} = {max_per_minute}/min")
    
    def check_rate_limit(self, operation: str) -> bool:
        """Check if operation exceeds rate limit"""
        if operation not in self.rate_limits:
            return True
        
        current_count = self.request_counts.get(operation, 0)
        max_count = self.rate_limits[operation]
        
        if current_count >= max_count:
            logger.warning(f"Rate limit exceeded for {operation}")
            return False
        
        self.request_counts[operation] = current_count + 1
        return True
    
    def reset_rate_limits(self):
        """Reset rate limit counters"""
        self.request_counts.clear()
    
    def activate_emergency_stop(self, reason: str):
        """Activate emergency stop"""
        self.emergency_stop = True
        logger.critical(f"EMERGENCY STOP ACTIVATED: {reason}")
    
    def deactivate_emergency_stop(self):
        """Deactivate emergency stop"""
        self.emergency_stop = False
        logger.info("Emergency stop deactivated")
    
    def is_safe_target(self, target: str) -> bool:
        """Check if target is safe to test"""
        # Check against known production indicators
        unsafe_keywords = [
            'production',
            'prod',
            'live',
            'www',
            'api',
            'payment',
            'bank'
        ]
        
        target_lower = target.lower()
        for keyword in unsafe_keywords:
            if keyword in target_lower:
                logger.warning(f"Potentially unsafe target: {target} (contains '{keyword}')")
                return False
        
        return True
    
    def validate_attack_chain(self, chain_steps: List[str]) -> bool:
        """Validate attack chain steps are safe"""
        dangerous_operations = [
            'format_disk',
            'delete_all',
            'drop_table',
            'shutdown',
            'reboot'
        ]
        
        for step in chain_steps:
            step_lower = step.lower()
            for dangerous in dangerous_operations:
                if dangerous in step_lower:
                    logger.error(f"Dangerous operation detected: {dangerous}")
                    return False
        
        return True

