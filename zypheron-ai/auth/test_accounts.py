"""
Test Account Management - Create, use, and cleanup test accounts
"""

import logging
import uuid
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
import json
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TestAccount:
    """Test account for penetration testing"""
    account_id: str
    username: str
    password: str
    email: str
    role: str
    target_url: str
    
    # Status
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    is_active: bool = True
    auto_cleanup: bool = True
    
    # Metadata
    session_id: Optional[str] = None
    additional_data: Dict = field(default_factory=dict)
    
    # Audit
    created_by: str = "zypheron"
    cleanup_callback: Optional[Callable] = None
    
    def is_expired(self) -> bool:
        """Check if account has expired"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat() if self.expires_at else None
        data.pop('cleanup_callback', None)  # Can't serialize callback
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'TestAccount':
        """Create from dictionary"""
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'expires_at' in data and data['expires_at']:
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        data.pop('cleanup_callback', None)
        return cls(**data)


class TestAccountManager:
    """
    Manage test accounts for penetration testing
    
    Features:
    - Automated test account creation
    - Role-based accounts (admin, user, guest)
    - Account isolation per test run
    - Automatic cleanup after testing
    - Account state tracking
    """
    
    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = Path.home() / '.zypheron' / 'test_accounts'
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.accounts: Dict[str, TestAccount] = {}
        self.creation_callbacks: Dict[str, Callable] = {}
        self.deletion_callbacks: Dict[str, Callable] = {}
        
        self._load_accounts()
    
    def register_creation_callback(
        self,
        target_pattern: str,
        callback: Callable
    ):
        """
        Register callback for account creation
        
        Args:
            target_pattern: URL pattern to match
            callback: Function(username, password, role) -> bool
        """
        self.creation_callbacks[target_pattern] = callback
        logger.info(f"Registered creation callback for {target_pattern}")
    
    def register_deletion_callback(
        self,
        target_pattern: str,
        callback: Callable
    ):
        """
        Register callback for account deletion
        
        Args:
            target_pattern: URL pattern to match
            callback: Function(username) -> bool
        """
        self.deletion_callbacks[target_pattern] = callback
        logger.info(f"Registered deletion callback for {target_pattern}")
    
    def create_account(
        self,
        target_url: str,
        role: str = "user",
        username: Optional[str] = None,
        password: Optional[str] = None,
        email: Optional[str] = None,
        lifetime_hours: int = 24,
        auto_cleanup: bool = True,
        **kwargs
    ) -> Optional[TestAccount]:
        """
        Create a test account
        
        Args:
            target_url: Target application URL
            role: Account role (admin, user, guest)
            username: Username (auto-generated if not provided)
            password: Password (auto-generated if not provided)
            email: Email (auto-generated if not provided)
            lifetime_hours: How long account should live
            auto_cleanup: Whether to auto-cleanup when expired
            **kwargs: Additional account data
            
        Returns:
            TestAccount object
        """
        # Generate account details if not provided
        timestamp = int(datetime.now().timestamp())
        
        if not username:
            username = f"test_{role}_{timestamp}"
        
        if not password:
            # Generate secure password
            password = self._generate_password()
        
        if not email:
            email = f"{username}@zypheron-test.local"
        
        # Create account
        account_id = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(hours=lifetime_hours)
        
        account = TestAccount(
            account_id=account_id,
            username=username,
            password=password,
            email=email,
            role=role,
            target_url=target_url,
            expires_at=expires_at,
            auto_cleanup=auto_cleanup,
            additional_data=kwargs
        )
        
        # Call creation callback if registered
        created = False
        for pattern, callback in self.creation_callbacks.items():
            if pattern in target_url:
                try:
                    created = callback(username, password, email, role)
                    if created:
                        logger.info(f"Account created via callback for {pattern}")
                        break
                except Exception as e:
                    logger.error(f"Creation callback failed: {e}")
        
        # If no callback succeeded, mark as created anyway (manual creation needed)
        if not created and not self.creation_callbacks:
            logger.info(f"No creation callback registered for {target_url}")
            created = True
        
        if created:
            self.accounts[account_id] = account
            self._save_account(account)
            logger.info(f"Created test account {username} ({role}) for {target_url}")
            return account
        else:
            logger.error(f"Failed to create test account {username}")
            return None
    
    def get_account(
        self,
        account_id: Optional[str] = None,
        username: Optional[str] = None,
        role: Optional[str] = None,
        target_url: Optional[str] = None
    ) -> Optional[TestAccount]:
        """
        Get test account by ID, username, role, or target
        
        Priority: account_id > username > role+target > target
        """
        if account_id:
            return self.accounts.get(account_id)
        
        if username:
            for account in self.accounts.values():
                if account.username == username and account.is_active:
                    return account
        
        if role and target_url:
            for account in self.accounts.values():
                if (account.role == role and 
                    account.target_url == target_url and 
                    account.is_active and 
                    not account.is_expired()):
                    return account
        
        if target_url:
            for account in self.accounts.values():
                if (account.target_url == target_url and 
                    account.is_active and 
                    not account.is_expired()):
                    return account
        
        return None
    
    def list_accounts(
        self,
        target_url: Optional[str] = None,
        role: Optional[str] = None,
        active_only: bool = True
    ) -> List[TestAccount]:
        """List test accounts"""
        accounts = list(self.accounts.values())
        
        if active_only:
            accounts = [a for a in accounts if a.is_active and not a.is_expired()]
        
        if target_url:
            accounts = [a for a in accounts if a.target_url == target_url]
        
        if role:
            accounts = [a for a in accounts if a.role == role]
        
        return accounts
    
    def delete_account(
        self,
        account_id: str,
        call_callback: bool = True
    ) -> bool:
        """Delete test account"""
        account = self.accounts.get(account_id)
        if not account:
            logger.warning(f"Account {account_id} not found")
            return False
        
        # Call deletion callback if registered
        if call_callback:
            for pattern, callback in self.deletion_callbacks.items():
                if pattern in account.target_url:
                    try:
                        callback(account.username)
                        logger.info(f"Account deleted via callback for {pattern}")
                    except Exception as e:
                        logger.error(f"Deletion callback failed: {e}")
        
        # Remove from storage
        del self.accounts[account_id]
        
        account_file = self.storage_dir / f"{account_id}.json"
        if account_file.exists():
            account_file.unlink()
        
        logger.info(f"Deleted test account {account.username}")
        return True
    
    def cleanup_expired_accounts(self) -> int:
        """
        Clean up expired accounts with auto_cleanup enabled
        
        Returns:
            Number of accounts cleaned up
        """
        expired_ids = []
        
        for account_id, account in self.accounts.items():
            if account.is_expired() and account.auto_cleanup:
                expired_ids.append(account_id)
        
        for account_id in expired_ids:
            self.delete_account(account_id, call_callback=True)
        
        logger.info(f"Cleaned up {len(expired_ids)} expired accounts")
        return len(expired_ids)
    
    def cleanup_all_accounts(self, target_url: Optional[str] = None) -> int:
        """
        Clean up all test accounts (for target or all)
        
        Args:
            target_url: Optional URL to limit cleanup
            
        Returns:
            Number of accounts cleaned up
        """
        account_ids = list(self.accounts.keys())
        cleaned = 0
        
        for account_id in account_ids:
            account = self.accounts[account_id]
            
            if target_url and account.target_url != target_url:
                continue
            
            self.delete_account(account_id, call_callback=True)
            cleaned += 1
        
        logger.info(f"Cleaned up {cleaned} test accounts")
        return cleaned
    
    def extend_lifetime(
        self,
        account_id: str,
        additional_hours: int
    ) -> bool:
        """Extend account lifetime"""
        account = self.accounts.get(account_id)
        if not account:
            return False
        
        if account.expires_at:
            account.expires_at += timedelta(hours=additional_hours)
            self._save_account(account)
            logger.info(f"Extended lifetime for {account.username} by {additional_hours}h")
            return True
        
        return False
    
    def deactivate_account(self, account_id: str) -> bool:
        """Deactivate account without deletion"""
        account = self.accounts.get(account_id)
        if not account:
            return False
        
        account.is_active = False
        self._save_account(account)
        logger.info(f"Deactivated account {account.username}")
        return True
    
    def _generate_password(self, length: int = 16) -> str:
        """Generate secure random password"""
        import secrets
        import string
        
        # Ensure password has mix of characters
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        # Ensure at least one of each type
        if not any(c.isupper() for c in password):
            password = password[:-1] + secrets.choice(string.ascii_uppercase)
        if not any(c.islower() for c in password):
            password = password[:-2] + secrets.choice(string.ascii_lowercase)
        if not any(c.isdigit() for c in password):
            password = password[:-3] + secrets.choice(string.digits)
        
        return password
    
    def _save_account(self, account: TestAccount):
        """Save account to disk"""
        account_file = self.storage_dir / f"{account.account_id}.json"
        
        try:
            with open(account_file, 'w') as f:
                json.dump(account.to_dict(), f, indent=2)
            
            # Secure file permissions (passwords stored here)
            account_file.chmod(0o600)
            
        except Exception as e:
            logger.error(f"Failed to save account {account.account_id}: {e}")
    
    def _load_accounts(self):
        """Load accounts from disk"""
        if not self.storage_dir.exists():
            return
        
        for account_file in self.storage_dir.glob('*.json'):
            try:
                with open(account_file, 'r') as f:
                    data = json.load(f)
                
                account = TestAccount.from_dict(data)
                self.accounts[account.account_id] = account
                
                logger.debug(f"Loaded test account {account.username}")
                
            except Exception as e:
                logger.error(f"Failed to load account from {account_file}: {e}")
        
        logger.info(f"Loaded {len(self.accounts)} test accounts")
    
    def export_accounts(self, output_file: str) -> bool:
        """Export all test accounts to file"""
        try:
            data = {
                'accounts': [account.to_dict() for account in self.accounts.values()]
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Exported {len(self.accounts)} accounts to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export accounts: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get account statistics"""
        total = len(self.accounts)
        active = sum(1 for a in self.accounts.values() if a.is_active and not a.is_expired())
        expired = sum(1 for a in self.accounts.values() if a.is_expired())
        
        roles = {}
        for account in self.accounts.values():
            roles[account.role] = roles.get(account.role, 0) + 1
        
        return {
            'total': total,
            'active': active,
            'expired': expired,
            'by_role': roles
        }

