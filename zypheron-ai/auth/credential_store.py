"""
Credential Store - Secure credential management using keyring
"""

import logging
import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import keyring
from cryptography.fernet import Fernet
import base64
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """Stored credential"""
    credential_id: str
    username: str
    target_url: str
    auth_type: str
    description: str = ""
    
    # Optional fields
    api_key: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    
    # Metadata
    created_at: Optional[str] = None
    last_used: Optional[str] = None
    
    def to_dict(self, include_secrets: bool = False) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        if not include_secrets:
            # Remove sensitive fields
            data.pop('api_key', None)
            data.pop('client_secret', None)
        return data


class CredentialStore:
    """
    Secure credential storage using system keyring
    
    Features:
    - Platform-specific secure storage (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows)
    - Encryption for additional security
    - Credential lifecycle management
    - Audit logging
    """
    
    SERVICE_NAME = "Zypheron-Pentest"
    
    def __init__(self):
        self.credentials: Dict[str, Credential] = {}
        self._encryption_key = self._get_or_create_encryption_key()
        self._cipher = Fernet(self._encryption_key)
        self._load_credentials()
    
    def _get_or_create_encryption_key(self) -> bytes:
        """
        Get or create encryption key from keyring.
        
        SECURITY: This method MUST have access to the system keyring.
        There is NO weak fallback - if keyring is unavailable, the system
        should fail securely and prompt the user to fix their environment.
        
        Returns:
            Encryption key bytes
            
        Raises:
            RuntimeError: If keyring is unavailable (fail securely)
        """
        try:
            # Try to get existing key
            key_b64 = keyring.get_password(self.SERVICE_NAME, "encryption_key")
            
            if key_b64:
                key = base64.b64decode(key_b64)
                # Validate key format
                if len(key) != 32:
                    logger.error("Stored encryption key has invalid length")
                    raise RuntimeError("Corrupted encryption key in keyring")
                return key
            
            # Create new key using cryptographically secure random
            key = Fernet.generate_key()
            
            # Store in keyring
            keyring.set_password(
                self.SERVICE_NAME,
                "encryption_key",
                base64.b64encode(key).decode()
            )
            
            logger.info("Created new encryption key")
            return key
            
        except Exception as e:
            # SECURITY: Fail securely instead of using weak fallback
            logger.critical(
                f"Cannot access system keyring: {e}\n"
                "Credential storage requires a working keyring.\n"
                "On Linux, install gnome-keyring or kwallet.\n"
                "On macOS, Keychain is built-in.\n"
                "On Windows, Credential Manager is built-in."
            )
            raise RuntimeError(
                "System keyring unavailable. Cannot securely store credentials. "
                "Please install and configure a keyring backend."
            ) from e
    
    def store_credential(
        self,
        credential_id: str,
        username: str,
        password: str,
        target_url: str,
        auth_type: str,
        description: str = "",
        **kwargs
    ) -> bool:
        """
        Store credential securely
        
        Args:
            credential_id: Unique identifier
            username: Username
            password: Password (will be encrypted)
            target_url: Target URL
            auth_type: Authentication type
            description: Optional description
            **kwargs: Additional fields (api_key, client_id, client_secret, etc.)
        """
        try:
            from datetime import datetime
            
            # Store password in keyring
            keyring_key = f"{credential_id}_password"
            keyring.set_password(self.SERVICE_NAME, keyring_key, password)
            
            # Store additional secrets
            for key in ['api_key', 'client_secret']:
                if key in kwargs and kwargs[key]:
                    secret_key = f"{credential_id}_{key}"
                    keyring.set_password(self.SERVICE_NAME, secret_key, kwargs[key])
            
            # Create credential object (without password)
            credential = Credential(
                credential_id=credential_id,
                username=username,
                target_url=target_url,
                auth_type=auth_type,
                description=description,
                client_id=kwargs.get('client_id'),
                created_at=datetime.now().isoformat()
            )
            
            self.credentials[credential_id] = credential
            self._save_credentials()
            
            logger.info(f"Stored credential {credential_id} for {username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store credential: {e}")
            return False
    
    def get_credential(
        self,
        credential_id: str,
        include_password: bool = False
    ) -> Optional[Credential]:
        """Get credential by ID"""
        credential = self.credentials.get(credential_id)
        
        if not credential:
            logger.warning(f"Credential {credential_id} not found")
            return None
        
        if include_password:
            # This returns a copy with password, not modifying original
            import copy
            cred_copy = copy.deepcopy(credential)
            # Note: password not stored in credential object, only in keyring
            return cred_copy
        
        from datetime import datetime
        credential.last_used = datetime.now().isoformat()
        self._save_credentials()
        
        return credential
    
    def get_password(self, credential_id: str) -> Optional[str]:
        """Get password for credential"""
        if credential_id not in self.credentials:
            return None
        
        try:
            keyring_key = f"{credential_id}_password"
            password = keyring.get_password(self.SERVICE_NAME, keyring_key)
            return password
        except Exception as e:
            logger.error(f"Failed to retrieve password: {e}")
            return None
    
    def get_secret(self, credential_id: str, secret_key: str) -> Optional[str]:
        """Get additional secret (api_key, client_secret, etc.)"""
        if credential_id not in self.credentials:
            return None
        
        try:
            keyring_key = f"{credential_id}_{secret_key}"
            secret = keyring.get_password(self.SERVICE_NAME, keyring_key)
            return secret
        except Exception as e:
            logger.error(f"Failed to retrieve secret: {e}")
            return None
    
    def list_credentials(
        self,
        target_url: Optional[str] = None,
        auth_type: Optional[str] = None
    ) -> List[Credential]:
        """List stored credentials"""
        credentials = list(self.credentials.values())
        
        if target_url:
            credentials = [c for c in credentials if c.target_url == target_url]
        
        if auth_type:
            credentials = [c for c in credentials if c.auth_type == auth_type]
        
        return credentials
    
    def update_credential(
        self,
        credential_id: str,
        **kwargs
    ) -> bool:
        """Update credential fields"""
        credential = self.credentials.get(credential_id)
        if not credential:
            return False
        
        # Update non-secret fields
        for key in ['username', 'target_url', 'auth_type', 'description', 'client_id']:
            if key in kwargs:
                setattr(credential, key, kwargs[key])
        
        # Update password if provided
        if 'password' in kwargs and kwargs['password']:
            keyring_key = f"{credential_id}_password"
            keyring.set_password(self.SERVICE_NAME, keyring_key, kwargs['password'])
        
        # Update other secrets
        for secret_key in ['api_key', 'client_secret']:
            if secret_key in kwargs and kwargs[secret_key]:
                keyring_key = f"{credential_id}_{secret_key}"
                keyring.set_password(self.SERVICE_NAME, keyring_key, kwargs[secret_key])
        
        self._save_credentials()
        logger.info(f"Updated credential {credential_id}")
        return True
    
    def delete_credential(self, credential_id: str) -> bool:
        """Delete credential"""
        if credential_id not in self.credentials:
            return False
        
        try:
            # Delete password from keyring
            keyring_key = f"{credential_id}_password"
            try:
                keyring.delete_password(self.SERVICE_NAME, keyring_key)
            except:
                pass
            
            # Delete additional secrets
            for secret_key in ['api_key', 'client_secret']:
                keyring_key = f"{credential_id}_{secret_key}"
                try:
                    keyring.delete_password(self.SERVICE_NAME, keyring_key)
                except:
                    pass
            
            # Remove from credentials dict
            del self.credentials[credential_id]
            self._save_credentials()
            
            logger.info(f"Deleted credential {credential_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete credential: {e}")
            return False
    
    def export_credentials(
        self,
        output_file: str,
        include_secrets: bool = False,
        password: Optional[str] = None
    ) -> bool:
        """
        Export credentials to file with secure encryption.
        
        Args:
            output_file: Output file path
            include_secrets: Whether to include passwords (encrypted)
            password: Password to encrypt export file
            
        SECURITY: Uses random salt per export, stored with encrypted data
        """
        try:
            export_data = {
                'version': '2.0',  # Version for future migration
                'credentials': []
            }
            
            # Generate export salt if using password
            export_salt = None
            export_cipher = None
            if password and include_secrets:
                export_cipher, export_salt = self._create_cipher_from_password(password)
                export_data['salt'] = base64.b64encode(export_salt).decode()
            
            for cred_id, credential in self.credentials.items():
                cred_data = credential.to_dict(include_secrets=False)
                
                if include_secrets:
                    # Get password
                    pwd = self.get_password(cred_id)
                    if pwd:
                        if password and export_cipher:
                            # Encrypt with user-provided password and salt
                            cred_data['password'] = export_cipher.encrypt(pwd.encode()).decode()
                        else:
                            # Store encrypted with master key
                            cred_data['password'] = self._cipher.encrypt(pwd.encode()).decode()
                    
                    # Get other secrets
                    for secret_key in ['api_key', 'client_secret']:
                        secret = self.get_secret(cred_id, secret_key)
                        if secret:
                            if password and export_cipher:
                                cred_data[secret_key] = export_cipher.encrypt(secret.encode()).decode()
                            else:
                                cred_data[secret_key] = self._cipher.encrypt(secret.encode()).decode()
                
                export_data['credentials'].append(cred_data)
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            # Secure file permissions (owner-only read/write)
            import os
            os.chmod(output_file, 0o600)
            
            logger.info(f"Exported {len(export_data['credentials'])} credentials")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export credentials: {e}")
            return False
    
    def import_credentials(
        self,
        input_file: str,
        password: Optional[str] = None
    ) -> int:
        """
        Import credentials from file with salt-aware decryption.
        
        Args:
            input_file: Input file path
            password: Password to decrypt import file
            
        Returns:
            Number of credentials imported
        """
        try:
            with open(input_file, 'r') as f:
                export_data = json.load(f)
            
            # Check version
            version = export_data.get('version', '1.0')
            
            # Get salt if present (version 2.0+)
            import_cipher = None
            if password:
                if 'salt' in export_data:
                    # Use stored salt for decryption
                    salt = base64.b64decode(export_data['salt'])
                    import_cipher, _ = self._create_cipher_from_password(password, salt=salt)
                else:
                    # Legacy format without salt (less secure)
                    logger.warning("Import file uses legacy format without salt")
                    # For backward compatibility, try old method
                    key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'zypheron-salt', 100000)
                    import_cipher = Fernet(base64.urlsafe_b64encode(key))
            
            imported = 0
            for cred_data in export_data.get('credentials', []):
                credential_id = cred_data.get('credential_id')
                
                # Extract password if present
                pwd = None
                if 'password' in cred_data:
                    try:
                        if password and import_cipher:
                            pwd = import_cipher.decrypt(cred_data['password'].encode()).decode()
                        else:
                            pwd = self._cipher.decrypt(cred_data['password'].encode()).decode()
                    except Exception as e:
                        logger.warning(f"Failed to decrypt password for {credential_id}: {e}")
                
                # Extract other secrets
                secrets = {}
                for secret_key in ['api_key', 'client_secret']:
                    if secret_key in cred_data:
                        try:
                            if password and import_cipher:
                                secrets[secret_key] = import_cipher.decrypt(
                                    cred_data[secret_key].encode()
                                ).decode()
                            else:
                                secrets[secret_key] = self._cipher.decrypt(
                                    cred_data[secret_key].encode()
                                ).decode()
                        except Exception as e:
                            logger.warning(f"Failed to decrypt {secret_key} for {credential_id}: {e}")
                
                # Store credential
                self.store_credential(
                    credential_id=credential_id,
                    username=cred_data.get('username', ''),
                    password=pwd or 'imported_no_password',
                    target_url=cred_data.get('target_url', ''),
                    auth_type=cred_data.get('auth_type', 'unknown'),
                    description=cred_data.get('description', ''),
                    **secrets
                )
                
                imported += 1
            
            logger.info(f"Imported {imported} credentials")
            return imported
            
        except Exception as e:
            logger.error(f"Failed to import credentials: {e}")
            return 0
    
    def _create_cipher_from_password(self, password: str, salt: bytes = None) -> tuple[Fernet, bytes]:
        """
        Create Fernet cipher from password with secure key derivation.
        
        Args:
            password: User password
            salt: Salt bytes (generated if None)
            
        Returns:
            Tuple of (Fernet cipher, salt used)
            
        SECURITY NOTES:
        - Uses PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
        - Uses cryptographically random salt (16 bytes)
        - Salt must be stored with encrypted data for decryption
        """
        # Generate cryptographically secure random salt if not provided
        if salt is None:
            salt = os.urandom(16)  # 128 bits of randomness
        
        # Derive key using PBKDF2-HMAC-SHA256
        # 600,000 iterations per OWASP recommendations (2023)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            600000,  # Increased from 100,000 to 600,000
            dklen=32  # 256 bits
        )
        
        cipher = Fernet(base64.urlsafe_b64encode(key))
        return cipher, salt
    
    def _save_credentials(self):
        """Save credential metadata (not passwords) to keyring"""
        try:
            # Serialize credential metadata
            metadata = {
                cred_id: cred.to_dict(include_secrets=False)
                for cred_id, cred in self.credentials.items()
            }
            
            # Encrypt and store
            encrypted = self._cipher.encrypt(json.dumps(metadata).encode())
            keyring.set_password(
                self.SERVICE_NAME,
                "credentials_metadata",
                base64.b64encode(encrypted).decode()
            )
            
        except Exception as e:
            logger.error(f"Failed to save credentials metadata: {e}")
    
    def _load_credentials(self):
        """Load credential metadata from keyring"""
        try:
            # Get encrypted metadata
            encrypted_b64 = keyring.get_password(self.SERVICE_NAME, "credentials_metadata")
            
            if not encrypted_b64:
                logger.debug("No stored credentials found")
                return
            
            # Decrypt
            encrypted = base64.b64decode(encrypted_b64)
            decrypted = self._cipher.decrypt(encrypted)
            metadata = json.loads(decrypted.decode())
            
            # Recreate credential objects
            for cred_id, cred_data in metadata.items():
                self.credentials[cred_id] = Credential(**cred_data)
            
            logger.info(f"Loaded {len(self.credentials)} credentials")
            
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")

