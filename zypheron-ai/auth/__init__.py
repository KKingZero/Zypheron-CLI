"""
Authentication & Session Management

Provides authenticated testing capabilities for penetration testing.
"""

from .session_manager import SessionManager, Session
from .auth_providers import (
    AuthProvider,
    BasicAuthProvider,
    BearerAuthProvider,
    FormAuthProvider,
    CookieAuthProvider,
    OAuth2Provider,
    APIKeyAuthProvider
)
from .credential_store import CredentialStore, Credential
from .test_accounts import TestAccountManager, TestAccount

__all__ = [
    'SessionManager',
    'Session',
    'AuthProvider',
    'BasicAuthProvider',
    'BearerAuthProvider',
    'FormAuthProvider',
    'CookieAuthProvider',
    'OAuth2Provider',
    'APIKeyAuthProvider',
    'CredentialStore',
    'Credential',
    'TestAccountManager',
    'TestAccount'
]

