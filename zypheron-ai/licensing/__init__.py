"""
Zypheron Licensing Module

Provides license validation and feature gating for the Python AI engine.
This module reads the shared SQLite database created by the CLI/Electron app.
"""

from .validator import LicenseValidator, License, Tier, Feature
from .token_counter import TokenCounter
from .exceptions import (
    FeatureLockedError,
    InsufficientTokensError,
    NotAuthenticatedError,
    LicenseExpiredError
)

__all__ = [
    'LicenseValidator',
    'License',
    'Tier',
    'Feature',
    'TokenCounter',
    'FeatureLockedError',
    'InsufficientTokensError',
    'NotAuthenticatedError',
    'LicenseExpiredError'
]
