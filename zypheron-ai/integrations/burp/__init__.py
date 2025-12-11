"""
Burp Suite Integration

Provides integration with Burp Suite Professional for advanced web application testing.
"""

from .burp_api import BurpAPI, BurpConfig
from .burp_scanner import BurpScanner, ScanConfig
from .burp_reporter import BurpReporter, BurpFinding

__all__ = [
    'BurpAPI',
    'BurpConfig',
    'BurpScanner',
    'ScanConfig',
    'BurpReporter',
    'BurpFinding'
]

