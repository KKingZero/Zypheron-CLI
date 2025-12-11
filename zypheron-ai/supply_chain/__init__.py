"""
Supply Chain Security Analysis

Scan dependencies for known vulnerabilities and generate SBOM.
"""

from .dependency_scanner import DependencyScanner, DependencyVulnerability
from .sbom_generator import SBOMGenerator, Component
from .cve_matcher import CVEMatcher

__all__ = [
    'DependencyScanner',
    'DependencyVulnerability',
    'SBOMGenerator',
    'Component',
    'CVEMatcher'
]

