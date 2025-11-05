"""
Automated Penetration Testing Framework

Provides intelligent, safe automated penetration testing with:
- Authorization checks
- Safety controls
- Attack chain planning
- Exploitation
- Post-exploitation
"""

from .autopent_engine import AutoPentEngine, PentestPhase, PentestResult
from .attack_chain import AttackChain, AttackStep
from .safety_controls import SafetyController, AuthorizationManager

__all__ = [
    'AutoPentEngine',
    'PentestPhase',
    'PentestResult',
    'AttackChain',
    'AttackStep',
    'SafetyController',
    'AuthorizationManager'
]

