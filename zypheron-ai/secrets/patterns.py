"""
Secret Patterns - Regex patterns for detecting various types of secrets
"""

import re
from typing import Dict, Any, Optional, List


class SecretPatterns:
    """
    Collection of regex patterns for secret detection
    
    Patterns inspired by TruffleHog, GitLeaks, and industry standards
    """
    
    def __init__(self):
        self.patterns = {
            # API Keys
            'aws_access_key': {
                'regex': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
                'type': 'aws_access_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            'aws_secret_key': {
                'regex': r'aws(.{0,20})?[\'\"][0-9a-zA-Z\/+]{40}[\'\"]',
                'type': 'aws_secret_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            'github_token': {
                'regex': r'ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}',
                'type': 'github_token',
                'confidence': 'high',
                'severity': 'critical'
            },
            'slack_token': {
                'regex': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
                'type': 'slack_token',
                'confidence': 'high',
                'severity': 'high'
            },
            'stripe_key': {
                'regex': r'sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}',
                'type': 'stripe_api_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            'google_api_key': {
                'regex': r'AIza[0-9A-Za-z\\-_]{35}',
                'type': 'google_api_key',
                'confidence': 'high',
                'severity': 'high'
            },
            'google_oauth': {
                'regex': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'type': 'google_oauth_client',
                'confidence': 'high',
                'severity': 'high'
            },
            'heroku_api_key': {
                'regex': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
                'type': 'heroku_api_key',
                'confidence': 'high',
                'severity': 'high'
            },
            'mailgun_api_key': {
                'regex': r'key-[0-9a-zA-Z]{32}',
                'type': 'mailgun_api_key',
                'confidence': 'medium',
                'severity': 'high'
            },
            'twilio_api_key': {
                'regex': r'SK[0-9a-fA-F]{32}',
                'type': 'twilio_api_key',
                'confidence': 'high',
                'severity': 'high'
            },
            
            # Private Keys
            'rsa_private_key': {
                'regex': r'-----BEGIN RSA PRIVATE KEY-----',
                'type': 'rsa_private_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            'ssh_private_key': {
                'regex': r'-----BEGIN OPENSSH PRIVATE KEY-----',
                'type': 'ssh_private_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            'pgp_private_key': {
                'regex': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'type': 'pgp_private_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            
            # Database Credentials
            'postgres_url': {
                'regex': r'postgres://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+',
                'type': 'postgres_connection',
                'confidence': 'high',
                'severity': 'critical'
            },
            'mysql_url': {
                'regex': r'mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+',
                'type': 'mysql_connection',
                'confidence': 'high',
                'severity': 'critical'
            },
            'mongodb_url': {
                'regex': r'mongodb(\+srv)?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+',
                'type': 'mongodb_connection',
                'confidence': 'high',
                'severity': 'critical'
            },
            
            # Generic Patterns
            'generic_api_key': {
                'regex': r'(?i)api[_-]?key[\s]*[=:>]\s*[\'\"]?([a-zA-Z0-9_\-]{32,})[\'\"]?',
                'type': 'api_key',
                'confidence': 'medium',
                'severity': 'high'
            },
            'generic_secret': {
                'regex': r'(?i)secret[\s]*[=:>]\s*[\'\"]?([a-zA-Z0-9_\-]{16,})[\'\"]?',
                'type': 'generic_secret',
                'confidence': 'medium',
                'severity': 'medium'
            },
            'generic_password': {
                'regex': r'(?i)password[\s]*[=:>]\s*[\'\"]([^\'\"\s]{8,})[\'\"]',
                'type': 'password',
                'confidence': 'low',
                'severity': 'medium'
            },
            'generic_token': {
                'regex': r'(?i)token[\s]*[=:>]\s*[\'\"]?([a-zA-Z0-9_\-]{20,})[\'\"]?',
                'type': 'token',
                'confidence': 'medium',
                'severity': 'high'
            },
            
            # JWT
            'jwt_token': {
                'regex': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                'type': 'jwt_token',
                'confidence': 'high',
                'severity': 'high'
            },
            
            # Cryptocurrency
            'bitcoin_address': {
                'regex': r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
                'type': 'bitcoin_address',
                'confidence': 'medium',
                'severity': 'medium'
            },
            
            # Cloud Providers
            'azure_storage_key': {
                'regex': r'(?i)(?:azure|account)(?:.*)?key[\s]*[=:>]\s*[\'\"]?([a-zA-Z0-9+/=]{88})[\'\"]?',
                'type': 'azure_storage_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            'gcp_service_account': {
                'regex': r'\{[^}]*"type":\s*"service_account"[^}]*\}',
                'type': 'gcp_service_account',
                'confidence': 'high',
                'severity': 'critical'
            },
            
            # Auth Tokens
            'bearer_token': {
                'regex': r'Bearer\s+[a-zA-Z0-9_\-\.=]{20,}',
                'type': 'bearer_token',
                'confidence': 'high',
                'severity': 'high'
            },
            
            # Anthropic (Claude)
            'anthropic_api_key': {
                'regex': r'sk-ant-api03-[a-zA-Z0-9_\-]{93,}',
                'type': 'anthropic_api_key',
                'confidence': 'high',
                'severity': 'critical'
            },
            
            # OpenAI
            'openai_api_key': {
                'regex': r'sk-[a-zA-Z0-9]{48}',
                'type': 'openai_api_key',
                'confidence': 'high',
                'severity': 'critical'
            },
        }
    
    def get_all_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Get all secret patterns"""
        return self.patterns
    
    def get_pattern(self, pattern_name: str) -> Optional[Dict[str, Any]]:
        """Get specific pattern"""
        return self.patterns.get(pattern_name)
    
    def add_custom_pattern(
        self,
        name: str,
        regex: str,
        secret_type: str,
        confidence: str = 'medium',
        severity: str = 'high'
    ):
        """Add custom pattern"""
        self.patterns[name] = {
            'regex': regex,
            'type': secret_type,
            'confidence': confidence,
            'severity': severity
        }
        logger.info(f"Added custom pattern: {name}")


class PatternMatcher:
    """Utility for pattern matching operations"""
    
    @staticmethod
    def test_pattern(pattern: str, test_string: str) -> bool:
        """Test if pattern matches string"""
        try:
            return bool(re.search(pattern, test_string, re.IGNORECASE))
        except Exception as e:
            logger.error(f"Pattern test failed: {e}")
            return False
    
    @staticmethod
    def extract_matches(pattern: str, text: str) -> List[str]:
        """Extract all matches from text"""
        try:
            matches = re.findall(pattern, text, re.IGNORECASE)
            return matches
        except Exception as e:
            logger.error(f"Pattern extraction failed: {e}")
            return []
    
    @staticmethod
    def validate_regex(pattern: str) -> bool:
        """Validate regex pattern"""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

