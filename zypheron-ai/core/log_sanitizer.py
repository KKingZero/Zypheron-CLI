"""
Log Sanitization Module

Prevents sensitive data (API keys, tokens, passwords, etc.) from leaking into logs.
Implements a logging filter that redacts secrets and provides audit logging capabilities.
"""

import re
import logging
import json
from typing import Any, Dict, List, Pattern, Optional
from datetime import datetime
from pathlib import Path


class SensitiveDataPattern:
    """Defines patterns for detecting sensitive data"""
    
    # API Keys and Tokens
    API_KEY = re.compile(r'(api[_-]?key|apikey)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.IGNORECASE)
    BEARER_TOKEN = re.compile(r'Bearer\s+([a-zA-Z0-9_\-\.]{20,})', re.IGNORECASE)
    ACCESS_TOKEN = re.compile(r'(access[_-]?token|token)[\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', re.IGNORECASE)
    
    # AWS Credentials
    AWS_ACCESS_KEY = re.compile(r'(AKIA[0-9A-Z]{16})', re.IGNORECASE)
    AWS_SECRET_KEY = re.compile(r'(aws[_-]?secret[_-]?access[_-]?key)[\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?', re.IGNORECASE)
    
    # Private Keys
    PRIVATE_KEY = re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----', re.IGNORECASE)
    
    # Passwords
    PASSWORD = re.compile(r'(password|passwd|pwd)[\s:=]+["\']?([^\s"\']{8,})["\']?', re.IGNORECASE)
    
    # Database Connection Strings
    DB_CONNECTION = re.compile(r'(mysql|postgresql|mongodb|redis)://[^:]+:([^@]+)@', re.IGNORECASE)
    
    # Generic Secrets
    SECRET = re.compile(r'(secret[_-]?key|client[_-]?secret)[\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', re.IGNORECASE)
    
    # Credit Cards (basic)
    CREDIT_CARD = re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b')
    
    # Social Security Numbers (US)
    SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
    
    # JWT Tokens
    JWT = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
    
    # IP Addresses (for redaction in certain contexts)
    # IP_ADDRESS = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    
    @classmethod
    def get_all_patterns(cls) -> List[tuple[str, Pattern]]:
        """Returns all patterns with their names"""
        return [
            ('API_KEY', cls.API_KEY),
            ('BEARER_TOKEN', cls.BEARER_TOKEN),
            ('ACCESS_TOKEN', cls.ACCESS_TOKEN),
            ('AWS_ACCESS_KEY', cls.AWS_ACCESS_KEY),
            ('AWS_SECRET_KEY', cls.AWS_SECRET_KEY),
            ('PRIVATE_KEY', cls.PRIVATE_KEY),
            ('PASSWORD', cls.PASSWORD),
            ('DB_CONNECTION', cls.DB_CONNECTION),
            ('SECRET', cls.SECRET),
            ('CREDIT_CARD', cls.CREDIT_CARD),
            ('SSN', cls.SSN),
            ('JWT', cls.JWT),
        ]


class LogSanitizer:
    """
    Sanitizes log messages by redacting sensitive information.
    
    SECURITY: Prevents API keys, passwords, and other secrets from leaking into logs.
    """
    
    def __init__(self, redaction_text: str = "[REDACTED]"):
        """
        Initialize the log sanitizer.
        
        Args:
            redaction_text: Text to replace sensitive data with
        """
        self.redaction_text = redaction_text
        self.patterns = SensitiveDataPattern.get_all_patterns()
        self.redaction_count = 0
    
    def sanitize(self, message: str) -> str:
        """
        Sanitize a log message by redacting sensitive information.
        
        Args:
            message: The log message to sanitize
            
        Returns:
            Sanitized message with sensitive data redacted
        """
        sanitized = message
        
        for pattern_name, pattern in self.patterns:
            if pattern.search(sanitized):
                # Different redaction strategies for different patterns
                if pattern_name in ['PRIVATE_KEY']:
                    # Completely redact private keys
                    sanitized = pattern.sub(f'[REDACTED_{pattern_name}]', sanitized)
                    self.redaction_count += 1
                elif pattern_name in ['PASSWORD', 'SECRET', 'AWS_SECRET_KEY', 'DB_CONNECTION']:
                    # Keep field name, redact value
                    sanitized = pattern.sub(lambda m: f'{m.group(1)}={self.redaction_text}', sanitized)
                    self.redaction_count += 1
                elif pattern_name in ['API_KEY', 'ACCESS_TOKEN']:
                    # Partial redaction (keep first few chars for debugging)
                    def partial_redact(match):
                        key = match.group(2) if len(match.groups()) > 1 else match.group(1)
                        if len(key) > 8:
                            return f'{match.group(1)}={key[:4]}...{self.redaction_text}'
                        return f'{match.group(1)}={self.redaction_text}'
                    sanitized = pattern.sub(partial_redact, sanitized)
                    self.redaction_count += 1
                elif pattern_name == 'CREDIT_CARD':
                    # Keep last 4 digits for debugging
                    sanitized = pattern.sub(lambda m: f'****-****-****-{m.group(0)[-4:]}', sanitized)
                    self.redaction_count += 1
                elif pattern_name == 'SSN':
                    # Keep last 4 digits
                    sanitized = pattern.sub(lambda m: f'***-**-{m.group(0)[-4:]}', sanitized)
                    self.redaction_count += 1
                else:
                    # Default: complete redaction
                    sanitized = pattern.sub(self.redaction_text, sanitized)
                    self.redaction_count += 1
        
        return sanitized
    
    def sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize a dictionary, redacting sensitive keys.
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary copy
        """
        sensitive_keys = {
            'password', 'passwd', 'pwd', 'api_key', 'apikey', 'access_token',
            'secret', 'secret_key', 'private_key', 'token', 'bearer',
            'credit_card', 'ssn', 'authorization', 'auth'
        }
        
        def sanitize_value(key: str, value: Any) -> Any:
            # Check if key is sensitive
            if isinstance(key, str) and any(sk in key.lower() for sk in sensitive_keys):
                return self.redaction_text
            
            # Recursively sanitize nested structures
            if isinstance(value, dict):
                return self.sanitize_dict(value)
            elif isinstance(value, list):
                return [sanitize_value(key, v) for v in value]
            elif isinstance(value, str):
                return self.sanitize(value)
            else:
                return value
        
        return {k: sanitize_value(k, v) for k, v in data.items()}
    
    def get_redaction_count(self) -> int:
        """Returns the number of redactions performed"""
        return self.redaction_count


class SanitizingFilter(logging.Filter):
    """
    Logging filter that sanitizes log records before they're written.
    
    Usage:
        handler.addFilter(SanitizingFilter())
    """
    
    def __init__(self):
        super().__init__()
        self.sanitizer = LogSanitizer()
    
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Sanitize the log record message.
        
        Args:
            record: The log record to filter
            
        Returns:
            True to keep the record (always returns True after sanitizing)
        """
        # Sanitize the message
        if isinstance(record.msg, str):
            record.msg = self.sanitizer.sanitize(record.msg)
        
        # Sanitize arguments if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = self.sanitizer.sanitize_dict(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self.sanitizer.sanitize(str(arg)) if isinstance(arg, str) else arg
                    for arg in record.args
                )
        
        return True


class AuditLogger:
    """
    Separate audit logger for security-sensitive operations.
    
    SECURITY: Logs important security events (auth, API key access, etc.)
    to a separate audit trail that can't be disabled.
    """
    
    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory for audit logs (default: ~/.zypheron/audit)
        """
        if log_dir is None:
            log_dir = str(Path.home() / ".zypheron" / "audit")
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Create audit logger
        self.logger = logging.getLogger("zypheron.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Don't propagate to root logger
        
        # Add file handler with secure permissions
        log_file = self.log_dir / f"audit-{datetime.now().strftime('%Y%m%d')}.log"
        handler = logging.FileHandler(str(log_file), mode='a')
        handler.setLevel(logging.INFO)
        
        # Set secure file permissions
        log_file.touch(mode=0o600, exist_ok=True)
        
        # Format: timestamp | event_type | user | details
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def log_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        level: str = "INFO"
    ):
        """
        Log a security audit event.
        
        Args:
            event_type: Type of event (auth, api_key_access, scan_start, etc.)
            details: Event details (will be sanitized)
            level: Log level (INFO, WARNING, ERROR)
        """
        # Sanitize details
        sanitizer = LogSanitizer()
        sanitized_details = sanitizer.sanitize_dict(details)
        
        # Format message
        message = f"{event_type} | {json.dumps(sanitized_details)}"
        
        # Log at appropriate level
        if level.upper() == "WARNING":
            self.logger.warning(message)
        elif level.upper() == "ERROR":
            self.logger.error(message)
        else:
            self.logger.info(message)
    
    def log_authentication(self, success: bool, user: Optional[str] = None, reason: Optional[str] = None):
        """Log authentication attempt"""
        self.log_event("AUTH", {
            "success": success,
            "user": user or "unknown",
            "reason": reason or "N/A"
        }, level="WARNING" if not success else "INFO")
    
    def log_api_key_access(self, provider: str, success: bool):
        """Log API key access"""
        self.log_event("API_KEY_ACCESS", {
            "provider": provider,
            "success": success
        })
    
    def log_scan_start(self, scan_type: str, target: str):
        """Log scan start"""
        self.log_event("SCAN_START", {
            "scan_type": scan_type,
            "target": target
        })
    
    def log_vulnerability_found(self, vuln_type: str, severity: str, target: str):
        """Log vulnerability discovery"""
        self.log_event("VULNERABILITY_FOUND", {
            "type": vuln_type,
            "severity": severity,
            "target": target
        }, level="WARNING")
    
    def log_config_change(self, setting: str, old_value: Any, new_value: Any):
        """Log configuration change"""
        self.log_event("CONFIG_CHANGE", {
            "setting": setting,
            "old_value": str(old_value),
            "new_value": str(new_value)
        })


# Global sanitizer instance
_global_sanitizer = LogSanitizer()
_global_audit_logger: Optional[AuditLogger] = None


def get_sanitizer() -> LogSanitizer:
    """Get the global sanitizer instance"""
    return _global_sanitizer


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance"""
    global _global_audit_logger
    if _global_audit_logger is None:
        _global_audit_logger = AuditLogger()
    return _global_audit_logger


def configure_sanitized_logging():
    """
    Configure all loggers to use sanitization filter.
    
    Call this early in application startup to ensure all logs are sanitized.
    """
    # Add sanitizing filter to root logger
    root_logger = logging.getLogger()
    sanitizing_filter = SanitizingFilter()
    
    for handler in root_logger.handlers:
        handler.addFilter(sanitizing_filter)
    
    # Also add to common library loggers
    for logger_name in ['urllib3', 'requests', 'httpx', 'aiohttp']:
        logger = logging.getLogger(logger_name)
        for handler in logger.handlers:
            handler.addFilter(sanitizing_filter)

