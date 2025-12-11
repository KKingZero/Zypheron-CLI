"""
Tamper-evident audit logging for security operations

This module provides comprehensive audit logging with integrity protection
for all security-sensitive operations in Zypheron.
"""

import json
import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
import fcntl


@dataclass
class AuditEvent:
    """Audit event with all security-relevant fields"""
    timestamp: str
    event_type: str
    user: str
    pid: int
    tool: Optional[str] = None
    target: Optional[str] = None
    args: Optional[list] = None
    result: Optional[str] = None
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    authorization_token: Optional[str] = None
    error_message: Optional[str] = None
    previous_hash: Optional[str] = None
    event_hash: Optional[str] = None


class AuditLogger:
    """
    Tamper-evident audit logging with hash chain

    Features:
    - JSON Lines format for easy parsing
    - Hash chain for tamper detection
    - Automatic log rotation
    - Secure file permissions
    - SIEM-compatible output
    """

    def __init__(self, log_dir: str = None):
        """
        Initialize audit logger

        Args:
            log_dir: Directory for audit logs (default: ~/.zypheron/audit)
        """
        if log_dir is None:
            log_dir = os.path.expanduser("~/.zypheron/audit")

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Set restrictive permissions on directory
        os.chmod(self.log_dir, 0o700)

        self.log_file = self.log_dir / f"audit-{datetime.now().strftime('%Y%m%d')}.jsonl"
        self.previous_hash = self._get_last_hash()

    def log_tool_execution(
        self,
        tool: str,
        target: str,
        args: list,
        result: str = "success",
        exit_code: int = 0,
        duration_ms: int = 0,
        authorization_token: str = None,
        error_message: str = None
    ):
        """
        Log security tool execution

        Args:
            tool: Tool name
            target: Target of the scan
            args: Arguments passed to tool
            result: Execution result (success/failure)
            exit_code: Tool exit code
            duration_ms: Execution duration in milliseconds
            authorization_token: Authorization token used
            error_message: Error message if failed
        """
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            event_type='tool_execution',
            user=os.getenv('USER', 'unknown'),
            pid=os.getpid(),
            tool=tool,
            target=target,
            args=args,
            result=result,
            exit_code=exit_code,
            duration_ms=duration_ms,
            authorization_token=authorization_token,
            error_message=error_message
        )

        self._write_event(event)

    def log_authorization_check(
        self,
        target: str,
        authorization_token: str,
        result: str,
        reason: str = None
    ):
        """
        Log authorization validation attempt

        Args:
            target: Target being authorized
            authorization_token: Token used for authorization
            result: Authorization result (granted/denied)
            reason: Reason for denial (if applicable)
        """
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            event_type='authorization_check',
            user=os.getenv('USER', 'unknown'),
            pid=os.getpid(),
            target=target,
            authorization_token=authorization_token,
            result=result,
            error_message=reason
        )

        self._write_event(event)

    def log_ai_request(
        self,
        provider: str,
        model: str,
        tokens_used: int,
        cost_estimate: float = None
    ):
        """
        Log AI API request for cost tracking

        Args:
            provider: AI provider (anthropic, openai, etc.)
            model: Model used
            tokens_used: Number of tokens consumed
            cost_estimate: Estimated cost in USD
        """
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            event_type='ai_request',
            user=os.getenv('USER', 'unknown'),
            pid=os.getpid(),
            tool=provider,
            args=[model, str(tokens_used), str(cost_estimate)]
        )

        self._write_event(event)

    def log_security_event(
        self,
        event_type: str,
        **details
    ):
        """
        Log generic security event

        Args:
            event_type: Type of security event
            **details: Additional event details
        """
        event = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            event_type=event_type,
            user=os.getenv('USER', 'unknown'),
            pid=os.getpid(),
            **details
        )

        self._write_event(event)

    def _write_event(self, event: AuditEvent):
        """
        Write audit event to log with integrity protection

        Args:
            event: Audit event to write
        """
        # Add previous hash to chain
        event.previous_hash = self.previous_hash

        # Convert to dict and calculate hash
        event_dict = asdict(event)
        event_json = json.dumps({k: v for k, v in event_dict.items() if k != 'event_hash'}, sort_keys=True)
        event_hash = hashlib.sha256(event_json.encode()).hexdigest()
        event.event_hash = event_hash
        event_dict['event_hash'] = event_hash

        # Write to log file with file locking
        try:
            with open(self.log_file, 'a') as f:
                # Acquire exclusive lock
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(event_dict) + '\n')
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Ensure restrictive permissions
            os.chmod(self.log_file, 0o600)

            # Update chain
            self.previous_hash = event_hash

        except Exception as e:
            # Log to stderr if file write fails (don't lose audit trail)
            import sys
            print(f"AUDIT LOG ERROR: {e}", file=sys.stderr)
            print(f"Event: {event_json}", file=sys.stderr)

    def _get_last_hash(self) -> str:
        """
        Get hash of last log entry for integrity chain

        Returns:
            Hash of last entry or genesis hash
        """
        if not self.log_file.exists():
            return '0' * 64  # Genesis hash

        try:
            with open(self.log_file, 'r') as f:
                # Read last line
                lines = f.readlines()
                if lines:
                    last_event = json.loads(lines[-1])
                    return last_event.get('event_hash', '0' * 64)
        except Exception:
            pass

        return '0' * 64

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify integrity of audit log

        Returns:
            (is_valid, list of errors)
        """
        if not self.log_file.exists():
            return True, []

        errors = []
        expected_hash = '0' * 64  # Genesis

        with open(self.log_file, 'r') as f:
            for line_no, line in enumerate(f, 1):
                try:
                    event = json.loads(line)

                    # Check previous hash matches
                    if event.get('previous_hash') != expected_hash:
                        errors.append(f"Line {line_no}: Hash chain broken")

                    # Recalculate hash
                    event_copy = {k: v for k, v in event.items() if k != 'event_hash'}
                    event_json = json.dumps(event_copy, sort_keys=True)
                    calculated_hash = hashlib.sha256(event_json.encode()).hexdigest()

                    if event.get('event_hash') != calculated_hash:
                        errors.append(f"Line {line_no}: Event hash mismatch (tampered?)")

                    expected_hash = event.get('event_hash')

                except json.JSONDecodeError:
                    errors.append(f"Line {line_no}: Invalid JSON")

        return len(errors) == 0, errors


# Global audit logger instance
_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
