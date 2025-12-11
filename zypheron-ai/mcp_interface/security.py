"""
Security utilities for safe command execution and input validation.

This module provides defense against command injection, path traversal,
and other input-based attacks.
"""

import re
import shlex
import subprocess
from typing import List, Optional, Dict, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CommandInjectionError(Exception):
    """Raised when command injection is detected"""
    pass


class InputValidator:
    """
    Centralized input validation with strict allowlists.
    
    Uses allowlist-based validation to prevent injection attacks.
    """
    
    # Allowlist of safe tool names (alphanumeric, dash, underscore only)
    TOOL_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    # Allowlist for IP addresses (IPv4 and IPv6)
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    IPV6_PATTERN = re.compile(
        r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,7}:|'
        r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
        r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
        r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
        r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
        r':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
        r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
        r'::(ffff(:0{1,4}){0,1}:){0,1}'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
        r'([0-9a-fA-F]{1,4}:){1,4}:'
        r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
        r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$'
    )
    
    # Allowlist for hostnames/domains
    HOSTNAME_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    # Allowlist for URLs
    URL_PATTERN = re.compile(
        r'^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'(?::[0-9]{1,5})?(?:/[^\s]*)?$'
    )
    
    # Allowlist for port specifications
    PORT_PATTERN = re.compile(r'^[0-9,-]+$')
    
    # Dangerous characters that should never appear in security tool arguments
    DANGEROUS_CHARS = ['&', '|', ';', '`', '$', '(', ')', '<', '>', '\n', '\r']
    
    @classmethod
    def validate_tool_name(cls, tool_name: str) -> bool:
        """
        Validate tool name against allowlist.
        
        Args:
            tool_name: Tool name to validate
            
        Returns:
            True if valid, False otherwise
            
        Raises:
            CommandInjectionError: If dangerous characters detected
        """
        if not tool_name or len(tool_name) > 64:
            return False
        
        # Check for dangerous characters
        if any(char in tool_name for char in cls.DANGEROUS_CHARS):
            raise CommandInjectionError(
                f"Dangerous characters detected in tool name: {tool_name}"
            )
        
        return bool(cls.TOOL_NAME_PATTERN.match(tool_name))
    
    @classmethod
    def validate_target(cls, target: str) -> bool:
        """
        Validate scan target (IP, hostname, or URL).
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid, False otherwise
            
        Raises:
            CommandInjectionError: If dangerous characters detected
        """
        if not target or len(target) > 512:
            return False
        
        # Check for dangerous characters
        if any(char in target for char in cls.DANGEROUS_CHARS):
            raise CommandInjectionError(
                f"Dangerous characters detected in target: {target}"
            )
        
        # Try each pattern
        return (
            bool(cls.IPV4_PATTERN.match(target)) or
            bool(cls.IPV6_PATTERN.match(target)) or
            bool(cls.HOSTNAME_PATTERN.match(target)) or
            bool(cls.URL_PATTERN.match(target))
        )
    
    @classmethod
    def validate_port_spec(cls, ports: str) -> bool:
        """
        Validate port specification.
        
        Args:
            ports: Port specification (e.g., "80,443" or "1-1000")
            
        Returns:
            True if valid, False otherwise
            
        Raises:
            CommandInjectionError: If dangerous characters detected
        """
        if not ports or len(ports) > 128:
            return False
        
        # Check for dangerous characters
        if any(char in ports for char in cls.DANGEROUS_CHARS):
            raise CommandInjectionError(
                f"Dangerous characters detected in port spec: {ports}"
            )
        
        return bool(cls.PORT_PATTERN.match(ports))
    
    @classmethod
    def validate_file_path(cls, file_path: str) -> bool:
        """
        Validate file path for safety.
        
        Args:
            file_path: File path to validate
            
        Returns:
            True if valid, False otherwise
            
        Raises:
            CommandInjectionError: If path traversal detected
        """
        if not file_path or len(file_path) > 4096:
            return False
        
        # Check for path traversal attempts
        if '..' in file_path:
            raise CommandInjectionError(
                f"Path traversal detected in file path: {file_path}"
            )
        
        # Check for dangerous characters
        dangerous_path_chars = ['&', '|', ';', '`', '$', '<', '>', '\n', '\r']
        if any(char in file_path for char in dangerous_path_chars):
            raise CommandInjectionError(
                f"Dangerous characters detected in file path: {file_path}"
            )
        
        # Ensure path doesn't escape allowed directories
        try:
            resolved = Path(file_path).resolve()
            # Additional checks can be added here for allowed directories
            return True
        except Exception:
            return False
    
    @classmethod
    def sanitize_for_logging(cls, value: str, redact: bool = False) -> str:
        """
        Sanitize value for safe logging.
        
        Args:
            value: Value to sanitize
            redact: If True, redact potential secrets
            
        Returns:
            Sanitized value safe for logging
        """
        if not value:
            return ""
        
        # Redact potential secrets
        if redact:
            if len(value) > 16:
                return value[:4] + "***" + value[-4:]
            return "***"
        
        # Truncate very long values
        max_len = 200
        if len(value) > max_len:
            return value[:max_len] + f"... ({len(value)} chars total)"
        
        return value


class SecureCommandExecutor:
    """
    Secure command executor that prevents injection attacks.
    
    Never uses shell=True, properly quotes all arguments, and validates inputs.
    """
    
    def __init__(self):
        self.validator = InputValidator()
    
    def execute_tool(
        self,
        tool_name: str,
        args: List[str],
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Execute a security tool with validated arguments.
        
        Args:
            tool_name: Name of the tool (validated)
            args: List of arguments (each validated)
            timeout: Execution timeout in seconds
            env: Optional environment variables
            
        Returns:
            Execution results
            
        Raises:
            CommandInjectionError: If validation fails
        """
        # Validate tool name
        if not self.validator.validate_tool_name(tool_name):
            raise CommandInjectionError(f"Invalid tool name: {tool_name}")
        
        # Validate all arguments
        validated_args = []
        for arg in args:
            if not isinstance(arg, str):
                raise CommandInjectionError(f"Non-string argument: {type(arg)}")
            
            if len(arg) > 4096:
                raise CommandInjectionError(f"Argument too long: {len(arg)} chars")
            
            # Check for dangerous characters in arguments
            if any(char in arg for char in self.validator.DANGEROUS_CHARS):
                raise CommandInjectionError(
                    f"Dangerous characters in argument: "
                    f"{self.validator.sanitize_for_logging(arg)}"
                )
            
            validated_args.append(arg)
        
        # Build command array (NOT a shell string)
        command = [tool_name] + validated_args
        
        logger.info(f"Executing: {tool_name} with {len(validated_args)} args")
        logger.debug(f"Full command: {' '.join(shlex.quote(c) for c in command)}")
        
        try:
            # Execute WITHOUT shell=True to prevent injection
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                shell=False  # CRITICAL: Never use shell=True
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'tool': tool_name
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout after {timeout}s: {tool_name}")
            return {
                'success': False,
                'error': f'Command timeout after {timeout} seconds',
                'timeout': True,
                'tool': tool_name
            }
        except FileNotFoundError:
            logger.error(f"Tool not found: {tool_name}")
            return {
                'success': False,
                'error': f'Tool not found: {tool_name}',
                'not_found': True,
                'tool': tool_name
            }
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return {
                'success': False,
                'error': str(e),
                'tool': tool_name
            }
    
    def execute_with_piping(
        self,
        commands: List[List[str]],
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Execute multiple commands with piping (e.g., echo | httpx).
        
        This is safer than shell piping as we control the entire execution.
        
        Args:
            commands: List of command arrays to pipe together
            timeout: Total execution timeout
            
        Returns:
            Execution results
        """
        if len(commands) < 2:
            raise ValueError("Need at least 2 commands for piping")
        
        # Validate all commands
        for cmd in commands:
            if not cmd or not isinstance(cmd, list):
                raise CommandInjectionError("Invalid command format")
            
            tool_name = cmd[0]
            if not self.validator.validate_tool_name(tool_name):
                raise CommandInjectionError(f"Invalid tool name: {tool_name}")
        
        try:
            # Execute first command
            processes = []
            prev_stdout = None
            
            for i, cmd in enumerate(commands):
                if i == 0:
                    # First command
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=False
                    )
                else:
                    # Subsequent commands take input from previous
                    proc = subprocess.Popen(
                        cmd,
                        stdin=prev_stdout,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=False
                    )
                
                processes.append(proc)
                prev_stdout = proc.stdout
            
            # Wait for final process
            stdout, stderr = processes[-1].communicate(timeout=timeout)
            
            # Close all pipes
            for proc in processes:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            
            return {
                'success': processes[-1].returncode == 0,
                'stdout': stdout,
                'stderr': stderr,
                'return_code': processes[-1].returncode
            }
            
        except subprocess.TimeoutExpired:
            # Kill all processes
            for proc in processes:
                proc.kill()
            return {
                'success': False,
                'error': f'Pipeline timeout after {timeout} seconds',
                'timeout': True
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

