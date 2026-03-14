"""
Secure argument validation for MCP server tool execution

This module provides validation for all tool arguments to prevent command injection.
"""

import re
import ipaddress
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse


class ArgumentValidator:
    """Validates and sanitizes arguments for security tool execution"""

    # Allowed characters for different argument types
    SAFE_HOSTNAME_CHARS = set('abcdefghijklmnopqrstuvwxyz'
                               'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                               '0123456789.-_')

    SAFE_PATH_CHARS = set('abcdefghijklmnopqrstuvwxyz'
                          'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                          '0123456789/-_.')

    SAFE_PORT_CHARS = set('0123456789,-')

    # Allowlists for specific tools
    NMAP_SAFE_FLAGS = {
        '-sS', '-sT', '-sU', '-sV', '-O', '-A', '-p', '-Pn', '-n',
        '--script', '--open', '-T', '-v', '-vv', '-d', '--reason',
        '--packet-trace', '-oA', '-oX', '-oN', '-oG'
    }

    MASSCAN_SAFE_FLAGS = {
        '-p', '--rate', '--banners', '--open', '--excludefile',
        '--exclude', '--append-output', '--iflist'
    }

    GOBUSTER_SAFE_FLAGS = {
        'dir', 'dns', 'vhost', 's3', 'gcs', '-u', '-w', '-t', '-q',
        '-x', '-s', '-k', '-n', '-v', '-z', '-c', '--no-error'
    }

    SQLMAP_SAFE_FLAGS = {
        '-u', '--url', '--data', '--batch', '--dbs', '--tables',
        '--columns', '--dump', '--risk', '--level', '--technique',
        '--threads', '--random-agent', '--tamper'
    }

    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str]:
        """
        Validate target is a safe IP, domain, or CIDR

        Args:
            target: Target to validate

        Returns:
            (is_valid, error_message)
        """
        # Try as IP address
        try:
            ipaddress.ip_address(target)
            return True, ""
        except ValueError:
            pass

        # Try as CIDR
        try:
            network = ipaddress.ip_network(target, strict=False)
            # Prevent scanning entire internet
            if network.prefixlen < 16:
                return False, f"CIDR too large (/{network.prefixlen}). Minimum: /16"
            return True, ""
        except ValueError:
            pass

        # Try as hostname/domain
        if ArgumentValidator._is_valid_hostname(target):
            return True, ""

        return False, f"Invalid target format: {target}"

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """Check if hostname contains only safe characters"""
        if len(hostname) > 255:
            return False

        if not all(c in ArgumentValidator.SAFE_HOSTNAME_CHARS for c in hostname):
            return False

        # Basic format check
        if hostname.startswith('-') or hostname.endswith('-'):
            return False

        if '..' in hostname:
            return False

        return True

    @staticmethod
    def validate_ports(ports: str) -> Tuple[bool, str]:
        """
        Validate port specification

        Args:
            ports: Port range (e.g., "80,443", "1-1000")

        Returns:
            (is_valid, error_message)
        """
        if not all(c in ArgumentValidator.SAFE_PORT_CHARS for c in ports):
            return False, "Invalid characters in port specification"

        # Parse and validate port numbers
        for part in ports.split(','):
            if '-' in part:
                # Port range
                try:
                    start, end = part.split('-')
                    start_port = int(start)
                    end_port = int(end)
                    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                        return False, f"Port out of range: {part}"
                    if start_port > end_port:
                        return False, f"Invalid range: {part}"
                except ValueError:
                    return False, f"Invalid port range: {part}"
            else:
                # Single port
                try:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        return False, f"Port out of range: {port}"
                except ValueError:
                    return False, f"Invalid port: {part}"

        return True, ""

    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str]:
        """
        Validate URL for web scanning

        Args:
            url: URL to validate

        Returns:
            (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)

            if parsed.scheme not in ['http', 'https']:
                return False, f"Invalid scheme: {parsed.scheme}"

            if not parsed.netloc:
                return False, "No hostname in URL"

            # Extract hostname (without port)
            hostname = parsed.hostname
            if not hostname:
                return False, "Cannot parse hostname"

            # Validate hostname
            if not ArgumentValidator._is_valid_hostname(hostname):
                return False, f"Invalid hostname: {hostname}"

            return True, ""

        except Exception as e:
            return False, f"URL validation error: {e}"

    @staticmethod
    def validate_file_path(path: str) -> Tuple[bool, str]:
        """
        Validate file path for wordlists, etc.

        Args:
            path: File path to validate

        Returns:
            (is_valid, error_message)
        """
        # Check for path traversal
        if '..' in path:
            return False, "Path traversal not allowed"

        # Check for absolute paths only (more secure)
        if not path.startswith('/'):
            return False, "Only absolute paths allowed"

        # Check safe characters
        if not all(c in ArgumentValidator.SAFE_PATH_CHARS for c in path):
            return False, "Invalid characters in path"

        return True, ""

    @staticmethod
    def validate_rate(rate: int) -> Tuple[bool, str]:
        """
        Validate scan rate

        Args:
            rate: Packets per second

        Returns:
            (is_valid, error_message)
        """
        if not isinstance(rate, int):
            return False, "Rate must be an integer"

        if rate < 1:
            return False, "Rate must be positive"

        # Prevent DoS with excessive rate
        if rate > 10000:
            return False, "Rate too high (max: 10000 pps)"

        return True, ""

    @staticmethod
    def validate_nmap_flags(flags: List[str]) -> Tuple[bool, str]:
        """
        Validate nmap flags against allowlist

        Args:
            flags: List of nmap flags

        Returns:
            (is_valid, error_message)
        """
        for flag in flags:
            # Extract flag name (before =)
            flag_name = flag.split('=')[0]

            if flag_name not in ArgumentValidator.NMAP_SAFE_FLAGS:
                return False, f"Flag not allowed: {flag_name}"

        return True, ""

    @staticmethod
    def parse_additional_args(args_str: str, tool: str) -> Tuple[bool, List[str], str]:
        """
        Safely parse additional arguments string

        Args:
            args_str: Additional arguments as string
            tool: Tool name (for allowlist lookup)

        Returns:
            (is_valid, parsed_args_list, error_message)
        """
        import shlex

        try:
            parsed = shlex.split(args_str)
        except ValueError as e:
            return False, [], f"Failed to parse arguments: {e}"

        # Get allowlist for tool
        allowlist_map = {
            'nmap': ArgumentValidator.NMAP_SAFE_FLAGS,
            'masscan': ArgumentValidator.MASSCAN_SAFE_FLAGS,
            'gobuster': ArgumentValidator.GOBUSTER_SAFE_FLAGS,
            'sqlmap': ArgumentValidator.SQLMAP_SAFE_FLAGS,
        }

        allowlist = allowlist_map.get(tool)
        if not allowlist:
            return False, [], f"No allowlist defined for tool: {tool}"

        # Validate each arg
        validated_args = []
        for arg in parsed:
            if arg.startswith('-'):
                # It's a flag
                flag_name = arg.split('=')[0]
                if flag_name not in allowlist:
                    return False, [], f"Flag not allowed: {flag_name}"

            validated_args.append(arg)

        return True, validated_args, ""
