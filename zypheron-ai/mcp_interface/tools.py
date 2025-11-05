"""
Zypheron Security Tool Orchestration Layer

Provides adapters that integrate MCP protocol requests with Zypheron's
native security tool execution infrastructure.
"""

import logging
import subprocess
import json
from typing import Dict, Any, Optional, List
from pathlib import Path

from mcp_interface.client import ZypheronClient
from mcp_interface.colors import ZypheronColors, colorize, format_tool_output
from mcp_interface.security import SecureCommandExecutor, InputValidator, CommandInjectionError

logger = logging.getLogger(__name__)


class ZypheronToolExecutor:
    """
    Security tool orchestration adapter for MCP integration.
    
    Bridges AI agent requests to Zypheron's native tool execution framework,
    providing unified error handling, result caching, and output standardization.
    """

    def __init__(self, client: Optional[ZypheronClient] = None):
        """
        Initialize tool executor.
        
        Args:
            client: ZypheronClient instance (creates default if None)
        """
        self.client = client or ZypheronClient()
        self.secure_executor = SecureCommandExecutor()
        self.validator = InputValidator()
        self._check_zypheron_cli()

    def _check_zypheron_cli(self) -> bool:
        """Check if Zypheron CLI is available"""
        try:
            result = subprocess.run(
                ['which', 'zypheron'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info("Zypheron CLI detected")
                return True
            else:
                logger.warning("Zypheron CLI not found in PATH")
                return False
        except Exception as e:
            logger.warning(f"Could not check for Zypheron CLI: {e}")
            return False

    def execute_tool(self, tool_name: str, args: List[str], 
                    timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a Zypheron tool via CLI with secure input validation.
        
        Args:
            tool_name: Name of the tool/command
            args: Command line arguments
            timeout: Execution timeout in seconds
            
        Returns:
            Execution results with stdout, stderr, and return code
        """
        try:
            # Validate tool name
            if not self.validator.validate_tool_name(tool_name):
                raise CommandInjectionError(f"Invalid tool name: {tool_name}")
            
            logger.info(format_tool_output(tool_name, 'running', f'with {len(args)} args'))
            
            # Use secure executor to run: zypheron <tool_name> <args>
            result = self.secure_executor.execute_tool(
                'zypheron',
                [tool_name] + args,
                timeout=timeout
            )
            
            # Format response
            response = {
                'success': result.get('success', False),
                'tool': tool_name,
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', ''),
                'return_code': result.get('return_code', -1)
            }
            
            if response['success']:
                logger.info(format_tool_output(tool_name, 'success', 'Completed successfully'))
            else:
                logger.error(format_tool_output(tool_name, 'error', f'Exit code {response["return_code"]}'))
            
            return response
            
        except CommandInjectionError as e:
            logger.error(format_tool_output(tool_name, 'security_error', str(e)))
            return {
                'success': False,
                'tool': tool_name,
                'error': f'Security validation failed: {str(e)}',
                'security_error': True
            }
        except subprocess.TimeoutExpired:
            logger.error(format_tool_output(tool_name, 'timeout', f'Timeout after {timeout}s'))
            return {
                'success': False,
                'tool': tool_name,
                'error': f'Command timeout after {timeout} seconds',
                'timeout': True
            }
        except FileNotFoundError:
            logger.error(format_tool_output(tool_name, 'error', 'Zypheron CLI not found'))
            return {
                'success': False,
                'tool': tool_name,
                'error': 'Zypheron CLI not found. Please install Zypheron first.',
                'not_found': True
            }
        except Exception as e:
            logger.error(format_tool_output(tool_name, 'error', str(e)))
            return {
                'success': False,
                'tool': tool_name,
                'error': str(e)
            }

    def execute_raw_command(self, command: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a raw command securely (DEPRECATED - use execute_tool instead).
        
        This method parses a command string and executes it safely without shell=True.
        For security, use execute_tool() with explicit arguments instead.
        
        Args:
            command: Command string to parse and execute
            timeout: Execution timeout in seconds
            
        Returns:
            Execution results
        """
        try:
            # Parse command into components
            import shlex
            parts = shlex.split(command)
            
            if not parts:
                return {
                    'success': False,
                    'error': 'Empty command',
                    'command': command
                }
            
            tool_name = parts[0]
            args = parts[1:] if len(parts) > 1 else []
            
            logger.info(format_tool_output(tool_name, 'running', 
                                          f'parsed from command string'))
            
            # Use secure executor (NO shell=True)
            result = self.secure_executor.execute_tool(
                tool_name,
                args,
                timeout=timeout
            )
            
            response = {
                'success': result.get('success', False),
                'command': command,
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', ''),
                'return_code': result.get('return_code', -1)
            }
            
            if response['success']:
                logger.info(format_tool_output(tool_name, 'success', 'Completed'))
            else:
                logger.error(format_tool_output(tool_name, 'error', 
                                               f'Exit code {response["return_code"]}'))
            
            return response
            
        except CommandInjectionError as e:
            logger.error(format_tool_output('shell', 'security_error', str(e)))
            return {
                'success': False,
                'command': command,
                'error': f'Security validation failed: {str(e)}',
                'security_error': True
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'command': command,
                'error': f'Command timeout after {timeout} seconds',
                'timeout': True
            }
        except Exception as e:
            logger.error(format_tool_output('shell', 'error', str(e)))
            return {
                'success': False,
                'command': command,
                'error': str(e)
            }

    def check_tool_availability(self, tool_name: str) -> bool:
        """
        Check if a security tool is available.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is available, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', tool_name],
                capture_output=True,
                timeout=5
            )
            available = result.returncode == 0
            
            if available:
                logger.debug(f"Tool {tool_name} is available")
            else:
                logger.debug(f"Tool {tool_name} is not available")
            
            return available
        except Exception as e:
            logger.debug(f"Error checking tool {tool_name}: {e}")
            return False

    def get_tool_version(self, tool_name: str) -> Optional[str]:
        """
        Get version of a security tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Version string or None if not available
        """
        try:
            # Try common version flags
            for flag in ['--version', '-version', '-v', 'version']:
                result = subprocess.run(
                    [tool_name, flag],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout:
                    version = result.stdout.strip().split('\n')[0]
                    return version
        except Exception:
            pass
        
        return None

    def format_results(self, raw_results: Dict[str, Any], 
                      tool_name: str) -> Dict[str, Any]:
        """
        Format tool execution results for MCP response.
        
        Args:
            raw_results: Raw execution results
            tool_name: Name of the tool
            
        Returns:
            Formatted results for MCP clients
        """
        formatted = {
            'tool': tool_name,
            'success': raw_results.get('success', False),
            'output': raw_results.get('stdout', ''),
            'errors': raw_results.get('stderr', ''),
        }
        
        # Add additional metadata
        if 'return_code' in raw_results:
            formatted['return_code'] = raw_results['return_code']
        
        if 'command' in raw_results:
            formatted['command'] = raw_results['command']
        
        # Add error details if present
        if 'error' in raw_results:
            formatted['error_message'] = raw_results['error']
        
        if raw_results.get('timeout'):
            formatted['timeout'] = True
        
        return formatted

