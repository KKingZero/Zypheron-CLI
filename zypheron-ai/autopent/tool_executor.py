"""
Real Tool Executor - Execute actual security tools

Replaces simulation with real tool execution
Integrates with existing Zypheron tool infrastructure
"""

import asyncio
import subprocess
import logging
import json
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .attack_path_graph import GraphEdge

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Result from tool execution"""
    success: bool
    tool: str
    output: str
    parsed_data: Dict[str, Any]
    error: Optional[str] = None
    exit_code: int = 0


class ToolExecutor:
    """
    Real tool execution engine

    Executes actual security tools (nmap, sqlmap, nikto, etc.)
    and parses their output for vulnerability discovery
    """

    def __init__(self):
        self.tool_paths = self._detect_tools()

    def _detect_tools(self) -> Dict[str, str]:
        """Detect available security tools"""
        tools = {}

        # Common tool names
        tool_list = [
            'nmap', 'masscan', 'rustscan',
            'sqlmap', 'nikto', 'nuclei',
            'ffuf', 'gobuster', 'dirb',
            'wpscan', 'sslscan', 'whatweb',
            'hydra', 'john', 'hashcat',
            'metasploit', 'searchsploit'
        ]

        for tool in tool_list:
            try:
                result = subprocess.run(
                    ['which', tool],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    tools[tool] = result.stdout.strip()
                    logger.debug(f"Found tool: {tool} at {tools[tool]}")
            except Exception:
                pass

        logger.info(f"Detected {len(tools)} security tools")
        return tools

    async def execute_edge(self, edge: GraphEdge) -> ToolResult:
        """
        Execute an attack edge (step) using appropriate tool

        Args:
            edge: Attack edge to execute

        Returns:
            ToolResult with execution outcome
        """
        tool = edge.tool.lower()

        # Route to appropriate executor
        if 'nmap' in tool or 'scan' in edge.description.lower():
            return await self._execute_nmap(edge)
        elif 'sqlmap' in tool or 'sql' in edge.description.lower():
            return await self._execute_sqlmap(edge)
        elif 'nikto' in tool:
            return await self._execute_nikto(edge)
        elif 'nuclei' in tool:
            return await self._execute_nuclei(edge)
        elif 'ssh' in tool or 'ssh' in edge.description.lower():
            return await self._execute_ssh(edge)
        elif 'credential' in edge.description.lower():
            return await self._execute_credential_attack(edge)
        else:
            # Generic execution
            return await self._execute_generic(edge)

    async def _execute_nmap(self, edge: GraphEdge) -> ToolResult:
        """Execute nmap scan"""
        if 'nmap' not in self.tool_paths:
            return ToolResult(
                success=False,
                tool='nmap',
                output='',
                parsed_data={},
                error='nmap not found'
            )

        target = edge.target_id
        logger.info(f"Executing nmap scan on {target}")

        # Build nmap command (fast scan for demo)
        cmd = [
            self.tool_paths['nmap'],
            '-sV',  # Version detection
            '-T4',  # Timing template
            '--top-ports', '100',  # Top 100 ports
            '-oX', '-',  # XML output to stdout
            target
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300  # 5 minute timeout
            )

            output = stdout.decode('utf-8', errors='ignore')

            # Parse nmap output
            parsed = self._parse_nmap_output(output)

            return ToolResult(
                success=(proc.returncode == 0 and len(parsed.get('open_ports', [])) > 0),
                tool='nmap',
                output=output,
                parsed_data=parsed,
                exit_code=proc.returncode
            )

        except asyncio.TimeoutError:
            logger.warning(f"nmap scan timed out on {target}")
            return ToolResult(
                success=False,
                tool='nmap',
                output='',
                parsed_data={},
                error='Scan timed out'
            )
        except Exception as e:
            logger.error(f"nmap execution failed: {e}")
            return ToolResult(
                success=False,
                tool='nmap',
                output='',
                parsed_data={},
                error=str(e)
            )

    async def _execute_sqlmap(self, edge: GraphEdge) -> ToolResult:
        """Execute sqlmap for SQL injection testing"""
        if 'sqlmap' not in self.tool_paths:
            return ToolResult(
                success=False,
                tool='sqlmap',
                output='',
                parsed_data={},
                error='sqlmap not found'
            )

        target = edge.target_id
        logger.info(f"Executing sqlmap on {target}")

        # Build sqlmap command (basic test)
        cmd = [
            self.tool_paths['sqlmap'],
            '-u', target,
            '--batch',  # Never ask for user input
            '--level=1',  # Basic tests
            '--risk=1',  # Low risk
            '--threads=4',
            '--timeout=30',
            '--technique=BEUST',  # All techniques
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600  # 10 minute timeout
            )

            output = stdout.decode('utf-8', errors='ignore')

            # Parse sqlmap output
            parsed = self._parse_sqlmap_output(output)

            return ToolResult(
                success=(proc.returncode == 0 and parsed.get('vulnerable', False)),
                tool='sqlmap',
                output=output,
                parsed_data=parsed,
                exit_code=proc.returncode
            )

        except asyncio.TimeoutError:
            logger.warning(f"sqlmap timed out on {target}")
            return ToolResult(
                success=False,
                tool='sqlmap',
                output='',
                parsed_data={},
                error='sqlmap timed out'
            )
        except Exception as e:
            logger.error(f"sqlmap execution failed: {e}")
            return ToolResult(
                success=False,
                tool='sqlmap',
                output='',
                parsed_data={},
                error=str(e)
            )

    async def _execute_nikto(self, edge: GraphEdge) -> ToolResult:
        """Execute nikto web vulnerability scanner"""
        if 'nikto' not in self.tool_paths:
            return ToolResult(
                success=False,
                tool='nikto',
                output='',
                parsed_data={},
                error='nikto not found'
            )

        target = edge.target_id
        logger.info(f"Executing nikto on {target}")

        cmd = [
            self.tool_paths['nikto'],
            '-h', target,
            '-o', '-',  # Output to stdout
            '-Format', 'txt'
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300
            )

            output = stdout.decode('utf-8', errors='ignore')
            parsed = self._parse_nikto_output(output)

            return ToolResult(
                success=(proc.returncode == 0),
                tool='nikto',
                output=output,
                parsed_data=parsed,
                exit_code=proc.returncode
            )

        except Exception as e:
            logger.error(f"nikto execution failed: {e}")
            return ToolResult(
                success=False,
                tool='nikto',
                output='',
                parsed_data={},
                error=str(e)
            )

    async def _execute_nuclei(self, edge: GraphEdge) -> ToolResult:
        """Execute nuclei vulnerability scanner"""
        if 'nuclei' not in self.tool_paths:
            return ToolResult(
                success=False,
                tool='nuclei',
                output='',
                parsed_data={},
                error='nuclei not found'
            )

        target = edge.target_id
        logger.info(f"Executing nuclei on {target}")

        cmd = [
            self.tool_paths['nuclei'],
            '-u', target,
            '-severity', 'high,critical',  # High severity only
            '-silent',
            '-json'  # JSON output
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300
            )

            output = stdout.decode('utf-8', errors='ignore')
            parsed = self._parse_nuclei_output(output)

            return ToolResult(
                success=(len(parsed.get('vulnerabilities', [])) > 0),
                tool='nuclei',
                output=output,
                parsed_data=parsed,
                exit_code=proc.returncode
            )

        except Exception as e:
            logger.error(f"nuclei execution failed: {e}")
            return ToolResult(
                success=False,
                tool='nuclei',
                output='',
                parsed_data={},
                error=str(e)
            )

    async def _execute_ssh(self, edge: GraphEdge) -> ToolResult:
        """Execute SSH connection attempt"""
        logger.info(f"Attempting SSH connection to {edge.target_id}")

        # This would use credentials from edge.credential_id
        # For safety, we'll just verify SSH is accessible

        target = edge.target_id

        # Extract host and port
        if ':' in target:
            host, port = target.rsplit(':', 1)
        else:
            host, port = target, '22'

        cmd = ['nc', '-zv', host, port]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=10
            )

            output = stderr.decode('utf-8', errors='ignore')  # nc outputs to stderr

            return ToolResult(
                success=(proc.returncode == 0),
                tool='ssh',
                output=output,
                parsed_data={'port_open': proc.returncode == 0},
                exit_code=proc.returncode
            )

        except Exception as e:
            logger.error(f"SSH check failed: {e}")
            return ToolResult(
                success=False,
                tool='ssh',
                output='',
                parsed_data={},
                error=str(e)
            )

    async def _execute_credential_attack(self, edge: GraphEdge) -> ToolResult:
        """Execute credential-based attack (password spray, etc.)"""
        logger.info(f"Credential attack on {edge.target_id}")

        # For safety, we'll just simulate this
        # Real implementation would use hydra, etc.

        return ToolResult(
            success=False,
            tool='credential_attack',
            output='Credential attack simulation (not executed for safety)',
            parsed_data={'simulated': True},
            error='Not implemented (safety)'
        )

    async def _execute_generic(self, edge: GraphEdge) -> ToolResult:
        """Generic tool execution"""
        logger.warning(f"No specific executor for {edge.tool}, using generic")

        return ToolResult(
            success=False,
            tool=edge.tool,
            output=f'Generic executor for {edge.tool} (not implemented)',
            parsed_data={},
            error='No specific executor'
        )

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap XML output"""
        parsed = {
            'open_ports': [],
            'services': [],
            'os': None,
            'vulnerabilities': []
        }

        # Simple regex parsing (in production, use XML parser)
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
        matches = re.findall(port_pattern, output)

        for port, service in matches:
            parsed['open_ports'].append(int(port))
            parsed['services'].append({
                'port': int(port),
                'service': service
            })

        return parsed

    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output"""
        parsed = {
            'vulnerable': False,
            'injection_type': None,
            'payload': None
        }

        # Look for vulnerability indicators
        if 'is vulnerable' in output.lower() or 'injectable' in output.lower():
            parsed['vulnerable'] = True

        if 'GET parameter' in output or 'POST parameter' in output:
            parsed['injection_type'] = 'parameter'

        return parsed

    def _parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """Parse nikto output"""
        parsed = {
            'findings': [],
            'vulnerabilities': []
        }

        # Parse nikto findings
        lines = output.split('\n')
        for line in lines:
            if line.startswith('+'):
                parsed['findings'].append(line.strip('+ '))

        return parsed

    def _parse_nuclei_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei JSON output"""
        parsed = {
            'vulnerabilities': []
        }

        # Parse JSON lines
        for line in output.split('\n'):
            if not line.strip():
                continue
            try:
                vuln = json.loads(line)
                parsed['vulnerabilities'].append({
                    'template': vuln.get('template-id'),
                    'name': vuln.get('info', {}).get('name'),
                    'severity': vuln.get('info', {}).get('severity'),
                    'matched': vuln.get('matched-at')
                })
            except json.JSONDecodeError:
                pass

        return parsed
