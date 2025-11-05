#!/usr/bin/env python3
"""
Zypheron AI MCP Server - Professional Security Testing Interface

Enterprise-Grade Penetration Testing Platform with AI Integration
🔴 Security Research | Penetration Testing | Vulnerability Assessment

Architecture: MCP Server enabling AI-powered security tool orchestration
Framework: FastMCP protocol for seamless agent communication
"""

import sys
import os
import logging
import argparse
from typing import Dict, Any
from pathlib import Path

# Add parent directory to path for imports
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from mcp.server.fastmcp import FastMCP

from mcp_interface.client import ZypheronClient, DEFAULT_SERVER_URL
from mcp_interface.tools import ZypheronToolExecutor
from mcp_interface.colors import ZypheronColors, ColoredFormatter, print_banner, colorize
from mcp_interface.security import InputValidator, CommandInjectionError

# Configure logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter(
    fmt='%(levelname)s [%(name)s] - %(message)s'
))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def setup_mcp_server(zypheron_client: ZypheronClient) -> FastMCP:
    """
    Setup and configure FastMCP server with Zypheron tools.
    
    Args:
        zypheron_client: ZypheronClient instance for backend communication
        
    Returns:
        Configured FastMCP server instance
    """
    # Initialize FastMCP server
    mcp = FastMCP("Zypheron AI")
    
    # Initialize tool executor and validator
    executor = ZypheronToolExecutor(zypheron_client)
    validator = InputValidator()
    
    logger.info(colorize("⚡ Initializing Zypheron MCP Interface...", ZypheronColors.INFO))
    
    # ============================================================================
    # NETWORK SECURITY TOOLS
    # ============================================================================
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", 
                 additional_args: str = "") -> Dict[str, Any]:
        """
        Advanced Nmap network scanning.
        
        Args:
            target: Target IP address, hostname, or CIDR range
            scan_type: Scan type (-sV for version, -sS for SYN, -sT for TCP)
            ports: Port specification (e.g., "80,443" or "1-65535")
            additional_args: Additional nmap arguments
            
        Returns:
            Scan results with discovered services and versions
        """
        try:
            # Validate inputs
            if not validator.validate_target(target):
                return {
                    'success': False,
                    'error': f'Invalid target: {target}',
                    'tool': 'nmap'
                }
            
            if ports and not validator.validate_port_spec(ports):
                return {
                    'success': False,
                    'error': f'Invalid port specification: {ports}',
                    'tool': 'nmap'
                }
            
            # Build safe arguments list
            args = ['nmap', target]
            if scan_type:
                args.append(scan_type)
            if ports:
                args.extend(['-p', ports])
            if additional_args:
                # Parse additional args safely
                import shlex
                args.extend(shlex.split(additional_args))
            
            result = executor.secure_executor.execute_tool(args[0], args[1:])
            return executor.format_results(result, 'nmap')
            
        except CommandInjectionError as e:
            return {
                'success': False,
                'error': f'Security validation failed: {str(e)}',
                'tool': 'nmap'
            }
    
    @mcp.tool()
    def rustscan_fast_scan(target: str, ports: str = "", ulimit: int = 5000,
                          batch_size: int = 4500, timeout: int = 1500) -> Dict[str, Any]:
        """
        Ultra-fast port scanning with Rustscan.
        
        Args:
            target: Target IP or hostname
            ports: Port range (default: all ports)
            ulimit: File descriptor limit (default: 5000)
            batch_size: Batch size for parallel scanning
            timeout: Connection timeout in milliseconds
            
        Returns:
            Fast scan results with open ports
        """
        try:
            # Validate inputs
            if not validator.validate_target(target):
                return {
                    'success': False,
                    'error': f'Invalid target: {target}',
                    'tool': 'rustscan'
                }
            
            if ports and not validator.validate_port_spec(ports):
                return {
                    'success': False,
                    'error': f'Invalid port specification: {ports}',
                    'tool': 'rustscan'
                }
            
            # Build safe arguments
            args = ['rustscan', '-a', target, '--ulimit', str(ulimit), 
                   '-b', str(batch_size), '-t', str(timeout)]
            if ports:
                args.extend(['-p', ports])
            
            result = executor.secure_executor.execute_tool(args[0], args[1:])
            return executor.format_results(result, 'rustscan')
            
        except CommandInjectionError as e:
            return {
                'success': False,
                'error': f'Security validation failed: {str(e)}',
                'tool': 'rustscan'
            }
    
    @mcp.tool()
    def masscan_high_speed(target: str, ports: str = "1-65535", rate: int = 1000) -> Dict[str, Any]:
        """
        High-speed Internet-scale port scanning.
        
        Args:
            target: Target IP range or CIDR
            ports: Port range to scan
            rate: Packet transmission rate (packets/second)
            
        Returns:
            Masscan results with discovered open ports
        """
        cmd = f"masscan {target} -p{ports} --rate {rate}"
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'masscan')
    
    @mcp.tool()
    def amass_enum(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """
        Advanced subdomain enumeration and OSINT gathering.
        
        Args:
            domain: Target domain
            mode: Amass mode (enum, intel, track, db)
            additional_args: Additional amass arguments
            
        Returns:
            Discovered subdomains and DNS information
        """
        cmd = f"amass {mode} -d {domain}"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'amass')
    
    @mcp.tool()
    def subfinder_scan(domain: str, silent: bool = True, all_sources: bool = False) -> Dict[str, Any]:
        """
        Fast passive subdomain discovery.
        
        Args:
            domain: Target domain
            silent: Show only subdomains in output
            all_sources: Use all available sources
            
        Returns:
            List of discovered subdomains
        """
        cmd = f"subfinder -d {domain}"
        if silent:
            cmd += " -silent"
        if all_sources:
            cmd += " -all"
        
        result = executor.execute_raw_command(cmd)
        return executor.format_results(result, 'subfinder')
    
    # ============================================================================
    # WEB APPLICATION SECURITY TOOLS
    # ============================================================================
    
    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", 
                     wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                     additional_args: str = "") -> Dict[str, Any]:
        """
        Directory and file enumeration with Gobuster.
        
        Args:
            url: Target URL
            mode: Scan mode (dir, dns, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional gobuster arguments
            
        Returns:
            Discovered directories, files, or DNS records
        """
        cmd = f"gobuster {mode} -u {url} -w {wordlist}"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'gobuster')
    
    @mcp.tool()
    def nuclei_scan(target: str, severity: str = "", tags: str = "", 
                   template: str = "") -> Dict[str, Any]:
        """
        Fast vulnerability scanner with 4000+ templates.
        
        Args:
            target: Target URL or host
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags
            template: Specific template to use
            
        Returns:
            Discovered vulnerabilities with details
        """
        cmd = f"nuclei -u {target}"
        if severity:
            cmd += f" -severity {severity}"
        if tags:
            cmd += f" -tags {tags}"
        if template:
            cmd += f" -t {template}"
        
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'nuclei')
    
    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Comprehensive web server vulnerability scanner.
        
        Args:
            target: Target URL or IP
            additional_args: Additional nikto arguments
            
        Returns:
            Web server vulnerabilities and misconfigurations
        """
        cmd = f"nikto -h {target}"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'nikto')
    
    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Automatic SQL injection detection and exploitation.
        
        Args:
            url: Target URL
            data: POST data
            additional_args: Additional sqlmap arguments
            
        Returns:
            SQL injection vulnerabilities and exploitation results
        """
        cmd = f"sqlmap -u {url} --batch"
        if data:
            cmd += f" --data='{data}'"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=900)
        return executor.format_results(result, 'sqlmap')
    
    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        WordPress security scanner.
        
        Args:
            url: WordPress site URL
            additional_args: Additional wpscan arguments
            
        Returns:
            WordPress vulnerabilities and security issues
        """
        cmd = f"wpscan --url {url}"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'wpscan')
    
    @mcp.tool()
    def httpx_probe(target: str, probe: bool = True, tech_detect: bool = False,
                   status_code: bool = False, threads: int = 50) -> Dict[str, Any]:
        """
        Fast HTTP probing and technology detection.
        
        Args:
            target: Target URL or file with URLs
            probe: Probe for live hosts
            tech_detect: Detect technologies
            status_code: Show status codes
            threads: Number of threads
            
        Returns:
            HTTP probe results with technology stack
        """
        try:
            # Validate target
            if not validator.validate_target(target):
                return {
                    'success': False,
                    'error': f'Invalid target: {target}',
                    'tool': 'httpx'
                }
            
            # Build httpx command with piping (echo | httpx)
            echo_cmd = ['echo', target]
            httpx_args = ['httpx', '-threads', str(threads)]
            if not probe:
                httpx_args.append('-no-probe')
            if tech_detect:
                httpx_args.append('-tech-detect')
            if status_code:
                httpx_args.append('-status-code')
            
            # Use secure piping
            result = executor.secure_executor.execute_with_piping(
                [echo_cmd, httpx_args],
                timeout=300
            )
            return executor.format_results(result, 'httpx')
            
        except CommandInjectionError as e:
            return {
                'success': False,
                'error': f'Security validation failed: {str(e)}',
                'tool': 'httpx'
            }
    
    @mcp.tool()
    def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                        threads: int = 10, additional_args: str = "") -> Dict[str, Any]:
        """
        Fast recursive content discovery.
        
        Args:
            url: Target URL
            wordlist: Wordlist path
            threads: Number of concurrent threads
            additional_args: Additional arguments
            
        Returns:
            Discovered directories and files
        """
        cmd = f"feroxbuster -u {url} -w {wordlist} -t {threads}"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'feroxbuster')
    
    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                 mode: str = "directory", additional_args: str = "") -> Dict[str, Any]:
        """
        Fast web fuzzer for parameter and directory discovery.
        
        Args:
            url: Target URL with FUZZ keyword
            wordlist: Wordlist path
            mode: Fuzzing mode (directory, parameter, subdomain)
            additional_args: Additional ffuf arguments
            
        Returns:
            Fuzzing results with discovered endpoints
        """
        cmd = f"ffuf -u {url} -w {wordlist}"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=600)
        return executor.format_results(result, 'ffuf')
    
    # ============================================================================
    # BINARY ANALYSIS & REVERSE ENGINEERING TOOLS
    # ============================================================================
    
    @mcp.tool()
    def ghidra_analysis(binary: str, project_name: str = "zypheron_analysis",
                       output_format: str = "xml") -> Dict[str, Any]:
        """
        Software reverse engineering with Ghidra.
        
        Args:
            binary: Path to binary file
            project_name: Ghidra project name
            output_format: Output format (xml, json)
            
        Returns:
            Binary analysis results including functions and strings
        """
        args = ['reverse-eng', binary, '--tool', 'ghidra']
        if project_name:
            args.extend(['--project', project_name])
        
        result = executor.execute_tool('zypheron', args, timeout=900)
        return result
    
    @mcp.tool()
    def radare2_analyze(binary: str, commands: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Advanced reverse engineering with Radare2.
        
        Args:
            binary: Path to binary file
            commands: Radare2 commands to execute
            additional_args: Additional r2 arguments
            
        Returns:
            Binary analysis results
        """
        cmd = f"r2 -q -c 'aaa;{commands}' {binary}"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=300)
        return executor.format_results(result, 'radare2')
    
    @mcp.tool()
    def checksec_analyze(binary: str) -> Dict[str, Any]:
        """
        Check binary security properties.
        
        Args:
            binary: Path to binary file
            
        Returns:
            Security properties (NX, PIE, RELRO, Canary, etc.)
        """
        cmd = f"checksec --file={binary}"
        result = executor.execute_raw_command(cmd)
        return executor.format_results(result, 'checksec')
    
    @mcp.tool()
    def strings_extract(file_path: str, min_len: int = 4) -> Dict[str, Any]:
        """
        Extract printable strings from binary.
        
        Args:
            file_path: Path to file
            min_len: Minimum string length
            
        Returns:
            Extracted strings
        """
        cmd = f"strings -n {min_len} {file_path}"
        result = executor.execute_raw_command(cmd)
        return executor.format_results(result, 'strings')
    
    @mcp.tool()
    def gdb_debug(binary: str, commands: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        GNU debugger for exploit development.
        
        Args:
            binary: Path to binary
            commands: GDB commands to execute
            additional_args: Additional GDB arguments
            
        Returns:
            Debugging output
        """
        cmd = f"gdb {binary} -batch"
        if commands:
            cmd += f" -ex '{commands}'"
        if additional_args:
            cmd += f" {additional_args}"
        
        result = executor.execute_raw_command(cmd, timeout=300)
        return executor.format_results(result, 'gdb')
    
    # ============================================================================
    # ZYPHERON-SPECIFIC FEATURES
    # ============================================================================
    
    @mcp.tool()
    def zypheron_scan(target: str, scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Run Zypheron security scan on target.
        
        Args:
            target: Target domain, IP, or URL
            scan_type: Type of scan (quick, comprehensive, api, authenticated)
            
        Returns:
            Complete scan results with vulnerabilities
        """
        args = ['scan', target]
        if scan_type != "comprehensive":
            args.append(f'--type={scan_type}')
        
        result = executor.execute_tool('zypheron', args, timeout=1800)
        return result
    
    @mcp.tool()
    def zypheron_api_pentest(url: str, schema_url: str = "") -> Dict[str, Any]:
        """
        API security testing with Zypheron.
        
        Args:
            url: API base URL
            schema_url: OpenAPI/Swagger schema URL (optional)
            
        Returns:
            API security assessment results
        """
        args = ['api-pentest', url]
        if schema_url:
            args.extend(['--schema', schema_url])
        
        result = executor.execute_tool('zypheron', args, timeout=900)
        return result
    
    @mcp.tool()
    def zypheron_secrets_scan(path: str) -> Dict[str, Any]:
        """
        Scan for exposed secrets and credentials.
        
        Args:
            path: Path to scan (directory or repository)
            
        Returns:
            Discovered secrets with severity and recommendations
        """
        result = executor.execute_tool('zypheron', ['secrets', path], timeout=300)
        return result
    
    @mcp.tool()
    def zypheron_deps_analyze(path: str) -> Dict[str, Any]:
        """
        Dependency analysis with CVE matching.
        
        Args:
            path: Project path
            
        Returns:
            Dependencies with known CVEs and SBOM
        """
        result = executor.execute_tool('zypheron', ['deps', path], timeout=300)
        return result
    
    @mcp.tool()
    def zypheron_pwn(binary: str) -> Dict[str, Any]:
        """
        Binary exploitation with Zypheron.
        
        Args:
            binary: Path to binary
            
        Returns:
            Exploitation analysis and payload generation
        """
        result = executor.execute_tool('zypheron', ['pwn', binary], timeout=600)
        return result
    
    # ============================================================================
    # SYSTEM & HEALTH CHECK TOOLS
    # ============================================================================
    
    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check Zypheron backend server health.
        
        Returns:
            Health status and available tools
        """
        return zypheron_client.check_health()
    
    @mcp.tool()
    def list_available_tools() -> Dict[str, Any]:
        """
        List all available security tools.
        
        Returns:
            Complete list of available tools with versions
        """
        result = executor.execute_tool('zypheron', ['tools', 'list'])
        return result
    
    @mcp.tool()
    def check_tool_status(tool_name: str) -> Dict[str, Any]:
        """
        Check if specific security tool is installed.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool availability and version information
        """
        available = executor.check_tool_availability(tool_name)
        version = executor.get_tool_version(tool_name) if available else None
        
        return {
            'tool': tool_name,
            'available': available,
            'version': version
        }
    
    logger.info(colorize(f"✅ Loaded {len(mcp.list_tools())} security tools", ZypheronColors.SUCCESS))
    
    return mcp


def main():
    """Main entry point for Zypheron MCP Interface"""
    parser = argparse.ArgumentParser(
        description='Zypheron MCP Interface - Professional Security Testing Platform'
    )
    parser.add_argument(
        '--server',
        default=DEFAULT_SERVER_URL,
        help=f'Zypheron backend server URL (default: {DEFAULT_SERVER_URL})'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Print banner
    print_banner()
    
    # Initialize client and interface
    try:
        logger.info(colorize("Initializing Zypheron MCP Interface...", ZypheronColors.INFO))
        
        zypheron_client = ZypheronClient(server_url=args.server)
        mcp = setup_mcp_server(zypheron_client)
        
        logger.info(colorize("⚡ Zypheron MCP Interface operational!", ZypheronColors.SUCCESS))
        logger.info(colorize(f"   Endpoint: {args.server}", ZypheronColors.INFO))
        logger.info(colorize(f"   Arsenal: {len(mcp.list_tools())} security tools loaded", ZypheronColors.INFO))
        
        # Run the MCP server
        mcp.run()
        
    except KeyboardInterrupt:
        logger.info(colorize("\n⏹️  Terminating Zypheron MCP Interface...", ZypheronColors.WARNING))
    except Exception as e:
        logger.error(colorize(f"💥 Critical error: {e}", ZypheronColors.ERROR))
        sys.exit(1)


if __name__ == '__main__':
    main()

