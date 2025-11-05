"""
Unit tests for Zypheron MCP Integration

Tests the MCP server, client, and tool adapter functionality.
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_interface.client import ZypheronClient
from mcp_interface.tools import ZypheronToolExecutor
from mcp_interface.colors import ZypheronColors, colorize, format_tool_output


class TestZypheronClient:
    """Test ZypheronClient HTTP client"""
    
    def test_client_initialization(self):
        """Test client initialization with default parameters"""
        client = ZypheronClient()
        assert client.server_url == "http://localhost:8080"
        assert client.timeout == 300
    
    def test_client_custom_url(self):
        """Test client initialization with custom URL"""
        custom_url = "http://192.168.1.100:9000"
        client = ZypheronClient(server_url=custom_url)
        assert client.server_url == custom_url
    
    @patch('mcp.client.requests.Session.get')
    def test_safe_get_success(self, mock_get):
        """Test successful GET request"""
        mock_response = Mock()
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        client = ZypheronClient()
        result = client.safe_get('/health')
        
        assert result == {"status": "ok"}
    
    @patch('mcp.client.requests.Session.get')
    def test_safe_get_timeout(self, mock_get):
        """Test GET request timeout handling"""
        mock_get.side_effect = Exception("Timeout")
        
        client = ZypheronClient()
        result = client.safe_get('/health')
        
        assert result['success'] is False
        assert 'error' in result
    
    @patch('mcp.client.requests.Session.post')
    def test_safe_post_success(self, mock_post):
        """Test successful POST request"""
        mock_response = Mock()
        mock_response.json.return_value = {"result": "success"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        client = ZypheronClient()
        result = client.safe_post('/api/command', {'command': 'test'})
        
        assert result == {"result": "success"}


class TestZypheronToolExecutor:
    """Test ZypheronToolExecutor adapter layer"""
    
    def test_executor_initialization(self):
        """Test executor initialization"""
        executor = ZypheronToolExecutor()
        assert executor.client is not None
    
    @patch('subprocess.run')
    def test_check_tool_availability_found(self, mock_run):
        """Test checking for available tool"""
        mock_run.return_value = Mock(returncode=0)
        
        executor = ZypheronToolExecutor()
        assert executor.check_tool_availability('nmap') is True
    
    @patch('subprocess.run')
    def test_check_tool_availability_not_found(self, mock_run):
        """Test checking for unavailable tool"""
        mock_run.return_value = Mock(returncode=1)
        
        executor = ZypheronToolExecutor()
        assert executor.check_tool_availability('nonexistent_tool') is False
    
    @patch('subprocess.run')
    def test_execute_raw_command_success(self, mock_run):
        """Test successful command execution"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Command output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        executor = ZypheronToolExecutor()
        result = executor.execute_raw_command('echo test')
        
        assert result['success'] is True
        assert result['stdout'] == "Command output"
        assert result['return_code'] == 0
    
    @patch('subprocess.run')
    def test_execute_raw_command_failure(self, mock_run):
        """Test failed command execution"""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error message"
        mock_run.return_value = mock_result
        
        executor = ZypheronToolExecutor()
        result = executor.execute_raw_command('false')
        
        assert result['success'] is False
        assert result['return_code'] == 1
    
    def test_format_results(self):
        """Test result formatting"""
        executor = ZypheronToolExecutor()
        
        raw_results = {
            'success': True,
            'stdout': 'Test output',
            'stderr': '',
            'return_code': 0,
            'command': 'test command'
        }
        
        formatted = executor.format_results(raw_results, 'test_tool')
        
        assert formatted['tool'] == 'test_tool'
        assert formatted['success'] is True
        assert formatted['output'] == 'Test output'
        assert formatted['return_code'] == 0


class TestZypheronColors:
    """Test ZypheronColors utility functions"""
    
    def test_colorize(self):
        """Test text colorization"""
        text = "Test message"
        colored = colorize(text, ZypheronColors.ZYPHERON_RED)
        
        assert ZypheronColors.ZYPHERON_RED in colored
        assert text in colored
        assert ZypheronColors.RESET in colored
    
    def test_format_tool_output_success(self):
        """Test tool output formatting with success status"""
        output = format_tool_output('nmap', 'success', 'Scan completed')
        
        assert 'nmap' in output
        assert 'SUCCESS' in output.upper()
        assert 'Scan completed' in output
    
    def test_format_tool_output_error(self):
        """Test tool output formatting with error status"""
        output = format_tool_output('nmap', 'error', 'Scan failed')
        
        assert 'nmap' in output
        assert 'ERROR' in output.upper()
        assert 'Scan failed' in output
    
    def test_color_constants(self):
        """Test that color constants are defined"""
        assert hasattr(ZypheronColors, 'ZYPHERON_RED')
        assert hasattr(ZypheronColors, 'ZYPHERON_CRIMSON')
        assert hasattr(ZypheronColors, 'SUCCESS')
        assert hasattr(ZypheronColors, 'ERROR')
        assert hasattr(ZypheronColors, 'WARNING')
        assert hasattr(ZypheronColors, 'RESET')


class TestMCPIntegration:
    """Integration tests for MCP functionality"""
    
    @patch('subprocess.run')
    def test_end_to_end_tool_execution(self, mock_run):
        """Test complete flow of tool execution"""
        # Mock successful command execution
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Nmap scan completed"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        # Execute tool
        executor = ZypheronToolExecutor()
        result = executor.execute_raw_command('nmap -sV example.com')
        
        # Verify result
        assert result['success'] is True
        assert 'Nmap scan completed' in result['stdout']
        
        # Format for MCP response
        formatted = executor.format_results(result, 'nmap')
        assert formatted['tool'] == 'nmap'
        assert formatted['success'] is True
    
    def test_client_executor_integration(self):
        """Test client and executor work together"""
        client = ZypheronClient()
        executor = ZypheronToolExecutor(client)
        
        assert executor.client is client
        assert executor.client.server_url == client.server_url


# Integration test markers
pytestmark = pytest.mark.integration


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])

