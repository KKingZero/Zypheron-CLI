"""
Tests for IPC server
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from core.server import IPCServer


class MockStreamReader:
    """Mock StreamReader for testing"""
    def __init__(self, data):
        self.data = data
    
    async def read(self, size):
        return self.data


class MockStreamWriter:
    """Mock StreamWriter for testing"""
    def __init__(self):
        self.data = b""
        self.closed = False
    
    def write(self, data):
        self.data += data
    
    async def drain(self):
        pass
    
    def close(self):
        self.closed = True
    
    async def wait_closed(self):
        pass


class TestIPCServer:
    """Test IPC Server functionality"""
    
    @pytest.fixture
    def server(self, tmp_path):
        """Create a test server instance"""
        socket_path = str(tmp_path / "test.sock")
        with patch('core.server.config') as mock_config:
            mock_config.IPC_SOCKET_PATH = socket_path
            mock_config.IPC_BUFFER_SIZE = 65536
            server = IPCServer(socket_path=socket_path)
            return server
    
    def test_init_auth_token(self, server, tmp_path):
        """Test authentication token initialization"""
        assert server.auth_token is not None
        assert len(server.auth_token) == 64  # 32 bytes hex = 64 chars
    
    def test_auth_token_persistence(self, tmp_path):
        """Test auth token persists across restarts"""
        socket_path = str(tmp_path / "test.sock")
        
        # Create first server
        with patch('core.server.config.IPC_SOCKET_PATH', socket_path):
            server1 = IPCServer(socket_path=socket_path)
            token1 = server1.auth_token
        
        # Create second server (should load same token)
        with patch('core.server.config.IPC_SOCKET_PATH', socket_path):
            server2 = IPCServer(socket_path=socket_path)
            token2 = server2.auth_token
        
        assert token1 == token2
    
    @pytest.mark.asyncio
    async def test_handle_client_valid_auth(self, server):
        """Test client handling with valid authentication"""
        request_data = {
            'method': 'health',
            'params': {},
            'auth_token': server.auth_token
        }
        
        reader = MockStreamReader(json.dumps(request_data).encode('utf-8'))
        writer = MockStreamWriter()
        
        await server.handle_client(reader, writer)
        
        response = json.loads(writer.data.decode('utf-8'))
        assert response['success'] == True
        assert writer.closed == True
    
    @pytest.mark.asyncio
    async def test_handle_client_invalid_auth(self, server):
        """Test client handling with invalid authentication"""
        request_data = {
            'method': 'health',
            'params': {},
            'auth_token': 'invalid-token'
        }
        
        reader = MockStreamReader(json.dumps(request_data).encode('utf-8'))
        writer = MockStreamWriter()
        
        await server.handle_client(reader, writer)
        
        response = json.loads(writer.data.decode('utf-8'))
        assert response['success'] == False
        assert 'Authentication failed' in response['error']
        assert writer.closed == True
    
    @pytest.mark.asyncio
    async def test_handle_health(self, server):
        """Test health check handler"""
        result = await server.handle_health({})
        
        assert result['status'] == 'healthy'
        assert 'version' in result
        assert 'providers' in result
    
    @pytest.mark.asyncio
    async def test_handle_list_providers(self, server):
        """Test list providers handler"""
        with patch('core.server.ai_manager') as mock_manager:
            mock_manager.list_available_providers.return_value = ['claude', 'openai']
            
            result = await server.handle_list_providers({})
            
            assert 'providers' in result
            assert isinstance(result['providers'], list)
    
    @pytest.mark.asyncio
    async def test_handle_store_api_key(self, server):
        """Test API key storage handler"""
        params = {
            'provider': 'anthropic',
            'api_key': 'test-key-123'
        }
        
        with patch('core.server.store_api_key') as mock_store:
            mock_store.return_value = True
            
            result = await server.handle_store_api_key(params)
            
            assert result['success'] == True
            assert result['provider'] == 'anthropic'
    
    @pytest.mark.asyncio
    async def test_handle_store_api_key_missing_params(self, server):
        """Test API key storage with missing parameters"""
        params = {
            'provider': 'anthropic'
            # Missing api_key
        }
        
        with pytest.raises(ValueError):
            await server.handle_store_api_key(params)
    
    @pytest.mark.asyncio
    async def test_handle_request_unknown_method(self, server):
        """Test handling unknown method"""
        request = {
            'method': 'unknown_method',
            'params': {}
        }
        
        response = await server.handle_request(request)
        
        assert response['success'] == False
        assert 'Unknown method' in response['error']
    
    @pytest.mark.asyncio
    async def test_handle_request_handler_exception(self, server):
        """Test handling exception in handler"""
        request = {
            'method': 'health',
            'params': {}
        }
        
        # Mock handler to raise exception
        async def failing_handler(params):
            raise Exception("Test error")
        
        server.handle_health = failing_handler
        
        response = await server.handle_request(request)
        
        assert response['success'] == False
        assert 'Test error' in response['error']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

