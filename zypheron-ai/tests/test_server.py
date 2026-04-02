"""
Tests for IPC server
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from contracts.runtime import QueryResponse, TaskStatus
from core.server import IPCServer


class MockStreamReader:
    """Mock StreamReader for testing"""
    def __init__(self, data):
        self.data = data
        self._consumed = False
    
    async def read(self, size):
        if self._consumed:
            return b""
        self._consumed = True
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
    async def test_handle_chat_uses_query_engine(self, server):
        """Chat should be routed through the unified query engine."""
        params = {
            'messages': [{'role': 'user', 'content': 'What configured providers do I have?'}],
            'provider': 'anthropic',
        }
        mocked_response = QueryResponse(
            content='configured providers: anthropic',
            provider='zypheron-query-engine',
            model='tool-runtime',
            session_id='session-test',
            task_id='task-test',
            task_status=TaskStatus.COMPLETED,
        )
        server.query_engine.execute = AsyncMock(return_value=mocked_response)

        result = await server.handle_chat(params)

        server.query_engine.execute.assert_awaited_once()
        assert result['content'] == 'configured providers: anthropic'
        assert result['task_status'] == 'completed'

    @pytest.mark.asyncio
    async def test_handle_task_list(self, server):
        """Task list should be served from the shared task store."""
        mock_task = MagicMock()
        mock_task.to_dict.return_value = {'task_id': 'task-1', 'status': 'running'}
        server.query_engine.task_store.list_tasks = MagicMock(return_value=[mock_task])

        result = await server.handle_task_list({'limit': 10, 'session_id': 'session-1'})

        assert result['tasks'] == [{'task_id': 'task-1', 'status': 'running'}]
        server.query_engine.task_store.list_tasks.assert_called_once_with(limit=10, session_id='session-1', task_id=None)

    @pytest.mark.asyncio
    async def test_handle_task_events(self, server):
        """Task events should be returned for a known task."""
        server.query_engine.task_store.get_task = MagicMock(return_value=MagicMock())
        server.query_engine.task_store.list_events = MagicMock(
            return_value=[{'event_type': 'step_started', 'payload': {'step': 1}}]
        )

        result = await server.handle_task_events({'task_id': 'task-1'})

        assert result['events'][0]['event_type'] == 'step_started'

    @pytest.mark.asyncio
    async def test_handle_task_events_missing_task_raises(self, server):
        """Unknown task ids should be rejected consistently."""
        server.query_engine.task_store.get_task = MagicMock(return_value=None)

        with pytest.raises(ValueError, match="Task not found"):
            await server.handle_task_events({'task_id': 'missing-task'})

    @pytest.mark.asyncio
    async def test_handle_task_approve(self, server):
        """Approval submissions should route through the query engine."""
        task = MagicMock()
        task.kind = "chat_turn"
        server.query_engine.task_store.get_task = MagicMock(return_value=task)
        server.query_engine.submit_approval = AsyncMock(
            return_value=QueryResponse(
                content='approved and executed',
                provider='zypheron-query-engine',
                model='tool-runtime',
                session_id='session-1',
                task_id='task-1',
                task_status=TaskStatus.COMPLETED,
            )
        )

        result = await server.handle_task_approve({
            'task_id': 'task-1',
            'request_id': 'approval-1',
            'decision': 'approve_once',
        })

        assert result['content'] == 'approved and executed'
        server.query_engine.submit_approval.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_handle_task_approve_routes_autopent_to_store(self, server):
        """Autopent approvals should update shared task metadata instead of query-engine flow."""
        task = MagicMock()
        task.kind = "autopent"
        task.session_id = "session-1"
        task.task_id = "autopent-1"
        task.status = TaskStatus.WAITING_APPROVAL
        server.query_engine.task_store.get_task = MagicMock(return_value=task)
        server.query_engine.task_store.set_approval_response = MagicMock()
        server.query_engine.submit_approval = AsyncMock()

        result = await server.handle_task_approve({
            'task_id': 'autopent-1',
            'request_id': 'approval-1',
            'decision': 'approve_once',
        })

        assert "Queued approval decision" in result['content']
        server.query_engine.task_store.set_approval_response.assert_called_once_with(
            task_id='autopent-1',
            request_id='approval-1',
            decision='approve_once',
        )
        server.query_engine.submit_approval.assert_not_awaited()
    
    @pytest.mark.asyncio
    async def test_handle_store_api_key(self, server):
        """Test API key storage handler"""
        params = {
            'provider': 'anthropic',
            'api_key': 'test-key-123'
        }

        with patch('core.server.validate_api_key_with_provider', return_value=(True, "ok")) as mock_validate, \
             patch('core.secure_config.store_api_key') as mock_store, \
             patch('core.server.ai_manager') as mock_manager, \
             patch('core.server.config') as mock_config:
            mock_store.return_value = True
            
            result = await server.handle_store_api_key(params)
            
            assert result['success'] == True
            assert result['provider'] == 'anthropic'
            mock_validate.assert_awaited_once()
            mock_config.reload_api_keys.assert_called_once()
            mock_manager.reload.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_store_api_key_invalid(self, server):
        """Test invalid API key is rejected and not stored."""
        params = {
            'provider': 'anthropic',
            'api_key': 'bad-key'
        }

        with patch('core.server.validate_api_key_with_provider', return_value=(False, "Invalid Claude API key")) as mock_validate, \
             patch('core.secure_config.store_api_key') as mock_store:
            result = await server.handle_store_api_key(params)

            assert result['success'] == False
            assert result['message'] == 'Invalid Claude API key'
            mock_validate.assert_awaited_once()
            mock_store.assert_not_called()
    
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
