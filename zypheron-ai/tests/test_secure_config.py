"""
Tests for secure API key storage
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from core.secure_config import (
    store_api_key,
    get_api_key,
    delete_api_key,
    list_configured_providers,
    migrate_from_env,
    check_keyring_available,
    PROVIDERS,
    SERVICE_NAME
)


class TestSecureConfig:
    """Test secure configuration management"""
    
    @patch('core.secure_config.keyring')
    def test_store_api_key_success(self, mock_keyring):
        """Test successful API key storage"""
        mock_keyring.set_password = Mock()
        
        result = store_api_key("anthropic", "test-key-123")
        
        assert result == True
        mock_keyring.set_password.assert_called_once_with(
            SERVICE_NAME, "anthropic", "test-key-123"
        )
    
    @patch('core.secure_config.keyring')
    def test_store_api_key_failure(self, mock_keyring):
        """Test API key storage failure"""
        mock_keyring.set_password = Mock(side_effect=Exception("Keyring error"))
        
        result = store_api_key("anthropic", "test-key-123")
        
        assert result == False
    
    @patch('core.secure_config.keyring')
    def test_get_api_key_success(self, mock_keyring):
        """Test successful API key retrieval"""
        mock_keyring.get_password = Mock(return_value="test-key-123")
        
        result = get_api_key("anthropic")
        
        assert result == "test-key-123"
        mock_keyring.get_password.assert_called_once_with(SERVICE_NAME, "anthropic")
    
    @patch('core.secure_config.keyring')
    def test_get_api_key_not_found(self, mock_keyring):
        """Test API key not found"""
        mock_keyring.get_password = Mock(return_value=None)
        
        result = get_api_key("anthropic")
        
        assert result is None
    
    @patch('core.secure_config.keyring')
    def test_delete_api_key_success(self, mock_keyring):
        """Test successful API key deletion"""
        mock_keyring.delete_password = Mock()
        
        result = delete_api_key("anthropic")
        
        assert result == True
        mock_keyring.delete_password.assert_called_once_with(SERVICE_NAME, "anthropic")
    
    @patch('core.secure_config.keyring')
    def test_delete_api_key_not_found(self, mock_keyring):
        """Test deleting non-existent key"""
        import keyring.errors
        mock_keyring.delete_password = Mock(side_effect=keyring.errors.PasswordDeleteError())
        
        result = delete_api_key("anthropic")
        
        assert result == False
    
    @patch('core.secure_config.get_api_key')
    def test_list_configured_providers(self, mock_get_key):
        """Test listing configured providers"""
        # Simulate some providers having keys
        def mock_get(provider):
            return "key" if provider in ["anthropic", "openai"] else None
        
        mock_get_key.side_effect = mock_get
        
        result = list_configured_providers()
        
        assert "anthropic" in result
        assert "openai" in result
        assert len(result) == 2
    
    @patch('core.secure_config.get_api_key')
    @patch('core.secure_config.store_api_key')
    def test_migrate_from_env(self, mock_store, mock_get):
        """Test migrating keys from environment variables"""
        # No existing keys in keyring
        mock_get.return_value = None
        mock_store.return_value = True
        
        env_vars = {
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "OPENAI_API_KEY": "sk-openai-test",
        }
        
        count = migrate_from_env(env_vars)
        
        assert count == 2
        assert mock_store.call_count == 2
    
    @patch('core.secure_config.get_api_key')
    @patch('core.secure_config.store_api_key')
    def test_migrate_from_env_skip_existing(self, mock_store, mock_get):
        """Test migration skips existing keys"""
        # One key already in keyring
        def mock_get_existing(provider):
            return "existing-key" if provider == "anthropic" else None
        
        mock_get.side_effect = mock_get_existing
        mock_store.return_value = True
        
        env_vars = {
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "OPENAI_API_KEY": "sk-openai-test",
        }
        
        count = migrate_from_env(env_vars)
        
        # Should only migrate openai (anthropic already exists)
        assert count == 1
    
    @patch('core.secure_config.keyring')
    def test_check_keyring_available_success(self, mock_keyring):
        """Test keyring availability check success"""
        mock_keyring.get_keyring = Mock(return_value="SecretService Keyring")
        
        result = check_keyring_available()
        
        assert result == True
    
    @patch('core.secure_config.keyring')
    def test_check_keyring_available_failure(self, mock_keyring):
        """Test keyring availability check failure"""
        mock_keyring.get_keyring = Mock(side_effect=Exception("No keyring"))
        
        result = check_keyring_available()
        
        assert result == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

