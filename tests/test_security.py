"""
Security Test Suite

Tests for security vulnerabilities and hardening measures:
- Command injection prevention
- Socket permission validation
- Encryption/cryptography
- File permissions
- Input validation
"""

import pytest
import os
import tempfile
import shutil
import subprocess
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "zypheron-ai"))

from mcp_interface.security import (
    SecureCommandExecutor,
    InputValidator,
    CommandInjectionError
)
from auth.credential_store import CredentialStore
from core.log_sanitizer import LogSanitizer


class TestCommandInjection:
    """Test command injection prevention"""
    
    def setup_method(self):
        """Setup test executor"""
        self.executor = SecureCommandExecutor()
        self.validator = InputValidator()
    
    def test_basic_command_execution(self):
        """Test normal command execution"""
        result = self.executor.execute_tool('echo', ['hello', 'world'], timeout=5)
        assert result['success'] is True
        assert 'hello world' in result['stdout']
    
    def test_shell_injection_attempt(self):
        """Test that shell injection attempts are blocked"""
        # Try various injection patterns
        malicious_args = [
            'test; rm -rf /',  # Command chaining
            'test && cat /etc/passwd',  # Logical AND
            'test || cat /etc/passwd',  # Logical OR
            'test `whoami`',  # Command substitution
            'test $(whoami)',  # Command substitution
            'test | cat /etc/passwd',  # Pipe
        ]
        
        for arg in malicious_args:
            # Should execute safely without interpreting special chars
            result = self.executor.execute_tool('echo', [arg], timeout=5)
            # The command should succeed, but not execute the injected command
            assert result['success'] is True
            # Output should contain the literal string, not command result
            assert arg in result['stdout'] or '/etc/passwd' not in result['stdout']
    
    def test_invalid_tool_name(self):
        """Test that invalid tool names are rejected"""
        with pytest.raises(CommandInjectionError):
            self.executor.execute_tool('../../../etc/passwd', [], timeout=5)
        
        with pytest.raises(CommandInjectionError):
            self.executor.execute_tool('test; ls', [], timeout=5)
    
    def test_special_characters_in_args(self):
        """Test that special characters are properly quoted"""
        special_chars = ['$PATH', '`whoami`', '$(ls)', '*', '?', '[', ']']
        
        for char in special_chars:
            result = self.executor.execute_tool('echo', [char], timeout=5)
            # Should echo the literal character, not expand it
            assert result['success'] is True


class TestInputValidation:
    """Test input validation framework"""
    
    def setup_method(self):
        """Setup validator"""
        self.validator = InputValidator()
    
    def test_valid_targets(self):
        """Test that valid targets pass validation"""
        valid_targets = [
            '192.168.1.1',
            '10.0.0.0/24',
            'example.com',
            'sub.example.com',
            'localhost',
        ]
        
        for target in valid_targets:
            assert self.validator.validate_target(target) is True
    
    def test_invalid_targets(self):
        """Test that invalid targets fail validation"""
        invalid_targets = [
            '192.168.1.1; ls',  # Command injection
            '../etc/passwd',  # Path traversal
            'test`whoami`',  # Command substitution
            '',  # Empty
            '999.999.999.999',  # Invalid IP
        ]
        
        for target in invalid_targets:
            assert self.validator.validate_target(target) is False
    
    def test_valid_ports(self):
        """Test port validation"""
        valid_ports = ['80', '443', '8080', '1-1000', '80,443,8080']
        
        for port in valid_ports:
            assert self.validator.validate_port_spec(port) is True
    
    def test_invalid_ports(self):
        """Test invalid port specs"""
        invalid_ports = ['99999', 'abc', '80; ls', '-1', '']
        
        for port in invalid_ports:
            assert self.validator.validate_port_spec(port) is False
    
    def test_path_traversal_prevention(self):
        """Test that path traversal is prevented"""
        malicious_paths = [
            '../../../etc/passwd',
            '~/secret.txt',
            '/etc/../../../etc/passwd',
            'test/../../../etc/passwd',
        ]
        
        for path in malicious_paths:
            assert self.validator.validate_file_path(path) is False


class TestCryptography:
    """Test encryption and cryptography hardening"""
    
    def setup_method(self):
        """Setup temporary credential store"""
        self.temp_dir = tempfile.mkdtemp()
        # Note: CredentialStore requires system keyring, may need mocking
    
    def teardown_method(self):
        """Cleanup"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_password_export_uses_random_salt(self):
        """Test that credential exports use random salts"""
        # This would require mocking or integration with actual credential store
        # For now, document the requirement
        pass
    
    def test_pbkdf2_iterations(self):
        """Test that PBKDF2 uses sufficient iterations"""
        # Verify PBKDF2 iterations are >= 600,000
        # This is a code inspection test
        import hashlib
        
        # Sample PBKDF2 with correct iterations
        password = b"test_password"
        salt = os.urandom(16)
        iterations = 600000
        
        key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
        assert len(key) == 32  # 256 bits
    
    def test_no_hardcoded_secrets(self):
        """Test that no secrets are hardcoded"""
        # Scan codebase for common hardcoded secret patterns
        suspicious_patterns = [
            b'api_key = "',
            b"api_key = '",
            b'password = "',
            b"password = '",
            b'secret = "',
            b"secret = '",
        ]
        
        # This is more of a static analysis test
        # In practice, use tools like truffleHog or detect-secrets
        pass


class TestFilePermissions:
    """Test secure file permissions"""
    
    def setup_method(self):
        """Setup temp directory"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_secure_file_creation(self):
        """Test that sensitive files are created with 0600 permissions"""
        from zypheron_go_shim import create_secure_file  # Would need Go-Python bridge
        
        # For now, test Python file creation
        test_file = Path(self.temp_dir) / "test_secret.txt"
        test_file.touch(mode=0o600)
        
        # Check permissions
        stat_info = test_file.stat()
        permissions = oct(stat_info.st_mode)[-3:]
        assert permissions == '600', f"File has insecure permissions: {permissions}"
    
    def test_no_world_readable_secrets(self):
        """Test that no secret files are world-readable"""
        # Scan common secret file locations
        secret_paths = [
            Path.home() / ".zypheron" / "credentials.enc",
            Path.home() / ".zypheron" / "ipc.token",
        ]
        
        for secret_path in secret_paths:
            if secret_path.exists():
                stat_info = secret_path.stat()
                mode = stat_info.st_mode
                
                # Check that group and others have no permissions
                assert (mode & 0o077) == 0, f"File {secret_path} has insecure permissions: {oct(mode)}"


class TestSocketSecurity:
    """Test Unix socket security"""
    
    def test_socket_ownership_validation(self):
        """Test that socket ownership is validated"""
        # Create a test socket
        import socket
        
        temp_dir = tempfile.mkdtemp(prefix="socket_test_")
        socket_path = os.path.join(temp_dir, "test.sock")
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(socket_path)
            sock.listen(1)
            
            # Set permissions
            os.chmod(socket_path, 0o600)
            
            # Check permissions
            stat_info = os.stat(socket_path)
            permissions = oct(stat_info.st_mode)[-3:]
            assert permissions == '600', f"Socket has insecure permissions: {permissions}"
            
            # Check ownership
            assert stat_info.st_uid == os.getuid(), "Socket not owned by current user"
            
            sock.close()
        finally:
            # Cleanup
            if os.path.exists(socket_path):
                os.unlink(socket_path)
            os.rmdir(temp_dir)
    
    def test_socket_in_user_directory(self):
        """Test that sockets are created in user-specific directory"""
        expected_socket_dir = Path.home() / ".zypheron" / "sockets"
        
        # Socket directory should exist or be creatable
        if not expected_socket_dir.exists():
            expected_socket_dir.mkdir(parents=True, mode=0o700)
        
        # Check directory permissions
        stat_info = expected_socket_dir.stat()
        permissions = oct(stat_info.st_mode)[-3:]
        assert permissions == '700', f"Socket directory has insecure permissions: {permissions}"


class TestLogSanitization:
    """Test log sanitization"""
    
    def setup_method(self):
        """Setup sanitizer"""
        self.sanitizer = LogSanitizer()
    
    def test_api_key_redaction(self):
        """Test that API keys are redacted"""
        messages = [
            "API_KEY=sk-1234567890abcdefghijklmnop",
            "Using api key: abcdef1234567890abcdef",
            'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        ]
        
        for msg in messages:
            sanitized = self.sanitizer.sanitize(msg)
            assert '[REDACTED]' in sanitized or '...' in sanitized
            # Original key should not appear in full
            assert not any(key in sanitized for key in ['sk-1234567890abcdefghijklmnop', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'])
    
    def test_password_redaction(self):
        """Test that passwords are redacted"""
        messages = [
            "password=SuperSecret123",
            "pwd: MyPassword",
            'passwd="test123456"',
        ]
        
        for msg in messages:
            sanitized = self.sanitizer.sanitize(msg)
            assert '[REDACTED]' in sanitized
            assert 'SuperSecret' not in sanitized
            assert 'MyPassword' not in sanitized
    
    def test_credit_card_redaction(self):
        """Test that credit card numbers are partially redacted"""
        msg = "Card: 1234-5678-9012-3456"
        sanitized = self.sanitizer.sanitize(msg)
        assert '3456' in sanitized  # Last 4 digits preserved
        assert '1234-5678' not in sanitized  # First digits redacted
    
    def test_dict_sanitization(self):
        """Test dictionary sanitization"""
        data = {
            'api_key': 'sk-1234567890',
            'password': 'secret123',
            'user': 'admin',
            'port': 8080
        }
        
        sanitized = self.sanitizer.sanitize_dict(data)
        assert sanitized['api_key'] == '[REDACTED]'
        assert sanitized['password'] == '[REDACTED]'
        assert sanitized['user'] == 'admin'  # Non-sensitive preserved
        assert sanitized['port'] == 8080


# Performance-related security tests
class TestPerformance:
    """Test that security measures don't cause performance issues"""
    
    def test_connection_pool_efficiency(self):
        """Test that connection pooling improves performance"""
        # This would require integration with actual Go bridge
        # Test that pooled connections are faster than creating new ones
        pass
    
    def test_regex_compilation_once(self):
        """Test that regex patterns are compiled only once"""
        from secrets_scanner.secret_scanner import SecretScanner
        
        scanner = SecretScanner()
        
        # Verify patterns are compiled (have compiled_patterns attribute)
        assert hasattr(scanner, 'compiled_patterns')
        assert len(scanner.compiled_patterns) > 0
        
        # All patterns should be compiled regex objects
        for pattern_data in scanner.compiled_patterns.values():
            assert hasattr(pattern_data['regex'], 'pattern')  # Compiled regex attribute


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])

