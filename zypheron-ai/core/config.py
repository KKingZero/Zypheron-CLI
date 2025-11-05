"""
Zypheron AI Engine - Configuration
"""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings
from loguru import logger

try:
    from .secure_config import get_api_key, migrate_from_env, check_keyring_available
    KEYRING_AVAILABLE = check_keyring_available()
except ImportError:
    KEYRING_AVAILABLE = False
    logger.warning("Keyring not available, using environment variables only")


def get_secure_api_key(provider: str, env_var: str) -> Optional[str]:
    """
    Get API key from keyring first, fallback to environment variable
    
    Args:
        provider: Provider name for keyring lookup
        env_var: Environment variable name for fallback
        
    Returns:
        API key if found, None otherwise
    """
    # Try keyring first
    if KEYRING_AVAILABLE:
        api_key = get_api_key(provider)
        if api_key:
            return api_key
        
        # Check if env var exists and migrate it
        env_value = os.getenv(env_var)
        if env_value:
            logger.warning(
                f"⚠️  {env_var} found in environment. "
                f"Consider migrating to keyring: zypheron config set-key {provider}"
            )
            return env_value
    
    # Fallback to environment variable
    return os.getenv(env_var)


class AIConfig(BaseSettings):
    """AI Provider Configuration"""
    
    # API Keys - these will try keyring first, then environment variables
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None)
    OPENAI_API_KEY: Optional[str] = Field(default=None)
    GOOGLE_API_KEY: Optional[str] = Field(default=None)
    KIMI_API_KEY: Optional[str] = Field(default=None)
    DEEPSEEK_API_KEY: Optional[str] = Field(default=None)
    GROK_API_KEY: Optional[str] = Field(default=None)
    
    # Ollama Configuration
    OLLAMA_HOST: str = Field(default="http://localhost:11434", env="OLLAMA_HOST")
    OLLAMA_MODEL: str = Field(default="llama2", env="OLLAMA_MODEL")
    
    # Default Model Selection
    DEFAULT_PROVIDER: str = Field(default="claude", env="DEFAULT_AI_PROVIDER")
    
    # Model Names
    CLAUDE_MODEL: str = Field(default="claude-sonnet-4-20250514", env="CLAUDE_MODEL")
    OPENAI_MODEL: str = Field(default="gpt-4-turbo-preview", env="OPENAI_MODEL")
    GEMINI_MODEL: str = Field(default="gemini-1.5-pro", env="GEMINI_MODEL")
    DEEPSEEK_MODEL: str = Field(default="deepseek-chat", env="DEEPSEEK_MODEL")
    GROK_MODEL: str = Field(default="grok-1", env="GROK_MODEL")
    
    # Performance Settings
    MAX_TOKENS: int = Field(default=4096, env="AI_MAX_TOKENS")
    TEMPERATURE: float = Field(default=0.7, env="AI_TEMPERATURE")
    STREAMING: bool = Field(default=True, env="AI_STREAMING")
    
    # IPC Settings
    IPC_SOCKET_PATH: str = Field(default="/tmp/zypheron-ai.sock", env="IPC_SOCKET_PATH")
    IPC_BUFFER_SIZE: int = Field(default=65536, env="IPC_BUFFER_SIZE")
    
    # CVE Database
    NVD_API_KEY: Optional[str] = Field(default=None, env="NVD_API_KEY")
    
    # ML Model Paths
    VULN_CLASSIFIER_MODEL: str = Field(
        default="models/vuln-classifier",
        env="VULN_CLASSIFIER_MODEL"
    )
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FILE: str = Field(default="zypheron-ai.log", env="LOG_FILE")
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",  # Ignore extra fields from .env file
    }
    
    def __init__(self, **kwargs):
        """Initialize config with keyring-first API key loading"""
        super().__init__(**kwargs)
        
        # Load API keys from keyring with fallback to env vars
        self.ANTHROPIC_API_KEY = self.ANTHROPIC_API_KEY or get_secure_api_key("anthropic", "ANTHROPIC_API_KEY")
        self.OPENAI_API_KEY = self.OPENAI_API_KEY or get_secure_api_key("openai", "OPENAI_API_KEY")
        self.GOOGLE_API_KEY = self.GOOGLE_API_KEY or get_secure_api_key("google", "GOOGLE_API_KEY")
        self.KIMI_API_KEY = self.KIMI_API_KEY or get_secure_api_key("kimi", "KIMI_API_KEY")
        self.DEEPSEEK_API_KEY = self.DEEPSEEK_API_KEY or get_secure_api_key("deepseek", "DEEPSEEK_API_KEY")
        self.GROK_API_KEY = self.GROK_API_KEY or get_secure_api_key("grok", "GROK_API_KEY")
        self.NVD_API_KEY = self.NVD_API_KEY or get_secure_api_key("nvd", "NVD_API_KEY")


# Global config instance
config = AIConfig()

