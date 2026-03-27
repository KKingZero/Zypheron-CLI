"""
Zypheron AI Engine - Configuration
"""

import os
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
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
    OLLAMA_MODEL: str = Field(default="qwen3-coder", env="OLLAMA_MODEL")

    # Default Model Selection
    DEFAULT_PROVIDER: str = Field(default="anthropic", env="DEFAULT_AI_PROVIDER")

    # Model Names — resolved via core.model_registry, these are env overrides only
    CLAUDE_MODEL: str = Field(default="claude-opus-4-6", env="CLAUDE_MODEL")
    CLAUDE_MODEL_FAST: str = Field(default="claude-sonnet-4-6", env="CLAUDE_MODEL_FAST")
    OPENAI_MODEL: str = Field(default="gpt-5.4", env="OPENAI_MODEL")
    GEMINI_MODEL: str = Field(default="gemini-3.1-pro-preview", env="GEMINI_MODEL")
    GEMINI_MODEL_FAST: str = Field(default="gemini-3-flash-preview", env="GEMINI_MODEL_FAST")
    DEEPSEEK_MODEL: str = Field(default="deepseek-r1", env="DEEPSEEK_MODEL")
    KIMI_MODEL: str = Field(default="kimi-k2", env="KIMI_MODEL")
    GROK_MODEL: str = Field(default="grok-3", env="GROK_MODEL")
    
    # Performance Settings
    MAX_TOKENS: int = Field(default=4096, env="AI_MAX_TOKENS")
    TEMPERATURE: float = Field(default=0.7, env="AI_TEMPERATURE")
    STREAMING: bool = Field(default=True, env="AI_STREAMING")

    # AI Analysis Aggressiveness Settings
    # "conservative" = fewer false positives, might miss some vulns
    # "balanced" = balanced detection
    # "aggressive" = more detections, may have false positives
    AI_AGGRESSIVENESS: str = Field(default="aggressive", env="AI_AGGRESSIVENESS")

    # Confidence thresholds for vulnerability detection
    VULN_CONFIDENCE_THRESHOLD: float = Field(default=0.3, env="VULN_CONFIDENCE_THRESHOLD")

    # Minimum CVSS score to report (0.0 - 10.0)
    MIN_CVSS_REPORT: float = Field(default=1.0, env="MIN_CVSS_REPORT")
    
    # IPC Settings
    IPC_SOCKET_PATH: str = Field(
        default=str(Path.home() / ".zypheron" / "sockets" / "ai-default.sock"),
        env="IPC_SOCKET_PATH",
    )
    IPC_TRANSPORT: str = Field(default="stdio", env="IPC_TRANSPORT")
    IPC_TCP_HOST: str = Field(default="127.0.0.1", env="IPC_TCP_HOST")
    IPC_TCP_PORT: int = Field(default=0, env="IPC_TCP_PORT")
    IPC_BUFFER_SIZE: int = Field(default=65536, env="IPC_BUFFER_SIZE")
    IPC_MAX_REQUEST_BYTES: int = Field(default=5 * 1024 * 1024, env="IPC_MAX_REQUEST_BYTES")
    
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
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    def __init__(self, **kwargs):
        """Initialize config with keyring-first API key loading"""
        super().__init__(**kwargs)
        self.reload_api_keys()

    def reload_api_keys(self) -> None:
        """Reload secure API keys from keyring or environment."""
        self.ANTHROPIC_API_KEY = get_secure_api_key("anthropic", "ANTHROPIC_API_KEY")
        self.OPENAI_API_KEY = get_secure_api_key("openai", "OPENAI_API_KEY")
        self.GOOGLE_API_KEY = get_secure_api_key("google", "GOOGLE_API_KEY")
        self.KIMI_API_KEY = get_secure_api_key("kimi", "KIMI_API_KEY")
        self.DEEPSEEK_API_KEY = get_secure_api_key("deepseek", "DEEPSEEK_API_KEY")
        self.GROK_API_KEY = get_secure_api_key("grok", "GROK_API_KEY")
        self.NVD_API_KEY = get_secure_api_key("nvd", "NVD_API_KEY")


# Global config instance
config = AIConfig()
