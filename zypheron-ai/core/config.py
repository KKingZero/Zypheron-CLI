"""
Zypheron AI Engine - Configuration
"""

import os
from typing import Optional
from pydantic import BaseSettings, Field


class AIConfig(BaseSettings):
    """AI Provider Configuration"""
    
    # API Keys
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")
    OPENAI_API_KEY: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    GOOGLE_API_KEY: Optional[str] = Field(default=None, env="GOOGLE_API_KEY")
    KIMI_API_KEY: Optional[str] = Field(default=None, env="KIMI_API_KEY")
    DEEPSEEK_API_KEY: Optional[str] = Field(default=None, env="DEEPSEEK_API_KEY")
    GROK_API_KEY: Optional[str] = Field(default=None, env="GROK_API_KEY")
    
    # Ollama Configuration
    OLLAMA_HOST: str = Field(default="http://localhost:11434", env="OLLAMA_HOST")
    OLLAMA_MODEL: str = Field(default="llama2", env="OLLAMA_MODEL")
    
    # Default Model Selection
    DEFAULT_PROVIDER: str = Field(default="claude", env="DEFAULT_AI_PROVIDER")
    
    # Model Names
    CLAUDE_MODEL: str = Field(default="claude-sonnet-4-20250514", env="CLAUDE_MODEL")
    OPENAI_MODEL: str = Field(default="gpt-4-turbo-preview", env="OPENAI_MODEL")
    GEMINI_MODEL: str = Field(default="gemini-pro", env="GEMINI_MODEL")
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
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global config instance
config = AIConfig()

