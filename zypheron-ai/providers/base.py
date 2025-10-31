"""
Base AI Provider Interface
"""

from abc import ABC, abstractmethod
from typing import Optional, AsyncIterator, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class AIProvider(str, Enum):
    """Supported AI Providers"""
    CLAUDE = "claude"
    OPENAI = "openai"
    GEMINI = "gemini"
    KIMI = "kimi"
    DEEPSEEK = "deepseek"
    GROK = "grok"
    OLLAMA = "ollama"


@dataclass
class AIMessage:
    """AI Message Structure"""
    role: str  # 'user', 'assistant', 'system'
    content: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AIResponse:
    """AI Response Structure"""
    content: str
    provider: str
    model: str
    tokens_used: Optional[int] = None
    finish_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseAIProvider(ABC):
    """Base class for all AI providers"""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        self.api_key = api_key
        self.config = kwargs
    
    @abstractmethod
    async def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """
        Send a chat request to the AI provider
        
        Args:
            messages: List of conversation messages
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
            **kwargs: Provider-specific parameters
            
        Returns:
            AIResponse object
        """
        pass
    
    @abstractmethod
    async def stream_chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream a chat response from the AI provider
        
        Args:
            messages: List of conversation messages
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
            **kwargs: Provider-specific parameters
            
        Yields:
            Chunks of the response text
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and available"""
        pass
    
    @abstractmethod
    def get_model_name(self) -> str:
        """Get the model name for this provider"""
        pass

