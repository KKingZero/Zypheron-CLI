"""
AI Provider Manager - Orchestrates multiple AI providers
"""

from typing import Optional, List, AsyncIterator
from loguru import logger

from .base import BaseAIProvider, AIMessage, AIResponse, AIProvider
from .claude import ClaudeProvider
from .openai_provider import OpenAIProvider
from .gemini import GeminiProvider
from .kimi import KimiProvider
from .deepseek import DeepSeekProvider
from .grok import GrokProvider
from .ollama import OllamaProvider
from core.config import config


class AIProviderManager:
    """Manages multiple AI providers and routes requests"""
    
    def __init__(self):
        self.providers = {}
        self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize all AI providers"""
        
        # Claude
        try:
            claude = ClaudeProvider()
            if claude.is_available():
                self.providers[AIProvider.CLAUDE] = claude
                logger.info("✓ Claude provider initialized")
            else:
                logger.warning("✗ Claude provider not configured (missing API key)")
        except Exception as e:
            logger.error(f"✗ Failed to initialize Claude: {e}")
        
        # OpenAI
        try:
            openai = OpenAIProvider()
            if openai.is_available():
                self.providers[AIProvider.OPENAI] = openai
                logger.info("✓ OpenAI provider initialized")
            else:
                logger.warning("✗ OpenAI provider not configured (missing API key)")
        except Exception as e:
            logger.error(f"✗ Failed to initialize OpenAI: {e}")
        
        # Gemini
        try:
            gemini = GeminiProvider()
            if gemini.is_available():
                self.providers[AIProvider.GEMINI] = gemini
                logger.info("✓ Gemini provider initialized")
            else:
                logger.warning("✗ Gemini provider not configured (missing API key)")
        except Exception as e:
            logger.error(f"✗ Failed to initialize Gemini: {e}")
        
        # Kimi
        try:
            kimi = KimiProvider()
            if kimi.is_available():
                self.providers[AIProvider.KIMI] = kimi
                logger.info("✓ Kimi provider initialized")
            else:
                logger.warning("✗ Kimi provider not configured (missing API key)")
        except Exception as e:
            logger.error(f"✗ Failed to initialize Kimi: {e}")
        
        # DeepSeek
        try:
            deepseek = DeepSeekProvider()
            if deepseek.is_available():
                self.providers[AIProvider.DEEPSEEK] = deepseek
                logger.info("✓ DeepSeek provider initialized")
            else:
                logger.warning("✗ DeepSeek provider not configured (missing API key)")
        except Exception as e:
            logger.error(f"✗ Failed to initialize DeepSeek: {e}")
        
        # Grok
        try:
            grok = GrokProvider()
            if grok.is_available():
                self.providers[AIProvider.GROK] = grok
                logger.info("✓ Grok provider initialized")
            else:
                logger.warning("✗ Grok provider not configured (missing API key)")
        except Exception as e:
            logger.error(f"✗ Failed to initialize Grok: {e}")
        
        # Ollama
        try:
            ollama = OllamaProvider()
            # Ollama availability check is async, so we'll add it and check later
            self.providers[AIProvider.OLLAMA] = ollama
            logger.info("✓ Ollama provider initialized (check availability on first use)")
        except Exception as e:
            logger.error(f"✗ Failed to initialize Ollama: {e}")
        
        if not self.providers:
            logger.error("⚠️  NO AI PROVIDERS CONFIGURED! Please set at least one API key.")
    
    def get_provider(self, provider_name: Optional[str] = None) -> BaseAIProvider:
        """
        Get an AI provider by name
        
        Args:
            provider_name: Name of the provider (claude, openai, gemini, etc.)
                          If None, uses the default provider from config
        
        Returns:
            BaseAIProvider instance
        
        Raises:
            ValueError: If provider not found or not configured
        """
        if provider_name is None:
            provider_name = config.DEFAULT_PROVIDER
        
        try:
            provider_enum = AIProvider(provider_name.lower())
        except ValueError:
            available = ", ".join([p.value for p in self.providers.keys()])
            raise ValueError(
                f"Unknown provider '{provider_name}'. "
                f"Available providers: {available}"
            )
        
        if provider_enum not in self.providers:
            available = ", ".join([p.value for p in self.providers.keys()])
            raise ValueError(
                f"Provider '{provider_name}' not configured. "
                f"Available providers: {available}"
            )
        
        return self.providers[provider_enum]
    
    def list_available_providers(self) -> List[str]:
        """List all available (configured) providers"""
        return [provider.value for provider in self.providers.keys()]
    
    async def chat(
        self,
        messages: List[AIMessage],
        provider: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """
        Send a chat request using the specified provider
        
        Args:
            messages: List of conversation messages
            provider: Provider name (uses default if None)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
            **kwargs: Provider-specific parameters
        
        Returns:
            AIResponse object
        """
        ai_provider = self.get_provider(provider)
        return await ai_provider.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
            **kwargs
        )
    
    async def stream_chat(
        self,
        messages: List[AIMessage],
        provider: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream a chat response using the specified provider
        
        Args:
            messages: List of conversation messages
            provider: Provider name (uses default if None)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            **kwargs: Provider-specific parameters
        
        Yields:
            Chunks of the response text
        """
        ai_provider = self.get_provider(provider)
        async for chunk in ai_provider.stream_chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        ):
            yield chunk


# Global instance
ai_manager = AIProviderManager()

