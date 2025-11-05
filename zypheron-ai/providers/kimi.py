"""
Kimi Provider (Moonshot AI)
"""

from typing import List, AsyncIterator, Optional
from openai import AsyncOpenAI
from .base import BaseAIProvider, AIMessage, AIResponse
from core.config import config
from loguru import logger


class KimiProvider(BaseAIProvider):
    """Kimi Provider (Moonshot AI - OpenAI-compatible API)"""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key or config.KIMI_API_KEY, **kwargs)
        if self.api_key:
            self.client = AsyncOpenAI(
                api_key=self.api_key,
                base_url="https://api.moonshot.cn/v1"
            )
        else:
            self.client = None
            logger.warning("Kimi provider initialized without API key")
    
    async def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """Send a chat request to Kimi"""
        
        if not self.client:
            raise ValueError("Kimi API key not configured")
        
        # Convert our message format to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Make the API call
        response = await self.client.chat.completions.create(
            model="moonshot-v1-8k",  # Kimi's model identifier
            messages=formatted_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        
        return AIResponse(
            content=response.choices[0].message.content,
            provider="kimi",
            model="moonshot-v1-8k",
            tokens_used=response.usage.total_tokens if response.usage else None,
            finish_reason=response.choices[0].finish_reason,
            metadata={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else None,
                "completion_tokens": response.usage.completion_tokens if response.usage else None,
            }
        )
    
    async def stream_chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> AsyncIterator[str]:
        """Stream a chat response from Kimi"""
        
        if not self.client:
            raise ValueError("Kimi API key not configured")
        
        # Convert our message format to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Stream the response
        stream = await self.client.chat.completions.create(
            model="moonshot-v1-8k",
            messages=formatted_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **kwargs
        )
        
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
    
    def is_available(self) -> bool:
        """Check if Kimi is configured"""
        return self.client is not None
    
    def get_model_name(self) -> str:
        """Get the Kimi model name"""
        return "moonshot-v1-8k"

