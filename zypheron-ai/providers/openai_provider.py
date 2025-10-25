"""
OpenAI Provider
"""

from typing import List, AsyncIterator, Optional
from openai import AsyncOpenAI
from .base import BaseAIProvider, AIMessage, AIResponse
from core.config import config
from loguru import logger


class OpenAIProvider(BaseAIProvider):
    """OpenAI Provider (GPT-4, GPT-3.5)"""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key or config.OPENAI_API_KEY, **kwargs)
        if self.api_key:
            self.client = AsyncOpenAI(api_key=self.api_key)
        else:
            self.client = None
            logger.warning("OpenAI provider initialized without API key")
    
    async def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """Send a chat request to OpenAI"""
        
        if not self.client:
            raise ValueError("OpenAI API key not configured")
        
        # Convert our message format to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Make the API call
        response = await self.client.chat.completions.create(
            model=config.OPENAI_MODEL,
            messages=formatted_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        
        return AIResponse(
            content=response.choices[0].message.content,
            provider="openai",
            model=config.OPENAI_MODEL,
            tokens_used=response.usage.total_tokens,
            finish_reason=response.choices[0].finish_reason,
            metadata={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
            }
        )
    
    async def stream_chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> AsyncIterator[str]:
        """Stream a chat response from OpenAI"""
        
        if not self.client:
            raise ValueError("OpenAI API key not configured")
        
        # Convert our message format to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Stream the response
        stream = await self.client.chat.completions.create(
            model=config.OPENAI_MODEL,
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
        """Check if OpenAI is configured"""
        return self.client is not None
    
    def get_model_name(self) -> str:
        """Get the OpenAI model name"""
        return config.OPENAI_MODEL

