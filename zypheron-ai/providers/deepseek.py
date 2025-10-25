"""
DeepSeek Provider
"""

from typing import List, AsyncIterator, Optional
from openai import AsyncOpenAI
from .base import BaseAIProvider, AIMessage, AIResponse
from core.config import config
from loguru import logger


class DeepSeekProvider(BaseAIProvider):
    """DeepSeek Provider (OpenAI-compatible API)"""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key or config.DEEPSEEK_API_KEY, **kwargs)
        if self.api_key:
            self.client = AsyncOpenAI(
                api_key=self.api_key,
                base_url="https://api.deepseek.com/v1"
            )
        else:
            self.client = None
            logger.warning("DeepSeek provider initialized without API key")
    
    async def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """Send a chat request to DeepSeek"""
        
        if not self.client:
            raise ValueError("DeepSeek API key not configured")
        
        # Convert our message format to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Make the API call
        response = await self.client.chat.completions.create(
            model=config.DEEPSEEK_MODEL,
            messages=formatted_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        
        return AIResponse(
            content=response.choices[0].message.content,
            provider="deepseek",
            model=config.DEEPSEEK_MODEL,
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
        """Stream a chat response from DeepSeek"""
        
        if not self.client:
            raise ValueError("DeepSeek API key not configured")
        
        # Convert our message format to OpenAI format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Stream the response
        stream = await self.client.chat.completions.create(
            model=config.DEEPSEEK_MODEL,
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
        """Check if DeepSeek is configured"""
        return self.client is not None
    
    def get_model_name(self) -> str:
        """Get the DeepSeek model name"""
        return config.DEEPSEEK_MODEL

