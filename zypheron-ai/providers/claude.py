"""
Claude AI Provider (Anthropic)
"""

from typing import List, AsyncIterator, Optional
from anthropic import AsyncAnthropic
from .base import BaseAIProvider, AIMessage, AIResponse
from core.config import config
from loguru import logger


class ClaudeProvider(BaseAIProvider):
    """Claude AI Provider using Anthropic API"""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key or config.ANTHROPIC_API_KEY, **kwargs)
        if self.api_key:
            self.client = AsyncAnthropic(api_key=self.api_key)
        else:
            self.client = None
            logger.warning("Claude provider initialized without API key")
    
    async def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """Send a chat request to Claude"""
        
        if not self.client:
            raise ValueError("Claude API key not configured")
        
        # Convert our message format to Anthropic format
        formatted_messages = []
        system_message = None
        
        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                formatted_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        # Make the API call
        response = await self.client.messages.create(
            model=config.CLAUDE_MODEL,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_message,
            messages=formatted_messages,
            **kwargs
        )
        
        return AIResponse(
            content=response.content[0].text,
            provider="claude",
            model=config.CLAUDE_MODEL,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            finish_reason=response.stop_reason,
            metadata={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
        )
    
    async def stream_chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> AsyncIterator[str]:
        """Stream a chat response from Claude"""
        
        if not self.client:
            raise ValueError("Claude API key not configured")
        
        # Convert our message format to Anthropic format
        formatted_messages = []
        system_message = None
        
        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                formatted_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        # Stream the response
        async with self.client.messages.stream(
            model=config.CLAUDE_MODEL,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_message,
            messages=formatted_messages,
            **kwargs
        ) as stream:
            async for text in stream.text_stream:
                yield text
    
    def is_available(self) -> bool:
        """Check if Claude is configured"""
        return self.client is not None
    
    def get_model_name(self) -> str:
        """Get the Claude model name"""
        return config.CLAUDE_MODEL

