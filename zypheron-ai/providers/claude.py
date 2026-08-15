"""
Claude AI Provider (Anthropic)
"""

from typing import List, AsyncIterator, Optional
from anthropic import AsyncAnthropic
from .base import BaseAIProvider, AIMessage, AIResponse
from .capabilities import validate_effort
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
        model_override = kwargs.pop("model", None)
        effort = validate_effort("claude", kwargs.pop("effort", None))
        model_name = model_override or config.CLAUDE_MODEL
        if effort:
            output_config = dict(kwargs.pop("output_config", {}) or {})
            output_config["effort"] = effort
            kwargs["output_config"] = output_config
        
        # Convert our message format to Anthropic format
        formatted_messages = []
        system_message = None
        
        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                formatted_messages.append({
                    "role": msg.role,
                    "content": self._format_content(msg)
                })
        
        # Make the API call
        response = await self.client.messages.create(
            model=model_name,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_message,
            messages=formatted_messages,
            **kwargs
        )
        
        return AIResponse(
            content=response.content[0].text,
            provider="claude",
            model=model_name,
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
        model_override = kwargs.pop("model", None)
        effort = validate_effort("claude", kwargs.pop("effort", None))
        model_name = model_override or config.CLAUDE_MODEL
        if effort:
            output_config = dict(kwargs.pop("output_config", {}) or {})
            output_config["effort"] = effort
            kwargs["output_config"] = output_config
        
        # Convert our message format to Anthropic format
        formatted_messages = []
        system_message = None
        
        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                formatted_messages.append({
                    "role": msg.role,
                    "content": self._format_content(msg)
                })
        
        # Stream the response
        async with self.client.messages.stream(
            model=model_name,
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

    def _format_content(self, msg: AIMessage):
        images = (msg.metadata or {}).get("images") or []
        if not images:
            return msg.content
        content = [{"type": "text", "text": msg.content}]
        for image in images:
            if image.get("url"):
                content.append({
                    "type": "image",
                    "source": {"type": "url", "url": image["url"]},
                })
                continue
            mime_type = image.get("mime_type")
            data = image.get("data_base64")
            if not mime_type or not data:
                raise ValueError("Claude image input requires url or mime_type with data_base64")
            content.append({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": mime_type,
                    "data": data,
                },
            })
        return content
