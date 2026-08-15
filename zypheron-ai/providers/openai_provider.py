"""
OpenAI Provider
"""

from typing import List, AsyncIterator, Optional
from openai import AsyncOpenAI
from .base import BaseAIProvider, AIMessage, AIResponse
from .capabilities import validate_effort
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
        model_override = kwargs.pop("model", None)
        effort = validate_effort("openai", kwargs.pop("effort", None))
        model_name = model_override or config.OPENAI_MODEL
        if self._should_use_responses_api(messages):
            return await self._responses_chat(
                messages=messages,
                model_name=model_name,
                temperature=temperature,
                max_tokens=max_tokens,
                effort=effort,
                **kwargs,
            )
        if effort and effort != "none":
            kwargs["reasoning_effort"] = effort
        
        # Convert our message format to OpenAI format
        formatted_messages = [self._format_message(msg) for msg in messages]
        
        # Make the API call
        response = await self.client.chat.completions.create(
            model=model_name,
            messages=formatted_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        
        return AIResponse(
            content=response.choices[0].message.content,
            provider="openai",
            model=model_name,
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
        model_override = kwargs.pop("model", None)
        effort = validate_effort("openai", kwargs.pop("effort", None))
        model_name = model_override or config.OPENAI_MODEL
        if self._should_use_responses_api(messages):
            raise ValueError("OpenAI streaming with image inputs requires a Responses API-capable SDK")
        if effort and effort != "none":
            kwargs["reasoning_effort"] = effort
        
        # Convert our message format to OpenAI format
        formatted_messages = [self._format_message(msg) for msg in messages]
        
        # Stream the response
        stream = await self.client.chat.completions.create(
            model=model_name,
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

    def _format_message(self, msg: AIMessage) -> dict:
        images = (msg.metadata or {}).get("images") or []
        if not images:
            return {"role": msg.role, "content": msg.content}
        content = [{"type": "text", "text": msg.content}]
        for image in images:
            url = image.get("url")
            if not url:
                mime_type = image.get("mime_type")
                data = image.get("data_base64")
                if not mime_type or not data:
                    raise ValueError("OpenAI image input requires url or mime_type with data_base64")
                url = f"data:{mime_type};base64,{data}"
            content.append({"type": "image_url", "image_url": {"url": url}})
        return {"role": msg.role, "content": content}

    def _should_use_responses_api(self, messages: List[AIMessage]) -> bool:
        has_images = any((msg.metadata or {}).get("images") for msg in messages)
        return has_images and hasattr(self.client, "responses")

    async def _responses_chat(
        self,
        messages: List[AIMessage],
        model_name: str,
        temperature: float,
        max_tokens: int,
        effort: Optional[str],
        **kwargs,
    ) -> AIResponse:
        response_kwargs = dict(kwargs)
        if effort and effort != "none":
            response_kwargs["reasoning"] = {"effort": effort}

        response = await self.client.responses.create(
            model=model_name,
            input=[self._format_response_message(msg) for msg in messages],
            temperature=temperature,
            max_output_tokens=max_tokens,
            **response_kwargs,
        )
        content = getattr(response, "output_text", None) or self._extract_response_text(response)
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
        output_tokens = getattr(usage, "output_tokens", 0) if usage else 0
        total_tokens = getattr(usage, "total_tokens", None) if usage else None
        if total_tokens is None and usage:
            total_tokens = input_tokens + output_tokens
        return AIResponse(
            content=content,
            provider="openai",
            model=model_name,
            tokens_used=total_tokens,
            finish_reason=getattr(response, "status", None),
            metadata={
                "api": "responses",
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
        )

    def _format_response_message(self, msg: AIMessage) -> dict:
        images = (msg.metadata or {}).get("images") or []
        content = [{"type": "input_text", "text": msg.content}]
        for image in images:
            url = image.get("url")
            if not url:
                mime_type = image.get("mime_type")
                data = image.get("data_base64")
                if not mime_type or not data:
                    raise ValueError("OpenAI image input requires url or mime_type with data_base64")
                url = f"data:{mime_type};base64,{data}"
            content.append({"type": "input_image", "image_url": url})
        role = "user" if msg.role == "system" else msg.role
        return {"role": role, "content": content}

    def _extract_response_text(self, response) -> str:
        parts = []
        for item in getattr(response, "output", []) or []:
            for content in getattr(item, "content", []) or []:
                text = getattr(content, "text", None)
                if text:
                    parts.append(text)
        return "\n".join(parts)
