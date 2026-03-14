"""
Ollama Provider (Local LLM)
"""

from typing import List, AsyncIterator, Optional
import aiohttp
import json
from .base import BaseAIProvider, AIMessage, AIResponse
from core.config import config
from loguru import logger


class OllamaProvider(BaseAIProvider):
    """Ollama Provider for local LLM inference"""
    
    def __init__(self, host: Optional[str] = None, model: Optional[str] = None, **kwargs):
        super().__init__(api_key=None, **kwargs)
        self.host = host or config.OLLAMA_HOST
        self.model = model or config.OLLAMA_MODEL
        logger.info(f"Ollama provider initialized with host: {self.host}, model: {self.model}")

    async def _list_models(self, session: aiohttp.ClientSession) -> List[str]:
        """Return available local Ollama model tags."""
        try:
            async with session.get(f"{self.host}/api/tags", timeout=aiohttp.ClientTimeout(total=3)) as response:
                if response.status != 200:
                    return []
                data = await response.json()
                models = data.get("models", [])
                return [m.get("name", "") for m in models if m.get("name")]
        except Exception:
            return []

    async def _resolve_model_fallback(
        self,
        requested_model: str,
        session: aiohttp.ClientSession,
    ) -> Optional[str]:
        """
        Find a compatible fallback when requested model is missing.
        Preference:
        1) same family prefix (e.g. llama3.2:*),
        2) configured default model if installed,
        3) llama3:latest if installed,
        4) first available model.
        """
        available = await self._list_models(session)
        if not available:
            return None
        if requested_model in available:
            return requested_model

        family = requested_model.split(":", 1)[0]
        for m in available:
            if m.startswith(family + ":"):
                return m

        if self.model in available:
            return self.model
        if "llama3:latest" in available:
            return "llama3:latest"
        return available[0]
    
    async def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """Send a chat request to Ollama"""
        model_override = kwargs.pop("model", None)
        model_name = model_override or self.model
        
        # Convert our message format to Ollama format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Prepare the request
        url = f"{self.host}/api/chat"
        payload = {
            "model": model_name,
            "messages": formatted_messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            }
        }
        
        # Make the API call
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    # Graceful retry for missing model tags.
                    if "model" in error_text.lower() and "not found" in error_text.lower():
                        fallback = await self._resolve_model_fallback(model_name, session)
                        if fallback and fallback != model_name:
                            logger.warning(
                                f"Ollama model '{model_name}' not found; retrying with '{fallback}'"
                            )
                            payload["model"] = fallback
                            async with session.post(url, json=payload) as retry_response:
                                if retry_response.status != 200:
                                    retry_error = await retry_response.text()
                                    raise ValueError(f"Ollama API error: {retry_error}")
                                data = await retry_response.json()
                                return AIResponse(
                                    content=data["message"]["content"],
                                    provider="ollama",
                                    model=fallback,
                                    tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
                                    finish_reason=data.get("done_reason"),
                                    metadata={
                                        "total_duration": data.get("total_duration"),
                                        "load_duration": data.get("load_duration"),
                                        "prompt_eval_count": data.get("prompt_eval_count"),
                                        "eval_count": data.get("eval_count"),
                                        "fallback_from": model_name,
                                    },
                                )
                    raise ValueError(f"Ollama API error: {error_text}")

                data = await response.json()

                return AIResponse(
                    content=data["message"]["content"],
                    provider="ollama",
                    model=model_name,
                    tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
                    finish_reason=data.get("done_reason"),
                    metadata={
                        "total_duration": data.get("total_duration"),
                        "load_duration": data.get("load_duration"),
                        "prompt_eval_count": data.get("prompt_eval_count"),
                        "eval_count": data.get("eval_count"),
                    }
                )
    
    async def stream_chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> AsyncIterator[str]:
        """Stream a chat response from Ollama"""
        model_override = kwargs.pop("model", None)
        model_name = model_override or self.model
        
        # Convert our message format to Ollama format
        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]
        
        # Prepare the request
        url = f"{self.host}/api/chat"
        payload = {
            "model": model_name,
            "messages": formatted_messages,
            "stream": True,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            }
        }
        
        # Stream the response
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(f"Ollama API error: {error_text}")
                
                async for line in response.content:
                    if line:
                        try:
                            data = json.loads(line.decode('utf-8'))
                            if "message" in data and "content" in data["message"]:
                                yield data["message"]["content"]
                        except json.JSONDecodeError:
                            continue
    
    async def is_available(self) -> bool:
        """Check if Ollama is running and available"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.host}/api/tags", timeout=aiohttp.ClientTimeout(total=2)) as response:
                    return response.status == 200
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return False
    
    def get_model_name(self) -> str:
        """Get the Ollama model name"""
        return self.model
