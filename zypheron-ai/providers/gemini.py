"""
Google Gemini Provider
"""

from typing import List, AsyncIterator, Optional
import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="google\\.generativeai")
import google.generativeai as genai
from .base import BaseAIProvider, AIMessage, AIResponse
from core.config import config
from loguru import logger


class GeminiProvider(BaseAIProvider):
    """Google Gemini Provider"""
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        super().__init__(api_key or config.GOOGLE_API_KEY, **kwargs)
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(config.GEMINI_MODEL)
        else:
            self.model = None
            logger.warning("Gemini provider initialized without API key")
    
    async def chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False,
        **kwargs
    ) -> AIResponse:
        """Send a chat request to Gemini"""
        
        if not self.model:
            raise ValueError("Gemini API key not configured")
        model_override = kwargs.pop("model", None)
        model_obj = self.model
        if model_override:
            model_obj = genai.GenerativeModel(model_override)
        
        # Convert our message format to Gemini format
        # Gemini uses a different conversation format
        conversation_text = "\n".join([
            f"{msg.role}: {msg.content}" for msg in messages
        ])
        
        # Make the API call
        response = await model_obj.generate_content_async(
            conversation_text,
            generation_config={
                "temperature": temperature,
                "max_output_tokens": max_tokens,
            }
        )
        
        return AIResponse(
            content=response.text,
            provider="gemini",
            model=model_override or config.GEMINI_MODEL,
            tokens_used=None,  # Gemini doesn't always provide token counts
            finish_reason=response.candidates[0].finish_reason.name if response.candidates else None,
            metadata={}
        )
    
    async def stream_chat(
        self,
        messages: List[AIMessage],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> AsyncIterator[str]:
        """Stream a chat response from Gemini"""
        
        if not self.model:
            raise ValueError("Gemini API key not configured")
        model_override = kwargs.pop("model", None)
        model_obj = self.model
        if model_override:
            model_obj = genai.GenerativeModel(model_override)
        
        # Convert our message format to Gemini format
        conversation_text = "\n".join([
            f"{msg.role}: {msg.content}" for msg in messages
        ])
        
        # Stream the response
        response = await model_obj.generate_content_async(
            conversation_text,
            generation_config={
                "temperature": temperature,
                "max_output_tokens": max_tokens,
            },
            stream=True
        )
        
        async for chunk in response:
            if chunk.text:
                yield chunk.text
    
    def is_available(self) -> bool:
        """Check if Gemini is configured"""
        return self.model is not None
    
    def get_model_name(self) -> str:
        """Get the Gemini model name"""
        return config.GEMINI_MODEL
