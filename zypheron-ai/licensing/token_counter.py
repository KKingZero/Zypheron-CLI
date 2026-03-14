"""
Token counting utilities for AI requests.

Provides estimation and tracking of token usage across different AI providers.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from loguru import logger


@dataclass
class TokenEstimate:
    """Estimated token usage for a request."""
    input_tokens: int
    output_tokens: int
    total_tokens: int
    provider: str
    model: str


class TokenCounter:
    """
    Counts and estimates tokens for AI API calls.

    Different providers use different tokenization methods, so this provides
    rough estimates based on character/word counts and provider-specific factors.
    """

    # Average tokens per character for different providers (rough estimates)
    TOKENS_PER_CHAR = {
        "claude": 0.25,
        "openai": 0.25,
        "gemini": 0.25,
        "deepseek": 0.3,
        "grok": 0.25,
        "kimi": 0.35,  # Chinese-optimized, different ratio
        "ollama": 0.25,
    }

    # Default output tokens estimate if not specified
    DEFAULT_OUTPUT_ESTIMATE = 500

    # Provider-specific model multipliers (some models are more expensive)
    MODEL_MULTIPLIERS = {
        # Claude
        "claude-3-opus": 1.5,
        "claude-3-sonnet": 1.0,
        "claude-3-haiku": 0.5,
        "claude-3.5-sonnet": 1.0,
        # OpenAI
        "gpt-4": 1.5,
        "gpt-4-turbo": 1.2,
        "gpt-4o": 1.0,
        "gpt-3.5-turbo": 0.5,
        # Others default to 1.0
    }

    def __init__(self, provider: str = "claude"):
        self.provider = provider.lower()
        self.tokens_per_char = self.TOKENS_PER_CHAR.get(self.provider, 0.25)

    def estimate_input_tokens(self, text: str) -> int:
        """
        Estimate tokens for input text.

        Args:
            text: The input text

        Returns:
            Estimated token count
        """
        if not text:
            return 0

        # Basic character-based estimation
        char_estimate = int(len(text) * self.tokens_per_char)

        # Adjust for special characters and formatting
        # Code blocks and special syntax tend to use more tokens
        code_blocks = len(re.findall(r'```[\s\S]*?```', text))
        json_blocks = len(re.findall(r'\{[\s\S]*?\}', text))
        adjustment = (code_blocks * 50) + (json_blocks * 20)

        return char_estimate + adjustment

    def estimate_messages_tokens(self, messages: List[Dict]) -> int:
        """
        Estimate tokens for a list of chat messages.

        Args:
            messages: List of message dicts with 'role' and 'content'

        Returns:
            Estimated token count
        """
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += self.estimate_input_tokens(content)
            # Add overhead for message structure
            total += 4  # Approximate overhead per message

        return total

    def estimate_output_tokens(self, expected_length: Optional[int] = None) -> int:
        """
        Estimate tokens for expected output.

        Args:
            expected_length: Expected character length of output, or None for default

        Returns:
            Estimated token count
        """
        if expected_length is None:
            return self.DEFAULT_OUTPUT_ESTIMATE

        return int(expected_length * self.tokens_per_char)

    def estimate_request(
        self,
        messages: List[Dict],
        expected_output_length: Optional[int] = None,
        model: Optional[str] = None
    ) -> TokenEstimate:
        """
        Estimate total tokens for a request.

        Args:
            messages: List of chat messages
            expected_output_length: Expected output length in characters
            model: Model name for cost multiplier

        Returns:
            TokenEstimate with breakdown
        """
        input_tokens = self.estimate_messages_tokens(messages)
        output_tokens = self.estimate_output_tokens(expected_output_length)

        # Apply model multiplier if known
        if model:
            multiplier = self.MODEL_MULTIPLIERS.get(model.lower(), 1.0)
            input_tokens = int(input_tokens * multiplier)
            output_tokens = int(output_tokens * multiplier)

        total = input_tokens + output_tokens

        return TokenEstimate(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total,
            provider=self.provider,
            model=model or "unknown"
        )

    @staticmethod
    def count_actual_tokens(text: str, provider: str = "openai") -> int:
        """
        Count actual tokens using provider-specific tokenizer if available.

        Falls back to estimation if tokenizer not available.

        Args:
            text: Text to count
            provider: Provider name

        Returns:
            Token count
        """
        try:
            if provider in ("openai", "gpt"):
                import tiktoken
                encoding = tiktoken.get_encoding("cl100k_base")
                return len(encoding.encode(text))
        except ImportError:
            pass

        # Fall back to estimation
        counter = TokenCounter(provider)
        return counter.estimate_input_tokens(text)

    def track_usage(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        model: str,
        action: str = "chat"
    ) -> Dict:
        """
        Track actual token usage after API response.

        Args:
            prompt_tokens: Actual prompt tokens from API response
            completion_tokens: Actual completion tokens from API response
            model: Model used
            action: Type of action

        Returns:
            Usage record dict
        """
        from datetime import datetime

        return {
            "timestamp": datetime.now().isoformat(),
            "provider": self.provider,
            "model": model,
            "action": action,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }


# Convenience functions for common operations

def estimate_chat_tokens(messages: List[Dict], provider: str = "claude") -> int:
    """Quick estimation for chat messages."""
    counter = TokenCounter(provider)
    return counter.estimate_messages_tokens(messages)


def estimate_request_tokens(
    messages: List[Dict],
    provider: str = "claude",
    expected_output: int = 500
) -> int:
    """Quick estimation for a full request (input + output)."""
    counter = TokenCounter(provider)
    estimate = counter.estimate_request(messages, expected_output)
    return estimate.total_tokens


def should_warn_token_usage(estimated_tokens: int, remaining_tokens: int, threshold: float = 0.1) -> bool:
    """
    Check if user should be warned about token usage.

    Args:
        estimated_tokens: Estimated tokens for this request
        remaining_tokens: User's remaining token balance
        threshold: Percentage threshold (0.1 = 10%)

    Returns:
        True if warning should be shown
    """
    if remaining_tokens <= 0:
        return True

    usage_ratio = estimated_tokens / remaining_tokens
    return usage_ratio > threshold
