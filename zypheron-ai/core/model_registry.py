"""
Zypheron AI Model Registry & Resolver

Central registry for all AI model identifiers. Never hardcode model names
in business logic — always resolve through this registry.

Update this file when providers release new models.
Last updated: March 2026
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, List
from loguru import logger


@dataclass
class ModelEntry:
    """A single model definition with metadata."""
    model_id: str
    context_window: int = 0
    max_output: int = 4096
    supports_streaming: bool = True
    supports_tools: bool = False
    notes: str = ""


@dataclass
class ProviderConfig:
    """Configuration for a single AI provider."""
    default_model: str
    fallback_model: Optional[str] = None
    available_models: Dict[str, ModelEntry] = field(default_factory=dict)


# ── Provider Registry ────────────────────────────────────────────────────────
# Update model IDs here when new versions ship. Business logic never touches
# raw model strings — it calls resolve_model() instead.

PROVIDER_REGISTRY: Dict[str, ProviderConfig] = {
    "anthropic": ProviderConfig(
        default_model="claude-opus-4-6",
        fallback_model="claude-sonnet-4-6",
        available_models={
            "claude-opus-4-6": ModelEntry(
                model_id="claude-opus-4-6",
                context_window=200000,
                max_output=32000,
                supports_tools=True,
                notes="Most capable, March 2026",
            ),
            "claude-sonnet-4-6": ModelEntry(
                model_id="claude-sonnet-4-6",
                context_window=200000,
                max_output=16000,
                supports_tools=True,
                notes="Fast + capable, March 2026",
            ),
            "claude-haiku-4-5": ModelEntry(
                model_id="claude-haiku-4-5-20251001",
                context_window=200000,
                max_output=8192,
                supports_tools=True,
                notes="Fastest, cost-effective",
            ),
        },
    ),
    "openai": ProviderConfig(
        default_model="gpt-5.4",
        fallback_model="gpt-5.2",
        available_models={
            "gpt-5.4": ModelEntry(
                model_id="gpt-5.4",
                context_window=256000,
                max_output=32000,
                supports_tools=True,
                notes="Latest flagship, March 2026",
            ),
            "gpt-5.2": ModelEntry(
                model_id="gpt-5.2",
                context_window=128000,
                max_output=16384,
                supports_tools=True,
                notes="Previous gen fallback",
            ),
            "gpt-4.1": ModelEntry(
                model_id="gpt-4.1",
                context_window=1047576,
                max_output=32768,
                supports_tools=True,
                notes="Budget option, huge context",
            ),
        },
    ),
    "gemini": ProviderConfig(
        default_model="gemini-3.1-pro-preview",
        fallback_model="gemini-3-flash-preview",
        available_models={
            "gemini-3.1-pro-preview": ModelEntry(
                model_id="gemini-3.1-pro-preview",
                context_window=1000000,
                max_output=65536,
                supports_tools=True,
                notes="Latest Gemini pro, March 2026",
            ),
            "gemini-3-flash-preview": ModelEntry(
                model_id="gemini-3-flash-preview",
                context_window=1000000,
                max_output=32768,
                supports_tools=True,
                notes="Fast + cheap",
            ),
        },
    ),
    "deepseek": ProviderConfig(
        default_model="deepseek-r1",
        fallback_model="deepseek-chat",
        available_models={
            "deepseek-r1": ModelEntry(
                model_id="deepseek-r1",
                context_window=128000,
                max_output=16384,
                supports_tools=True,
                notes="Reasoning model, March 2026",
            ),
            "deepseek-chat": ModelEntry(
                model_id="deepseek-chat",
                context_window=128000,
                max_output=8192,
                supports_tools=True,
                notes="General chat model",
            ),
        },
    ),
    "kimi": ProviderConfig(
        default_model="kimi-k2",
        fallback_model="moonshot-v1-128k",
        available_models={
            "kimi-k2": ModelEntry(
                model_id="kimi-k2",
                context_window=128000,
                max_output=8192,
                supports_tools=True,
                notes="Latest Moonshot model",
            ),
            "moonshot-v1-128k": ModelEntry(
                model_id="moonshot-v1-128k",
                context_window=128000,
                max_output=8192,
                notes="Legacy fallback",
            ),
        },
    ),
    "ollama": ProviderConfig(
        default_model="llama3.2",
        fallback_model="llama3.2",
        available_models={
            "llama3.2": ModelEntry(
                model_id="llama3.2",
                context_window=131072,
                max_output=4096,
                notes="Default local model",
            ),
            "qwen3-coder": ModelEntry(
                model_id="qwen3-coder",
                context_window=131072,
                max_output=16384,
                notes="Local coding model",
            ),
            "mistral:latest": ModelEntry(
                model_id="mistral:latest",
                context_window=32768,
                max_output=4096,
                notes="Mistral 7B local",
            ),
        },
    ),
}

# Aliases for convenience / backwards compat
MODEL_ALIASES: Dict[str, str] = {
    # Old wrong names → correct current IDs
    "claude-opus-4.6": "claude-opus-4-6",
    "claude-sonnet-4.5": "claude-sonnet-4-6",
    "claude-sonnet-4-20250514": "claude-sonnet-4-6",
    "gpt-5.3": "gpt-5.4",
    "gpt-5": "gpt-5.4",
    "gpt-4o": "gpt-5.4",
    "gemini-3-flash": "gemini-3-flash-preview",
    "gemini-3-high": "gemini-3.1-pro-preview",
    "gemini-3-pro": "gemini-3.1-pro-preview",
    "grok-1": "gpt-5.4",  # Grok removed, redirect to OpenAI
    "grok-3": "gpt-5.4",  # Grok removed, redirect to OpenAI
    "deepseek-coder": "deepseek-r1",
    "moonshot-v1-8k": "kimi-k2",
    "llama3:latest": "llama3.2",
    "llama3.2:3b": "llama3.2",
}

# Provider name aliases
PROVIDER_ALIASES: Dict[str, str] = {
    "claude": "anthropic",
    "gpt": "openai",
    "google": "gemini",
    "moonshot": "kimi",
    "grok": "openai",  # Grok removed — fall through to OpenAI
    "xai": "openai",
}


def resolve_provider(name: str) -> str:
    """Resolve a provider name to canonical form."""
    name = name.lower().strip()
    return PROVIDER_ALIASES.get(name, name)


def resolve_model(model_name: Optional[str] = None, provider: Optional[str] = None) -> str:
    """
    Resolve a model name to a valid API model ID.

    Priority:
      1. Direct match in a provider's available_models
      2. Alias lookup
      3. Provider default
      4. Return as-is (custom/unknown model)
    """
    # If no model specified, use provider default
    if not model_name and provider:
        canonical = resolve_provider(provider)
        cfg = PROVIDER_REGISTRY.get(canonical)
        if cfg:
            logger.debug(f"No model specified, using {canonical} default: {cfg.default_model}")
            return cfg.default_model
        return ""

    if not model_name:
        return ""

    model_name = model_name.strip()

    # Check aliases first
    if model_name in MODEL_ALIASES:
        resolved = MODEL_ALIASES[model_name]
        logger.debug(f"Model alias: {model_name} -> {resolved}")
        return resolved

    # Check if it's a direct match in any provider
    for prov_cfg in PROVIDER_REGISTRY.values():
        if model_name in prov_cfg.available_models:
            return model_name

    # Return as-is for custom models (e.g. ollama custom pulls)
    return model_name


def get_provider_models(provider: str) -> List[str]:
    """Get all available model IDs for a provider."""
    canonical = resolve_provider(provider)
    cfg = PROVIDER_REGISTRY.get(canonical)
    if not cfg:
        return []
    return list(cfg.available_models.keys())


def get_default_model(provider: str) -> str:
    """Get the default model for a provider."""
    canonical = resolve_provider(provider)
    cfg = PROVIDER_REGISTRY.get(canonical)
    if not cfg:
        return ""
    return cfg.default_model


def get_fallback_model(provider: str) -> str:
    """Get the fallback model for a provider."""
    canonical = resolve_provider(provider)
    cfg = PROVIDER_REGISTRY.get(canonical)
    if not cfg or not cfg.fallback_model:
        return ""
    return cfg.fallback_model


def get_all_display_models() -> List[str]:
    """Get a flat list of all model IDs for UI display (e.g. TUI selector)."""
    models = []
    for provider, cfg in PROVIDER_REGISTRY.items():
        if provider == "ollama":
            for mid in cfg.available_models:
                models.append(f"ollama-{mid}")
        else:
            models.extend(cfg.available_models.keys())
    return models
