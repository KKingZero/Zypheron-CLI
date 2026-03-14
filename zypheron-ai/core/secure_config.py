"""
Secure API Key Storage using OS keyring
"""

import keyring
from typing import Optional
from loguru import logger


# Service name for keyring storage
SERVICE_NAME = "zypheron-ai"

# Known AI providers
PROVIDERS = [
    "anthropic",
    "openai",
    "google",
    "kimi",
    "deepseek",
    "grok",
    "nvd",  # NVD API key
]


def store_api_key(provider: str, api_key: str) -> bool:
    """
    Store an API key securely in the system keyring
    
    Args:
        provider: Provider name (e.g., 'anthropic', 'openai')
        api_key: The API key to store
        
    Returns:
        True if successful, False otherwise
    """
    try:
        keyring.set_password(SERVICE_NAME, provider, api_key)
        logger.info(f"Stored API key for provider: {provider}")
        return True
    except Exception as e:
        logger.error(f"Failed to store API key for {provider}: {e}")
        return False


def get_api_key(provider: str) -> Optional[str]:
    """
    Retrieve an API key from the system keyring
    
    Args:
        provider: Provider name (e.g., 'anthropic', 'openai')
        
    Returns:
        The API key if found, None otherwise
    """
    try:
        api_key = keyring.get_password(SERVICE_NAME, provider)
        if api_key:
            logger.debug(f"Retrieved API key for provider: {provider}")
        return api_key
    except Exception as e:
        logger.error(f"Failed to retrieve API key for {provider}: {e}")
        return None


def delete_api_key(provider: str) -> bool:
    """
    Delete an API key from the system keyring
    
    Args:
        provider: Provider name
        
    Returns:
        True if successful, False otherwise
    """
    try:
        keyring.delete_password(SERVICE_NAME, provider)
        logger.info(f"Deleted API key for provider: {provider}")
        return True
    except keyring.errors.PasswordDeleteError:
        logger.warning(f"No API key found for provider: {provider}")
        return False
    except Exception as e:
        logger.error(f"Failed to delete API key for {provider}: {e}")
        return False


def list_configured_providers() -> list:
    """
    List all providers that have API keys configured
    
    Returns:
        List of provider names
    """
    configured = []
    for provider in PROVIDERS:
        if get_api_key(provider):
            configured.append(provider)
    return configured


def migrate_from_env(env_vars: dict) -> int:
    """
    Migrate API keys from environment variables to keyring
    
    Args:
        env_vars: Dictionary of environment variables
        
    Returns:
        Number of keys migrated
    """
    migration_map = {
        "ANTHROPIC_API_KEY": "anthropic",
        "OPENAI_API_KEY": "openai",
        "GOOGLE_API_KEY": "google",
        "KIMI_API_KEY": "kimi",
        "DEEPSEEK_API_KEY": "deepseek",
        "GROK_API_KEY": "grok",
        "NVD_API_KEY": "nvd",
    }
    
    migrated = 0
    for env_var, provider in migration_map.items():
        if env_var in env_vars and env_vars[env_var]:
            api_key = env_vars[env_var]
            # Only migrate if not already in keyring
            if not get_api_key(provider):
                if store_api_key(provider, api_key):
                    migrated += 1
                    logger.info(f"Migrated {env_var} to keyring")
    
    if migrated > 0:
        logger.warning(
            f"Migrated {migrated} API keys to keyring. "
            "Consider removing them from .env file for security."
        )
    
    return migrated


def check_keyring_available() -> bool:
    """
    Check if keyring backend is available
    
    Returns:
        True if keyring is available, False otherwise
    """
    try:
        # Try to get the current backend
        backend = keyring.get_keyring()
        logger.debug(f"Keyring backend: {backend}")
        return True
    except Exception as e:
        logger.error(f"Keyring not available: {e}")
        return False

