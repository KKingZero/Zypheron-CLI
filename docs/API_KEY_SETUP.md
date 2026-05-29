# API Key Setup Guide

## Quick Start

```bash
# Configure provider (secure keyring storage)
zypheron config set-key anthropic

# Verify
zypheron config get-providers

# Test
zypheron ai chat "Hello"
```

## Supported Providers

| Provider | Key Format | Get Key | Free Tier |
|----------|-----------|---------|-----------|
| **Anthropic Claude** | `sk-ant-api03-...` (95+ chars) | [console.anthropic.com](https://console.anthropic.com/settings/keys) | $5 credit |
| **OpenAI GPT** | `sk-...` (32+ chars) | [platform.openai.com](https://platform.openai.com/api-keys) | $5 credit |
| **Google Gemini** | `AIza...` (39 chars) | [aistudio.google.com](https://aistudio.google.com/app/apikey) | Free tier |
| **DeepSeek** | `sk-...` (32+ chars) | [platform.deepseek.com](https://platform.deepseek.com/api_keys) | Limited free |
| **Kimi (Moonshot)** | Various (32+ chars) | [platform.moonshot.cn](https://platform.moonshot.cn/console/api-keys) | Limited free |
| **Grok (xAI)** | `xai-...` (40+ chars) | [console.x.ai](https://console.x.ai/) | Beta access |
| **Ollama** | N/A (local) | [ollama.ai](https://ollama.ai/download) | Free |

**Recommendations**: Claude for best overall, Gemini or Ollama for free testing, Ollama for privacy.

## Configuration Methods

### 1. Keyring Storage (Recommended)

Encrypted at OS level. Works out of the box on macOS (Keychain) and Windows (Credential Manager).

```bash
zypheron config set-key anthropic    # Set key (hidden input)
zypheron config get-providers        # List configured
zypheron config delete-key anthropic # Remove key
```

**Linux** requires a keyring backend:
```bash
# Ubuntu/Debian
sudo apt install gnome-keyring dbus-x11 libsecret-1-0
eval $(gnome-keyring-daemon --start)

# Fedora
sudo dnf install gnome-keyring dbus-x11 libsecret

# Arch
sudo pacman -S gnome-keyring libsecret

# Headless/server: use .env file instead, or `pip install keyrings.alt`
```

### 2. Environment File (.env)

```bash
nano zypheron-ai/.env
# Add: ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
chmod 600 zypheron-ai/.env
```

### 3. Environment Variables (temporary)

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-your-key-here"
```

## Ollama (No API Key)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2:3b
ollama serve
# Auto-detected by Zypheron
```

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "Keyring backend not available" | Install gnome-keyring (Linux) or use .env file |
| "Invalid API key format" | Regenerate key, paste without quotes or whitespace |
| "No AI providers configured" | Run `zypheron config set-key <provider>` |
| "API authentication failed" | Test key directly with `curl`, regenerate if expired |
| Permission denied on .env | `chmod 600 zypheron-ai/.env` |

## Multiple Providers

```bash
zypheron config set-key anthropic
zypheron config set-key openai
zypheron ai chat --provider claude "task 1"
zypheron ai chat --provider openai "task 2"
```

## Key Rotation

1. Generate new key from provider dashboard
2. `zypheron config set-key <provider>` with new key
3. Revoke old key in provider dashboard

## Migrating from .env to Keyring

```bash
zypheron config set-key anthropic   # Paste existing key
zypheron config get-providers       # Verify: should show (keyring)
# Remove key line from zypheron-ai/.env
```

---

See also: [HELP.md](HELP.md) | [SECURITY.md](../SECURITY.md) | [AI_GUIDE.md](AI_GUIDE.md)
