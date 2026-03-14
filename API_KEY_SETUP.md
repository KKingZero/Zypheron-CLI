# API Key Setup Guide

Complete guide for configuring AI provider API keys in Zypheron.

## Table of Contents

- [Quick Start](#quick-start)
- [Supported Providers](#supported-providers)
- [Configuration Methods](#configuration-methods)
- [Platform-Specific Setup](#platform-specific-setup)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Quick Start

**Recommended Method** (secure keyring storage):

```bash
# Configure your AI provider (e.g., Claude)
zypheron config set-key anthropic

# Verify configuration
zypheron config get-providers

# Test it works
zypheron ai chat "Hello"
```

Your API key is now stored securely in your system keyring (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux).

---

## Supported Providers

| Provider | API Key Format | Get Key From | Free Tier |
|----------|----------------|--------------|-----------|
| **Anthropic Claude** | `sk-ant-api03-...` (95+ chars) | [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys) | $5 credit |
| **OpenAI GPT** | `sk-...` (32+ chars) | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) | $5 credit (3 months) |
| **Google Gemini** | `AIza...` (39 chars) | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) | Free tier |
| **DeepSeek** | `sk-...` (32+ chars) | [platform.deepseek.com/api_keys](https://platform.deepseek.com/api_keys) | Limited free |
| **Kimi (Moonshot)** | Various (32+ chars) | [platform.moonshot.cn/console/api-keys](https://platform.moonshot.cn/console/api-keys) | Limited free |
| **Grok (xAI)** | `xai-...` (40+ chars) | [console.x.ai](https://console.x.ai/) | Beta access |
| **Ollama** | N/A (local) | [ollama.ai/download](https://ollama.ai/download) | Free (runs locally) |

### Recommendations

- **Best Overall**: Anthropic Claude (Sonnet 4) - Most capable
- **Most Affordable**: DeepSeek - Best price/quality ratio
- **Best for Code**: OpenAI GPT-4 or Claude
- **Best Free**: Google Gemini or Ollama (local)
- **Privacy First**: Ollama (runs locally, no cloud)

---

## Configuration Methods

Zypheron supports three methods (checked in order):

### 1. Keyring Storage (Recommended) ⭐

**Security**: ✅ Encrypted at OS level
**Convenience**: ✅ Set once, forget it
**Best for**: Production, personal use

```bash
# Set API key
zypheron config set-key anthropic
# Enter key when prompted (hidden input)

# List configured providers
zypheron config get-providers

# Remove a key
zypheron config delete-key anthropic
```

**How it works**:
- **macOS**: Stored in Keychain
- **Windows**: Stored in Credential Manager
- **Linux**: Stored in Secret Service (gnome-keyring, KWallet, etc.)

### 2. Environment Variables (.env file)

**Security**: ⚠️ Plain-text, requires file permissions
**Convenience**: ✅ Easy to edit
**Best for**: Development, CI/CD with restricted permissions

```bash
# Create/edit .env file
nano zypheron-ai/.env

# Add your keys
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
OPENAI_API_KEY=sk-your-key-here
DEFAULT_AI_PROVIDER=claude

# IMPORTANT: Secure the file
chmod 600 zypheron-ai/.env
```

**Security Note**: Zypheron will show a warning suggesting migration to keyring storage.

### 3. Direct Environment Variables

**Security**: ⚠️ Visible in shell history and process list
**Convenience**: ❌ Must set every session
**Best for**: Temporary testing only

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-your-key-here"
zypheron ai chat "Hello"
```

---

## Platform-Specific Setup

### macOS

✅ **Built-in support** - Keychain works out of the box.

No setup required!

### Windows

✅ **Built-in support** - Credential Manager works out of the box.

No setup required!

### Linux

Requires D-Bus and a keyring backend (pre-installed on most desktop distros).

#### Ubuntu/Debian

```bash
# Install keyring support
sudo apt update
sudo apt install gnome-keyring dbus-x11 libsecret-1-0

# Start keyring daemon
eval $(gnome-keyring-daemon --start)

# Add to ~/.bashrc for persistence
echo 'eval $(gnome-keyring-daemon --start)' >> ~/.bashrc
```

#### Fedora/RHEL/CentOS

```bash
sudo dnf install gnome-keyring dbus-x11 libsecret
```

#### Arch Linux

```bash
sudo pacman -S gnome-keyring libsecret
```

#### Headless/Server Linux

For systems without a desktop environment:

```bash
# Option 1: Use simple backend (less secure)
pip install keyrings.alt

# Option 2: Use .env file instead
nano zypheron-ai/.env
chmod 600 zypheron-ai/.env
```

### Docker/Containers

Keyring not recommended for containers. Use environment variables:

```dockerfile
# Pass as build arg
ENV ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

# Or use secrets
COPY --from=secrets /run/secrets/anthropic_key /etc/zypheron/api_key
```

---

## Troubleshooting

### "Keyring backend not available"

**Linux only**: Install gnome-keyring

```bash
sudo apt install gnome-keyring dbus-x11
eval $(gnome-keyring-daemon --start)
```

**Quick workaround**: Use .env file

```bash
nano zypheron-ai/.env
# Add: ANTHROPIC_API_KEY=sk-ant-...
chmod 600 zypheron-ai/.env
```

### "Invalid API key format"

**Common mistakes**:
- Including quotes: `"sk-ant-..."` ❌
- Truncated key: Didn't copy full key ❌
- Whitespace: Extra spaces before/after ❌
- Wrong prefix: Using old API key format ❌

**Fix**: Regenerate key from provider dashboard and re-enter carefully

```bash
zypheron config set-key anthropic
# Paste entire key exactly as shown
```

### "No AI providers configured"

**Solution**: Configure at least one provider

```bash
# Option 1: Cloud provider
zypheron config set-key anthropic

# Option 2: Local Ollama (no key needed)
ollama pull llama2
ollama serve
# Auto-detected by Zypheron
```

### "API authentication failed"

**Test manually**:

```bash
# Claude example
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-3-5-sonnet-20241022","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'
```

If this fails, regenerate your API key.

### Permission Denied on .env File

```bash
# Fix permissions
chmod 600 zypheron-ai/.env

# Fix ownership (if needed)
sudo chown $USER:$USER zypheron-ai/.env

# Verify
ls -la zypheron-ai/.env
# Should show: -rw------- 1 your_user your_group
```

---

## FAQ

### Which provider should I use?

**For general use**: Anthropic Claude (Sonnet 4)
- Most capable
- Good pricing
- Excellent for security tasks

**For cost-sensitive projects**: DeepSeek
- Very affordable (~$0.14/million tokens)
- Good quality
- High-volume friendly

**For free testing**: Google Gemini or Ollama
- Gemini has generous free tier
- Ollama is completely free (local)

**For privacy**: Ollama
- Runs entirely on your machine
- No data sent to cloud
- Requires good hardware (8GB+ RAM)

### Can I use multiple providers?

Yes! Configure as many as you want:

```bash
zypheron config set-key anthropic
zypheron config set-key openai
zypheron config set-key gemini

# Switch between them
zypheron ai chat --provider claude "task 1"
zypheron ai chat --provider openai "task 2"
```

### How do I rotate API keys?

```bash
# 1. Generate new key from provider dashboard
# 2. Update in Zypheron
zypheron config set-key anthropic
# Enter new key

# 3. Revoke old key in provider dashboard
```

### How do I check if my key is working?

```bash
# Method 1: Check provider status
zypheron ai config

# Method 2: Simple test
zypheron ai chat "Hello, are you working?"

# Method 3: Check usage in provider dashboard
# Anthropic: https://console.anthropic.com/settings/usage
```

### Is keyring storage secure?

**Yes**, keyring is more secure than .env files:

| Storage | Encrypted | Access Control | Commit Risk |
|---------|-----------|----------------|-------------|
| Keyring | ✅ Yes | ✅ OS-managed | ✅ Impossible |
| .env | ❌ No | ⚠️ File perms | ⚠️ Possible |
| Env var | ❌ No | ❌ Process-wide | ⚠️ Possible |

**Best practices**:
- Use keyring for personal/production
- Rotate keys regularly
- Monitor usage for anomalies
- Use separate keys per environment

### How do I use Ollama (no API key)?

```bash
# 1. Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# 2. Download a model
ollama pull llama2

# 3. Start Ollama
ollama serve

# 4. Use with Zypheron (auto-detected)
zypheron chat "Hello!"
```

### How do I remove all API keys?

```bash
# Remove from keyring
zypheron config delete-key anthropic
zypheron config delete-key openai
# ... repeat for all providers

# Remove from .env
nano zypheron-ai/.env
# Delete all API key lines

# Verify
zypheron config get-providers
# Should show: No providers configured
```

---

## Migration Guide

### From .env to Keyring

**Why?** Better security, no file management, can't accidentally commit to git.

```bash
# 1. Check current keys
cat zypheron-ai/.env

# 2. Migrate to keyring
zypheron config set-key anthropic
# Paste your existing key when prompted

# 3. Verify migration
zypheron config get-providers
# Should show: anthropic (keyring)

# 4. (Optional) Remove from .env for extra security
nano zypheron-ai/.env
# Comment out or delete the key line

# 5. Test
zypheron ai chat "test"
```

### From Environment Variables to Keyring

```bash
# If you had: export ANTHROPIC_API_KEY="sk-ant-..."

# 1. Run config command
zypheron config set-key anthropic
# Paste the same key

# 2. Remove from shell config
nano ~/.bashrc
# Delete line: export ANTHROPIC_API_KEY="..."
source ~/.bashrc
```

---

## API Key Validation

Zypheron validates all API keys before storing to prevent common errors.

### Validation Rules

**Anthropic**: `sk-ant-api03-*` (95+ chars)
**OpenAI**: `sk-*` (32+ chars)
**Google**: `AIza*` (39 chars)
**Grok**: `xai-*` (40+ chars)

### Common Validation Errors

```
❌ Invalid Anthropic API key: Keys should start with 'sk-ant-api03-'
   and be at least 95 characters long.

   Get your API key from: https://console.anthropic.com/settings/keys
```

**Solutions**:
- Copy entire key from provider dashboard
- Remove any quotes or whitespace
- Check key hasn't expired
- Regenerate if needed

---

## Security Best Practices

### ✅ DO

1. **Use keyring storage** for production
2. **Set file permissions** `chmod 600` on .env files
3. **Never commit** API keys to git
4. **Rotate keys** periodically
5. **Use separate keys** per environment/project

### ❌ DON'T

1. **Don't hardcode** keys in source code
2. **Don't share** keys via email/Slack
3. **Don't use** same key across projects
4. **Don't commit** .env files (already in .gitignore)
5. **Don't leave** default permissions on .env

---

## Quick Reference

```bash
# Setup
zypheron config set-key anthropic          # Configure provider (secure)
chmod 600 zypheron-ai/.env                 # Secure .env file (if using)

# Usage
zypheron ai chat "your question"           # Use default provider
zypheron ai chat --provider openai "..."   # Specific provider

# Management
zypheron config get-providers              # List providers
zypheron config delete-key <provider>      # Remove provider
zypheron ai config                         # Show detailed config

# Testing
zypheron ai chat "test"                    # Quick test
curl https://api.anthropic.com/v1/...      # Manual test
```

---

## Getting Help

**Quick troubleshooting**: [HELP.md](HELP.md)
**Full setup guide**: [docs/SETUP.md](docs/SETUP.md)
**Security policy**: [SECURITY.md](SECURITY.md)
**Issues**: [GitHub Issues](https://github.com/KKingZero/Cobra-AI/issues)

**Provider Documentation**:
- [Anthropic API Docs](https://docs.anthropic.com/)
- [OpenAI API Docs](https://platform.openai.com/docs/)
- [Google Gemini Docs](https://ai.google.dev/docs)

---

**Last Updated**: November 2024
**Zypheron Version**: 1.0+
