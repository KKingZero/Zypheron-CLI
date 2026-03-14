# Zypheron AI Configuration Guide

## ✅ Status: **AI Engine is Working!**

All 7 AI providers are successfully integrated and ready to use.

---

## 🚀 Quick Start

### 1. Install the Binary

```bash
cd /home/zero/Downloads/Cobra-AI-Zypheron-CLI/zypheron-go
sudo cp zypheron /usr/local/bin/  # Or add to your PATH
```

### 2. Start the AI Engine

```bash
zypheron ai start
```

### 3. Check Status

```bash
zypheron ai status
zypheron ai providers
```

---

## 🏠 Setting Up Ollama (Local AI) - **Recommended for Privacy**

Ollama lets you run AI models locally without sending data to cloud providers.

### Step 1: Install Ollama

```bash
# Linux/Mac
curl -fsSL https://ollama.com/install.sh | sh

# Or download from: https://ollama.com/download
```

### Step 2: Pull a Model

```bash
# Choose one or more models:
ollama pull llama2          # General purpose (3.8GB)
ollama pull mistral         # Fast and capable (4.1GB) - Recommended!
ollama pull codellama       # Code-focused (3.8GB)
ollama pull llama3.2        # Latest Llama (if available)
ollama pull phi             # Small and fast (1.3GB) - Great for quick testing
```

### Step 3: Test Ollama

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Test with a simple prompt
ollama run mistral "What is SQL injection?"
```

### Step 4: Configure Zypheron for Ollama

Edit `/home/zero/Downloads/Cobra-AI-Zypheron-CLI/zypheron-ai/.env`:

```bash
# Set Ollama as default provider
DEFAULT_AI_PROVIDER=ollama

# Configure Ollama settings
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mistral    # or llama2, codellama, phi, etc.
```

### Step 5: Restart AI Engine

```bash
zypheron ai stop
zypheron ai start
```

### Step 6: Test with Zypheron

```bash
# Chat with local AI
zypheron chat --provider ollama "Explain XSS attacks"

# Interactive chat
zypheron chat --provider ollama --interactive

# Use in scans
zypheron scan target.com --ai-analysis --provider ollama
```

---

## 🌐 Setting Up Cloud AI Providers

If you want to use cloud AI providers (faster but requires API keys):

### Method 1: Secure Keyring Storage (Recommended)

```bash
# Store API keys securely in system keyring
zypheron config set-key anthropic     # For Claude
zypheron config set-key openai        # For GPT-4
zypheron config set-key google        # For Gemini
```

You'll be prompted to enter each API key securely (no echo).

### Method 2: Environment File

Edit `/home/zero/Downloads/Cobra-AI-Zypheron-CLI/zypheron-ai/.env`:

```bash
# Get API keys from:
# - Anthropic: https://console.anthropic.com/
# - OpenAI: https://platform.openai.com/api-keys
# - Google: https://makersuite.google.com/app/apikey

ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here
GOOGLE_API_KEY=your-key-here
DEEPSEEK_API_KEY=your-key-here      # Optional
GROK_API_KEY=your-key-here           # Optional
KIMI_API_KEY=your-key-here           # Optional

# Set your preferred default provider
DEFAULT_AI_PROVIDER=claude    # or openai, gemini, ollama, etc.
```

---

## 🎯 Usage Examples

### Basic Commands

```bash
# Start/stop AI engine
zypheron ai start
zypheron ai stop
zypheron ai status

# List providers
zypheron ai providers

# Test AI engine
zypheron ai test --provider ollama
```

### Chat with AI

```bash
# Single question
zypheron chat "How do I test for SQL injection?"

# Use specific provider
zypheron chat --provider ollama "Explain CSRF attacks"
zypheron chat --provider claude "What is XXE vulnerability?"

# Interactive mode
zypheron chat --interactive --provider ollama
```

### AI-Powered Scanning

```bash
# Scan with AI analysis
zypheron scan target.com --ai-analysis

# Scan with specific AI provider
zypheron scan 192.168.1.100 --ai-analysis --provider ollama

# ML-guided scanning
zypheron scan target.com --ai-guided --ai-analysis
```

### Switch Between Providers

```bash
# Use Ollama (local, private)
zypheron chat --provider ollama "your question"

# Use Claude (powerful reasoning)
zypheron chat --provider claude "complex security question"

# Use OpenAI (general purpose)
zypheron chat --provider openai "your question"
```

---

## 🔧 Configuration Files

### Main Config: `~/.config/zypheron/config.yaml`

```yaml
api:
  url: http://localhost:3001
  timeout: 30000

scanning:
  default_ports: "1-1000"
  timeout: 300

output:
  format: text
  colorize: true
```

### AI Config: `/home/zero/Downloads/Cobra-AI-Zypheron-CLI/zypheron-ai/.env`

```bash
# AI Provider Settings
DEFAULT_AI_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mistral

# Cloud AI API Keys (optional)
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
GOOGLE_API_KEY=your_key_here

# AI Performance
AI_MAX_TOKENS=4096
AI_TEMPERATURE=0.7
AI_STREAMING=true
```

---

## 📊 Available AI Providers

| Provider | Type | Speed | Cost | Best For |
|----------|------|-------|------|----------|
| **Ollama** | Local | Medium | FREE ✅ | Privacy, offline use, no API limits |
| Claude | Cloud | Fast | Paid | Security reasoning, complex analysis |
| GPT-4 | Cloud | Fast | Paid | General knowledge, coding help |
| Gemini | Cloud | Very Fast | Paid | Fast responses, efficiency |
| DeepSeek | Cloud | Fast | Low Cost | Cost-effective alternative |
| Grok | Cloud | Fast | Paid | Real-time web access |
| Kimi | Cloud | Fast | Paid | Long context (up to 128K tokens) |

**Recommended Setup:**
- **Ollama (mistral)** as default for everyday use (free, private)
- **Claude** for complex security analysis (paid, powerful)

---

## 🔒 Security & Privacy

### Ollama Advantages

✅ **100% Private** - Data never leaves your machine  
✅ **No API Costs** - Free to use  
✅ **Works Offline** - No internet required  
✅ **No Rate Limits** - Use as much as you want  
✅ **Data Control** - Full control over your data  

### API Key Security

- **Keyring Storage**: Keys stored in OS keychain (most secure)
- **Environment Files**: `.env` files (ignored by git)
- **Never commit** API keys to version control

---

## 🐛 Troubleshooting

### AI Engine Won't Start

```bash
# Check Python dependencies
cd /home/zero/Downloads/Cobra-AI-Zypheron-CLI/zypheron-ai
source venv/bin/activate
pip install -r requirements.txt

# Check for errors
zypheron ai start --debug
```

### Ollama Not Working

```bash
# Check if Ollama is running
systemctl status ollama   # If installed as service
ps aux | grep ollama

# Restart Ollama
systemctl restart ollama  # If installed as service

# Or run manually
ollama serve
```

### "Provider not configured" Error

Make sure you have either:
1. Ollama installed and running (for local AI)
2. API keys configured (for cloud AI)

```bash
# For Ollama
ollama pull mistral

# For cloud AI
zypheron config set-key anthropic
```

---

## 📚 Next Steps

1. **Install Ollama** for free local AI (recommended)
2. **Pull a model**: `ollama pull mistral`
3. **Test it**: `zypheron chat --provider ollama "test"`
4. **Start scanning**: `zypheron scan target.com --ai-analysis`

For more examples, see:
- `/home/zero/Downloads/Cobra-AI-Zypheron-CLI/AI_HYBRID_README.md`
- `/home/zero/Downloads/Cobra-AI-Zypheron-CLI/ZYPHERON_CLI_GUIDE.md`

---

## 🎉 You're All Set!

The AI engine is fully functional and ready to use. Start with Ollama for free, private AI assistance in your penetration testing workflow!

```bash
# Quick test
zypheron ai status
zypheron chat --provider ollama "Hello!"
```

