# Ollama Provider for Zypheron AI Proxy

The Ollama provider enables you to run local Large Language Models (LLMs) through the Zypheron AI proxy, providing a free, private alternative to cloud-based AI services.

## Overview

Ollama is a local LLM server that allows you to run models like Llama3, CodeLlama, Mistral, and many others on your own hardware. Unlike cloud providers, Ollama:

- **Runs completely locally** - No data leaves your machine
- **Requires no API key** - Free to use with no token costs
- **Provides privacy** - Your prompts and responses stay private
- **Works offline** - No internet connection required after model download

## Installation & Setup

### 1. Install Ollama

Download and install Ollama from [https://ollama.ai/download](https://ollama.ai/download)

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

**Windows:**
Download from the official website.

### 2. Start Ollama Server

```bash
ollama serve
```

The server will start on `http://localhost:11434` by default.

### 3. Pull Models

Download the models you want to use:

```bash
# Llama 3 (8B parameters)
ollama pull llama3

# Code-specialized model
ollama pull codellama

# Mistral (7B parameters)
ollama pull mistral

# Mixtral (8x7B parameters)
ollama pull mixtral

# Phi (small, efficient model)
ollama pull phi

# Google's Gemma
ollama pull gemma
```

### 4. Configure Zypheron

The Ollama provider is enabled by default. You can customize the configuration via environment variables:

```bash
# Enable/disable Ollama provider
ENABLE_OLLAMA=true

# Custom Ollama server URL (if not using default)
OLLAMA_BASE_URL=http://localhost:11434
```

## Usage

### Via API

**Chat Completion:**

```bash
curl -X POST http://localhost:8000/api/v1/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ollama",
    "model": "llama3",
    "messages": [
      {"role": "user", "content": "Explain quantum computing in simple terms"}
    ],
    "temperature": 0.7
  }'
```

**Streaming:**

```bash
curl -X POST http://localhost:8000/api/v1/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ollama",
    "model": "codellama",
    "messages": [
      {"role": "user", "content": "Write a Python function to sort a list"}
    ],
    "stream": true
  }'
```

### Via Python SDK

```python
from zypheron import ZypheronClient

client = ZypheronClient(api_key="your-api-key")

# Non-streaming
response = client.chat.completions.create(
    provider="ollama",
    model="llama3",
    messages=[
        {"role": "user", "content": "What is machine learning?"}
    ]
)

print(response.content)

# Streaming
for chunk in client.chat.completions.create(
    provider="ollama",
    model="mistral",
    messages=[
        {"role": "user", "content": "Write a poem about coding"}
    ],
    stream=True
):
    print(chunk.content, end="", flush=True)
```

## Supported Models

Common models available through Ollama:

| Model | Size | Description | Best For |
|-------|------|-------------|----------|
| `llama3` | 8B | Meta's Llama 3 | General purpose, chat |
| `codellama` | 7B/13B/34B | Code-specialized Llama | Code generation, explanation |
| `mistral` | 7B | Mistral AI's model | General purpose, efficient |
| `mixtral` | 8x7B | Mixture of Experts | Complex reasoning |
| `phi` | 2.7B | Microsoft's efficient model | Fast inference, low memory |
| `gemma` | 2B/7B | Google's open model | General purpose |
| `neural-chat` | 7B | Intel's chat model | Conversational AI |
| `starling-lm` | 7B | Berkeley's model | Instruction following |

Full list: [https://ollama.ai/library](https://ollama.ai/library)

## Health Checking

The Ollama provider includes built-in health checking to verify the server is running:

```bash
# Check provider availability
curl http://localhost:8000/api/v1/ai/providers
```

If Ollama is not running, the API will return an appropriate error message with instructions to start the server.

## Performance Considerations

### Hardware Requirements

- **Minimum RAM:** 8GB (for small models like Phi)
- **Recommended RAM:** 16GB+ (for models like Llama3)
- **GPU:** Optional but highly recommended for faster inference
  - NVIDIA GPU with CUDA support
  - Apple Silicon (M1/M2/M3) with Metal acceleration

### Inference Speed

Local inference is generally slower than cloud APIs but provides:
- No network latency
- Unlimited requests (no rate limits)
- No per-token costs

Typical generation speeds on consumer hardware:
- **CPU only:** 5-15 tokens/second
- **GPU (NVIDIA RTX 3090):** 30-50 tokens/second
- **Apple M2 Max:** 20-35 tokens/second

### Timeouts

The Ollama provider uses a default timeout of 60 seconds (vs 30s for cloud providers) to accommodate slower local inference.

## Error Handling

### Common Errors

**1. Ollama Not Running**

```json
{
  "error": "Ollama server not reachable at http://localhost:11434. Please ensure Ollama is installed and running. Install: https://ollama.ai/download or start with: ollama serve"
}
```

**Solution:** Start the Ollama server with `ollama serve`

**2. Model Not Found**

```json
{
  "error": "Model 'llama3' not found. Pull it with: ollama pull llama3"
}
```

**Solution:** Download the model with `ollama pull llama3`

**3. Out of Memory**

```json
{
  "error": "Failed to load model: out of memory"
}
```

**Solution:**
- Try a smaller model (e.g., `phi` instead of `mixtral`)
- Close other applications
- Add more RAM or use GPU

## Advanced Configuration

### Custom Ollama Server URL

If running Ollama on a different port or remote server:

```bash
# Environment variable
export OLLAMA_BASE_URL=http://192.168.1.100:11434

# Or in .env file
OLLAMA_BASE_URL=http://192.168.1.100:11434
```

### Model Parameters

The Ollama provider supports standard parameters:

```json
{
  "provider": "ollama",
  "model": "llama3",
  "messages": [...],
  "temperature": 0.7,      // Randomness (0.0-1.0)
  "max_tokens": 2048,      // Maximum tokens to generate
  "stream": true           // Enable streaming
}
```

### Checking Available Models

List models installed on your Ollama server:

```bash
ollama list
```

Or via the Ollama API:

```bash
curl http://localhost:11434/api/tags
```

## Cost Comparison

**Ollama (Local):**
- Setup cost: $0 (free software)
- Runtime cost: $0 (no API fees)
- Hardware cost: Your existing computer
- Hidden cost: Electricity (~$0.10-0.50/hour on GPU)

**Cloud Providers (for comparison):**
- OpenAI GPT-4: ~$0.03 per 1K tokens
- Anthropic Claude: ~$0.025 per 1K tokens
- Typical monthly cost: $20-200+ depending on usage

**Recommendation:** Use Ollama for:
- Development and testing
- Privacy-sensitive workloads
- High-volume requests
- Offline environments

Use cloud providers for:
- Production workloads requiring highest quality
- Scaling beyond local hardware
- Accessing cutting-edge models (GPT-4, Claude Opus)

## Security & Privacy

**Advantages:**
- All data stays local - no prompts sent to cloud
- No API key required - no risk of key leakage
- Full control over model and data
- Compliance-friendly for sensitive data

**Considerations:**
- Models are downloaded from Ollama's servers
- Model weights are public (not private training)
- Still need to secure your local server

## Troubleshooting

### Slow Performance

1. **Use GPU acceleration:**
   ```bash
   # Check if GPU is being used
   ollama run llama3 --verbose
   ```

2. **Reduce model size:**
   - Use quantized models (e.g., `llama3:7b` instead of `llama3:70b`)
   - Try smaller models (e.g., `phi`, `gemma:2b`)

3. **Increase timeout:**
   ```python
   # In your client code
   client = OllamaProvider(timeout=120)  # 2 minutes
   ```

### Model Quality Issues

1. **Try different models** - Each model has different strengths
2. **Adjust temperature** - Lower (0.3-0.5) for factual, higher (0.7-0.9) for creative
3. **Use specialized models** - `codellama` for code, `mistral` for reasoning

### Connection Issues

1. **Verify Ollama is running:**
   ```bash
   curl http://localhost:11434/api/tags
   ```

2. **Check firewall settings** if using remote Ollama server

3. **Verify base URL configuration** in Zypheron settings

## Integration with Zypheron Features

### Token Tracking

Ollama requests are tracked but marked as **free** (no cost):
- Token counts are still recorded for metrics
- No deduction from user's token balance
- Usage statistics available in dashboard

### Rate Limiting

Ollama requests are subject to the same rate limits as cloud providers:
- Free tier: 10 requests/minute
- Paid tiers: Higher limits

### Caching

Ollama responses can be cached like cloud providers:
- Identical prompts return cached results
- Reduces local compute usage
- Faster response times for repeated queries

## Example Use Cases

### 1. Development & Testing
```python
# Test your prompts locally before using cloud APIs
response = client.chat.completions.create(
    provider="ollama",
    model="llama3",
    messages=[{"role": "user", "content": "Test prompt"}]
)
```

### 2. Privacy-Sensitive Data
```python
# Analyze sensitive documents locally
response = client.chat.completions.create(
    provider="ollama",
    model="mistral",
    messages=[{
        "role": "user",
        "content": f"Summarize this confidential report: {report}"
    }]
)
```

### 3. High-Volume Processing
```python
# Process thousands of items without API costs
for item in large_dataset:
    response = client.chat.completions.create(
        provider="ollama",
        model="phi",  # Fast, efficient model
        messages=[{"role": "user", "content": f"Process: {item}"}]
    )
```

### 4. Offline Environments
```python
# Works without internet connection (after model download)
response = client.chat.completions.create(
    provider="ollama",
    model="codellama",
    messages=[{"role": "user", "content": "Generate code"}]
)
```

## Further Resources

- **Ollama Documentation:** [https://github.com/ollama/ollama](https://github.com/ollama/ollama)
- **Model Library:** [https://ollama.ai/library](https://ollama.ai/library)
- **Community Discord:** [https://discord.gg/ollama](https://discord.gg/ollama)
- **Zypheron Docs:** [https://docs.zypheron.com](https://docs.zypheron.com)

## Support

If you encounter issues with the Ollama provider:

1. Check Ollama server is running: `ollama list`
2. Verify model is downloaded: `ollama pull <model>`
3. Check Zypheron logs for detailed error messages
4. Contact support: support@zypheron.com
