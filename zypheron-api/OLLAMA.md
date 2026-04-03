# Ollama Provider

Ollama enables local LLM inference through the Zypheron AI proxy. It runs on your own hardware with no API key, no cost, and full privacy.

## Setup

### 1. Install Ollama

```bash
# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# macOS
brew install ollama
```

### 2. Start the server and pull models

```bash
ollama serve
ollama pull llama3
ollama pull codellama    # optional
ollama pull mistral      # optional
```

### 3. Configure Zypheron

The Ollama provider is enabled by default. Optionally customize in `.env`:

```bash
ENABLE_OLLAMA=true
OLLAMA_BASE_URL=http://localhost:11434
```

## Usage

```bash
curl -X POST http://localhost:8000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ollama",
    "model": "llama3",
    "messages": [{"role": "user", "content": "Hello"}],
    "temperature": 0.7,
    "stream": false
  }'
```

Streaming:

```bash
curl -X POST http://localhost:8000/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ollama",
    "model": "codellama",
    "messages": [{"role": "user", "content": "Write a sort function"}],
    "stream": true
  }'
```

## Common Models

| Model | Size | Best For |
|-------|------|----------|
| `llama3` | 8B | General purpose, chat |
| `codellama` | 7B-34B | Code generation |
| `mistral` | 7B | General purpose, efficient |
| `mixtral` | 8x7B | Complex reasoning |
| `phi` | 2.7B | Fast inference, low memory |
| `gemma` | 2B-7B | General purpose |

Any model installed on your Ollama server can be used. List installed models with `ollama list`.

## Integration Details

- **No API key required** (uses dummy key internally)
- **60-second timeout** (vs 30s for cloud providers)
- **Free token tracking** (counts recorded but no cost deducted)
- **Unlimited rate limits** (no per-provider rate limit for Ollama)
- **Caching supported** (identical prompts return cached results)

## Hardware Requirements

- **Minimum:** 8GB RAM (small models like Phi)
- **Recommended:** 16GB+ RAM (Llama3, Mistral)
- **GPU:** Optional but recommended (NVIDIA CUDA, Apple Metal)

Typical speeds: 5-15 tokens/sec (CPU), 20-50 tokens/sec (GPU).

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Ollama server not reachable" | Start with `ollama serve` |
| "Model not found" | Pull with `ollama pull <model>` |
| Out of memory | Use a smaller model (phi, gemma:2b) |
| Slow inference | Use GPU, or try quantized/smaller models |
| Connection issues (remote) | Check firewall, verify `OLLAMA_BASE_URL` |

## Key Files

- Provider: `app/services/ai_providers/ollama_client.py`
- Config: `app/core/config.py` (`enable_ollama`, `ollama_base_url`)
- Tests: `tests/test_ollama_provider.py`
- Examples: `examples/ollama_example.py`
