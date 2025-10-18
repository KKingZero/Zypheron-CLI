# Local Models Setup Guide for COBRA AI

This guide explains how to set up and use local AI models with COBRA AI, supporting multiple providers.

## Overview

COBRA AI now supports running AI models locally on your machine, giving you:
- **Privacy**: All conversations stay on your device
- **No API costs**: Run models without cloud API fees
- **Offline capability**: Works without internet connection
- **Model flexibility**: Choose from various open-source models

## Supported Local Model Providers

COBRA AI supports the following local model providers with automatic endpoint configuration:

1. **LM Studio** (Recommended) - User-friendly GUI with model management
   - Default endpoint: `http://localhost:1234/v1`
2. **Ollama** - Command-line based, lightweight
   - Default endpoint: `http://localhost:11434/api`
3. **vLLM** - High-performance inference server
   - Default endpoint: `http://localhost:8000/v1`
4. **GPT4All** - Privacy-focused desktop application
   - Default endpoint: `http://localhost:4891/v1`

## Quick Start with LM Studio

### Step 1: Install LM Studio

1. Download LM Studio from [https://lmstudio.ai/](https://lmstudio.ai/)
2. Install for your operating system (Windows, macOS, or Linux)
3. Launch LM Studio

### Step 2: Download DeepSeek R1 Distill Qwen 7B

1. In LM Studio, click on the **"Discover"** tab
2. Search for: `deepseek-r1-distill-qwen-7b`
3. Select the appropriate quantization (recommended: Q4_K_M for balanced performance/quality)
4. Click **"Download"** and wait for the model to download

### Step 3: Load the Model

1. Go to the **"Local Server"** tab in LM Studio
2. Select the downloaded DeepSeek model from the dropdown
3. Click **"Load Model"** (this may take a few moments)
4. Once loaded, click **"Start Server"**
5. The server should start at `http://localhost:1234/v1`

### Step 4: Configure COBRA AI

1. In COBRA AI, look for the model provider toggle above the model selector
2. Click on **"Local"** to switch to local models
3. Click **"Settings"** to expand the local provider options
4. Select **"LM Studio"** from the provider dropdown (should be selected by default)
5. The endpoint will automatically update to `http://localhost:1234/v1`
6. Select **"DeepSeek R1 Distill Qwen 7B"** from the model dropdown
7. Start chatting!

## Switching Between Providers

COBRA AI makes it easy to switch between different local providers:

1. Click the **"Settings"** button when in local mode
2. Select your provider from the dropdown:
   - **LM Studio**: Best for beginners, GUI interface
   - **Ollama**: Best for command-line users
   - **vLLM**: Best for production deployments
   - **GPT4All**: Best for privacy-focused users
3. The endpoint will automatically update to the provider's default
4. You can customize the endpoint if using a non-standard port

## Model Recommendations

### DeepSeek R1 Distill Qwen 7B
- **Size**: 7B parameters
- **Use case**: Best for code generation and technical tasks
- **Performance**: Fast responses, good accuracy
- **RAM Required**: 8-16GB

### Qwen 2.5
- **Size**: Various sizes (7B, 14B, 32B)
- **Use case**: General purpose, multilingual support
- **Performance**: Excellent reasoning capabilities
- **RAM Required**: 8-32GB depending on size

### GPT-J
- **Size**: 6B parameters
- **Use case**: General conversation and creative tasks
- **Performance**: Good balance of speed and quality
- **RAM Required**: 8-12GB

### DeepSeek R1
- **Size**: Various sizes
- **Use case**: Advanced reasoning and coding
- **Performance**: State-of-the-art capabilities
- **RAM Required**: 16-64GB depending on size

## Provider-Specific Setup

### Ollama Setup

1. Install Ollama:
   ```bash
   # macOS/Linux
   curl -fsSL https://ollama.ai/install.sh | sh
   
   # Windows
   # Download from https://ollama.ai/download
   ```

2. Pull a model:
   ```bash
   ollama pull deepseek-r1:7b
   # or
   ollama pull qwen2.5:7b
   ```

3. The Ollama server starts automatically
4. In COBRA AI, select "Ollama" from the provider dropdown

### vLLM Setup

1. Install vLLM:
   ```bash
   pip install vllm
   ```

2. Start the server:
   ```bash
   python -m vllm.entrypoints.openai.api_server \
     --model TheBloke/deepseek-coder-7B-instruct-v1.5-GGUF \
     --port 8000
   ```

3. In COBRA AI, select "vLLM" from the provider dropdown

### GPT4All Setup

1. Download GPT4All from [https://gpt4all.io/](https://gpt4all.io/)
2. Install and launch the application
3. Download your preferred model within the app
4. Enable the API server in settings
5. In COBRA AI, select "GPT4All" from the provider dropdown

## Troubleshooting

### Connection Issues

1. **Check if server is running**: 
   - LM Studio: Look for "Server started" message
   - Ollama: Run `ollama list` to check status
   - vLLM: Check terminal for server logs
   - GPT4All: Check API server status in settings

2. **Verify endpoint**: The endpoint should match your provider's configuration
3. **Custom ports**: If using non-default ports, update the endpoint URL manually
4. **Firewall**: Ensure localhost connections aren't blocked

### Provider-Specific Issues

**LM Studio**:
- Ensure model is fully loaded before starting server
- Check GPU settings if performance is slow

**Ollama**:
- Make sure the model is fully downloaded: `ollama list`
- Check if service is running: `systemctl status ollama` (Linux)

**vLLM**:
- Verify CUDA installation for GPU support
- Check model path is correct

**GPT4All**:
- Enable API server in application settings
- Check model compatibility

## Performance Tips

1. **Use quantized models**: Q4_K_M or Q5_K_M offer good balance
2. **GPU acceleration**: Enable in your provider's settings
3. **Context length**: Reduce for faster responses
4. **Model size**: Choose based on available RAM/VRAM

## Security Considerations

- Local models process all data on your device
- No data is sent to external servers
- Models and conversations remain private
- Ensure downloaded models are from trusted sources

## Advanced Configuration

### Custom Endpoints

Each provider can use custom endpoints:
1. Select your provider in COBRA AI
2. Modify the endpoint URL as needed
3. Common customizations:
   - Different ports
   - Network addresses for remote servers
   - Docker container endpoints

### Running Multiple Providers

You can run multiple providers simultaneously:
1. Use different ports for each provider
2. Switch between them in COBRA AI as needed
3. Example setup:
   - LM Studio: `localhost:1234`
   - Ollama: `localhost:11434`
   - vLLM: `localhost:8000`

## System Requirements

### Minimum Requirements
- **RAM**: 8GB (16GB recommended)
- **Storage**: 10-50GB free space
- **CPU**: Modern multi-core processor
- **GPU**: Optional but recommended

### Recommended Specifications
- **RAM**: 32GB or more
- **Storage**: 100GB+ SSD
- **GPU**: NVIDIA RTX 3060 or better
- **CPU**: Recent Intel i7/AMD Ryzen 7

## Getting Help

If you encounter issues:
1. Check the provider's logs/console output
2. Verify model is fully downloaded and loaded
3. Ensure sufficient system resources
4. Try a smaller quantized version
5. Check COBRA AI console for errors

For more advanced setups and configurations, refer to your chosen provider's documentation. 