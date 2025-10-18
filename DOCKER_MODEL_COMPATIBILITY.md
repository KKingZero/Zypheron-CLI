# LM Studio & Docker Provider Integration Guide

## Overview

COBRA AI has been streamlined to focus on the two most effective local AI hosting solutions: **LM Studio** and **Docker**. This simplified approach provides better user experience with automatic model detection and clear platform compatibility.

## ✨ New Features Implemented

### 1. Simplified Provider Options

COBRA AI now supports only two local providers for optimal user experience:
- **LM Studio** - 🎯 **Primary Choice** - GUI-based with automatic model detection
- **Docker** - 🐳 **Containerized** - For production deployments and specialized models

**Removed**: Ollama, vLLM, GPT4All (simplified for better UX)

### 2. Automatic LM Studio Model Detection

🚀 **Major Enhancement**: COBRA AI now automatically detects models available in LM Studio!

#### Features:
- **Real-time Detection**: Automatically discovers models when LM Studio is running
- **Model Information**: Shows model size, quantization, and other metadata
- **Refresh Button**: Manual refresh option with loading indicator
- **Smart Fallback**: Shows compatible models when LM Studio isn't running
- **Status Indicators**: Clear feedback about model availability

#### How It Works:
```typescript
// Fetches models from LM Studio's OpenAI-compatible API
const models = await fetch('http://localhost:1234/v1/models')
// Automatically parses model names, sizes, and quantization info
// Updates UI in real-time
```

### 3. Enhanced Model-Platform Compatibility

Clear restrictions ensure users only see models that work with their selected platform:

#### Multi-Platform Compatible Models (Work with Both LM Studio and Docker)
- ✅ **DeepSeek R1**: Latest reasoning model (8B/7B variants) - **Works with both platforms**
- ✅ **Llama Models**: Llama 3 8B/70B, Llama 2 7B/13B
- ✅ **Code Models**: CodeLlama, various code-specialized models  
- ✅ **General Models**: Mistral 7B, Mixtral 8x7B, Phi-3
- ✅ **Open Models**: Vicuna, Alpaca, GPT4All variants
- ✅ **Qwen 2.5**: Multi-platform compatibility

#### Docker-Specialized Configurations
- 🐳 **Automatic Model Download**: Docker setups include automated model downloading
- 🐳 **Pre-configured Environments**: Optimized container configurations
- 🐳 **Production Ready**: Health checks and restart policies included

## 🎯 User Experience Improvements

### LM Studio Integration
1. **Auto-Detection**: When you select LM Studio, COBRA AI immediately scans for available models
2. **Rich Model Info**: See model size (8B, 70B), quantization (Q4_K_M, Q8_0), and descriptions
3. **Refresh Button**: Manual refresh with spinning icon animation
4. **Status Messages**: 
   - ✅ "5 models detected" (green)
   - ⚠️ "No models detected - ensure LM Studio is running" (amber)

### Visual Enhancements
- **Provider Icons**: 
  - 🖥️ Monitor icon for LM Studio
  - 🐳 Container icon for Docker
  - ☁️ Cloud icon for cloud providers
- **Model Cards**: Enhanced display with size and quantization info
- **Smart Filtering**: Only shows compatible models based on selected provider

### Better Error Handling
- Clear messages when LM Studio isn't running
- Fallback to default compatible models
- Connection status indicators

## 🚀 Quick Start Guide

### Option 1: LM Studio (Recommended for Desktop)

1. **Install LM Studio**: Download from [lmstudio.ai](https://lmstudio.ai)
2. **Download Models**: Use LM Studio's GUI to download models like:
   - `deepseek-r1-8b-instruct-q4_k_m.gguf`
   - `llama-3-8b-instruct-q4_k_m.gguf`
   - `codellama-7b-instruct-q4_k_m.gguf`
   - `mistral-7b-instruct-q4_k_m.gguf`
3. **Start Local Server**: In LM Studio, go to "Local Server" tab and start server
4. **COBRA AI Setup**:
   - Select "Local" provider
   - Choose "LM Studio" 
   - Models will auto-detect ✨
   - Select your desired model

### Option 2: Docker (Recommended for Production)

1. **Start Docker Services**:
   ```bash
   # For latest DeepSeek R1 models
   docker-compose -f docker-compose.deepseek-only.yml up -d
   
   # Or integrated with COBRA AI
   docker-compose -f docker-compose.with-deepseek.yml up -d
   ```
2. **COBRA AI Setup**:
   - Select "Local" provider
   - Choose "Docker"
   - Select DeepSeek R1 8B/7B or other available models

## 🔧 Technical Implementation

### LM Studio Model Detection API

```typescript
export interface LMStudioModel {
  id: string           // Full model identifier
  name: string         // Display name  
  size?: string        // Model size (8B, 70B, etc.)
  quantization?: string // Quantization type (Q4_K_M, etc.)
  available: boolean   // Whether model is loaded
}

// Automatic detection function
export const fetchLMStudioModels = async (endpoint: string): Promise<LMStudioModel[]> => {
  const response = await fetch(`${endpoint}/models`)
  const data = await response.json()
  
  return data.data.map(model => ({
    id: model.id,
    name: extractModelName(model.id),
    size: extractModelSize(model.id),      // Regex: /(\d+[bB])/
    quantization: extractQuantization(model.id), // Regex: /(q\d+[_-]?[kmhg]?)/
    available: true
  }))
}
```

### Smart Model Filtering

```typescript
const getFilteredModels = (): ModelInfo[] => {
  if (localProvider === 'lm-studio') {
    // Use detected models if available
    if (lmStudioModels.length > 0) {
      return lmStudioModels.map(model => ({
        id: model.id,
        name: model.name,
        size: model.size,
        quantization: model.quantization,
        description: `Size: ${model.size}, Quantization: ${model.quantization}`
      }))
    }
    // Fallback to compatible default models
    return defaultModels.filter(model => 
      model.compatibleProviders?.includes('lm-studio')
    )
  }
  
  // Docker provider logic...
}
```

### Compatibility Matrix (Updated)

```typescript
export const MODEL_PLATFORM_COMPATIBILITY = {
  // Cloud models
  'gpt-4': ['cloud'],
  'claude-4-sonnet': ['cloud'],
  'gemini-2.5-flash': ['cloud'],
  
  // Multi-platform models (work with both LM Studio and Docker)
  'deepseek-r1-8b': ['lm-studio', 'docker'],
  'deepseek-r1-7b': ['lm-studio', 'docker'],
  'llama-3-8b': ['lm-studio', 'docker'],
  'codellama': ['lm-studio', 'docker'], 
  'mistral-7b': ['lm-studio', 'docker'],
  'qwen-2.5': ['lm-studio', 'docker'],
}
```

## 🔧 Current Docker Configurations

### DeepSeek-Only Setup (`docker-compose.deepseek-only.yml`)
**Downloads:**
- `deepseek-r1:8b` (5.2GB) - Latest reasoning model
- `deepseek-r1:7b` (4.7GB) - Alternative smaller model

**Access Points:**
- API: `http://localhost:11434`
- Web UI: `http://localhost:8080`

### Integrated Setup (`docker-compose.with-deepseek.yml`)
**Includes:**
- Full COBRA AI stack
- DeepSeek R1 models (updated to latest)
- PostgreSQL database
- All microservices

**⚠️ Note**: This configuration has been updated to use DeepSeek R1 models instead of the older DeepSeek Coder models.

## 📱 Mobile Experience

- **Model Grid**: Touch-friendly model selection with size/quantization info
- **Refresh Button**: Easy model refresh for LM Studio
- **Status Indicators**: Clear visual feedback about model availability
- **Responsive Design**: Optimized for phone and tablet screens

## 🎯 Benefits of This Approach

### For Users
- **Simplified Choice**: Only two providers to choose from
- **Auto-Detection**: No manual model configuration needed for LM Studio
- **Clear Guidance**: Always know which models work with which provider
- **Better Performance**: Focused on proven, reliable hosting solutions

### For Developers  
- **Maintainable Code**: Simpler provider logic
- **Type Safety**: Strong TypeScript integration
- **Extensible**: Easy to add new models to compatibility matrix
- **User-Friendly**: Automatic error handling and status feedback

## 🔄 Migration Guide

### From Previous Versions
- **Existing Docker Users**: Update your docker-compose files to use DeepSeek R1 models
- **Model Compatibility**: DeepSeek models now work with both LM Studio and Docker
- **Frontend Updates**: Model selection UI now correctly reflects multi-platform support

### Getting Started Fresh
1. Choose your primary use case:
   - **Desktop/Development**: Use LM Studio for GUI management and easy model switching
   - **Production/Containers**: Use Docker for automated deployment and management
2. Note that most models now work with both platforms
3. Follow the Quick Start Guide above
4. Let COBRA AI auto-detect your models ✨

## 🚨 **Fixed Issues**

### 1. **Updated Docker Model Downloads**
- Fixed `docker-compose.with-deepseek.yml` to download DeepSeek R1 models instead of outdated DeepSeek Coder
- Synchronized all Docker configurations to use consistent model versions

### 2. **Corrected Platform Compatibility**
- DeepSeek models actually work with both LM Studio and Docker (not Docker-only as previously stated)
- Updated documentation to reflect actual multi-platform support

### 3. **Accurate Model Information**
- Removed references to non-existent "DeepSeek R1 Distill" models
- Updated model names to match actual implementation: `deepseek-r1:8b`, `deepseek-r1:7b`

### 4. **Consistency Across Components**
- Aligned frontend, backend, and Docker configurations
- Ensured model lists match actual available models

## 🚀 Future Enhancements

### Planned Features
- **Model Health Monitoring**: Real-time status of LM Studio models
- **Model Recommendations**: Suggest best models for different tasks
- **Performance Metrics**: Show model response times and resource usage
- **One-Click Downloads**: Integrate with LM Studio's download API
- **Model Templates**: Pre-configured setups for common use cases

This streamlined approach provides a much cleaner user experience while maintaining all the power and flexibility needed for local AI model hosting. 