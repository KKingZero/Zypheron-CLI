# Kimi K2 API Integration Setup Guide for COBRA AI

## Overview

COBRA AI now supports **Kimi K2 API** (powered by Moonshot AI) as an additional AI provider. This integration provides Chinese-language expertise and enhanced cybersecurity capabilities while maintaining full compatibility with existing OpenAI functionality.

## ✅ What's New

### Kimi Models Available

COBRA AI now includes three Kimi models in the cloud provider selection:

1. **Kimi Moonshot 8K** (`moonshot-v1-8k`) - Fast response with 8K context window
2. **Kimi Moonshot 32K** (`moonshot-v1-32k`) - Extended context for complex conversations  
3. **Kimi Moonshot 128K** (`moonshot-v1-128k`) - Large context window for comprehensive analysis

### Key Features

- **Chinese Language Expertise**: Native Chinese cybersecurity analysis and recommendations
- **Penetration Test Analysis**: Specialized Chinese-language security assessments
- **Attack Payload Generation**: Culturally-aware security testing payloads
- **Seamless Integration**: Works alongside existing AI providers without conflicts

## 🔧 Setup Instructions

### Step 1: Get Your Kimi API Key

1. Visit the [Kimi Open Platform](https://platform.moonshot.cn/)
2. Create an account or sign in
3. Navigate to API Keys section
4. Generate a new API key
5. Copy the API key (format: `MOONSHOT_API_KEY`)

### Step 2: Configure Environment Variables

#### For Development (Local Setup)

1. **Backend Configuration**:
   ```bash
   cd backend
   # Edit your .env file
   nano .env
   ```

2. **Add Kimi API Key**:
   ```env
   # Kimi (Moonshot) API Key
   MOONSHOT_API_KEY=your_moonshot_api_key_here
   ```

#### For Production (Docker)

The following Docker Compose files have been updated to support `MOONSHOT_API_KEY`:

- `docker-compose.core.yml`
- `docker-compose.all-in-one.yml` 
- `docker-compose.with-deepseek.yml`

**Set environment variable before starting Docker**:
```bash
export MOONSHOT_API_KEY=your_moonshot_api_key_here
docker-compose up -d
```

### Step 3: Verify Integration

1. **Start COBRA AI**:
   ```bash
   npm run dev
   ```

2. **Check Model Availability**:
   - Open COBRA AI in your browser
   - Look for the model dropdown
   - Verify "Kimi Moonshot 8K/32K/128K" options appear

3. **Test Functionality**:
   - Select a Kimi model from the dropdown
   - Send a test message in Chinese or English
   - Verify responses are generated successfully

## 🚀 Usage Examples

### Basic Chat in Chinese
```
User: 你好，我想了解网络安全测试的最佳实践
Kimi: 您好！我是 Kimi，专注于网络安全领域。关于网络安全测试的最佳实践，我建议...
```

### Penetration Test Analysis
The Kimi models excel at analyzing penetration test results in Chinese:
- Comprehensive security assessments in Chinese
- Cultural context for Chinese security landscapes
- Detailed remediation recommendations

### Attack Payload Generation
Generate security testing payloads with Chinese documentation:
- Step-by-step instructions in Chinese
- Safety considerations for Chinese environments
- Compliance with local security standards

## 🔒 Security Considerations

### API Key Protection
- ✅ Kimi API keys use the same secure encryption system as OpenAI keys
- ✅ Keys are never logged or exposed in error messages
- ✅ Environment variables are properly isolated

### OpenAI Compatibility
- ✅ **OpenAI functionality remains completely unaffected**
- ✅ Existing OpenAI API keys continue to work normally
- ✅ No changes to OpenAI-specific features or configurations

### Fallback Behavior
- If Kimi API is unavailable, COBRA AI continues working with other providers
- Clear error messages guide users to check API key configuration
- No system crashes or data loss during API failures

## 🎯 Model Selection Guide

| Model | Context Window | Best For | Response Speed |
|-------|---------------|----------|----------------|
| **Moonshot 8K** | 8,192 tokens | Quick security queries, basic analysis | Fast ⚡ |
| **Moonshot 32K** | 32,768 tokens | Complex penetration tests, detailed reports | Medium 🔄 |
| **Moonshot 128K** | 131,072 tokens | Comprehensive security audits, large codebases | Slower 🐌 |

## 🛠️ Configuration Files Updated

The following files have been modified to support Kimi integration:

### Backend Files
- `backend/src/services/kimi.ts` - **NEW**: Kimi API service implementation
- `backend/src/services/ai.ts` - Updated to route Kimi requests
- `backend/src/routes/chat.ts` - Added Kimi model validation and handling
- `backend/env.example` - Added MOONSHOT_API_KEY configuration

### Frontend Files  
- `frontend/src/components/ChatLayout.tsx` - Added Kimi models to UI selector

### Docker & Scripts
- `docker-compose.core.yml` - Added MOONSHOT_API_KEY environment variable
- `docker-compose.all-in-one.yml` - Added MOONSHOT_API_KEY environment variable
- `docker-compose.with-deepseek.yml` - Added MOONSHOT_API_KEY environment variable  
- `scripts/update-env.ps1` - Added Kimi configuration guidance

## 🔍 API Endpoints

### Chat Messages
```http
POST /api/chat/message
Content-Type: application/json

{
  "messages": [
    {"role": "user", "content": "Analyze this security vulnerability"}
  ],
  "model": "moonshot-v1-8k"
}
```

### Penetration Test Analysis
```http
POST /api/chat/analyze-pentest
Content-Type: application/json

{
  "pentestResults": { ... },
  "model": "moonshot-v1-32k"
}
```

## 🐛 Troubleshooting

### Common Issues

1. **"Kimi API not available" Error**
   ```
   Solution: Check that MOONSHOT_API_KEY is properly set in your .env file
   ```

2. **Models Not Appearing in UI**
   ```
   Solution: Restart the frontend development server
   ```

3. **API Rate Limiting**
   ```
   Solution: Check your Kimi API quota and consider upgrading your plan
   ```

### Debug Steps

1. **Check API Key Configuration**:
   ```bash
   # In backend directory
   cat .env | grep MOONSHOT
   ```

2. **Verify Service Initialization**:
   ```bash
   # Check backend logs for Kimi service warnings
   npm run dev
   # Look for: "MOONSHOT_API_KEY not found. Kimi services will be unavailable."
   ```

3. **Test API Connection**:
   - Use a simple curl request to verify API key works
   - Check network connectivity to api.moonshot.cn

## 📋 Migration Notes

### Existing Users
- **No action required** - Kimi integration is completely optional
- **Existing configurations** remain unchanged
- **OpenAI functionality** is preserved exactly as before

### New Deployments
- Include `MOONSHOT_API_KEY` in your environment configuration
- Kimi models will appear automatically in the UI once configured

## 🎉 Benefits

✅ **Enhanced Chinese Language Support**: Native Chinese cybersecurity expertise  
✅ **Cultural Context**: Understanding of Chinese security landscape and practices  
✅ **Specialized Knowledge**: Cybersecurity focus with relevant training data  
✅ **Cost Effective**: Competitive pricing compared to other cloud AI providers  
✅ **No Conflicts**: Seamless integration without affecting existing functionality  

---

**Need Help?** 
- Check the main [SETUP.md](./SETUP.md) for general configuration guidance
- Review [SECURITY_TOOLS_SETUP.md](./SECURITY_TOOLS_SETUP.md) for security tool integration
- Consult the [Kimi API Documentation](https://platform.moonshot.cn/docs) for API-specific questions 