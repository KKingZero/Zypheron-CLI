# Google Gemini API Setup for COBRA AI

## ✅ API Status Update

**The Google Gemini API is WORKING with the provided key!** 

However, please note:
- **Gemini 2.5 Flash**: ✅ Latest hybrid reasoning model (recommended)
- **Gemini 2.5 Pro**: ✅ Most intelligent model for complex tasks

The API key (`AIzaSyAqwja_yFQu4Kx0g7mF9O-Rnv-aJHW2yuI`) is functional but has usage limits as it's a free tier key.

## API Key Configuration

The Google Gemini API has been integrated into COBRA AI to provide enhanced AI capabilities for security analysis, penetration test results analysis, and general cybersecurity queries.

### Setting up the API Key

1. Create a `.env` file in the backend directory if it doesn't exist:
   ```bash
   cd backend
   touch .env
   ```

2. Add the following to your `.env` file:
   ```env
   # Google Gemini API Key
   GEMINI_API_KEY=AIzaSyAqwja_yFQu4Kx0g7mF9O-Rnv-aJHW2yuI
   ```

### Available Gemini Models

COBRA AI now supports the latest Google Gemini 2.5 models:

1. **Gemini 2.5 Flash** - Hybrid reasoning model with adjustable thinking budgets (Recommended for general use)
2. **Gemini 2.5 Pro** - Most intelligent Google model for complex cybersecurity tasks and advanced reasoning

### Features Powered by Gemini

- **Penetration Test Analysis**: Comprehensive analysis of security vulnerabilities
- **Attack Payload Generation**: Professional penetration testing payloads
- **Network Configuration Analysis**: Security assessment of network setups
- **Threat Intelligence**: Real-time threat analysis for domains and IPs
- **OSINT Data Analysis**: Enhanced intelligence gathering and analysis

### Usage

Simply select either "Gemini 2.5 Flash" or "Gemini 2.5 Pro" from the model dropdown in the chat interface. The latest models provide enhanced capabilities for:

- General cybersecurity queries
- Analyzing penetration test results
- Generating security recommendations
- Providing threat intelligence

### API Limits and Quota

The provided API key is subject to Google's free tier limits:
- **Requests per minute**: Limited
- **Tokens per minute**: Limited for Pro model
- **Daily quota**: Shared across all users

If you encounter quota errors:
1. The system will automatically fallback from Pro to Flash model
2. Wait a few minutes before trying again
3. Consider using Flash model for general queries
4. For production use, obtain your own API key

### Getting Your Own API Key

For unlimited usage, obtain your own API key from:
https://makersuite.google.com/app/apikey

1. Sign in with your Google account
2. Create a new API key
3. Replace the key in your `.env` file
4. Restart the backend server

### Troubleshooting

If you encounter API errors:

1. **"Quota exceeded" error**: 
   - Switch to Gemini Flash model
   - Wait 1-2 minutes before retrying
   - Get your own API key for higher limits

2. **"Invalid API key" error**:
   - Verify the API key is correctly set in `.env`
   - Ensure no extra spaces or quotes around the key

3. **Connection errors**:
   - Check your internet connection
   - Verify firewall settings allow HTTPS connections to googleapis.com

4. **Model availability**:
   - Both models show as available in the dropdown
   - Flash model is more reliable for continuous use

## Security Note

Never commit API keys to version control. Always use environment variables and keep your `.env` file in `.gitignore`. 