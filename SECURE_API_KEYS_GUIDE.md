# 🛡️ Secure API Key Management Guide

This guide explains how COBRA AI implements **double protection** for API keys using both environment variables and encryption for maximum security.

## 🔐 Security Architecture

COBRA AI uses a **layered security approach** for API key protection:

1. **Primary Layer**: Environment variables (standard practice)
2. **Secondary Layer**: AES-256-GCM encryption (additional protection)
3. **Fallback System**: Encrypted storage as backup when env vars are unavailable

## 📋 Quick Setup

### 1. Copy Environment Templates

```bash
# Backend environment
cp backend/env.example backend/.env

# Frontend environment  
cp frontend/env.example frontend/.env
```

### 2. Configure Your API Keys

Edit `backend/.env` with your actual API keys:

```env
# Required
SUPABASE_URL=your_actual_supabase_url
SUPABASE_ANON_KEY=your_actual_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_actual_service_key
JWT_SECRET=your_strong_jwt_secret

# AI APIs (at least one required)
OPENAI_API_KEY=your_openai_key
GEMINI_API_KEY=your_gemini_key
XAI_API_KEY=your_xai_key

# Optional threat intelligence
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

### 3. Deploy Securely

```bash
# Run secure deployment script
.\scripts\secure-deploy.ps1

# Or generate encryption keys first
.\scripts\secure-deploy.ps1 -GenerateKeys
```

## 🔧 Advanced Encryption Setup

### Using the Encryption Service

For additional security, you can encrypt API keys:

```bash
# Run the key management utility
node scripts/manage-api-keys.js
```

This tool allows you to:
- Encrypt and store API keys
- View encrypted key names
- Retrieve decrypted values
- Generate environment templates

### Manual Encryption

```javascript
// Example usage in your code
import { getSecureApiKey, encryptionService } from './services/encryption'

// Get API key (tries env var first, then encrypted storage)
const apiKey = getSecureApiKey('OPENAI_API_KEY')

// Store encrypted key as backup
encryptionService.storeEncryptedKey('OPENAI_API_KEY', 'your-actual-key')
```

## 🔄 How It Works

### API Key Resolution Priority

1. **Environment Variable** (highest priority)
   ```javascript
   process.env.OPENAI_API_KEY
   ```

2. **Encrypted Storage** (fallback)
   ```javascript
   // Decrypted from .encrypted-keys.json
   encryptionService.getApiKey('OPENAI_API_KEY')
   ```

3. **None Found** (graceful degradation)
   ```javascript
   // Service unavailable, but app continues
   console.warn('API key not found, service disabled')
   ```

### Encryption Details

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: 256-bit random master key
- **Storage**: JSON file with encrypted values
- **Authentication**: Built-in tamper detection

## 📁 File Structure

```
CobraAI/
├── backend/
│   ├── .env                    # Your actual config (git-ignored)
│   ├── env.example            # Template file
│   └── src/services/
│       └── encryption.ts      # Encryption service
├── frontend/
│   ├── .env                   # Your frontend config (git-ignored)
│   └── env.example           # Template file
├── scripts/
│   ├── manage-api-keys.js    # Key management utility
│   └── secure-deploy.ps1     # Deployment script
├── .encryption-key           # Master key (git-ignored)
├── .encrypted-keys.json      # Encrypted storage (git-ignored)
└── .gitignore               # Excludes sensitive files
```

## 🚀 Deployment Options

### Local Development

```bash
# Copy templates and configure
cp backend/env.example backend/.env
cp frontend/env.example frontend/.env

# Edit .env files with your keys
# Start development
npm run dev
```

### Production Deployment

```bash
# Secure deployment with validation
.\scripts\secure-deploy.ps1 -Environment production

# Docker deployment
docker-compose -f docker-compose.core.yml up -d
```

### CI/CD Integration

Set environment variables in your deployment platform:

**GitHub Actions:**
```yaml
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

**Heroku:**
```bash
heroku config:set OPENAI_API_KEY=your-key
heroku config:set GEMINI_API_KEY=your-key
```

**Vercel:**
```bash
vercel env add OPENAI_API_KEY
vercel env add GEMINI_API_KEY
```

## 🔒 Security Best Practices

### ✅ Do's

- **Use environment variables** as primary method
- **Keep .env files local** (never commit)
- **Use different keys** for dev/staging/prod
- **Rotate keys regularly** (monthly recommended)
- **Monitor API usage** in provider dashboards
- **Back up encryption keys** securely
- **Use strong JWT secrets** (32+ characters)

### ❌ Don'ts

- **Never hardcode API keys** in source code
- **Don't commit .env files** to version control
- **Don't share keys** via insecure channels
- **Don't use the same key** across environments
- **Don't ignore quota limits** and usage alerts

## 🚨 Emergency Procedures

### Compromised API Key

1. **Immediately revoke** the key in provider dashboard
2. **Generate new key** with different name/scope
3. **Update environment variables** in all deployments
4. **Rotate related secrets** (JWT, encryption keys)
5. **Review access logs** for suspicious activity

### Lost Encryption Key

1. **Check backups** for `.encryption-key` file
2. **Regenerate keys** if no backup exists
3. **Re-encrypt all API keys** with new master key
4. **Update deployment** with new encryption key

## 📊 Monitoring & Alerts

### API Usage Monitoring

- **OpenAI**: Monitor usage at platform.openai.com
- **Google Gemini**: Check AI Studio console
- **VirusTotal**: Review quota at virustotal.com
- **Set up billing alerts** for cost control

### Application Monitoring

```bash
# Check API key validation
curl http://localhost:3001/api/models

# Verify encryption service
node scripts/manage-api-keys.js
```

## 🐛 Troubleshooting

### Common Issues

**"API key not configured"**
- Verify `.env` file exists and has correct keys
- Check environment variable names (exact match required)
- Ensure no extra spaces or quotes around values

**"Encryption service failed"**
- Check `.encryption-key` file exists and is readable
- Verify file permissions (should be 600)
- Regenerate keys if corrupted

**"Service unavailable"**
- API key not found in either env vars or encrypted storage
- Check API key validity in provider dashboard
- Verify network connectivity to API endpoints

### Debug Commands

```bash
# List environment variables
env | grep -E "(OPENAI|GEMINI|XAI)_API_KEY"

# Test encryption service
node -e "console.log(require('./backend/src/services/encryption').getSecureApiKey('OPENAI_API_KEY'))"

# Validate deployment
.\scripts\secure-deploy.ps1 -SkipValidation:$false
```

## 📞 Support

For additional help:
1. Check the [main README](README.md) for general setup
2. Review [SETUP.md](SETUP.md) for detailed installation
3. Open an issue on GitHub for specific problems

---

**Remember**: Security is a process, not a product. Regularly review and update your security practices to maintain protection against evolving threats. 