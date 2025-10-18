# COBRA AI Security Tools Setup Guide

This guide will help you set up THC Hydra and Hashcat for the brute force functionality in COBRA AI.

## 🔧 Automated Setup (Recommended)

### Quick Setup with Pre-compiled Binaries

Run the automated setup script as Administrator:

```powershell
# Run PowerShell as Administrator
cd "C:\Users\Shabb\OneDrive\Desktop\Curor apps\CobraAI"
.\scripts\setup-security-tools-simple.ps1
```

This script will:
- ✅ Download THC Hydra Windows binaries
- ✅ Download official Hashcat Windows binaries
- ✅ Create necessary wordlists
- ✅ Configure environment variables
- ✅ Test installations

### Alternative Setup with Source Code

For advanced users who want to compile from source:

```powershell
# Run PowerShell as Administrator
.\scripts\setup-security-tools.ps1
```

## 🎯 Manual Setup

If the automated scripts don't work, follow these manual steps:

### 1. THC Hydra Setup

#### Option A: Pre-compiled Windows Binary (Recommended)
1. Download from: https://github.com/maaaaz/thc-hydra-windows/releases
2. Extract to `C:\SecurityTools\thc-hydra-master\`
3. Ensure `hydra.exe` is present

#### Option B: Compile from Source
1. Download from: https://github.com/vanhauser-thc/thc-hydra
2. Follow Windows compilation instructions
3. Place binary in `C:\SecurityTools\thc-hydra-master\`

### 2. Hashcat Setup

1. Download from: https://hashcat.net/files/hashcat-6.2.6.7z
2. Extract with 7-Zip to `C:\SecurityTools\hashcat-master\`
3. Ensure `hashcat.exe` is present

### 3. Wordlists Setup

Create wordlist directories and download common lists:

```powershell
# Create directories
New-Item -ItemType Directory -Path "C:\SecurityTools\hashcat-master\wordlists" -Force
New-Item -ItemType Directory -Path "C:\SecurityTools\thc-hydra-master\wordlists" -Force

# Download RockYou wordlist
Invoke-WebRequest -Uri "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" -OutFile "C:\SecurityTools\hashcat-master\wordlists\rockyou.txt"
```

### 4. Environment Configuration

Update your `backend\.env` file with tool paths:

```env
# Security Tools Configuration
HYDRA_PATH=C:\SecurityTools\thc-hydra-master\hydra.exe
HASHCAT_PATH=C:\SecurityTools\hashcat-master\hashcat.exe
```

## 🧪 Testing Your Setup

### Test THC Hydra
```powershell
C:\SecurityTools\thc-hydra-master\hydra.exe -h
```

### Test Hashcat
```powershell
C:\SecurityTools\hashcat-master\hashcat.exe --version
```

### Test in COBRA AI
1. Start your COBRA AI backend and frontend
2. Log in to the application
3. Navigate to the Chat interface
4. Click the "Brute Force Tools" option
5. Try a test attack (only on systems you own!)

## 🛠️ Troubleshooting

### Common Issues

#### 1. "Tool not found" Error
- **Cause**: Tool paths are incorrect in `.env` file
- **Solution**: Check paths in `backend\.env` match actual installation

#### 2. Windows Defender Blocking Tools
- **Cause**: Antivirus software blocking security tools
- **Solution**: Add exceptions for `C:\SecurityTools\` directory

#### 3. "Access Denied" Error
- **Cause**: Insufficient permissions
- **Solution**: Run PowerShell as Administrator

#### 4. "Failed to perform brute force attack"
- **Cause**: Authentication or tool installation issue
- **Solution**: 
  1. Ensure you're logged in to COBRA AI
  2. Check tool paths in backend logs
  3. Verify tools work from command line

### Tool-Specific Issues

#### THC Hydra Issues
- **Missing DLL files**: Download Visual C++ Redistributable
- **Network errors**: Check Windows Firewall settings
- **Service not supported**: Verify service name is correct

#### Hashcat Issues
- **OpenCL errors**: Update graphics drivers
- **CUDA errors**: Install NVIDIA CUDA Toolkit (for NVIDIA GPUs)
- **Performance issues**: Check workload profile settings

## 📁 Directory Structure

After setup, your directory structure should look like:

```
C:\SecurityTools\
├── thc-hydra-master\
│   ├── hydra.exe                 # Main Hydra executable
│   ├── wordlists\
│   │   ├── users.txt             # Basic usernames
│   │   └── passwords.txt         # Basic passwords
│   └── ... (other Hydra files)
├── hashcat-master\
│   ├── hashcat.exe               # Main Hashcat executable
│   ├── wordlists\
│   │   ├── rockyou.txt           # Famous password list
│   │   └── sample.txt            # Small sample list
│   └── ... (other Hashcat files)
```

## 🎯 Usage Examples

### Hydra Brute Force
- **Target**: SSH service on local network
- **Service**: SSH (Port 22)
- **Wordlists**: Use provided username/password lists
- **AI Enhancement**: Enable for intelligent wordlist generation

### Hashcat Hash Cracking
- **Hash Types**: MD5, SHA1, SHA256, NTLM, etc.
- **Attack Modes**: Dictionary, Brute force, Hybrid
- **Wordlists**: RockYou.txt or custom lists

## 🔒 Legal & Ethical Guidelines

### ⚠️ IMPORTANT LEGAL NOTICE

These tools are for **authorized security testing only**:

✅ **Allowed Uses:**
- Testing your own systems
- Authorized penetration testing with written permission
- Educational purposes in controlled environments
- Security research with proper authorization

❌ **Prohibited Uses:**
- Attacking systems without permission
- Unauthorized access attempts
- Malicious activities
- Any illegal activities

### Best Practices

1. **Always obtain written permission** before testing
2. **Use test environments** when possible
3. **Document your testing** for compliance
4. **Respect rate limits** to avoid DoS conditions
5. **Follow responsible disclosure** for any findings

## 🆘 Support

### Getting Help

1. **Check logs**: Backend console for error messages
2. **Verify paths**: Ensure tool paths are correct
3. **Test manually**: Run tools from command line
4. **Check permissions**: Ensure Administrator rights

### Community Resources

- THC Hydra Documentation: https://github.com/vanhauser-thc/thc-hydra
- Hashcat Documentation: https://hashcat.net/wiki/
- COBRA AI Repository: Your GitHub repository

## 🔄 Updates

### Keeping Tools Updated

```powershell
# Re-run setup script to update tools
.\scripts\setup-security-tools-simple.ps1

# Or manually download latest versions:
# - Hydra: https://github.com/maaaaz/thc-hydra-windows/releases
# - Hashcat: https://hashcat.net/files/
```

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally! 🛡️ 