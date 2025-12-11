# 📚 Zypheron Documentation

Welcome to the Zypheron documentation! This directory contains all the guides and references you need to use Zypheron effectively.

## 📖 Documentation Index

### Essential Guides

| Document | Description | Status |
|----------|-------------|--------|
| **[SETUP.md](SETUP.md)** | Complete installation and configuration guide | ✅ Complete |
| **[CLI_GUIDE.md](CLI_GUIDE.md)** | Full CLI command reference | ✅ Complete |
| **[TOOL_CHAINS.md](TOOL_CHAINS.md)** | Tool chain configuration guide | ✅ Complete |
| **[DEV_STATUS.md](DEV_STATUS.md)** | Current development status and roadmap | ✅ Complete |

### Root Documentation

| Document | Description |
|----------|-------------|
| **[../README.md](../README.md)** | Main project README |
| **[../CHANGELOG.md](../CHANGELOG.md)** | Version history |
| **[../SECURITY.md](../SECURITY.md)** | Security policy |
| **[../TESTING.md](../TESTING.md)** | Testing guide |
| **[../LICENSE](../LICENSE)** | MIT License |

## 🚀 Quick Start

1. **Installation** → Start with [SETUP.md](SETUP.md)
2. **First Steps** → See [CLI_GUIDE.md](CLI_GUIDE.md) Quick Examples
3. **Tool Chains** → Configure workflows in [TOOL_CHAINS.md](TOOL_CHAINS.md)
4. **Development** → Check [DEV_STATUS.md](DEV_STATUS.md) for features

## 📂 Documentation Structure

```
docs/
├── README.md           # This file - documentation index
├── SETUP.md            # Installation and configuration
├── CLI_GUIDE.md        # Complete command reference
├── TOOL_CHAINS.md      # Tool chain configuration
├── DEV_STATUS.md       # Development status
└── archive/            # Old/deprecated documentation
```

## 🎯 Documentation by Topic

### Getting Started
- [Installation Guide](SETUP.md#quick-installation)
- [System Requirements](SETUP.md#system-requirements)
- [First Scan](CLI_GUIDE.md#getting-started)

### Commands
- [Network Security Commands](CLI_GUIDE.md#network-security)
- [Binary Analysis Commands](CLI_GUIDE.md#binary-analysis)
- [API Security Commands](CLI_GUIDE.md#api-security)
- [AI Features](CLI_GUIDE.md#ai-features)
- [Tool Management](CLI_GUIDE.md#tool-management)

### Configuration
- [Tool Installation](SETUP.md#tool-installation)
- [AI Configuration](SETUP.md#ai-configuration)
- [Tool Chains](TOOL_CHAINS.md#creating-custom-tool-chains)
- [Shell Completion](SETUP.md#shell-completion)

### Advanced Topics
- [Custom Tool Chains](TOOL_CHAINS.md#creating-custom-tool-chains)
- [AI Integration](SETUP.md#ai-configuration)
- [Distributed Testing](DEV_STATUS.md#enterprise-features)
- [Contributing](DEV_STATUS.md#contributing)

## 🔧 Common Tasks

### Network Scanning
```bash
# Quick scan
zypheron scan example.com

# Full pentest
zypheron scan example.com --full --ai-analysis
```
📖 [Full Guide →](CLI_GUIDE.md#scan---security-scanning)

### Binary Analysis
```bash
# Reverse engineering
zypheron reverse-eng /path/to/binary --chain reverse_engineering

# Binary exploitation
zypheron pwn /path/to/binary --tool checksec
```
📖 [Full Guide →](CLI_GUIDE.md#binary-analysis)

### API Security
```bash
# API testing
zypheron api-pentest https://api.example.com --bola --bfla
```
📖 [Full Guide →](CLI_GUIDE.md#api-pentest---api-security-testing)

### Tool Management
```bash
# Check tools
zypheron tools check

# Install all critical tools
zypheron tools install-all --critical-only
```
📖 [Full Guide →](CLI_GUIDE.md#tools---manage-security-tools)

## 🆘 Troubleshooting

Having issues? Check these resources:

1. **[Setup Troubleshooting](SETUP.md#troubleshooting)** - Installation issues
2. **[CLI Guide Examples](CLI_GUIDE.md#examples)** - Usage examples
3. **[GitHub Issues](https://github.com/KKingZero/Cobra-AI/issues)** - Known issues
4. **[GitHub Discussions](https://github.com/KKingZero/Cobra-AI/discussions)** - Community help

## 📊 Feature Status

Current status of major features:

| Feature | Status | Documentation |
|---------|--------|---------------|
| **Network Scanning** | ✅ Complete | [CLI Guide](CLI_GUIDE.md#network-security) |
| **Web Security** | ✅ Complete | [CLI Guide](CLI_GUIDE.md#web-security) |
| **Binary Analysis** | ✅ Complete | [CLI Guide](CLI_GUIDE.md#binary-analysis) |
| **API Testing** | ✅ Complete | [CLI Guide](CLI_GUIDE.md#api-security) |
| **Forensics** | ✅ Complete | [CLI Guide](CLI_GUIDE.md#forensics---digital-forensics) |
| **AI Integration** | ✅ Complete | [Setup Guide](SETUP.md#ai-configuration) |
| **AI Dorking** | 🚧 In Progress | [CLI Guide](CLI_GUIDE.md#dork---ai-powered-dorking) |
| **Tool Chains** | ✅ Complete | [Tool Chains](TOOL_CHAINS.md) |

See [DEV_STATUS.md](DEV_STATUS.md) for complete feature list and roadmap.

## 🤝 Contributing

Want to improve the documentation?

1. Documentation lives in the `docs/` directory
2. Use Markdown format
3. Keep language clear and concise
4. Include code examples
5. Test all commands before documenting

See [DEV_STATUS.md](DEV_STATUS.md#contributing) for contribution guidelines.

## 📝 Documentation Standards

### Format
- Use Markdown with GitHub-flavored extensions
- Include table of contents for long documents
- Use code blocks with language specification
- Include examples for all commands

### Structure
- Start with overview and purpose
- Include quick examples early
- Provide detailed reference later
- End with related resources

### Code Examples
```bash
# Always include comments
zypheron scan example.com     # Basic usage

# Show expected output when helpful
zypheron tools check
# Output: Found 25/30 tools installed
```

## 🔗 External Resources

- **GitHub**: https://github.com/KKingZero/Cobra-AI
- **Issues**: https://github.com/KKingZero/Cobra-AI/issues
- **Discussions**: https://github.com/KKingZero/Cobra-AI/discussions

## 📅 Documentation Updates

This documentation is regularly updated. Last major revision: **November 2025**

Check [DEV_STATUS.md](DEV_STATUS.md) for the most current feature information.

---

**Need help?** Start with [SETUP.md](SETUP.md) or open an issue on [GitHub](https://github.com/KKingZero/Cobra-AI/issues)!

