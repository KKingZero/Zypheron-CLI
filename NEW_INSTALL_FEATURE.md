# 🎉 New Feature: Automatic Tool Installation

## Overview

Added automated tool installation commands to Zypheron CLI, making it easy to install all missing Kali security tools with a single command!

---

## 🆕 New Commands

### 1. **Install Specific Tool**
```bash
zypheron tools install <tool-name>
```

**Example:**
```bash
zypheron tools install nmap
zypheron tools install nikto
zypheron tools install metasploit
```

**Features:**
- ✅ Shows tool information before installing
- ✅ Confirmation prompt (skip with `-y`)
- ✅ Real-time installation progress
- ✅ Automatic verification after installation
- ✅ Handles sudo requirements
- ✅ Shows detailed error messages if installation fails

---

### 2. **Install All Missing Tools**
```bash
zypheron tools install-all
```

**Features:**
- ✅ Detects all missing tools automatically
- ✅ Groups by priority (Critical, High, Medium, Low)
- ✅ Shows estimated time
- ✅ Installs each tool sequentially
- ✅ Progress indicator for each tool
- ✅ Summary report at the end
- ✅ Lists failed installations for manual review

**Options:**
```bash
# Install all missing tools (interactive)
zypheron tools install-all

# Skip confirmation prompts
zypheron tools install-all -y

# Install only critical priority tools
zypheron tools install-all --critical-only

# Install critical and high priority tools
zypheron tools install-all --high-priority
```

---

## 📊 Usage Examples

### Example 1: Install Single Tool

```bash
$ zypheron tools install nmap

╔═══ INSTALL NMAP ═══════════════════════════════════╗
╚════════════════════════════════════════════════════╝

Tool: nmap
Description: Network exploration and security auditing
Category: scanner
Priority: critical

Install Command:
  sudo apt install nmap

? Install nmap? (Y/n) y

⠋ Installing nmap...
✔ nmap installed successfully

[*] Verifying installation...
[+] nmap verified (v7.94)
```

### Example 2: Install All Missing Tools

```bash
$ zypheron tools install-all

╔═══════════════════════════════════════╗
║  INSTALL ALL MISSING TOOLS           ║
╚═══════════════════════════════════════╝

Found 12 missing tools:

Critical: nmap, metasploit
High: nikto, sqlmap, hydra, hashcat, nuclei
Medium: gobuster, ffuf, subfinder
Low: recon-ng, maltego

[!] Some installations may require sudo privileges
[*] Estimated time: 24 - 60 minutes

? Install 12 missing tools? (y/N) y

═══ Starting Installation ═══

[1/12] nmap
Command: sudo apt install nmap
⠋ Installing...
✔ Installed

[2/12] metasploit
Command: sudo apt install metasploit-framework
⠋ Installing...
✔ Installed

[3/12] nikto
Command: sudo apt install nikto
⠋ Installing...
✔ Installed

... (continues for all tools)

═══ Installation Complete ═══

✓ Successful: 11
✗ Failed: 1

[!] Failed tools:
  • maltego

[*] You can install failed tools manually:
  zypheron tools install maltego

[*] Verifying installations...

Final Status:
  Installed: 19/20
  Missing:   1/20

[+] Installation process completed!
[*] You may need to restart your terminal for changes to take effect
```

### Example 3: Install Only Critical Tools

```bash
$ zypheron tools install-all --critical-only -y

╔═══════════════════════════════════════╗
║  INSTALL ALL MISSING TOOLS           ║
╚═══════════════════════════════════════╝

Found 2 missing tools:

Critical: nmap, metasploit

[!] Some installations may require sudo privileges
[*] Estimated time: 4 - 10 minutes

═══ Starting Installation ═══

[1/2] nmap
✔ Installed

[2/2] metasploit
✔ Installed

═══ Installation Complete ═══

✓ Successful: 2
✗ Failed: 0

[+] Installation process completed!
```

---

## 🎯 Benefits

### Before:
```bash
# Had to manually install each tool
sudo apt install nmap
sudo apt install nikto
sudo apt install sqlmap
sudo apt install hydra
sudo apt install john
sudo apt install hashcat
sudo apt install metasploit-framework
sudo apt install nuclei
sudo apt install gobuster
# ... (and 11 more tools)
```

### After:
```bash
# One command installs everything
zypheron tools install-all -y
```

---

## 🔧 Technical Details

### Implementation:
- **File Modified**: `cli/src/cli/commands/tools.ts`
- **Lines Added**: ~240 lines
- **New Functions**:
  - `installTool(toolName, options)` - Install a specific tool
  - `installAllTools(options)` - Install all missing tools

### Features:
1. **Async Execution**: Uses Node.js `child_process.exec()` with promises
2. **Progress Indicators**: Ora spinners for real-time feedback
3. **Error Handling**: Catches and displays installation errors
4. **Verification**: Re-scans after installation to confirm success
5. **Timeout Protection**: 5-minute timeout per tool to prevent hangs
6. **Priority Filtering**: Can install only critical/high priority tools
7. **Interactive Prompts**: Confirms before installing (skip with `-y`)

### Command Structure:
```typescript
tools.command('install <tool>')
  .description('Install a specific tool')
  .option('-y, --yes', 'Skip confirmation prompt')
  .action(async (toolName, options) => {
    await installTool(toolName, options);
  });

tools.command('install-all')
  .description('Install all missing tools')
  .option('-y, --yes', 'Skip confirmation prompt')
  .option('--critical-only', 'Install only critical priority tools')
  .option('--high-priority', 'Install critical and high priority tools')
  .action(async (options) => {
    await installAllTools(options);
  });
```

---

## 📖 Updated Documentation

Updated files:
- ✅ `cli/README.md` - Added install commands to Tool Management section
- ✅ `cli/QUICK_START.md` - Added installation examples
- ✅ `NEW_INSTALL_FEATURE.md` - This document

---

## 🎬 Getting Started

Try it now:
```bash
# Check what tools you're missing
zypheron tools check

# Install all missing tools
zypheron tools install-all

# Or install specific tools
zypheron tools install nmap
zypheron tools install nikto
```

---

## 🔐 Security Notes

- Some tools require `sudo` privileges
- Installation commands use official package managers (apt, go install, etc.)
- All commands are defined in the tool registry
- You can review the command before confirming installation
- Failed installations show error details for troubleshooting

---

## 💡 Pro Tips

1. **Install Critical Tools First**: `zypheron tools install-all --critical-only`
2. **Skip Prompts for Automation**: Use `-y` flag for scripts
3. **Check Before Installing**: Run `zypheron tools check` first
4. **Review Failed Tools**: Check error messages for manual installation
5. **Restart Terminal**: Some tools may need a terminal restart to work

---

**🎉 Happy Installing!**

Now you can get all your security tools set up with a single command! ⚡

