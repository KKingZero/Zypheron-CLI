# Security Patches for Command Injection Vulnerabilities

## Overview

This document provides comprehensive patches for all command injection vulnerabilities found in the MCP server and related components.

## 1. MCP Server - Masscan Function Fix

### BEFORE (VULNERABLE):
```python
@mcp.tool()
def masscan_fast(target: str, ports: str = "1-65535", rate: int = 1000) -> Dict[str, Any]:
    """Fast TCP port scanner using masscan."""
    cmd = f"masscan {target} -p{ports} --rate {rate}"  # VULNERABLE!
    result = executor.execute_raw_command(cmd, timeout=600)
    return executor.format_results(result, 'masscan')
```

### AFTER (SECURE):
```python
@mcp.tool()
def masscan_fast(target: str, ports: str = "1-65535", rate: int = 1000) -> Dict[str, Any]:
    """Fast TCP port scanner using masscan."""
    from mcp_interface.arg_validator import ArgumentValidator

    # Validate all inputs
    valid, error = ArgumentValidator.validate_target(target)
    if not valid:
        raise ValueError(f"Invalid target: {error}")

    valid, error = ArgumentValidator.validate_ports(ports)
    if not valid:
        raise ValueError(f"Invalid ports: {error}")

    valid, error = ArgumentValidator.validate_rate(rate)
    if not valid:
        raise ValueError(f"Invalid rate: {error}")

    # Use parameterized execution
    args = [target, '-p', ports, '--rate', str(rate)]
    result = executor.execute_tool('masscan', args, timeout=600)
    return executor.format_results(result, 'masscan')
```

## 2. MCP Server - Gobuster Function Fix

### BEFORE (VULNERABLE):
```python
@mcp.tool()
def gobuster_scan(url: str, wordlist: str, mode: str = "dir", additional_args: str = "") -> Dict[str, Any]:
    """Directory and DNS enumeration using Gobuster."""
    cmd = f"gobuster {mode} -u {url} -w {wordlist}"
    if additional_args:
        cmd += f" {additional_args}"  # VULNERABLE!
    result = executor.execute_raw_command(cmd, timeout=300)
    return executor.format_results(result, 'gobuster')
```

### AFTER (SECURE):
```python
@mcp.tool()
def gobuster_scan(url: str, wordlist: str, mode: str = "dir", additional_args: str = "") -> Dict[str, Any]:
    """Directory and DNS enumeration using Gobuster."""
    from mcp_interface.arg_validator import ArgumentValidator

    # Validate inputs
    valid, error = ArgumentValidator.validate_url(url)
    if not valid:
        raise ValueError(f"Invalid URL: {error}")

    valid, error = ArgumentValidator.validate_file_path(wordlist)
    if not valid:
        raise ValueError(f"Invalid wordlist path: {error}")

    # Build argument list
    args = [mode, '-u', url, '-w', wordlist]

    # Parse and validate additional args
    if additional_args:
        valid, extra_args, error = ArgumentValidator.parse_additional_args(additional_args, 'gobuster')
        if not valid:
            raise ValueError(f"Invalid additional args: {error}")
        args.extend(extra_args)

    # Use parameterized execution
    result = executor.execute_tool('gobuster', args, timeout=300)
    return executor.format_results(result, 'gobuster')
```

## 3. MCP Server - SQLMap Function Fix

### BEFORE (VULNERABLE):
```python
@mcp.tool()
def sqlmap_scan(url: str, data: str = "", risk: int = 1, level: int = 1) -> Dict[str, Any]:
    """SQL injection detection and exploitation using SQLMap."""
    cmd = f"sqlmap -u {url} --batch"
    if data:
        cmd += f" --data='{data}'"  # VULNERABLE!
    cmd += f" --risk={risk} --level={level}"
    result = executor.execute_raw_command(cmd, timeout=900)
    return executor.format_results(result, 'sqlmap')
```

### AFTER (SECURE):
```python
@mcp.tool()
def sqlmap_scan(url: str, data: str = "", risk: int = 1, level: int = 1) -> Dict[str, Any]:
    """SQL injection detection and exploitation using SQLMap."""
    from mcp_interface.arg_validator import ArgumentValidator

    # Validate inputs
    valid, error = ArgumentValidator.validate_url(url)
    if not valid:
        raise ValueError(f"Invalid URL: {error}")

    # Validate risk and level
    if not (0 <= risk <= 3):
        raise ValueError(f"Risk must be 0-3, got {risk}")
    if not (1 <= level <= 5):
        raise ValueError(f"Level must be 1-5, got {level}")

    # Build argument list
    args = ['-u', url, '--batch', '--risk', str(risk), '--level', str(level)]

    if data:
        # Validate data parameter (basic check for injection attempts)
        if any(c in data for c in [';', '&', '|', '`', '$', '(', ')']):
            raise ValueError("Potentially unsafe characters in data parameter")
        args.extend(['--data', data])

    # Use parameterized execution
    result = executor.execute_tool('sqlmap', args, timeout=900)
    return executor.format_results(result, 'sqlmap')
```

## 4. Tools Executor - Remove execute_raw_command

### File: zypheron-ai/mcp_interface/tools.py

### ACTION: Remove Deprecated Method

```python
# REMOVE THIS ENTIRE METHOD:
def execute_raw_command(self, command: str, timeout: int = 300):
    """
    DEPRECATED: This method is unsafe and will be removed.
    Use execute_tool() instead.
    """
    # ... implementation ...
```

### REPLACE WITH:

```python
# Method removed - use execute_tool() with explicit argument arrays
# All callers have been migrated to secure parameterized execution
```

## 5. Update All Remaining Vulnerable Functions

Apply the same pattern to fix:

- `amass_enum()`
- `subfinder_scan()`
- `httpx_probe()`
- `nikto_scan()`
- `wpscan_enumerate()`
- `hydra_bruteforce()`

## 6. Python Subprocess Execution Update

### Secure Subprocess Pattern

```python
import subprocess
import shlex

def secure_execute(tool: str, args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """
    Securely execute tool with validated arguments

    Args:
        tool: Tool name (must be in allowlist)
        args: List of arguments (NOT a string!)
        timeout: Execution timeout in seconds

    Returns:
        CompletedProcess result
    """
    # Validate tool is allowed
    ALLOWED_TOOLS = {
        'nmap', 'masscan', 'gobuster', 'sqlmap', 'nikto',
        'wpscan', 'hydra', 'amass', 'subfinder', 'httpx'
    }

    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool not allowed: {tool}")

    # Build command array (NOT shell string!)
    command = [tool] + args

    # Execute with shell=False (CRITICAL!)
    result = subprocess.run(
        command,
        shell=False,  # NEVER use shell=True!
        capture_output=True,
        timeout=timeout,
        text=True,
        check=False
    )

    return result
```

## 7. Go PWN Command Fix

### File: zypheron-go/internal/commands/pwn.go

### BEFORE (VULNERABLE):
```go
func buildPwnArgs(tool, binary string) []string {
    switch tool {
    case "pwntools":
        // DANGEROUS: Executes arbitrary Python with binary path
        args = []string{"-c", fmt.Sprintf("from pwn import *; p = process('%s'); p.interactive()", binary)}
    }
    return args
}
```

### AFTER (SECURE):
```go
func buildPwnArgs(tool, binary string) ([]string, error) {
    // Validate binary path
    if err := validateBinaryPath(binary); err != nil {
        return nil, fmt.Errorf("invalid binary path: %w", err)
    }

    switch tool {
    case "pwntools":
        // Write script to temp file instead of -c flag
        scriptPath, err := createPwnScript(binary)
        if err != nil {
            return nil, err
        }
        return []string{scriptPath}, nil
    }
    return nil, fmt.Errorf("unknown tool: %s", tool)
}

func validateBinaryPath(binary string) error {
    // Check for path traversal
    if strings.Contains(binary, "..") {
        return fmt.Errorf("path traversal not allowed")
    }

    // Convert to absolute path
    absPath, err := filepath.Abs(binary)
    if err != nil {
        return err
    }

    // Verify file exists
    if _, err := os.Stat(absPath); os.IsNotExist(err) {
        return fmt.Errorf("binary does not exist: %s", absPath)
    }

    // Verify it's a regular file
    info, err := os.Lstat(absPath)
    if err != nil {
        return err
    }
    if !info.Mode().IsRegular() {
        return fmt.Errorf("not a regular file: %s", absPath)
    }

    return nil
}
```

## 8. Password Flags Removal

### File: zypheron-go/internal/commands/authenticated_scan.go

### BEFORE (VULNERABLE):
```go
cmd.Flags().StringVar(&password, "password", "", "Password (or prompt securely)")
```

### AFTER (SECURE):
```go
// REMOVED - passwords must be prompted securely

func promptPassword() (string, error) {
    prompt := &survey.Password{
        Message: "Enter password:",
    }
    var password string
    if err := survey.AskOne(prompt, &password); err != nil {
        return "", err
    }
    return password, nil
}
```

## Application Instructions

1. **Apply arg_validator.py**: Already created
2. **Update MCP server**: Apply patterns to all @mcp.tool() functions
3. **Remove execute_raw_command**: Delete from tools.py and update all callers
4. **Fix Go pwn command**: Apply validation pattern
5. **Remove password flags**: Update all commands accepting passwords
6. **Test thoroughly**: Run integration tests after each change

## Testing Validation

After applying patches, test with:

```bash
# Test command injection attempt (should FAIL):
zypheron scan "example.com; rm -rf /"  # Should be rejected

# Test with valid input (should SUCCEED):
zypheron scan "192.168.1.1"

# Test additional args injection (should FAIL):
gobuster scan -u http://test.com -w /path/wordlist.txt --additional "; whoami"

# Test with valid additional args (should SUCCEED):
gobuster scan -u http://test.com -w /path/wordlist.txt --additional "-t 10"
```

## Verification Checklist

- [ ] All `execute_raw_command()` calls removed
- [ ] All string concatenation replaced with argument arrays
- [ ] All user inputs validated before use
- [ ] shell=False used in all subprocess calls
- [ ] Password flags removed, prompts used instead
- [ ] Path traversal checks added
- [ ] Allowlists implemented for all tools
- [ ] Integration tests pass
- [ ] Security regression tests added

## Priority Order

1. **CRITICAL**: Fix MCP server command injection (masscan, gobuster, sqlmap)
2. **HIGH**: Remove execute_raw_command() method
3. **HIGH**: Fix Go pwn command
4. **HIGH**: Remove password command-line flags
5. **MEDIUM**: Apply to remaining functions (amass, subfinder, etc.)

---

**Status**: Patches ready for application
**Next Step**: Apply patches systematically, testing after each change
