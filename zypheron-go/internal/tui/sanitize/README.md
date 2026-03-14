# Output Sanitization Module

## Overview

The `sanitize` package provides security-critical output sanitization for the Zypheron TUI to prevent terminal injection attacks. This module strips dangerous ANSI escape sequences and control characters that could be exploited to manipulate terminal behavior, execute commands, or create UI confusion attacks.

## Security Threat Model

### Attack Vectors Mitigated

1. **Terminal Title Injection (OSC Sequences)**
   - Attackers can change the terminal window title to display misleading information
   - Example: `\x1b]0;Secure Connection\x07` while actually compromised
   - Can be used for social engineering attacks

2. **Cursor Manipulation (CSI Sequences)**
   - Attackers can reposition the cursor to overwrite displayed text
   - Example: `Balance: $1000\x1b[10D00` changes display to show $100000
   - Creates UI confusion and can trick users into making wrong decisions

3. **Line Overwrite via Carriage Return**
   - CR (`\r`) can overwrite the current line
   - Example: `Password: secret\rPassword: ******` hides the actual password shown
   - Critical for hiding malicious input/output

4. **Clipboard Manipulation (OSC 52)**
   - `\x1b]52;c;base64\x07` can write to the system clipboard
   - Attackers can inject malicious commands that get pasted later
   - Particularly dangerous in automation workflows

5. **Terminal Reprogramming (DCS Sequences)**
   - Device Control Strings can reprogram terminal behavior
   - Can remap keys or change terminal settings
   - Persistent across sessions in some terminals

6. **Application Program Commands (APC)**
   - Vendor-specific sequences that may trigger terminal-specific actions
   - Attack surface varies by terminal emulator
   - Defense in depth: strip even if impact unclear

## API Reference

### Core Functions

#### `SanitizeOutput(input string) string`

Primary sanitization function for untrusted output.

**Removes:**
- All ANSI escape sequences (colors, cursor movement, etc.)
- Dangerous control characters (including `\r`)
- 8-bit CSI sequences
- OSC, DCS, APC, PM sequences

**Preserves:**
- Newlines (`\n`)
- Tabs (`\t`)
- All printable characters

**Use Cases:**
- Displaying output from external commands
- Showing user-generated content
- Rendering API responses
- Any untrusted text source

**Example:**
```go
import "zypheron-go/internal/tui/sanitize"

// Sanitize command output
output := executeCommand(cmd)
safe := sanitize.SanitizeOutput(output)
fmt.Println(safe)
```

#### `SanitizeOutputPreserveColor(input string) string`

Sanitization that preserves ANSI color codes while removing dangerous sequences.

**Preserves:**
- SGR (Select Graphic Rendition) sequences: `\x1b[...m`
- Basic colors, 256 colors, RGB colors
- Bold, italic, underline formatting
- Newlines and tabs

**Removes:**
- Cursor movement sequences
- Terminal reprogramming (OSC, DCS, APC, PM)
- Carriage returns and other dangerous control chars

**Use Cases:**
- Displaying colorized output from trusted sources
- Showing syntax-highlighted code
- Rendering colored log output
- When you trust the source but not the channel

**Example:**
```go
// Preserve colors from syntax highlighter
highlighted := syntaxHighlight(code)
safe := sanitize.SanitizeOutputPreserveColor(highlighted)
display(safe)
```

#### `StripAllANSI(input string) string`

Completely removes all ANSI sequences including colors. Alias for `SanitizeOutput`.

**Use Cases:**
- Logging to files (plain text)
- Transmitting over non-terminal channels
- Email notifications
- Database storage

**Example:**
```go
// Log without ANSI codes
plainText := sanitize.StripAllANSI(coloredOutput)
log.WriteToFile(plainText)
```

#### `IsOutputSafe(input string) bool`

Checks if a string contains dangerous terminal sequences without modifying it.

**Returns:**
- `true`: String is safe to display without sanitization
- `false`: String contains dangerous sequences

**Use Cases:**
- Validation before displaying content
- Security auditing and monitoring
- Pre-flight checks in security-critical code paths
- Testing and verification

**Example:**
```go
// Validate before displaying
if !sanitize.IsOutputSafe(userInput) {
    log.SecurityWarning("Dangerous sequences detected in user input")
    userInput = sanitize.SanitizeOutput(userInput)
}
display(userInput)
```

## Usage Guidelines

### When to Sanitize

**ALWAYS sanitize:**
- Output from external commands/processes
- User-provided content
- Network responses (API data, downloaded content)
- File contents from untrusted sources
- Environment variables
- Any data crossing trust boundaries

**Consider sanitizing:**
- Data from internal services (defense in depth)
- Cached data (may have been compromised)
- Database content (if source was external)

**May skip sanitization:**
- Hard-coded strings in your code
- Output from trusted internal libraries (if you control the source)
- Content already validated by another security layer

### Security Best Practices

1. **Default to Strict Mode**
   ```go
   // Prefer SanitizeOutput over SanitizeOutputPreserveColor
   safe := sanitize.SanitizeOutput(untrustedInput)
   ```

2. **Validate Before Trust**
   ```go
   // Check safety before deciding to preserve formatting
   if sanitize.IsOutputSafe(input) {
       display(input)
   } else {
       display(sanitize.SanitizeOutput(input))
   }
   ```

3. **Layer Security**
   ```go
   // Multiple validation layers
   input = validateSchema(input)
   input = sanitize.SanitizeOutput(input)
   input = enforceMaxLength(input)
   ```

4. **Log Security Events**
   ```go
   if !sanitize.IsOutputSafe(data) {
       log.SecurityEvent("Dangerous sequences stripped", "source", source)
   }
   ```

## Performance Characteristics

### Algorithmic Complexity
- Time: O(n) where n is input length
- Space: O(n) for output buffer
- Single-pass algorithm for optimal cache performance

### Optimization Techniques
1. **Pre-allocated Builder**: Uses `strings.Builder.Grow()` to minimize allocations
2. **Byte-level Processing**: Avoids regex overhead
3. **Early Termination**: Checks sequence prefixes before full parsing
4. **No Regex**: All parsing done with efficient byte comparisons

### Benchmark Results
Expected performance (varies by content):
- Plain text (no escapes): ~1-2 ns/byte
- Text with escapes: ~3-5 ns/byte
- Safety checking only: ~0.5-1 ns/byte

**Hot Path Optimization**: Suitable for use in display loops and real-time output processing.

## Implementation Details

### ANSI Escape Sequence Format

The module understands and correctly parses:

1. **CSI (Control Sequence Introducer)**
   - Format: `ESC [ [parameters] [intermediate] (final)`
   - Parameters: `0x30-0x3F` (digits, semicolon)
   - Intermediate: `0x20-0x2F`
   - Final: `0x40-0x7E` (letters, @, etc.)

2. **OSC (Operating System Command)**
   - Format: `ESC ] ... (BEL or ST)`
   - Terminator: `\x07` (BEL) or `\x1b\` (ST) or `\x9c`

3. **DCS (Device Control String)**
   - Format: `ESC P ... (ST or BEL)`

4. **APC (Application Program Command)**
   - Format: `ESC _ ... (ST or BEL)`

5. **PM (Privacy Message)**
   - Format: `ESC ^ ... (ST or BEL)`

### Control Character Handling

| Char | Hex    | Action    | Reason                                    |
|------|--------|-----------|-------------------------------------------|
| NUL  | `\x00` | Remove    | String terminator, can truncate output    |
| TAB  | `\x09` | Preserve  | Safe formatting character                 |
| LF   | `\x0a` | Preserve  | Required for line breaks                  |
| CR   | `\x0d` | **Remove**| **Can overwrite lines - SECURITY RISK**   |
| BEL  | `\x07` | Remove    | Can cause audio/visual disruption         |
| BS   | `\x08` | Remove    | Can overwrite characters                  |
| VT   | `\x0b` | Remove    | Vertical tab, unpredictable behavior      |
| FF   | `\x0c` | Remove    | Form feed, can clear screen               |
| DEL  | `\x7f` | Remove    | Delete character                          |

## Testing

### Running Tests
```bash
cd /home/zero/Downloads/Zypheron\ project/Zypheron-CLI-Production/zypheron-go
go test -v ./internal/tui/sanitize/...
```

### Running Benchmarks
```bash
go test -bench=. -benchmem ./internal/tui/sanitize/...
```

### Test Coverage
The test suite includes:
- Basic safety tests (plain text, newlines, tabs)
- Carriage return removal (security critical)
- ANSI color removal
- Cursor manipulation removal
- OSC sequence removal (title injection, clipboard)
- DCS sequence removal (terminal reprogramming)
- APC and PM removal
- 8-bit CSI removal
- Control character removal
- Color preservation mode testing
- Real-world attack scenarios
- Edge cases and malformed sequences

### Security Testing Recommendations

1. **Fuzz Testing**
   ```bash
   go test -fuzz=FuzzSanitizeOutput -fuzztime=30s
   ```

2. **Manual Security Review**
   - Test with actual terminal emulators
   - Verify no bypass techniques exist
   - Check for timing side-channels

3. **Integration Testing**
   - Test with real command outputs
   - Verify against known CVEs
   - Test with various terminal types

## Known Limitations

1. **Unicode Handling**: The module preserves all Unicode characters as-is. If Unicode control characters are a concern for your threat model, additional filtering may be needed.

2. **Terminal-Specific Sequences**: Some terminals support proprietary sequences not in the ANSI standard. These are generally caught by the escape sequence parser but should be verified for your specific terminal.

3. **Performance on Extremely Large Inputs**: While O(n) is optimal, processing multi-megabyte strings will have proportional cost. Consider chunking very large outputs.

4. **No Semantic Analysis**: The module does not understand the semantic meaning of sequences, only their syntax. It cannot detect if a "safe" sequence is being used maliciously.

## Integration Examples

### Example 1: Command Output Display
```go
func displayCommandOutput(cmd *exec.Cmd) error {
    output, err := cmd.CombinedOutput()
    if err != nil {
        return err
    }

    // Sanitize before displaying
    safe := sanitize.SanitizeOutput(string(output))
    fmt.Println(safe)
    return nil
}
```

### Example 2: User Input Echo
```go
func echoUserInput(input string) {
    // Always sanitize user input before display
    safe := sanitize.SanitizeOutput(input)
    fmt.Printf("You entered: %s\n", safe)
}
```

### Example 3: Log File vs Terminal
```go
func displayWithLogging(msg string) {
    // Strip all ANSI for log file
    logFile.Write(sanitize.StripAllANSI(msg))

    // Preserve colors for terminal (if trusted source)
    if trustedSource {
        fmt.Println(sanitize.SanitizeOutputPreserveColor(msg))
    } else {
        fmt.Println(sanitize.SanitizeOutput(msg))
    }
}
```

### Example 4: Security Monitoring
```go
func monitoredDisplay(source string, data string) {
    if !sanitize.IsOutputSafe(data) {
        securityLog.Warn(
            "Dangerous sequences detected",
            "source", source,
            "data_preview", data[:min(len(data), 100)],
        )
        data = sanitize.SanitizeOutput(data)
    }
    display(data)
}
```

## Security Disclosure

If you discover a bypass technique or security vulnerability in this module, please report it through Zypheron's security disclosure process. This is security-critical infrastructure - responsible disclosure is appreciated.

## References

- [ANSI Escape Codes](https://en.wikipedia.org/wiki/ANSI_escape_code)
- [Terminal Injection Attacks](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=terminal+escape)
- [OWASP Output Encoding](https://cheatsheetseries.owasp.org/cheatsheets/Output_Encoding_Cheat_Sheet.html)

## License

This module is part of the Zypheron project. See the project root for license information.
