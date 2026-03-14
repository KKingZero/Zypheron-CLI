# Zypheron Tab Completion

Tab completion enables you to autocomplete Zypheron commands, subcommands, and flags by pressing the TAB key.

## Quick Install

Run the automatic installer script:

```bash
./scripts/install-completion.sh
```

The script will:
- Detect your shell (bash, zsh, or fish)
- Generate the appropriate completion file
- Install it to the correct location
- Update your shell configuration

## Manual Installation

### Bash

1. Generate completion file:
   ```bash
   zypheron completion bash > ~/.bash_completion.d/zypheron
   ```

2. Add to your `~/.bashrc`:
   ```bash
   [ -f ~/.bash_completion.d/zypheron ] && source ~/.bash_completion.d/zypheron
   ```

3. Reload shell:
   ```bash
   source ~/.bashrc
   ```

### Zsh

1. Create completion directory:
   ```bash
   mkdir -p ~/.zsh/completions
   ```

2. Generate completion file:
   ```bash
   zypheron completion zsh > ~/.zsh/completions/_zypheron
   ```

3. Add to your `~/.zshrc`:
   ```zsh
   fpath=(~/.zsh/completions $fpath)
   autoload -Uz compinit && compinit
   ```

4. Reload shell:
   ```bash
   source ~/.zshrc
   ```

### Fish

1. Generate completion file:
   ```bash
   zypheron completion fish > ~/.config/fish/completions/zypheron.fish
   ```

2. Fish will automatically load it on next startup, or reload now:
   ```bash
   source ~/.config/fish/config.fish
   ```

## Usage Examples

Once installed, you can use TAB completion:

```bash
# Complete commands
zypheron <TAB>
# Shows: ai, config, scan, tools, version, help, etc.

# Complete subcommands
zypheron config <TAB>
# Shows: get, set, show, path, wizard, set-key, get-providers

# Complete flags
zypheron scan --<TAB>
# Shows: --ports, --tool, --output, --format, --no-ai, etc.

# Complete tool names
zypheron scan example.com --tool <TAB>
# Shows: nmap, nikto, nuclei, masscan, sqlmap, etc.

# Complete output formats
zypheron scan example.com --format <TAB>
# Shows: text, html, json, markdown, pdf

# Complete AI providers
zypheron config set-key <TAB>
# Shows: anthropic, openai, google, deepseek, kimi, grok
```

## Verify Installation

Test that completion is working:

```bash
zypheron <TAB><TAB>
```

You should see a list of available commands.

## Troubleshooting

### Completion not working

1. **Verify zypheron is in PATH:**
   ```bash
   which zypheron
   ```

2. **Check if completion file exists:**
   ```bash
   # Bash
   ls -la ~/.bash_completion.d/zypheron

   # Zsh
   ls -la ~/.zsh/completions/_zypheron

   # Fish
   ls -la ~/.config/fish/completions/zypheron.fish
   ```

3. **Reload your shell configuration:**
   ```bash
   # Bash
   source ~/.bashrc

   # Zsh
   source ~/.zshrc

   # Fish
   source ~/.config/fish/config.fish
   ```

4. **Regenerate completion file:**
   ```bash
   # Remove old file
   rm ~/.bash_completion.d/zypheron  # or appropriate path

   # Run installer again
   ./scripts/install-completion.sh
   ```

### Bash: "command not found: compgen"

Install bash-completion package:
```bash
# Ubuntu/Debian
sudo apt-get install bash-completion

# macOS
brew install bash-completion@2
```

### Zsh: Completion not showing

Make sure compinit is running:
```zsh
# Add to ~/.zshrc if not present
autoload -Uz compinit && compinit
```

Rebuild completion cache:
```zsh
rm -f ~/.zcompdump; compinit
```

### Fish: Completions not loading

Check Fish version (needs 3.0+):
```bash
fish --version
```

Clear Fish completions cache:
```bash
rm -rf ~/.cache/fish/completions
```

## Advanced Configuration

### Bash: Case-insensitive completion

Add to `~/.inputrc`:
```
set completion-ignore-case on
```

### Zsh: Better completion menu

Add to `~/.zshrc`:
```zsh
zstyle ':completion:*' menu select
zstyle ':completion:*' matcher-list 'm:{a-z}={A-Z}'
```

### Fish: Fuzzy matching

Fish has fuzzy matching enabled by default for completions.

## Uninstall

### Bash
```bash
rm ~/.bash_completion.d/zypheron
# Remove from ~/.bashrc
```

### Zsh
```bash
rm ~/.zsh/completions/_zypheron
# Remove fpath line from ~/.zshrc
```

### Fish
```bash
rm ~/.config/fish/completions/zypheron.fish
```

## Supported Shells

| Shell | Version | Status |
|-------|---------|--------|
| Bash  | 4.0+    | ✅ Full support |
| Zsh   | 5.0+    | ✅ Full support |
| Fish  | 3.0+    | ✅ Full support |
| PowerShell | 5.0+ | ⚠️ Coming soon |

## What Gets Completed

Tab completion supports:

- **Commands**: `scan`, `tools`, `config`, `ai`, `version`, `help`
- **Subcommands**: `tools check`, `config show`, `ai start`, etc.
- **Flags**: `--ports`, `--tool`, `--output`, `--format`, `--no-ai`, etc.
- **Flag values**: Tool names, output formats, AI providers
- **File paths**: For `--output` and other file arguments

## Contributing

To add completion for new commands or flags:

1. Update the Cobra command definitions in Go code
2. Regenerate completion files:
   ```bash
   zypheron completion bash > completion.bash
   zypheron completion zsh > completion.zsh
   zypheron completion fish > completion.fish
   ```

Cobra automatically generates completion based on command structure.

## See Also

- [Cobra Shell Completions](https://github.com/spf13/cobra/blob/main/shell_completions.md)
- [Bash Completion Documentation](https://github.com/scop/bash-completion)
- [Zsh Completion System](http://zsh.sourceforge.net/Doc/Release/Completion-System.html)
- [Fish Completion Tutorial](https://fishshell.com/docs/current/completions.html)
