package tools

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

func ensurePrerequisites(opts ExecutionOptions) error {
	if strings.TrimSpace(opts.Tool) == "" {
		return fmt.Errorf("tool name is required")
	}
	if _, err := exec.LookPath(opts.Tool); err != nil {
		return fmt.Errorf("tool '%s' not found in PATH. Install it or run 'zypheron tools install'", opts.Tool)
	}
	return nil
}

func decorateArgs(opts ExecutionOptions) []string {
	args := append([]string{}, opts.Args...)
	tool := strings.ToLower(strings.TrimSpace(opts.Tool))

	switch tool {
	case "nuclei":
		args = appendIfMissing(args, "-json", "-no-color")
	case "httpx":
		args = appendIfMissing(args, "-silent")
	case "katana":
		args = appendIfMissing(args, "-silent")
	case "feroxbuster":
		args = appendIfMissing(args, "-q")
	case "dirsearch":
		args = appendIfMissing(args, "-q")
	case "nikto":
		if opts.AssumeYes {
			args = ensureArgPair(args, "-ask", "no")
		}
		if isIPAddress(opts.Target) {
			args = appendIfMissing(args, "-nolookup")
		}
	case "sqlmap":
		if opts.AssumeYes {
			args = appendIfMissing(args, "--batch", "--disable-coloring")
		}
	case "masscan":
		args = ensureArgPair(args, "--wait", "0")
	case "sliver":
		args = appendIfMissing(args, "--json")
	case "havoc":
		// No special args needed for basic operations
	}

	return args
}

func isProgressOnlyLine(tool, line string) bool {
	pattern, ok := ui.ProgressPatterns[strings.ToLower(tool)]
	if !ok {
		return false
	}
	return pattern.MatchString(line)
}

func isIPAddress(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	// Try direct parse first
	if net.ParseIP(target) != nil {
		return true
	}
	// Try stripping port (e.g., 192.168.1.1:8080)
	if host, _, err := net.SplitHostPort(target); err == nil {
		return net.ParseIP(host) != nil
	}
	return false
}

func appendIfMissing(args []string, values ...string) []string {
	result := append([]string{}, args...)
	for _, v := range values {
		if !containsArg(result, v) {
			result = append(result, v)
		}
	}
	return result
}

func ensureArgPair(args []string, key, value string) []string {
	for i := 0; i < len(args); i++ {
		if args[i] == key {
			return args
		}
	}
	return append(args, key, value)
}

func containsArg(args []string, value string) bool {
	if value == "" {
		return false
	}
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

// uniqueStrings returns a deduplicated slice with empty strings removed
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		result = append(result, s)
	}
	if result == nil {
		return []string{}
	}
	return result
}
