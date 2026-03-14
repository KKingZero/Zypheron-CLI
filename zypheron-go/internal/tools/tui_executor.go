package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
	"github.com/google/uuid"
)

// Tools that typically require root/sudo for full functionality
var rootRequiredTools = map[string]bool{
	"nmap":    true, // SYN scans, OS detection
	"masscan": true, // Raw packet scanning
	"tcpdump": true, // Packet capture
	"arpspoof": true,
	"ettercap": true,
	"bettercap": true,
	"hping3":   true,
}

// isRoot checks if we're running as root
func isRoot() bool {
	return os.Geteuid() == 0
}

// needsSudo checks if a tool needs sudo and we're not root
func needsSudo(tool string) bool {
	if isRoot() {
		return false
	}
	return rootRequiredTools[tool]
}

// canSudoWithoutPassword checks if sudo credentials are cached or passwordless
func canSudoWithoutPassword() bool {
	// Run `sudo -n true` which fails if password is required
	cmd := exec.Command("sudo", "-n", "true")
	err := cmd.Run()
	return err == nil
}

// TUIProgressCallback is called with progress updates
type TUIProgressCallback func(scanID string, percent float64, status string)

// TUIFindingCallback is called when a finding is discovered
type TUIFindingCallback func(scanID string, findingType, value, severity string)

// TUIOutputCallback is called with raw output lines
type TUIOutputCallback func(scanID string, line string)

// TUICompleteCallback is called when scan completes
type TUICompleteCallback func(scanID string, success bool, duration time.Duration, errMsg string)

// TUIExecutionOptions extends ExecutionOptions with callbacks for TUI mode
type TUIExecutionOptions struct {
	ExecutionOptions
	ScanID     string
	OnProgress TUIProgressCallback
	OnFinding  TUIFindingCallback
	OnOutput   TUIOutputCallback
	OnComplete TUICompleteCallback
}

// ExecuteForTUI runs a tool with TUI-friendly callbacks instead of CLI spinners
func ExecuteForTUI(ctx context.Context, opts TUIExecutionOptions) error {
	start := time.Now()

	// Generate scan ID if not provided
	if opts.ScanID == "" {
		opts.ScanID = uuid.New().String()[:8]
	}

	if opts.Tool == "" {
		if opts.OnComplete != nil {
			opts.OnComplete(opts.ScanID, false, 0, "tool name is required")
		}
		return fmt.Errorf("tool name is required")
	}

	// Validate tool name
	if err := validation.ValidateToolName(opts.Tool); err != nil {
		if opts.OnComplete != nil {
			opts.OnComplete(opts.ScanID, false, 0, err.Error())
		}
		return err
	}

	// Validate target if provided
	if opts.Target != "" {
		if err := validation.ValidateTarget(opts.Target); err != nil {
			if opts.OnComplete != nil {
				opts.OnComplete(opts.ScanID, false, 0, err.Error())
			}
			return err
		}
	}

	// Ensure required binaries are available
	if err := ensurePrerequisites(opts.ExecutionOptions); err != nil {
		if opts.OnComplete != nil {
			opts.OnComplete(opts.ScanID, false, 0, err.Error())
		}
		return err
	}

	// Decorate args
	opts.Args = decorateArgs(opts.ExecutionOptions)

	// Create command with context
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Use sudo for tools that require root privileges
	var cmd *exec.Cmd
	if needsSudo(opts.Tool) {
		// Check if sudo can run without password prompt (cached or passwordless)
		if !canSudoWithoutPassword() {
			errMsg := fmt.Sprintf("%s requires root privileges. Run 'sudo -v' first to cache credentials, or run zypheron as root", opts.Tool)
			if opts.OnComplete != nil {
				opts.OnComplete(opts.ScanID, false, 0, errMsg)
			}
			return fmt.Errorf("%s", errMsg)
		}
		// Prepend sudo to the command
		sudoArgs := append([]string{opts.Tool}, opts.Args...)
		cmd = exec.CommandContext(ctx, "sudo", sudoArgs...)
	} else {
		cmd = exec.CommandContext(ctx, opts.Tool, opts.Args...)
	}

	// Add ~/go/bin to PATH for Go-based tools (subfinder, amass, nuclei, httpx, etc.)
	homeDir, _ := os.UserHomeDir()
	goBinPath := ""
	if homeDir != "" {
		goBinPath = homeDir + "/go/bin"
	}
	currentPath := os.Getenv("PATH")
	enhancedPath := currentPath
	if goBinPath != "" {
		enhancedPath = goBinPath + ":" + currentPath
	}
	cmd.Env = append(os.Environ(),
		"PATH="+enhancedPath,
		"NO_COLOR=1",
		"CLICOLOR=0",
	)

	// Get stdout and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		if opts.OnComplete != nil {
			opts.OnComplete(opts.ScanID, false, 0, err.Error())
		}
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		if opts.OnComplete != nil {
			opts.OnComplete(opts.ScanID, false, 0, err.Error())
		}
		return err
	}

	// Start command
	if err := cmd.Start(); err != nil {
		if opts.OnComplete != nil {
			opts.OnComplete(opts.ScanID, false, 0, err.Error())
		}
		return err
	}

	// Initial progress
	if opts.OnProgress != nil {
		opts.OnProgress(opts.ScanID, 0, "Starting...")
	}

	// Process output
	done := make(chan struct{})
	go func() {
		defer close(done)
		processStream(opts, stdout, stderr)
	}()

	// Wait for command
	err = cmd.Wait()
	<-done

	duration := time.Since(start)

	if opts.OnComplete != nil {
		if err != nil {
			opts.OnComplete(opts.ScanID, false, duration, err.Error())
		} else {
			opts.OnComplete(opts.ScanID, true, duration, "")
		}
	}

	return err
}

// processStream reads output and sends updates via callbacks
func processStream(opts TUIExecutionOptions, stdout, stderr io.ReadCloser) {
	var lineCount int64 = 0
	var lastPercent float64 = 0.0
	var mu sync.Mutex

	// Helper to safely get and increment line count
	incrementAndGetLineCount := func() int {
		mu.Lock()
		lineCount++
		count := int(lineCount)
		mu.Unlock()
		return count
	}

	// Helper to safely update progress
	updateProgress := func(percent float64, status string) {
		mu.Lock()
		if percent > lastPercent {
			lastPercent = percent
			mu.Unlock()
			if opts.OnProgress != nil {
				opts.OnProgress(opts.ScanID, percent, status)
			}
		} else {
			mu.Unlock()
		}
	}

	// Read stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			count := incrementAndGetLineCount()

			// Send raw output
			if opts.OnOutput != nil {
				opts.OnOutput(opts.ScanID, line)
			}

			// Parse progress
			percent, status := parseProgressLine(opts.Tool, line, count)
			updateProgress(percent, status)

			// Parse findings
			finding := parseFindingLine(opts.Tool, line)
			if finding != nil && opts.OnFinding != nil {
				opts.OnFinding(opts.ScanID, finding.Type, finding.Value, finding.Severity)
			}
		}
	}()

	// Read stderr (often has progress info - nmap uses stderr!)
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		count := incrementAndGetLineCount()

		// Check for progress in stderr too (many tools output progress there)
		percent, status := parseProgressLine(opts.Tool, line, count)
		updateProgress(percent, status)

		// Send as output too if meaningful
		if len(strings.TrimSpace(line)) > 0 && !isProgressOnlyLine(opts.Tool, line) {
			if opts.OnOutput != nil {
				opts.OnOutput(opts.ScanID, line)
			}
		}
	}
}

// parseProgressLine extracts progress info from a line
func parseProgressLine(tool, line string, lineCount int) (float64, string) {
	// First try tool-specific progress patterns
	pattern, ok := ui.ProgressPatterns[tool]
	if ok {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			var percent float64
			fmt.Sscanf(matches[1], "%f", &percent)
			return percent, fmt.Sprintf("Progress: %.0f%%", percent)
		}
	}

	// Fallback: line-count based estimation with tool-specific expectations
	expectedLines := ui.ExpectedLineCount[tool]
	if expectedLines == 0 {
		expectedLines = 300 // Default if tool not in map
	}

	// Calculate progress based on lines received vs expected
	estimated := (float64(lineCount) / float64(expectedLines)) * 100.0

	// Cap at 95% until actual completion signal
	if estimated > 95 {
		estimated = 95
	}

	return estimated, "Scanning..."
}

// Finding represents a discovered item
type Finding struct {
	Type     string
	Value    string
	Severity string
}

// parseFindingLine extracts findings from output
func parseFindingLine(tool, line string) *Finding {
	pattern, ok := ui.FindingPatterns[tool]
	if !ok {
		return nil
	}

	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 0 {
		severity := determineSeverity(tool, line)
		return &Finding{
			Type:     tool,
			Value:    strings.TrimSpace(line),
			Severity: severity,
		}
	}

	return nil
}

// determineSeverity assigns severity based on content
func determineSeverity(tool, line string) string {
	lower := strings.ToLower(line)

	// Critical indicators
	if strings.Contains(lower, "critical") ||
		strings.Contains(lower, "rce") ||
		strings.Contains(lower, "remote code") ||
		strings.Contains(lower, "authentication bypass") {
		return "critical"
	}

	// High indicators
	if strings.Contains(lower, "high") ||
		strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "xss") ||
		strings.Contains(lower, "command injection") {
		return "high"
	}

	// Medium indicators
	if strings.Contains(lower, "medium") ||
		strings.Contains(lower, "sensitive") ||
		strings.Contains(lower, "exposure") {
		return "medium"
	}

	// Tool-specific defaults
	switch tool {
	case "nuclei":
		return "medium" // nuclei findings are usually at least medium
	case "nmap":
		return "info" // open ports are informational
	case "newman":
		if strings.Contains(lower, "fail") || strings.Contains(lower, "error") || strings.Contains(lower, "assertion") {
			return "high" // test failures are important
		}
		return "info" // test passes are informational
	default:
		return "info"
	}
}
