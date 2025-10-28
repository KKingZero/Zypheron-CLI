package tools

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
)

// ExecutionOptions represents options for executing a tool
type ExecutionOptions struct {
	Tool       string
	Args       []string
	Target     string
	Stream     bool
	Timeout    time.Duration
	AIAnalysis bool
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	Success  bool
	Tool     string
	Output   string
	Error    string
	Duration time.Duration
	ExitCode int
	Parsed   interface{}
}

// Execute executes a tool with the given options
func Execute(ctx context.Context, opts ExecutionOptions) (*ToolResult, error) {
	start := time.Now()

	// Validate tool name
	if err := validation.ValidateToolName(opts.Tool); err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	// Validate target if provided
	if opts.Target != "" {
		if err := validation.ValidateTarget(opts.Target); err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
	}

	// Create command with context for timeout
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Build command
	cmd := exec.CommandContext(ctx, opts.Tool, opts.Args...)

	// Stream output if requested
	if opts.Stream {
		return executeWithStream(cmd, opts, start)
	}

	// Capture output
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := &ToolResult{
		Success:  err == nil,
		Tool:     opts.Tool,
		Output:   string(output),
		Duration: duration,
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
		result.Error = err.Error()
	}

	return result, nil
}

// executeWithStream executes a command and streams output in real-time
func executeWithStream(cmd *exec.Cmd, opts ExecutionOptions, start time.Time) (*ToolResult, error) {
	s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
	s.Suffix = fmt.Sprintf(" Running %s...", opts.Tool)
	s.Start()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.Stop()
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.Stop()
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		s.Stop()
		return nil, err
	}

	var output strings.Builder
	outputChan := make(chan string, 100)
	errChan := make(chan string, 100)
	done := make(chan bool)

	// Stream stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			outputChan <- line
		}
	}()

	// Stream stderr
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			errChan <- line
		}
	}()

	// Display output
	go func() {
		for {
			select {
			case line := <-outputChan:
				s.Stop()
				output.WriteString(line + "\n")
				printColoredLine(line)
				s.Start()
			case line := <-errChan:
				s.Stop()
				output.WriteString(line + "\n")
				fmt.Println(ui.Error(line))
				s.Start()
			case <-done:
				return
			}
		}
	}()

	// Wait for command to finish
	err = cmd.Wait()
	close(done)
	s.Stop()

	duration := time.Since(start)

	result := &ToolResult{
		Success:  err == nil,
		Tool:     opts.Tool,
		Output:   output.String(),
		Duration: duration,
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		result.ExitCode = exitErr.ExitCode()
		result.Error = err.Error()
	}

	return result, nil
}

// printColoredLine prints a line with appropriate coloring based on content
func printColoredLine(line string) {
	lower := strings.ToLower(line)

	if containsAny(lower, []string{"open", "found", "success", "vulnerable"}) {
		fmt.Println(ui.Success.Sprintf("  %s", line))
	} else if containsAny(lower, []string{"error", "failed", "denied"}) {
		fmt.Println(ui.Danger.Sprintf("  %s", line))
	} else if containsAny(lower, []string{"warning", "timeout"}) {
		fmt.Println(ui.Warning.Sprintf("  %s", line))
	} else {
		fmt.Printf("  %s\n", line)
	}
}

// containsAny checks if a string contains any of the keywords
func containsAny(s string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// ParseNmapOutput parses nmap output
func ParseNmapOutput(output string) interface{} {
	// Simple parser for demonstration
	// In production, use a proper XML parser for nmap's -oX output
	hosts := []map[string]interface{}{}

	lines := strings.Split(output, "\n")
	var currentHost map[string]interface{}

	for _, line := range lines {
		// Match host line: Nmap scan report for example.com (93.184.216.34)
		if strings.Contains(line, "Nmap scan report for") {
			if currentHost != nil {
				hosts = append(hosts, currentHost)
			}
			currentHost = map[string]interface{}{
				"ports": []map[string]string{},
			}

			// Extract hostname/IP
			parts := strings.Split(line, "for ")
			if len(parts) > 1 {
				currentHost["target"] = strings.TrimSpace(parts[1])
			}
		}

		// Match port line: 80/tcp open http
		if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				portInfo := map[string]string{
					"port":    fields[0],
					"state":   fields[1],
					"service": fields[2],
				}
				if currentHost != nil {
					ports := currentHost["ports"].([]map[string]string)
					currentHost["ports"] = append(ports, portInfo)
				}
			}
		}
	}

	if currentHost != nil {
		hosts = append(hosts, currentHost)
	}

	return map[string]interface{}{
		"hosts": hosts,
	}
}
