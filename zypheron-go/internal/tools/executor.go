package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
	"github.com/briandowns/spinner"
)

// ExecutionOptions represents options for executing a tool
type ExecutionOptions struct {
	Tool       string
	Args       []string
	Target     string
	Stream     bool
	Timeout    time.Duration
	AIAnalysis bool
	AssumeYes  bool
	Requires   []string
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
	TimedOut bool
}

// Execute executes a tool with the given options
func Execute(ctx context.Context, opts ExecutionOptions) (*ToolResult, error) {
	start := time.Now()

	if opts.Tool == "" {
		return nil, fmt.Errorf("tool name is required")
	}

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

	// Ensure required binaries are available
	if err := ensurePrerequisites(opts); err != nil {
		return nil, err
	}

	// Ensure we keep command non-interactive where possible
	opts.Args = decorateArgs(opts)

	// Create command with context for timeout
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, opts.Tool, opts.Args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("ZYPHERON_ASSUME_YES=%t", opts.AssumeYes), "NO_COLOR=1", "CLICOLOR=0")

	var (
		result *ToolResult
		err    error
	)

	if opts.Stream {
		result, err = executeWithStream(cmd, opts, start)
	} else {
		result, err = executeWithoutStream(cmd, opts, start)
	}

	if err != nil {
		return nil, err
	}

	if result != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.TimedOut = true
			result.Success = false
			if result.Error == "" {
				result.Error = fmt.Sprintf("execution timed out after %s", opts.Timeout)
			}
		}
		result.Parsed = parseStructuredOutput(opts.Tool, result.Output)
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
	} else if err != nil {
		result.Error = err.Error()
	}

	return result, nil
}

func executeWithoutStream(cmd *exec.Cmd, opts ExecutionOptions, start time.Time) (*ToolResult, error) {
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
	} else if err != nil {
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

func ensurePrerequisites(opts ExecutionOptions) error {
	required := uniqueStrings(append([]string{opts.Tool}, opts.Requires...))
	for _, bin := range required {
		if bin == "" {
			continue
		}
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("required tool '%s' not found in PATH: %w", bin, err)
		}
	}
	return nil
}

func decorateArgs(opts ExecutionOptions) []string {
	args := append([]string{}, opts.Args...)
	switch opts.Tool {
	case "nuclei":
		args = appendIfMissing(args, "-json")
		args = appendIfMissing(args, "-no-color")
	case "nikto":
		if opts.AssumeYes {
			args = ensureArgPair(args, "-ask", "no")
		}
		args = appendIfMissing(args, "-nolookup")
	case "sqlmap":
		if opts.AssumeYes {
			args = appendIfMissing(args, "--batch")
		}
		args = appendIfMissing(args, "--disable-coloring")
	case "masscan":
		// masscan can hang waiting for rate confirmation when run as non-root; ensure non-interactive output
		args = ensureArgPair(args, "--wait", "0")
	}
	return args
}

func appendIfMissing(args []string, values ...string) []string {
	if len(values) == 0 {
		return args
	}
	for _, v := range values {
		if containsArg(args, v) {
			continue
		}
		args = append(args, v)
	}
	return args
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
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

func parseStructuredOutput(tool, output string) interface{} {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	switch tool {
	case "nmap":
		return ParseNmapOutput(output)
	case "nuclei":
		return parseNucleiOutput(output)
	case "nikto":
		return parseNiktoOutput(output)
	case "masscan":
		return parseMasscanOutput(output)
	case "sqlmap":
		return parseSQLMapOutput(output)
	default:
		return nil
	}
}

func parseNucleiOutput(output string) interface{} {
	var findings []map[string]interface{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			findings = append(findings, entry)
		}
	}
	if len(findings) == 0 {
		return nil
	}
	return map[string]interface{}{"findings": findings}
}

func parseNiktoOutput(output string) interface{} {
	var findings []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "+") {
			findings = append(findings, strings.TrimSpace(strings.TrimPrefix(line, "+")))
		}
	}
	if len(findings) == 0 {
		return nil
	}
	return map[string]interface{}{"findings": findings}
}

func parseMasscanOutput(output string) interface{} {
	var openPorts []map[string]string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, "Discovered open port") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		port := fields[3]
		host := fields[len(fields)-1]
		openPorts = append(openPorts, map[string]string{
			"port": port,
			"host": host,
		})
	}
	if len(openPorts) == 0 {
		return nil
	}
	return map[string]interface{}{"open_ports": openPorts}
}

func parseSQLMapOutput(output string) interface{} {
	var (
		findings []map[string]string
		current  map[string]string
	)

	flush := func() {
		if current != nil && len(current) > 0 {
			findings = append(findings, current)
		}
		current = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			flush()
			continue
		}

		if strings.HasPrefix(line, "Parameter:") {
			if current == nil {
				current = make(map[string]string)
			}
			current["parameter"] = strings.TrimSpace(strings.TrimPrefix(line, "Parameter:"))
			continue
		}

		if strings.HasPrefix(line, "Type:") {
			if current == nil {
				current = make(map[string]string)
			}
			current["type"] = strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			continue
		}

		if strings.HasPrefix(line, "Title:") {
			if current == nil {
				current = make(map[string]string)
			}
			current["title"] = strings.TrimSpace(strings.TrimPrefix(line, "Title:"))
			continue
		}

		if strings.HasPrefix(line, "Payload:") {
			if current == nil {
				current = make(map[string]string)
			}
			current["payload"] = strings.TrimSpace(strings.TrimPrefix(line, "Payload:"))
			continue
		}

		if strings.HasPrefix(line, "Vector:") {
			if current == nil {
				current = make(map[string]string)
			}
			current["vector"] = strings.TrimSpace(strings.TrimPrefix(line, "Vector:"))
		}
	}

	flush()

	if len(findings) == 0 {
		return nil
	}

	return map[string]interface{}{"findings": findings}
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
