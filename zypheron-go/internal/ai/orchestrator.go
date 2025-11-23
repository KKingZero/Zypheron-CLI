package ai

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ToolResult represents the result of executing a tool
type ToolResult struct {
	Tool      string
	Success   bool
	Output    string
	Error     string
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time
}

// OrchestrationResult represents the aggregated results from multiple tools
type OrchestrationResult struct {
	Target      string
	Tools       []string
	Results     []ToolResult
	TotalTime   time.Duration
	SuccessCount int
	FailureCount int
}

// Orchestrator manages execution of multiple tools
type Orchestrator struct {
	results []ToolResult
}

// NewOrchestrator creates a new orchestrator instance
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		results: []ToolResult{},
	}
}

// ExecuteTools executes multiple tools based on intent
func (o *Orchestrator) ExecuteTools(ctx context.Context, intent *Intent, progressCallback func(string)) (*OrchestrationResult, error) {
	if len(intent.Tools) == 0 {
		return nil, fmt.Errorf("no tools specified in intent")
	}

	if intent.Target == "" {
		return nil, fmt.Errorf("no target specified in intent")
	}

	orchestrationResult := &OrchestrationResult{
		Target: intent.Target,
		Tools:  intent.Tools,
		Results: []ToolResult{},
	}

	startTime := time.Now()

	// Execute tools sequentially (can be parallelized later if needed)
	for _, tool := range intent.Tools {
		if progressCallback != nil {
			progressCallback(fmt.Sprintf("performing %s...", getToolDisplayName(tool)))
		}

		result := o.executeTool(ctx, tool, intent.Target)
		orchestrationResult.Results = append(orchestrationResult.Results, result)

		if result.Success {
			orchestrationResult.SuccessCount++
		} else {
			orchestrationResult.FailureCount++
		}
	}

	orchestrationResult.TotalTime = time.Since(startTime)

	return orchestrationResult, nil
}

// executeTool executes a single tool command
func (o *Orchestrator) executeTool(ctx context.Context, tool, target string) ToolResult {
	result := ToolResult{
		Tool:      tool,
		StartTime: time.Now(),
	}

	// Build command based on tool
	cmd := buildCommand(tool, target)
	if cmd == nil {
		result.Success = false
		result.Error = fmt.Sprintf("unknown tool: %s", tool)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	// Execute command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Create command with context
	cmdWithCtx := exec.CommandContext(cmdCtx, cmd.Path, cmd.Args[1:]...)

	// Execute the command
	output, err := cmdWithCtx.CombinedOutput()
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	result.Success = true
	result.Output = string(output)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result
}

// buildCommand builds the command to execute based on tool name
func buildCommand(tool, target string) *exec.Cmd {
	// Get the zypheron binary path - use current executable
	zypheronPath, err := os.Executable()
	if err != nil {
		// Fallback to looking up in PATH
		zypheronPath, err = exec.LookPath("zypheron")
		if err != nil {
			zypheronPath = "zypheron" // Last resort
		}
	}

	var args []string

	switch tool {
	case "scan":
		args = []string{"scan", target, "--yes", "--no-input"}
	case "osint":
		args = []string{"osint", target}
	case "recon":
		args = []string{"recon", target}
	case "forensics":
		args = []string{"forensics", target, "--yes", "--no-input"}
	case "api-pentest":
		args = []string{"api-pentest", target, "--yes", "--no-input"}
	case "reverse-eng":
		args = []string{"reverse-eng", target, "--yes", "--no-input"}
	case "fuzz":
		args = []string{"fuzz", target, "--yes", "--no-input"}
	case "secrets":
		args = []string{"secrets", target, "--yes", "--no-input"}
	case "deps":
		args = []string{"deps", target, "--yes", "--no-input"}
	case "authenticated-scan":
		args = []string{"authenticated-scan", target, "--yes", "--no-input"}
	case "pwn":
		args = []string{"pwn", target, "--yes", "--no-input"}
	default:
		return nil
	}

	return exec.Command(zypheronPath, args...)
}

// getToolDisplayName returns a user-friendly name for the tool
func getToolDisplayName(tool string) string {
	displayNames := map[string]string{
		"scan":            "security scan",
		"osint":           "OSINT",
		"recon":           "reconnaissance",
		"forensics":       "forensics analysis",
		"api-pentest":     "API testing",
		"reverse-eng":     "reverse engineering",
		"fuzz":           "fuzzing",
		"secrets":         "secret scanning",
		"deps":            "dependency analysis",
		"authenticated-scan": "authenticated scanning",
		"pwn":             "exploitation",
	}

	if name, ok := displayNames[tool]; ok {
		return name
	}

	return strings.ToUpper(tool)
}

