package ai

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AggregatedResult represents aggregated results from multiple tools
type AggregatedResult struct {
	Target       string                 `json:"target"`
	Tools        []string               `json:"tools"`
	Results      []ToolResult           `json:"results"`
	TotalOutput  string                 `json:"total_output"`
	Summary      string                 `json:"summary"`
	AnalysisType string                 `json:"analysis_type"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Aggregator collects and structures results from multiple tools
type Aggregator struct{}

// NewAggregator creates a new aggregator instance
func NewAggregator() *Aggregator {
	return &Aggregator{}
}

// AggregateResults aggregates results from multiple tool executions
func (a *Aggregator) AggregateResults(orchestrationResult *OrchestrationResult, analysisType string) *AggregatedResult {
	aggregated := &AggregatedResult{
		Target:       orchestrationResult.Target,
		Tools:        orchestrationResult.Tools,
		Results:      orchestrationResult.Results,
		AnalysisType: analysisType,
		Metadata:     make(map[string]interface{}),
	}

	// Combine all outputs
	var outputs []string
	for _, result := range orchestrationResult.Results {
		if result.Success && result.Output != "" {
			outputs = append(outputs, fmt.Sprintf("=== %s ===\n%s", result.Tool, result.Output))
		}
	}
	aggregated.TotalOutput = strings.Join(outputs, "\n\n")

	// Generate summary
	aggregated.Summary = a.generateSummary(orchestrationResult)

	// Add metadata
	aggregated.Metadata["total_tools"] = len(orchestrationResult.Results)
	aggregated.Metadata["successful_tools"] = orchestrationResult.SuccessCount
	aggregated.Metadata["failed_tools"] = orchestrationResult.FailureCount
	aggregated.Metadata["total_duration"] = orchestrationResult.TotalTime.String()
	aggregated.Metadata["timestamp"] = time.Now().Format(time.RFC3339)

	return aggregated
}

// generateSummary generates a text summary of the orchestration results
func (a *Aggregator) generateSummary(orchestrationResult *OrchestrationResult) string {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("Analysis of %s\n", orchestrationResult.Target))
	summary.WriteString(fmt.Sprintf("Executed %d tools: %s\n", len(orchestrationResult.Tools), strings.Join(orchestrationResult.Tools, ", ")))
	summary.WriteString(fmt.Sprintf("Success: %d, Failed: %d\n", orchestrationResult.SuccessCount, orchestrationResult.FailureCount))
	summary.WriteString(fmt.Sprintf("Total duration: %s\n\n", orchestrationResult.TotalTime.Round(time.Second)))

	for _, result := range orchestrationResult.Results {
		status := "✓"
		if !result.Success {
			status = "✗"
		}
		summary.WriteString(fmt.Sprintf("%s %s (%s)\n", status, result.Tool, result.Duration.Round(time.Second)))
		if !result.Success && result.Error != "" {
			summary.WriteString(fmt.Sprintf("  Error: %s\n", result.Error))
		}
	}

	return summary.String()
}

// ToJSON converts aggregated results to JSON
func (a *Aggregator) ToJSON(aggregated *AggregatedResult) ([]byte, error) {
	return json.MarshalIndent(aggregated, "", "  ")
}

// FormatForAI formats aggregated results for AI analysis
func (a *Aggregator) FormatForAI(aggregated *AggregatedResult) string {
	var formatted strings.Builder

	formatted.WriteString(fmt.Sprintf("Target: %s\n", aggregated.Target))
	formatted.WriteString(fmt.Sprintf("Analysis Type: %s\n", aggregated.AnalysisType))
	formatted.WriteString(fmt.Sprintf("Tools Executed: %s\n\n", strings.Join(aggregated.Tools, ", ")))

	formatted.WriteString("Tool Results:\n")
	for i, result := range aggregated.Results {
		formatted.WriteString(fmt.Sprintf("\n[%d] Tool: %s\n", i+1, result.Tool))
		formatted.WriteString(fmt.Sprintf("Status: %s\n", getStatusString(result.Success)))
		formatted.WriteString(fmt.Sprintf("Duration: %s\n", result.Duration.Round(time.Second)))
		
		if result.Success {
			// Include first 500 chars of output for context
			outputPreview := result.Output
			if len(outputPreview) > 500 {
				outputPreview = outputPreview[:500] + "..."
			}
			formatted.WriteString(fmt.Sprintf("Output:\n%s\n", outputPreview))
		} else {
			formatted.WriteString(fmt.Sprintf("Error: %s\n", result.Error))
		}
	}

	formatted.WriteString("\nFull Combined Output:\n")
	formatted.WriteString(aggregated.TotalOutput)

	return formatted.String()
}

// getStatusString returns a string representation of the status
func getStatusString(success bool) string {
	if success {
		return "Success"
	}
	return "Failed"
}

