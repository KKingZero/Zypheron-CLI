package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/browser"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/components"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"
)

// AgentState tracks the current state of an AI agent task
type AgentState int

const (
	AgentIdle AgentState = iota
	AgentPlanning
	AgentExecuting
	AgentWaitingForUser
	AgentLookupCVE
	AgentAnalyzing
	AgentComplete
	AgentFailed
)

// ToolCall represents a tool the AI wants to execute
type ToolCall struct {
	ID       string            `json:"id"`
	Tool     string            `json:"tool"`
	Target   string            `json:"target"`
	Args     []string          `json:"args"`
	Reason   string            `json:"reason"`
	Priority int               `json:"priority"`
	Options  map[string]string `json:"options"`
}

// AgentQuestion represents a question the AI is asking the user
type AgentQuestion struct {
	ID       string   `json:"id"`
	Question string   `json:"question"`
	Options  []string `json:"options,omitempty"` // If provided, user selects from these
	Context  string   `json:"context,omitempty"` // Additional context
	Required bool     `json:"required"`
}

// AgentPlan represents the AI's execution plan
type AgentPlan struct {
	Objective string          `json:"objective"`
	Target    string          `json:"target"`
	ToolCalls []ToolCall      `json:"tool_calls"`
	Questions []AgentQuestion `json:"questions,omitempty"`
	Reasoning string          `json:"reasoning"`
}

// AgentResult holds the final result from the agent
type AgentResult struct {
	Summary         string         `json:"summary"`
	Findings        []AgentFinding `json:"findings"`
	AttackPaths     []AttackPath   `json:"attack_paths"`
	Recommendations []string       `json:"recommendations"`
}

// AgentFinding represents a discovered vulnerability or issue
type AgentFinding struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CVE         string   `json:"cve,omitempty"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	Exploits    []string `json:"exploits,omitempty"`
	Tool        string   `json:"tool"`
	Evidence    string   `json:"evidence"`
}

// CVELookupTask represents a CVE to look up
type CVELookupTask struct {
	Query   string // Product/version or CVE ID
	Source  string // Which tool found this
	Context string // Additional context
}

// AttackPath represents a suggested attack path
type AttackPath struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Tools       []string `json:"tools"`
	Risk        string   `json:"risk"`
}

// Agent manages the AI-driven multi-tool workflow
type Agent struct {
	ID          string
	Bridge      *aibridge.AIBridge
	State       AgentState
	Plan        *AgentPlan
	Results     map[string]*tools.ToolResult    // keyed by tool call ID
	CVEResults  map[string][]*browser.CVEResult // CVE lookup results keyed by query
	CurrentTool string
	Messages    []aibridge.Message // Conversation history
	UserQuery   string
	Provider    string
	ModelName   string

	// Cancellation support
	ctx    context.Context
	cancel context.CancelFunc

	// Channels for communication
	msgChan      chan tea.Msg
	questionChan chan string // User responses to questions
}

// TUI Messages for agent events
type (
	// AgentPlanMsg is sent when AI creates an execution plan
	AgentPlanMsg struct {
		AgentID string
		Plan    *AgentPlan
	}

	// AgentToolStartMsg is sent when a tool starts executing
	AgentToolStartMsg struct {
		AgentID   string
		ToolCall  ToolCall
		ToolIndex int
		Total     int
	}

	// AgentQuestionMsg is sent when AI needs user input
	AgentQuestionMsg struct {
		AgentID  string
		Question AgentQuestion
	}

	// AgentThinkingMsg is sent to show AI is processing
	AgentThinkingMsg struct {
		AgentID string
		Status  string
	}

	// AgentResultMsg is sent when agent completes
	AgentResultMsg struct {
		AgentID string
		Result  *AgentResult
	}

	// AgentErrorMsg is sent on error
	AgentErrorMsg struct {
		AgentID string
		Error   string
	}

	// AgentUserResponseMsg carries user's answer to a question
	AgentUserResponseMsg struct {
		AgentID    string
		QuestionID string
		Response   string
	}

	// AgentCVELookupMsg is sent when starting CVE lookup
	AgentCVELookupMsg struct {
		AgentID string
		Query   string
		Status  string
	}

	// AgentCVEResultMsg is sent when CVE lookup completes
	AgentCVEResultMsg struct {
		AgentID string
		CVEs    []*browser.CVEResult
		Query   string
	}
)

// NewAgent creates a new AI agent
func NewAgent(bridge *aibridge.AIBridge, provider string, modelName string) *Agent {
	ctx, cancel := context.WithCancel(context.Background())
	return &Agent{
		ID:           uuid.New().String()[:8],
		Bridge:       bridge,
		State:        AgentIdle,
		Results:      make(map[string]*tools.ToolResult),
		CVEResults:   make(map[string][]*browser.CVEResult),
		Messages:     make([]aibridge.Message, 0),
		Provider:     provider,
		ModelName:    modelName,
		ctx:          ctx,
		cancel:       cancel,
		msgChan:      make(chan tea.Msg, 100),
		questionChan: make(chan string, 1),
	}
}

// Cancel stops the agent and all running operations
func (a *Agent) Cancel() {
	if a.cancel != nil {
		a.cancel()
	}
	a.State = AgentFailed
}

// StartAgent creates a tea.Cmd that starts the agent workflow
func StartAgent(bridge *aibridge.AIBridge, userQuery, target, provider, modelName string) tea.Cmd {
	return func() tea.Msg {
		agent := NewAgent(bridge, provider, modelName)
		agent.UserQuery = userQuery

		// Start agent workflow in background
		go agent.run(target)

		return AgentThinkingMsg{
			AgentID: agent.ID,
			Status:  "Planning approach...",
		}
	}
}

// AgentDoneMsg signals the agent has finished (channel closed)
type AgentDoneMsg struct {
	AgentID string
}

// run executes the agent workflow
func (a *Agent) run(target string) {
	defer func() {
		if r := recover(); r != nil {
			// Send error on panic
			select {
			case a.msgChan <- AgentErrorMsg{AgentID: a.ID, Error: fmt.Sprintf("panic: %v", r)}:
			default:
			}
		}
		close(a.msgChan)
	}()

	// Phase 1: Planning
	a.State = AgentPlanning
	plan, err := a.createPlan(target)
	if err != nil {
		a.sendError(err.Error())
		return
	}
	a.Plan = plan

	// Send plan to TUI
	a.msgChan <- AgentPlanMsg{
		AgentID: a.ID,
		Plan:    plan,
	}

	// Phase 2: Handle pre-execution questions
	for _, q := range plan.Questions {
		a.State = AgentWaitingForUser
		a.msgChan <- AgentQuestionMsg{
			AgentID:  a.ID,
			Question: q,
		}

		// Wait for user response (with timeout)
		select {
		case response := <-a.questionChan:
			a.Messages = append(a.Messages, aibridge.Message{
				Role:    "user",
				Content: fmt.Sprintf("User answered '%s': %s", q.Question, response),
			})
		case <-time.After(5 * time.Minute):
			a.sendError("Timeout waiting for user response")
			return
		}
	}

	// Phase 3: Execute tools
	a.State = AgentExecuting
	allResults := make(map[string]interface{})

	for i, tc := range plan.ToolCalls {
		a.CurrentTool = tc.Tool

		// Notify TUI of tool start
		a.msgChan <- AgentToolStartMsg{
			AgentID:   a.ID,
			ToolCall:  tc,
			ToolIndex: i + 1,
			Total:     len(plan.ToolCalls),
		}

		// Execute tool with progress callbacks
		result, err := a.executeTool(tc)
		if err != nil {
			// Continue with other tools, don't fail completely
			a.msgChan <- components.ScanOutputMsg{
				ScanID: a.ID,
				Line:   fmt.Sprintf("Tool %s failed: %s", tc.Tool, err.Error()),
			}
			continue
		}

		a.Results[tc.ID] = result
		allResults[tc.Tool] = map[string]interface{}{
			"output":   result.Output,
			"success":  result.Success,
			"duration": result.Duration.String(),
		}

		// Send completion for this tool
		a.msgChan <- components.ScanCompleteMsg{
			ScanID:   tc.ID,
			Success:  result.Success,
			Duration: result.Duration,
		}
	}

	// Phase 4: CVE Lookup
	a.State = AgentLookupCVE
	a.msgChan <- AgentThinkingMsg{
		AgentID: a.ID,
		Status:  "Looking up CVEs for discovered services...",
	}

	// Extract service versions and CVE references from tool outputs
	cveTasks := a.extractCVELookupTasks(allResults)
	if len(cveTasks) > 0 {
		a.performCVELookups(cveTasks)
	}

	// Phase 5: Analyze results
	a.State = AgentAnalyzing
	a.msgChan <- AgentThinkingMsg{
		AgentID: a.ID,
		Status:  "Analyzing findings and generating report...",
	}

	finalResult, err := a.analyzeResults(allResults)
	if err != nil {
		a.sendError(fmt.Sprintf("Analysis failed: %s", err.Error()))
		return
	}

	// Phase 6: Complete
	a.State = AgentComplete
	a.msgChan <- AgentResultMsg{
		AgentID: a.ID,
		Result:  finalResult,
	}
}

// createPlan asks the AI to create an execution plan
func (a *Agent) createPlan(target string) (*AgentPlan, error) {
	systemPrompt := `You are a penetration testing assistant. The user wants to perform security testing.
Based on their request, create an execution plan with specific tools to run.

Respond ONLY with valid JSON in this exact format:
{
  "objective": "Brief description of the goal",
  "target": "The target system",
  "tool_calls": [
    {
      "id": "unique_id",
      "tool": "tool_name",
      "target": "target",
      "args": ["arg1", "arg2"],
      "reason": "Why this tool",
      "priority": 1
    }
  ],
  "questions": [
    {
      "id": "q1",
      "question": "Question for user?",
      "options": ["option1", "option2"],
      "required": true
    }
  ],
  "reasoning": "Overall approach explanation"
}

Available tools: nmap, nikto, nuclei, httpx, katana, gau, waybackurls, assetfinder, feroxbuster, dirsearch, wfuzz, kiterunner, newman, schemathesis, jwt-tool, gobuster, ffuf, sqlmap, hydra, amass, subfinder, masscan
Only include questions for critical decisions. Keep tool_calls focused and practical.`

	a.Messages = append(a.Messages, aibridge.Message{
		Role:    "system",
		Content: systemPrompt,
	})
	a.Messages = append(a.Messages, aibridge.Message{
		Role:    "user",
		Content: fmt.Sprintf("Target: %s\n\nRequest: %s", target, a.UserQuery),
	})

	detailed, err := a.Bridge.ChatDetailed(a.Messages, a.Provider, a.ModelName, 0.3, 2000, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create plan: %w", err)
	}
	if detailed.ApprovalRequest != nil {
		return nil, fmt.Errorf("agent planning requires runtime approval and cannot continue in JSON mode")
	}
	response := detailed.Content

	// Parse JSON response
	var plan AgentPlan

	// Extract JSON from response (might have markdown code blocks)
	jsonStr := extractJSON(response)
	if err := json.Unmarshal([]byte(jsonStr), &plan); err != nil {
		return nil, fmt.Errorf("failed to parse plan: %w (response: %s)", err, response)
	}

	// Ensure target is set
	if plan.Target == "" {
		plan.Target = target
	}

	return &plan, nil
}

// executeTool runs a single tool with progress reporting
func (a *Agent) executeTool(tc ToolCall) (*tools.ToolResult, error) {
	// Use agent's context so tools can be cancelled
	ctx := a.ctx

	// Build args with target
	args := tc.Args
	if tc.Target != "" && !containsTarget(args, tc.Target) {
		args = append(args, tc.Target)
	}

	opts := tools.TUIExecutionOptions{
		ExecutionOptions: tools.ExecutionOptions{
			Tool:    tc.Tool,
			Target:  tc.Target,
			Args:    args,
			Stream:  true,
			Timeout: 10 * time.Minute,
		},
		ScanID: tc.ID,
		OnProgress: func(scanID string, percent float64, status string) {
			select {
			case a.msgChan <- components.ScanProgressMsg{
				ScanID:  scanID,
				Percent: percent,
				Status:  status,
			}:
			default:
			}
		},
		OnFinding: func(scanID, findingType, value, severity string) {
			select {
			case a.msgChan <- components.ScanFindingMsg{
				ScanID: scanID,
				Finding: components.Finding{
					Type:      findingType,
					Value:     value,
					Severity:  severity,
					Timestamp: time.Now(),
				},
			}:
			default:
			}
		},
		OnOutput: func(scanID, line string) {
			select {
			case a.msgChan <- components.ScanOutputMsg{
				ScanID: scanID,
				Line:   line,
			}:
			default:
			}
		},
	}

	// Start the scan message
	a.msgChan <- components.ScanStartMsg{
		ScanID: tc.ID,
		Target: tc.Target,
		Tool:   tc.Tool,
	}

	// Execute
	err := tools.ExecuteForTUI(ctx, opts)

	// Build result
	result := &tools.ToolResult{
		Tool:    tc.Tool,
		Success: err == nil,
	}
	if err != nil {
		result.Error = err.Error()
	}

	return result, err
}

// analyzeResults sends all results to AI for final analysis
func (a *Agent) analyzeResults(allResults map[string]interface{}) (*AgentResult, error) {
	analysisPrompt := `Analyze these security scan results and provide:
1. A summary of findings
2. List of vulnerabilities with severity
3. Suggested attack paths using tools like Metasploit
4. Recommendations

Respond ONLY with valid JSON:
{
  "summary": "Overall summary",
  "findings": [
    {
      "type": "vulnerability type",
      "severity": "critical|high|medium|low|info",
      "title": "Short title",
      "description": "Details",
      "cve": "CVE-XXXX-XXXX if applicable",
      "tool": "which tool found it",
      "evidence": "relevant output snippet"
    }
  ],
  "attack_paths": [
    {
      "name": "Attack path name",
      "description": "What this achieves",
      "steps": ["Step 1", "Step 2"],
      "tools": ["msf module or tool"],
      "risk": "high|medium|low"
    }
  ],
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}`

	resultsJSON, _ := json.MarshalIndent(allResults, "", "  ")

	a.Messages = append(a.Messages, aibridge.Message{
		Role:    "user",
		Content: fmt.Sprintf("Scan results:\n```json\n%s\n```\n\n%s", string(resultsJSON), analysisPrompt),
	})

	detailed, err := a.Bridge.ChatDetailed(a.Messages, a.Provider, a.ModelName, 0.3, 3000, "")
	if err != nil {
		return nil, err
	}
	if detailed.ApprovalRequest != nil {
		return nil, fmt.Errorf("agent analysis requires runtime approval and cannot continue in JSON mode")
	}
	response := detailed.Content

	var result AgentResult
	jsonStr := extractJSON(response)
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		// Return a basic result with the raw response
		return &AgentResult{
			Summary: response,
		}, nil
	}

	return &result, nil
}

// sendError sends an error message
func (a *Agent) sendError(msg string) {
	a.State = AgentFailed
	a.msgChan <- AgentErrorMsg{
		AgentID: a.ID,
		Error:   msg,
	}
}

// AnswerQuestion provides a response to a pending question
func (a *Agent) AnswerQuestion(response string) {
	select {
	case a.questionChan <- response:
	default:
	}
}

// WaitForAgentUpdate returns a cmd that waits for agent messages
func WaitForAgentUpdate(agent *Agent) tea.Cmd {
	return func() tea.Msg {
		if agent == nil || agent.msgChan == nil {
			return nil
		}
		msg, ok := <-agent.msgChan
		if !ok {
			return nil
		}
		return msg
	}
}

// extractCVELookupTasks parses tool output to find service versions and CVE references
func (a *Agent) extractCVELookupTasks(allResults map[string]interface{}) []CVELookupTask {
	var tasks []CVELookupTask
	seen := make(map[string]bool)

	for toolName, resultData := range allResults {
		resultMap, ok := resultData.(map[string]interface{})
		if !ok {
			continue
		}

		output, _ := resultMap["output"].(string)
		if output == "" {
			continue
		}

		switch toolName {
		case "nmap":
			// Extract service versions from nmap output
			// Pattern: port/protocol open service version
			servicePattern := regexp.MustCompile(`\d+/tcp\s+open\s+\S+\s+(.+)`)
			matches := servicePattern.FindAllStringSubmatch(output, -1)
			for _, match := range matches {
				if len(match) >= 2 {
					version := browser.ExtractServiceVersion(match[1])
					if version != "" && !seen[version] {
						seen[version] = true
						tasks = append(tasks, CVELookupTask{
							Query:   version,
							Source:  "nmap",
							Context: match[0],
						})
					}
				}
			}

		case "nikto":
			// Extract CVE references from nikto output
			cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
			matches := cvePattern.FindAllString(output, -1)
			for _, cve := range matches {
				if !seen[cve] {
					seen[cve] = true
					tasks = append(tasks, CVELookupTask{
						Query:   cve,
						Source:  "nikto",
						Context: "Vulnerability scan finding",
					})
				}
			}

			// Also look for OSVDB references (older but still useful)
			osvdbPattern := regexp.MustCompile(`OSVDB-(\d+)`)
			osvdbMatches := osvdbPattern.FindAllStringSubmatch(output, -1)
			for _, match := range osvdbMatches {
				if len(match) >= 2 {
					query := "OSVDB-" + match[1]
					if !seen[query] {
						seen[query] = true
						tasks = append(tasks, CVELookupTask{
							Query:   query,
							Source:  "nikto",
							Context: "OSVDB reference",
						})
					}
				}
			}

		case "nuclei":
			// Extract CVE references and template IDs from nuclei output
			cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
			matches := cvePattern.FindAllString(output, -1)
			for _, cve := range matches {
				if !seen[cve] {
					seen[cve] = true
					tasks = append(tasks, CVELookupTask{
						Query:   cve,
						Source:  "nuclei",
						Context: "Template match",
					})
				}
			}

		case "sqlmap":
			// SQLmap might report specific database versions
			dbVersionPattern := regexp.MustCompile(`(?i)(mysql|postgresql|mssql|oracle|sqlite)\s*[\d.]+`)
			matches := dbVersionPattern.FindAllString(output, -1)
			for _, version := range matches {
				if !seen[version] {
					seen[version] = true
					tasks = append(tasks, CVELookupTask{
						Query:   version,
						Source:  "sqlmap",
						Context: "Database version detected",
					})
				}
			}
		}
	}

	// Limit to 10 lookups to avoid excessive API calls
	if len(tasks) > 10 {
		tasks = tasks[:10]
	}

	return tasks
}

// performCVELookups looks up CVEs for each task
func (a *Agent) performCVELookups(tasks []CVELookupTask) {
	// Try to create a CVE lookup instance (may fail if no browser)
	var lookup *browser.CVELookup

	// First try API-only lookup (no browser needed for NVD)
	lookup = browser.NewCVELookup(nil)

	for _, task := range tasks {
		a.msgChan <- AgentCVELookupMsg{
			AgentID: a.ID,
			Query:   task.Query,
			Status:  fmt.Sprintf("Looking up CVEs for %s...", task.Query),
		}

		var cves []*browser.CVEResult
		var err error

		// Check if it's a direct CVE ID lookup
		if strings.HasPrefix(strings.ToUpper(task.Query), "CVE-") {
			cve, lookupErr := lookup.LookupByCVEID(task.Query)
			if lookupErr == nil && cve != nil {
				cves = []*browser.CVEResult{cve}
			}
			err = lookupErr
		} else {
			// Product/version lookup
			result, lookupErr := lookup.LookupByProduct(task.Query)
			if lookupErr == nil && result != nil {
				cves = result.CVEs
			}
			err = lookupErr
		}

		if err != nil {
			a.msgChan <- components.ScanOutputMsg{
				ScanID: a.ID,
				Line:   fmt.Sprintf("CVE lookup for %s failed: %s", task.Query, err.Error()),
			}
			continue
		}

		if len(cves) > 0 {
			a.CVEResults[task.Query] = cves

			// Send result to TUI
			a.msgChan <- AgentCVEResultMsg{
				AgentID: a.ID,
				CVEs:    cves,
				Query:   task.Query,
			}

			// Also send as findings
			for _, cve := range cves {
				severity := cve.Severity
				if severity == "" {
					severity = "UNKNOWN"
				}

				a.msgChan <- components.ScanFindingMsg{
					ScanID: a.ID,
					Finding: components.Finding{
						Type:      "CVE",
						Value:     fmt.Sprintf("%s (CVSS: %.1f)", cve.CVEID, cve.CVSSScore),
						Severity:  severity,
						Timestamp: time.Now(),
					},
				}
			}
		}
	}
}

// Helper functions

func extractJSON(response string) string {
	// Try to find JSON in markdown code blocks
	if idx := strings.Index(response, "```json"); idx != -1 {
		start := idx + 7
		if end := strings.Index(response[start:], "```"); end != -1 {
			return strings.TrimSpace(response[start : start+end])
		}
	}

	// Try to find JSON in regular code blocks
	if idx := strings.Index(response, "```"); idx != -1 {
		start := idx + 3
		// Skip language identifier if present
		if newline := strings.Index(response[start:], "\n"); newline != -1 {
			start += newline + 1
		}
		if end := strings.Index(response[start:], "```"); end != -1 {
			return strings.TrimSpace(response[start : start+end])
		}
	}

	// Try to find raw JSON (starts with {)
	if idx := strings.Index(response, "{"); idx != -1 {
		// Find matching closing brace
		depth := 0
		for i := idx; i < len(response); i++ {
			if response[i] == '{' {
				depth++
			} else if response[i] == '}' {
				depth--
				if depth == 0 {
					return response[idx : i+1]
				}
			}
		}
	}

	return response
}

func containsTarget(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}
