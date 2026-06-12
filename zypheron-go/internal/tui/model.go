package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/agents"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/aibridge"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/config"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/intel"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/components"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/styles"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/views"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type sessionState int

const (
	stateSplash sessionState = iota
	stateDashboard
	stateScan
)

const (
	dashboardHeaderHeight = 1
	minConsoleHeight      = 5
)

type Model struct {
	state  sessionState
	keys   KeyMap
	header components.Header
	splash components.SplashModel
	bridge *aibridge.AIBridge

	// Core Views
	console       views.ConsoleModel
	summary       views.SummaryModel
	input         views.InputModel
	modelSelector views.ModelSelector
	slashMenu     views.SlashMenu

	// Scan Progress (multi-scan support for concurrent execution)
	scanProgress components.MultiScanProgressModel
	scanActive   bool

	// AI Agent System
	activeAgents      map[string]*Agent
	agentActive       bool
	pendingQuestion   *AgentQuestion
	awaitingInput     bool
	pendingAgentQuery string // Stores query while waiting for target
	awaitingTarget    bool   // True when waiting for user to enter target

	// Saved Agent Management
	agentManager *agents.AgentManager

	// Deep Pentest Context - tracks full engagement state for OSCP+ workflows
	pentestCtx *PentestContext

	// Help overlay
	showHelp bool

	// Raw output view toggle (Ctrl+O)
	showRawOutput bool

	// Sudo prompt for tools requiring root privileges
	sudoPrompt     components.SudoPromptModel
	showSudoPrompt bool
	pendingScan    *ScanRequest // Scan waiting for sudo auth
	sudoCacheMode  components.SudoCacheOption

	// API key prompt for cloud model selection
	apiKeyPrompt      components.APIKeyPromptModel
	showAPIKeyPrompt  bool
	confirmedModelIdx int
	pendingModelIdx   int

	// Runtime approval prompt for shared tool execution
	approvalPrompt      components.ApprovalPromptModel
	showApprovalPrompt  bool
	pendingApprovalTask string
	pendingApprovalReq  string

	// AI processing state
	aiProcessing bool
	cancelAI     chan struct{}

	// Chat conversation history (maintains context between messages)
	chatHistory       []aibridge.Message
	runtimeSessionID  string
	lastRuntimeTaskID string
	activeAuthSession string

	// Session stats
	sessionStart int64 // Unix timestamp
	scanCount    int
	findingCount int

	// Bash command execution
	workingDir       string               // Current working directory for $ commands
	bashHistory      []string             // History of bash commands for pentest context
	activeBashCmds   map[string]*exec.Cmd // Track running bash commands
	runtimeEventSeen map[string]bool
	runtimeTaskState map[string]string

	width    int
	height   int
	quitting bool
}

func NewModel() Model {
	// Use singleton AI Bridge - avoids duplicate socket discovery
	b := aibridge.GetSharedBridge()

	ms := views.NewModelSelector(100)
	cfg := config.Get()

	// Smart Default Logic
	// Indices: 0=Claude, 1=Gemini, 2=ChatGPT, 3=Kimi, 4=local ai
	if idx := views.FindModelIndex([]string{
		views.ClaudeModelLabel,
		views.GeminiModelLabel,
		views.ChatGPTModelLabel,
		views.KimiModelLabel,
		views.LocalAIModelLabel,
	}, cfg.AIModel); idx >= 0 {
		ms.SetIndex(idx)
	} else if strings.HasPrefix(cfg.AIModel, "ollama-") || strings.EqualFold(strings.TrimSpace(cfg.AIProvider), "ollama") {
		ms.SetIndex(4)
	} else if strings.HasPrefix(cfg.AIModel, "claude-") || strings.EqualFold(strings.TrimSpace(cfg.AIProvider), "claude") || strings.EqualFold(strings.TrimSpace(cfg.AIProvider), "anthropic") {
		ms.SetIndex(0)
	} else if strings.HasPrefix(cfg.AIModel, "gemini-") || strings.EqualFold(strings.TrimSpace(cfg.AIProvider), "gemini") || strings.EqualFold(strings.TrimSpace(cfg.AIProvider), "google") {
		ms.SetIndex(1)
	} else if strings.HasPrefix(cfg.AIModel, "gpt-") || strings.EqualFold(strings.TrimSpace(cfg.AIProvider), "openai") {
		ms.SetIndex(2)
	} else if strings.HasPrefix(cfg.AIModel, "kimi-") || strings.EqualFold(strings.TrimSpace(cfg.AIProvider), "kimi") {
		ms.SetIndex(3)
	} else {
		configuredProviders := make(map[string]bool)
		for _, provider := range config.ListProviders() {
			configuredProviders[strings.ToLower(strings.TrimSpace(provider))] = true
		}

		switch {
		case configuredProviders["anthropic"]:
			ms.SetIndex(0)
		case configuredProviders["google"]:
			ms.SetIndex(1)
		case configuredProviders["openai"]:
			ms.SetIndex(2)
		case configuredProviders["kimi"]:
			ms.SetIndex(3)
		default:
			ms.SetIndex(4)
		}
	}

	summary := views.NewSummary(100)
	summary.SetModelName(ms.SelectedModel()) // Initialize with current model

	// Initialize agent manager
	agentMgr, _ := agents.NewAgentManager() // Ignore error, will be nil if fails

	// Initialize or load pentest context for deep workflow memory
	pentestCtx, _ := LoadPentestContext()

	// Get current working directory
	cwd, _ := os.Getwd()

	return Model{
		state:             stateSplash,
		keys:              DefaultKeyMap(),
		header:            components.NewHeader(),
		splash:            components.NewSplash(),
		bridge:            b,
		console:           views.NewConsole(100, 20),
		summary:           summary,
		input:             views.NewInput(100),
		modelSelector:     ms,
		slashMenu:         views.NewSlashMenu(100),
		scanProgress:      components.NewMultiScanProgress(100, 20),
		scanActive:        false,
		activeAgents:      make(map[string]*Agent),
		agentActive:       false,
		agentManager:      agentMgr,
		pentestCtx:        pentestCtx,
		awaitingInput:     false,
		showHelp:          false,
		aiProcessing:      false,
		cancelAI:          make(chan struct{}),
		chatHistory:       make([]aibridge.Message, 0),
		sessionStart:      time.Now().Unix(),
		scanCount:         0,
		findingCount:      0,
		workingDir:        cwd,
		bashHistory:       make([]string, 0),
		activeBashCmds:    make(map[string]*exec.Cmd),
		runtimeEventSeen:  make(map[string]bool),
		runtimeTaskState:  make(map[string]string),
		confirmedModelIdx: ms.SelectedIndex(),
		pendingModelIdx:   -1,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.splash.Init(),
		m.input.Init(),
		m.summary.Init(),
		m.modelSelector.Init(),
		m.scanProgress.Init(),
		pollRuntimeTasks(m.bridge, "", ""),
	)
}

// Msg types for AI
type AIResponseMsg struct {
	Content         string
	SessionID       string
	TaskID          string
	TaskStatus      string
	ToolResults     []map[string]interface{}
	ProgressEvents  []map[string]interface{}
	ApprovalRequest map[string]interface{}
}

type AIErrorMsg struct {
	Err error
}

type AICancelledMsg struct{}
type RuntimeTasksMsg struct {
	Tasks  []map[string]interface{}
	Events map[string][]map[string]interface{}
}
type RuntimeTaskErrorMsg struct {
	Err error
}
type ApprovalResultMsg struct {
	Content         string
	SessionID       string
	TaskID          string
	TaskStatus      string
	ToolResults     []map[string]interface{}
	ProgressEvents  []map[string]interface{}
	ApprovalRequest map[string]interface{}
}
type ApprovalErrorMsg struct {
	Err error
}

type quitCompleteMsg struct{}

func beginQuitSequence() tea.Cmd {
	return tea.Tick(450*time.Millisecond, func(time.Time) tea.Msg {
		return quitCompleteMsg{}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	if _, ok := msg.(quitCompleteMsg); ok {
		return m, tea.Quit
	}

	// Global Key handling
	if k, ok := msg.(tea.KeyMsg); ok {
		if key.Matches(k, m.keys.Quit) {
			m.quitting = true
			return m, beginQuitSequence()
		}

		if key.Matches(k, m.keys.Settings) && m.state == stateDashboard {
			return m, m.handleCommand("/settings")
		}

		if m.state == stateDashboard && m.input.Value() == "" && !m.slashMenu.IsOpen() && !m.modelSelector.IsOpen() {
			switch {
			case key.Matches(k, m.keys.ScanView):
				m.header = m.header.Update("scan")
				return m, nil
			case key.Matches(k, m.keys.ReconView):
				m.header = m.header.Update("recon")
				return m, nil
			case key.Matches(k, m.keys.AIView):
				m.header = m.header.Update("ai")
				return m, nil
			case key.Matches(k, m.keys.ToolsView):
				m.header = m.header.Update("tools")
				return m, nil
			case key.Matches(k, m.keys.HistoryView):
				m.header = m.header.Update("history")
				return m, nil
			}
		}

		// Close help overlay with Escape
		if m.showHelp && k.Type == tea.KeyEsc {
			m.showHelp = false
			return m, nil
		}

		// Handle sudo prompt input when active
		if m.showSudoPrompt {
			var cmd tea.Cmd
			m.sudoPrompt, cmd = m.sudoPrompt.Update(msg)
			return m, cmd
		}

		if m.showAPIKeyPrompt {
			var cmd tea.Cmd
			m.apiKeyPrompt, cmd = m.apiKeyPrompt.Update(msg)
			return m, cmd
		}

		if m.showApprovalPrompt {
			var cmd tea.Cmd
			m.approvalPrompt, cmd = m.approvalPrompt.Update(msg)
			return m, cmd
		}

		// Cancel AI processing with Escape
		if m.aiProcessing && k.Type == tea.KeyEsc {
			// Signal cancellation
			select {
			case m.cancelAI <- struct{}{}:
			default:
			}
			m.aiProcessing = false
			m.console.AppendLog(styles.WarningStyle.Render("\n[Cancelled] AI request interrupted by user\n"))
			// Create new cancel channel for next request
			m.cancelAI = make(chan struct{})
			return m, nil
		}

		// Cancel active agent with Escape
		if m.agentActive && k.Type == tea.KeyEsc {
			// Cancel all active agents
			for id, agent := range m.activeAgents {
				agent.Cancel()
				delete(m.activeAgents, id)
			}
			m.agentActive = false
			m.scanActive = false
			m.console.AppendLog(styles.WarningStyle.Render("\n[Cancelled] Agent stopped by user\n"))
			return m, nil
		}

		// Toggle help with ? key
		if k.String() == "?" && !m.showHelp && m.state == stateDashboard {
			m.showHelp = true
			return m, nil
		}

		// Open command palette with ":" and slash menu with "/" from empty input.
		if m.state == stateDashboard && !m.showHelp {
			if k.String() == ":" && m.input.Value() == "" {
				if !m.slashMenu.IsOpen() {
					m.slashMenu.Open("/")
				}
				m.input.SetValue("/")
				return m, nil
			}
			if k.String() == "/" && m.input.Value() == "" && !m.slashMenu.IsOpen() {
				m.slashMenu.Open("/")
				m.input.SetValue("/")
				return m, nil
			}
		}

		// Toggle raw output view with Ctrl+O
		if k.Type == tea.KeyCtrlO && m.state == stateDashboard {
			m.showRawOutput = !m.showRawOutput
			return m, nil
		}

		// Model Selector Toggle (Tab key)
		if k.Type == tea.KeyTab && !m.showHelp {
			m.modelSelector.Toggle()
			return m, nil // Consume key
		}

	}

	// Window Size
	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		m.width = msg.Width
		m.height = msg.Height
		m.header.Width = msg.Width

		// Layout Calc
		// Header: 3
		// Summary: 7
		// Input: 3
		// Selector: Dynamic (but overlay or below?)
		// Used available space for Console

		availableHeight := m.height - dashboardHeaderHeight - m.summary.Height() - m.bottomAreaHeight()

		inputHeight := m.input.Height()
		var inputCmd tea.Cmd
		m.input, inputCmd = m.input.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		cmds = append(cmds, inputCmd)

		consoleHeight := availableHeight - inputHeight
		if consoleHeight < minConsoleHeight {
			consoleHeight = minConsoleHeight
		}
		var consoleCmd tea.Cmd
		m.console, consoleCmd = m.console.Update(tea.WindowSizeMsg{Width: m.width, Height: consoleHeight})
		cmds = append(cmds, consoleCmd)

		// Update scan progress size
		m.scanProgress.SetSize(m.width, consoleHeight)
	}

	// State Management
	switch msg := msg.(type) {
	case components.SplashCompleteMsg:
		m.state = stateDashboard
	case AIResponseMsg:
		m.aiProcessing = false
		if msg.SessionID != "" {
			m.runtimeSessionID = msg.SessionID
		}
		if msg.TaskID != "" {
			m.lastRuntimeTaskID = msg.TaskID
		}
		if msg.TaskStatus == "waiting_approval" {
			_ = m.summary.SetStatus("Approval", "Runtime is waiting for approval", "TASK", false)
		} else {
			_ = m.summary.SetStatus("Ready", "How can I help you today?", "IDLE", false)
		}
		for _, event := range msg.ProgressEvents {
			eventType, _ := event["status"].(string)
			message, _ := event["message"].(string)
			if eventType != "" || message != "" {
				m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("[Runtime] %s %s", eventType, message)))
			}
		}
		if msg.ApprovalRequest != nil {
			m.openApprovalPrompt(msg.TaskID, msg.ApprovalRequest)
			return m, nil
		}
		m.ingestRuntimeToolResults(msg.ToolResults)
		m.console.AppendLog("\n" + styles.AIResponseStyle.Render(msg.Content) + "\n")
		// Add AI response to conversation history for context
		m.chatHistory = append(m.chatHistory, aibridge.Message{
			Role:    "assistant",
			Content: msg.Content,
		})
		return m, nil
	case AICancelledMsg:
		m.aiProcessing = false
		// Already handled by escape key, this is just cleanup
		return m, nil
	case AIErrorMsg:
		m.aiProcessing = false
		_ = m.summary.SetStatus("Error", "AI Request Failed", "ERROR", false)
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("\nError: %v\n", msg.Err)))
		return m, nil
	case RuntimeTasksMsg:
		m.handleRuntimeTasks(msg)
		return m, pollRuntimeTasks(m.bridge, m.runtimeSessionID, m.lastRuntimeTaskID)
	case RuntimeTaskErrorMsg:
		if !m.aiProcessing && !m.agentActive && !m.scanActive {
			_ = m.summary.SetStatus("Runtime", "Task sync failed", "TASK", false)
		}
		return m, pollRuntimeTasks(m.bridge, m.runtimeSessionID, m.lastRuntimeTaskID)

	// Sudo Prompt Messages
	case components.SudoAuthSuccessMsg:
		m.showSudoPrompt = false
		m.sudoCacheMode = msg.CacheOption
		m.console.AppendLog(styles.SuccessStyle.Render("✓ Sudo authentication successful"))

		// Start the pending scan now that we have sudo
		if m.pendingScan != nil {
			scan := m.pendingScan
			m.pendingScan = nil
			return m, tea.Batch(
				StartScan(*scan),
				TickForScanUpdate(),
			)
		}

		// Start pending agent if any
		if pendingAgentInfo != nil {
			info := pendingAgentInfo
			pendingAgentInfo = nil
			return m, m.startAgentWithTargetAfterSudo(info.userQuery, info.target)
		}
		return m, nil

	case components.SudoAuthFailedMsg:
		m.showSudoPrompt = false
		m.pendingScan = nil
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("✗ Sudo authentication failed: %s", msg.Error)))
		return m, nil

	case components.SudoCancelledMsg:
		m.showSudoPrompt = false
		m.pendingScan = nil
		pendingAgentInfo = nil
		m.console.AppendLog(styles.WarningStyle.Render("Sudo authentication cancelled"))
		return m, nil

	case components.APIKeySubmittedMsg:
		return m, m.storeAPIKeyAndActivateModel(msg.Provider, msg.APIKey)

	case components.APIKeyCancelledMsg:
		m.showAPIKeyPrompt = false
		m.pendingModelIdx = -1
		m.modelSelector.SetIndex(m.confirmedModelIdx)
		m.console.AppendLog(styles.WarningStyle.Render("Model change cancelled"))
		return m, nil

	case components.ApprovalSubmittedMsg:
		m.showApprovalPrompt = false
		m.pendingApprovalTask = msg.TaskID
		m.pendingApprovalReq = msg.RequestID
		m.aiProcessing = true
		spinnerCmd := m.summary.SetStatus("Approval", "Submitting runtime decision", "TASK", true)
		return m, tea.Batch(spinnerCmd, submitTaskApprovalCmd(m.bridge, msg.TaskID, msg.RequestID, msg.Decision))

	case components.ApprovalCancelledMsg:
		m.showApprovalPrompt = false
		m.pendingApprovalTask = m.approvalPrompt.TaskID
		m.pendingApprovalReq = m.approvalPrompt.RequestID
		m.console.AppendLog(styles.WarningStyle.Render("Runtime approval prompt dismissed"))
		return m, nil

	case apiKeyStoredMsg:
		m.showAPIKeyPrompt = false
		if m.pendingModelIdx >= 0 {
			m.confirmModelSelection(m.pendingModelIdx)
		}
		m.console.AppendLog(styles.SuccessStyle.Render(
			fmt.Sprintf("%s API key saved securely. Active model: %s", views.CredentialProviderLabel(msg.Provider), m.modelSelector.SelectedModel()),
		))
		return m, nil

	case apiKeyStoreErrorMsg:
		m.modelSelector.SetIndex(m.confirmedModelIdx)
		m.showAPIKeyPrompt = true
		m.apiKeyPrompt.SetError(msg.Err.Error())
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("API key validation failed: %v", msg.Err)))
		return m, nil

	case ApprovalResultMsg:
		m.aiProcessing = false
		m.pendingApprovalTask = ""
		m.pendingApprovalReq = ""
		if msg.SessionID != "" {
			m.runtimeSessionID = msg.SessionID
		}
		if msg.TaskID != "" {
			m.lastRuntimeTaskID = msg.TaskID
		}
		if msg.ApprovalRequest != nil {
			m.openApprovalPrompt(msg.TaskID, msg.ApprovalRequest)
			_ = m.summary.SetStatus("Approval", "Runtime is waiting for approval", "TASK", false)
			return m, nil
		}
		for _, event := range msg.ProgressEvents {
			eventType, _ := event["status"].(string)
			message, _ := event["message"].(string)
			if eventType != "" || message != "" {
				m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("[Runtime] %s %s", eventType, message)))
			}
		}
		if msg.Content != "" {
			m.ingestRuntimeToolResults(msg.ToolResults)
			m.console.AppendLog("\n" + styles.AIResponseStyle.Render(msg.Content) + "\n")
			m.chatHistory = append(m.chatHistory, aibridge.Message{
				Role:    "assistant",
				Content: msg.Content,
			})
		}
		_ = m.summary.SetStatus("Ready", "How can I help you today?", "IDLE", false)
		return m, nil

	case ApprovalErrorMsg:
		m.aiProcessing = false
		m.showApprovalPrompt = false
		_ = m.summary.SetStatus("Error", "Approval submission failed", "ERROR", false)
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("\nApproval error: %v\n", msg.Err)))
		return m, nil

	// Scan Progress Messages
	case components.ScanStartMsg:
		m.scanActive = true
		m.scanProgress, cmd = m.scanProgress.Update(msg)
		m.summary.IncrementScanCount()
		_ = m.summary.SetStatus("Scanning", fmt.Sprintf("%s → %s", msg.Tool, msg.Target), "SCAN", true)

		// Record in deep pentest context
		if m.pentestCtx != nil {
			m.pentestCtx.AddTarget(msg.Target)
			m.pentestCtx.AddToolExecution(ToolExecution{
				Tool:      msg.Tool,
				Target:    msg.Target,
				StartTime: time.Now(),
			})
			if err := m.pentestCtx.Save(); err != nil {
				m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("[Warning] Failed to save context: %v", err)))
			}
		}

		// Continue polling active agent if this scan is from an agent
		if m.agentActive {
			return m, tea.Batch(cmd, m.pollActiveAgent())
		}
		return m, cmd
	case components.ScanProgressMsg:
		m.scanProgress, cmd = m.scanProgress.Update(msg)
		// Continue polling active agent
		if m.agentActive {
			return m, tea.Batch(cmd, m.pollActiveAgent())
		}
		return m, cmd
	case components.ScanFindingMsg:
		m.scanProgress, cmd = m.scanProgress.Update(msg)
		m.summary.AddFindings(1)

		// Record finding in deep pentest context
		if m.pentestCtx != nil {
			finding := msg.Finding
			// Classify finding type and record appropriately
			vuln := VulnerabilityFinding{
				Type:        finding.Type,
				Title:       finding.Value,
				Description: finding.Value,
				Severity:    finding.Severity,
				Tool:        finding.Type,
				Timestamp:   finding.Timestamp,
			}
			m.pentestCtx.AddVulnerability(vuln)
			if err := m.pentestCtx.Save(); err != nil {
				m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("[Warning] Failed to save context: %v", err)))
			}
		}

		// Continue polling active agent
		if m.agentActive {
			return m, tea.Batch(cmd, m.pollActiveAgent())
		}
		return m, cmd
	case components.ScanOutputMsg:
		m.scanProgress, cmd = m.scanProgress.Update(msg)
		// Continue polling active agent
		if m.agentActive {
			return m, tea.Batch(cmd, m.pollActiveAgent())
		}
		return m, cmd
	case components.ScanCompleteMsg:
		m.scanProgress, cmd = m.scanProgress.Update(msg)
		m.scanActive = false
		if msg.Success {
			m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("✓ Scan completed in %s", msg.Duration)))
		} else {
			// Show error prominently in console since summary was removed
			m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("✗ Scan failed: %s", msg.Error)))
		}
		// Continue polling active agent for next tool
		if m.agentActive {
			return m, tea.Batch(cmd, m.pollActiveAgent())
		}
		return m, cmd

	case ScanUpdateTick:
		// Poll for scan updates while scan is active
		if m.scanActive {
			return m, tea.Batch(WaitForScanUpdate(), TickForScanUpdate())
		}
		return m, nil

	// AI Agent Messages - continue polling after each message
	case AgentPlanMsg:
		m.agentActive = true
		m.console.AppendLog(styles.SuccessStyle.Render("\n[AI Agent] Created execution plan:"))
		m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  Objective: %s", msg.Plan.Objective)))
		m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  Tools: %d planned", len(msg.Plan.ToolCalls))))
		for i, tc := range msg.Plan.ToolCalls {
			m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("    %d. %s → %s", i+1, tc.Tool, tc.Target)))
		}
		m.console.AppendLog("")
		// Continue polling for more agent messages
		if agent, ok := m.activeAgents[msg.AgentID]; ok {
			return m, tickForAgentUpdates(agent)
		}
		return m, nil

	case AgentToolStartMsg:
		m.scanActive = true
		m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("\n[%d/%d] Starting %s...", msg.ToolIndex, msg.Total, msg.ToolCall.Tool)))
		_ = m.summary.SetStatus("Agent", fmt.Sprintf("%s (%d/%d)", msg.ToolCall.Tool, msg.ToolIndex, msg.Total), "SCAN", true)
		// Continue polling for more agent messages
		if agent, ok := m.activeAgents[msg.AgentID]; ok {
			return m, tickForAgentUpdates(agent)
		}
		return m, nil

	case AgentQuestionMsg:
		m.pendingQuestion = &msg.Question
		m.awaitingInput = true
		m.console.AppendLog(styles.WarningStyle.Render("\n[AI Question] " + msg.Question.Question))
		if len(msg.Question.Options) > 0 {
			m.console.AppendLog(styles.MutedStyle.Render("  Options:"))
			for i, opt := range msg.Question.Options {
				m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("    %d. %s", i+1, opt)))
			}
		}
		m.console.AppendLog(styles.PromptStyle.Render("  Your answer: "))
		_ = m.summary.SetStatus("Waiting", "AI needs your input", "INPUT", false)
		// Continue polling for more agent messages (waits for user input)
		if agent, ok := m.activeAgents[msg.AgentID]; ok {
			return m, tickForAgentUpdates(agent)
		}
		return m, nil

	case AgentThinkingMsg:
		_ = m.summary.SetStatus("AI Agent", msg.Status, "THINKING", true)
		m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("[AI] %s", msg.Status)))
		// Continue polling for more agent messages
		if agent, ok := m.activeAgents[msg.AgentID]; ok {
			return m, tickForAgentUpdates(agent)
		}
		return m, nil

	case AgentResultMsg:
		m.agentActive = false
		m.scanActive = false
		_ = m.summary.SetStatus("Complete", "Agent finished", "DONE", false)

		// Clean up completed agent
		delete(m.activeAgents, msg.AgentID)

		// Display results
		m.console.AppendLog(styles.SuccessStyle.Render("\n" + strings.Repeat("═", 50)))
		m.console.AppendLog(styles.SuccessStyle.Render("  AI AGENT REPORT"))
		m.console.AppendLog(styles.SuccessStyle.Render(strings.Repeat("═", 50)))

		if msg.Result != nil {
			m.console.AppendLog(styles.TextStyle.Render("\n Summary:"))
			m.console.AppendLog(styles.MutedStyle.Render("  " + msg.Result.Summary))

			// Record summary as key insight in pentest context
			if m.pentestCtx != nil {
				m.pentestCtx.AddInsight(msg.Result.Summary)
			}

			if len(msg.Result.Findings) > 0 {
				m.console.AppendLog(styles.TextStyle.Render("\n Findings:"))
				for _, f := range msg.Result.Findings {
					severityStyle := styles.MutedStyle
					switch f.Severity {
					case "critical":
						severityStyle = styles.CriticalStyle
					case "high":
						severityStyle = styles.HighStyle
					case "medium":
						severityStyle = styles.MediumStyle
					}
					m.console.AppendLog(severityStyle.Render(fmt.Sprintf("  [%s] %s", strings.ToUpper(f.Severity), f.Title)))
					m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("    %s", f.Description)))

					// Record finding in pentest context
					if m.pentestCtx != nil {
						m.pentestCtx.AddVulnerability(VulnerabilityFinding{
							Title:       f.Title,
							Description: f.Description,
							Severity:    f.Severity,
							Exploitable: f.Severity == "critical" || f.Severity == "high",
						})
					}
				}
			}

			if len(msg.Result.AttackPaths) > 0 {
				m.console.AppendLog(styles.TextStyle.Render("\n Suggested Attack Paths:"))
				for i, ap := range msg.Result.AttackPaths {
					m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("  %d. %s [%s risk]", i+1, ap.Name, ap.Risk)))
					m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("     %s", ap.Description)))
					m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("     Tools: %s", strings.Join(ap.Tools, ", "))))

					// Record as pending action in pentest context
					if m.pentestCtx != nil {
						action := fmt.Sprintf("[%s] %s using %s", ap.Risk, ap.Name, strings.Join(ap.Tools, ", "))
						m.pentestCtx.AddPendingAction(action)
					}
				}
			}

			if len(msg.Result.Recommendations) > 0 {
				m.console.AppendLog(styles.TextStyle.Render("\n Recommendations:"))
				for _, rec := range msg.Result.Recommendations {
					m.console.AppendLog(styles.MutedStyle.Render("  - " + rec))

					// Record as pending action
					if m.pentestCtx != nil {
						m.pentestCtx.AddPendingAction(rec)
					}
				}
			}

			// Save pentest context
			if m.pentestCtx != nil {
				if err := m.pentestCtx.Save(); err != nil {
					m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("[Warning] Failed to save context: %v", err)))
				}
			}
		}

		m.console.AppendLog(styles.SuccessStyle.Render("\n" + strings.Repeat("═", 50) + "\n"))
		return m, nil

	case AgentErrorMsg:
		m.agentActive = false
		m.scanActive = false
		_ = m.summary.SetStatus("Error", "Agent failed", "ERROR", false)
		// Clean up failed agent
		delete(m.activeAgents, msg.AgentID)
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("\n[AI Agent Error] %s\n", msg.Error)))
		return m, nil

	case AgentDoneMsg:
		// Agent channel was closed - clean up silently
		if msg.AgentID != "" {
			delete(m.activeAgents, msg.AgentID)
		}
		// Don't set any status - the AgentResultMsg already handled that
		return m, nil

	// CVE Lookup messages from agent
	case AgentCVELookupMsg:
		m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("[CVE] %s", msg.Status)))
		// Continue polling
		if agent, ok := m.activeAgents[msg.AgentID]; ok {
			return m, tickForAgentUpdates(agent)
		}
		return m, nil

	case AgentCVEResultMsg:
		if len(msg.CVEs) > 0 {
			m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("[CVE] Found %d CVEs for %s:", len(msg.CVEs), msg.Query)))
			for _, cve := range msg.CVEs {
				severity := cve.Severity
				if severity == "" {
					severity = "UNKNOWN"
				}
				m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  - %s (CVSS: %.1f) %s", cve.CVEID, cve.CVSSScore, severity)))

				// Record CVE in deep pentest context
				if m.pentestCtx != nil {
					cveRef := CVEReference{
						CVEID:           cve.CVEID,
						Description:     cve.Description,
						Severity:        cve.Severity,
						CVSSScore:       cve.CVSSScore,
						AffectedProduct: msg.Query,
						ExploitURLs:     cve.Exploits, // browser.CVEResult uses "Exploits"
						References:      cve.References,
					}
					m.pentestCtx.AddCVE(cveRef)
				}
			}
			if m.pentestCtx != nil {
				if err := m.pentestCtx.Save(); err != nil {
					m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("[Warning] Failed to save context: %v", err)))
				}
			}
		}
		// Continue polling
		if agent, ok := m.activeAgents[msg.AgentID]; ok {
			return m, tickForAgentUpdates(agent)
		}
		return m, nil

	// Saved Agent Creation Messages
	case AgentCreatedMsg:
		m.aiProcessing = false
		_ = m.summary.SetStatus("Ready", "Agent created!", "DONE", false)

		// Save the agent
		if m.agentManager != nil && msg.Agent != nil {
			if err := m.agentManager.Save(msg.Agent); err != nil {
				m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("\nFailed to save agent: %v", err)))
				return m, nil
			}

			m.console.AppendLog(styles.SuccessStyle.Render("\n╭─ Agent Created " + strings.Repeat("─", 38) + "╮"))
			m.console.AppendLog(styles.KeyStyle.Render(fmt.Sprintf("│  Name: %s", msg.Agent.Name)))
			m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("│  ID:   %s", msg.Agent.ID)))
			m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("│  %s", msg.Agent.Description)))
			if len(msg.Agent.Tools) > 0 {
				m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("│  Tools: %s", strings.Join(msg.Agent.Tools, ", "))))
			}
			m.console.AppendLog(styles.SuccessStyle.Render("╰" + strings.Repeat("─", 55) + "╯"))
			m.console.AppendLog("")
			m.console.AppendLog(styles.MutedStyle.Render("  Use this agent:"))
			m.console.AppendLog(styles.KeyStyle.Render(fmt.Sprintf("    /agents use %s <target>", msg.Agent.ID)))
			m.console.AppendLog(styles.MutedStyle.Render("  Edit in VSCode:"))
			m.console.AppendLog(styles.KeyStyle.Render(fmt.Sprintf("    /agents edit %s", msg.Agent.ID)))
			m.console.AppendLog("")
		}
		return m, nil

	case AgentCreationErrorMsg:
		m.aiProcessing = false
		_ = m.summary.SetStatus("Error", "Agent creation failed", "ERROR", false)
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("\n[Agent Creator] Failed: %v", msg.Err)))
		return m, nil

	// Bash command results
	case bashResultMsg:
		// Display output
		if msg.Output != "" {
			lines := strings.Split(strings.TrimSuffix(msg.Output, "\n"), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "[stderr]") {
					m.console.AppendLog(styles.WarningStyle.Render(line))
				} else {
					m.console.AppendLog(styles.MutedStyle.Render(line))
				}
			}
		}

		// Show completion status
		if msg.ExitCode == 0 {
			m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("[%s] Command completed", msg.CmdID[:12])))
		} else {
			m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("[%s] Command failed (exit code: %d)", msg.CmdID[:12], msg.ExitCode)))
		}

		// Record completion in pentest context
		if m.pentestCtx != nil {
			// Update the last tool execution with end time
			if len(m.pentestCtx.ToolHistory) > 0 {
				last := &m.pentestCtx.ToolHistory[len(m.pentestCtx.ToolHistory)-1]
				if last.Tool == "bash" && last.EndTime.IsZero() {
					last.EndTime = time.Now()
					last.Success = msg.ExitCode == 0
					last.Summary = fmt.Sprintf("Exit code: %d", msg.ExitCode)
					m.pentestCtx.Save()
				}
			}
		}
		return m, nil
	}

	if m.state == stateSplash {
		m.splash, cmd = m.splash.Update(msg)
		cmds = append(cmds, cmd)
	} else {
		// Active Dashboard

		if m.showAPIKeyPrompt {
			m.apiKeyPrompt, cmd = m.apiKeyPrompt.Update(msg)
			return m, cmd
		}

		var modSelCmd tea.Cmd
		// Priority: If Selector is Open, it traps keys
		if m.modelSelector.IsOpen() {
			if k, ok := msg.(tea.KeyMsg); ok {
				if k.Type == tea.KeyEnter {
					selectedModel := m.modelSelector.SelectedModel()
					selectedIdx := m.modelSelector.SelectedIndex()
					if views.ModelRequiresAPIKey(selectedModel) && !m.hasAPIKeyForModel(selectedModel) {
						credentialProvider := views.ModelToCredentialProvider(selectedModel)
						m.apiKeyPrompt = components.NewAPIKeyPrompt(
							credentialProvider,
							views.CredentialProviderLabel(credentialProvider),
							selectedModel,
							m.width,
							m.height,
						)
						m.showAPIKeyPrompt = true
						m.pendingModelIdx = selectedIdx
						m.modelSelector.Close()
						return m, m.apiKeyPrompt.Init()
					}

					m.modelSelector.Close()
					m.confirmModelSelection(selectedIdx)
					return m, nil
				}
				if k.Type == tea.KeyEsc {
					m.modelSelector.SetIndex(m.confirmedModelIdx)
					m.modelSelector.Close()
					return m, nil
				}
			}
			m.modelSelector, modSelCmd = m.modelSelector.Update(msg)
			cmds = append(cmds, modSelCmd)
			return m, tea.Batch(cmds...) // Trap other keys (like Up/Down)
		}

		// Handle slash menu
		if m.slashMenu.IsOpen() {
			if k, ok := msg.(tea.KeyMsg); ok {
				switch k.Type {
				case tea.KeyEnter:
					// Select and execute command from menu
					selected := m.slashMenu.SelectedCommand()
					m.slashMenu.Close()
					if selected != "" {
						// Commands that need arguments: put in input for user to complete
						needsArgs := map[string]bool{
							"/scan": true, "/recon": true, "/autopent": true,
							"/ai": true, "/auth": true, "/auth test": true, "/agent": true, "/dork": true,
						}
						if needsArgs[selected] {
							m.input.SetValue(selected + " ")
							return m, nil
						}
						// Commands that don't need args: execute immediately
						m.input.Reset()
						return m, m.handleCommand(selected)
					}
					return m, nil
				case tea.KeyEsc:
					m.slashMenu.Close()
					m.input.Reset()
					return m, nil
				case tea.KeyUp, tea.KeyDown:
					var menuCmd tea.Cmd
					m.slashMenu, menuCmd = m.slashMenu.Update(msg)
					return m, menuCmd
				case tea.KeyBackspace:
					// Let input handle backspace, then update filter
					var inputCmd tea.Cmd
					m.input, inputCmd = m.input.Update(msg)
					val := m.input.Value()
					if val == "" || !strings.HasPrefix(val, "/") {
						m.slashMenu.Close()
					} else {
						m.slashMenu.SetFilter(val)
					}
					return m, inputCmd
				default:
					// Pass to input and update filter
					var inputCmd tea.Cmd
					m.input, inputCmd = m.input.Update(msg)
					m.slashMenu.SetFilter(m.input.Value())
					return m, inputCmd
				}
			}
		}

		// Selector Closed -> Input Focus Logic
		if k, ok := msg.(tea.KeyMsg); ok {
			if k.Type == tea.KeyEnter {
				// Handle Command if input not empty and Selector is Closed
				if m.input.Value() != "" {
					val := m.input.Value()
					m.input.AddToHistory(val) // Add to command history for Up/Down recall
					m.input.Reset()
					return m, m.handleCommand(val)
				}
			}
		}

		var consoleCmd tea.Cmd
		m.console, consoleCmd = m.console.Update(msg)
		cmds = append(cmds, consoleCmd)

		var summaryCmd tea.Cmd
		m.summary, summaryCmd = m.summary.Update(msg)
		cmds = append(cmds, summaryCmd)

		var inputCmd tea.Cmd
		m.input, inputCmd = m.input.Update(msg)
		cmds = append(cmds, inputCmd)

		// Reflow layout when input height changes to avoid clipping on small terminals.
		if m.width > 0 && m.height > 0 {
			consoleHeight := m.height - dashboardHeaderHeight - m.summary.Height() - m.input.Height() - m.bottomAreaHeight()
			if consoleHeight < minConsoleHeight {
				consoleHeight = minConsoleHeight
			}
			var resizeCmd tea.Cmd
			m.console, resizeCmd = m.console.Update(tea.WindowSizeMsg{Width: m.width, Height: consoleHeight})
			cmds = append(cmds, resizeCmd)
			m.scanProgress.SetSize(m.width, consoleHeight)
		}

		// Update scan progress (for spinner animation)
		if m.scanActive {
			var scanCmd tea.Cmd
			m.scanProgress, scanCmd = m.scanProgress.Update(msg)
			cmds = append(cmds, scanCmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func pollRuntimeTasks(bridge *aibridge.AIBridge, sessionID string, taskID string) tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		if strings.TrimSpace(sessionID) == "" && strings.TrimSpace(taskID) == "" {
			return RuntimeTasksMsg{Tasks: []map[string]interface{}{}, Events: map[string][]map[string]interface{}{}}
		}
		filterTaskID := taskID
		if strings.TrimSpace(sessionID) != "" {
			filterTaskID = ""
		}
		tasks, err := bridge.ListTasks(10, sessionID, filterTaskID)
		if err != nil {
			return RuntimeTaskErrorMsg{Err: err}
		}
		events := make(map[string][]map[string]interface{})
		for _, task := range tasks {
			taskID, _ := task["task_id"].(string)
			if taskID == "" {
				continue
			}
			taskEvents, err := bridge.GetTaskEvents(taskID)
			if err == nil {
				events[taskID] = taskEvents
			}
		}
		return RuntimeTasksMsg{Tasks: tasks, Events: events}
	})
}

func submitTaskApprovalCmd(bridge *aibridge.AIBridge, taskID, requestID, decision string) tea.Cmd {
	return func() tea.Msg {
		resp, err := bridge.SubmitTaskApproval(taskID, requestID, decision)
		if err != nil {
			return ApprovalErrorMsg{Err: err}
		}
		return ApprovalResultMsg{
			Content:         resp.Content,
			SessionID:       resp.SessionID,
			TaskID:          resp.TaskID,
			TaskStatus:      resp.TaskStatus,
			ToolResults:     resp.ToolResults,
			ProgressEvents:  resp.ProgressEvents,
			ApprovalRequest: resp.ApprovalRequest,
		}
	}
}

func (m *Model) openApprovalPrompt(taskID string, request map[string]interface{}) {
	toolName, _ := request["tool_name"].(string)
	reason, _ := request["reason"].(string)
	riskCategory, _ := request["risk_category"].(string)
	requestID, _ := request["request_id"].(string)
	if strings.TrimSpace(taskID) == "" || strings.TrimSpace(requestID) == "" {
		return
	}
	m.approvalPrompt = components.NewApprovalPrompt(
		toolName,
		reason,
		riskCategory,
		requestID,
		taskID,
		m.width,
		m.height,
	)
	m.pendingApprovalTask = taskID
	m.pendingApprovalReq = requestID
	m.showApprovalPrompt = true
	m.console.AppendLog(styles.WarningStyle.Render(
		fmt.Sprintf("[Approval Required] %s - %s", toolName, reason),
	))
}

func (m *Model) handleRuntimeTasks(msg RuntimeTasksMsg) {
	activeTaskCount := 0
	visibleTaskIDs := make(map[string]bool)
	for _, task := range msg.Tasks {
		taskID, _ := task["task_id"].(string)
		kind, _ := task["kind"].(string)
		status, _ := task["status"].(string)
		inputSummary, _ := task["input_summary"].(string)

		if taskID == "" {
			continue
		}
		visibleTaskIDs[taskID] = true
		if status != "completed" && status != "failed" && status != "aborted" {
			activeTaskCount++
		}

		lastStatus, seen := m.runtimeTaskState[taskID]
		if !seen {
			m.runtimeTaskState[taskID] = status
			m.console.AppendLog(styles.MutedStyle.Render(
				fmt.Sprintf("[Runtime] %s %s started: %s", kind, taskID, inputSummary),
			))
		} else if lastStatus != status {
			m.runtimeTaskState[taskID] = status
			m.console.AppendLog(styles.MutedStyle.Render(
				fmt.Sprintf("[Runtime] %s %s -> %s", kind, taskID, status),
			))
		}

		for _, event := range msg.Events[taskID] {
			eventType, _ := event["event_type"].(string)
			createdAt, _ := event["created_at"].(string)
			eventKey := fmt.Sprintf("%s|%s|%s", taskID, eventType, createdAt)
			if m.runtimeEventSeen[eventKey] {
				continue
			}
			m.runtimeEventSeen[eventKey] = true

			payload, _ := event["payload"].(map[string]interface{})
			rendered := fmt.Sprintf("[Runtime:%s] %s", taskID, eventType)
			if len(payload) > 0 {
				if description, ok := payload["description"].(string); ok && description != "" {
					rendered = fmt.Sprintf("%s - %s", rendered, description)
				} else if phase, ok := payload["phase"].(string); ok && phase != "" {
					rendered = fmt.Sprintf("%s - %s", rendered, phase)
				}
			}
			m.console.AppendLog(styles.MutedStyle.Render(rendered))
			requestID, _ := payload["request_id"].(string)
			if eventType == "approval_required" && !m.showApprovalPrompt {
				if strings.TrimSpace(requestID) != "" && taskID == m.pendingApprovalTask && requestID == m.pendingApprovalReq {
					continue
				}
				m.openApprovalPrompt(taskID, payload)
			}
		}

		if !m.showApprovalPrompt && status == "waiting_approval" {
			if metadata, ok := task["metadata"].(map[string]interface{}); ok {
				if pending, ok := metadata["pending_approval_request"].(map[string]interface{}); ok {
					requestID, _ := pending["request_id"].(string)
					if strings.TrimSpace(requestID) != "" && taskID == m.pendingApprovalTask && requestID == m.pendingApprovalReq {
						continue
					}
					m.openApprovalPrompt(taskID, pending)
				}
			}
		}
	}

	for taskID := range m.runtimeTaskState {
		if !visibleTaskIDs[taskID] {
			delete(m.runtimeTaskState, taskID)
		}
	}
	for eventKey := range m.runtimeEventSeen {
		prefix := strings.SplitN(eventKey, "|", 2)[0]
		if !visibleTaskIDs[prefix] {
			delete(m.runtimeEventSeen, eventKey)
		}
	}

	if !m.aiProcessing && !m.agentActive && !m.scanActive {
		if activeTaskCount > 0 {
			_ = m.summary.SetStatus("Runtime", fmt.Sprintf("%d shared task(s) active", activeTaskCount), "TASK", true)
		} else if len(msg.Tasks) > 0 {
			m.summary.ResetToIdle()
		}
	}
}

func (m *Model) handleCommand(cmd string) tea.Cmd {
	// Echo to console
	m.console.AppendLog(styles.UserStyle.Render("> " + cmd))

	// Handle pending target input for agent creation
	if m.awaitingTarget && m.pendingAgentQuery != "" {
		m.awaitingTarget = false
		input := strings.TrimSpace(cmd)
		query := m.pendingAgentQuery
		m.pendingAgentQuery = ""

		// First, try to extract target from the input (user might have typed a full command)
		target := extractTarget(input)

		// If no target extracted, check if raw input is a valid target
		if target == "" {
			if looksLikeTarget(input) {
				target = input
			}
		}

		// Validate we got a valid target
		if target == "" || !looksLikeTarget(target) {
			m.console.AppendLog(styles.WarningStyle.Render("Could not find a valid target in your input."))
			m.console.AppendLog(styles.MutedStyle.Render("  Please enter just the target: example.com, 192.168.1.1, or https://api.example.com"))
			m.awaitingTarget = true
			m.pendingAgentQuery = query
			return nil
		}

		// If user typed a full command, update the query with it
		if input != target && len(input) > len(target) {
			query = input
		}

		return m.startAgentWithTarget(query, target)
	}

	// Handle pending question response
	if m.awaitingInput && m.pendingQuestion != nil {
		m.awaitingInput = false
		m.pendingQuestion = nil

		// Find the agent and send response
		for _, agent := range m.activeAgents {
			agent.AnswerQuestion(cmd)
		}

		m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  Answered: %s\n", cmd)))
		return nil
	}

	// Direct bash command with $ prefix
	if strings.HasPrefix(cmd, "$") {
		bashCmd := strings.TrimPrefix(cmd, "$")
		bashCmd = strings.TrimSpace(bashCmd)
		if bashCmd == "" {
			m.console.AppendLog(styles.WarningStyle.Render("Usage: $ <command>"))
			m.console.AppendLog(styles.MutedStyle.Render("  Example: $ ls -la"))
			return nil
		}
		return m.executeBashCommand(bashCmd)
	}

	// Basic Slash Command Routing
	if strings.HasPrefix(cmd, "/") {
		parts := strings.Fields(cmd)
		switch parts[0] {
		// === Scanning Commands ===
		case "/scan":
			if len(parts) < 2 {
				m.console.AppendLog(styles.WarningStyle.Render("Usage: /scan <target> [--tool <tool>]"))
				return nil
			}

			target := parts[1]
			tool := "nmap" // default tool

			// Parse optional --tool flag
			for i := 2; i < len(parts)-1; i++ {
				if parts[i] == "--tool" && i+1 < len(parts) {
					tool = parts[i+1]
					break
				}
			}

			m.header = m.header.Update("scan")

			// Start scan with sudo check (prompts for password if needed)
			return m.startScanWithSudoCheck(ScanRequest{
				Target: target,
				Tool:   tool,
				Args:   []string{"-sV", "-sC", target},
			})

		case "/recon":
			m.header = m.header.Update("recon")
			if len(parts) < 2 {
				_ = m.summary.SetStatus("Recon", "Usage: /recon <domain>", "RECON", false)
			} else {
				_ = m.summary.SetStatus("Recon Mode", fmt.Sprintf("Target: %s", parts[1]), "RECON", false)
			}

		case "/autopent":
			if len(parts) < 2 {
				m.console.AppendLog(styles.WarningStyle.Render("Usage: /autopent <target>"))
				return nil
			}
			return m.startAgentTask("autonomous pentest " + parts[1])

		// === AI Commands ===
		case "/ai":
			if len(parts) < 2 {
				m.console.AppendLog(styles.WarningStyle.Render("Usage: /ai <question>"))
				return nil
			}
			query := strings.Join(parts[1:], " ")
			m.header = m.header.Update("ai")
			return m.handleCommand(query) // Re-route as chat

		case "/auth":
			m.header = m.header.Update("ai")
			if len(parts) < 2 {
				m.console.AppendLog(styles.WarningStyle.Render("Usage: /auth use <session-id> | /auth status | /auth clear | /auth test <url> [idor|sqli|authz] [key=value ...]"))
				return nil
			}
			switch parts[1] {
			case "use":
				if len(parts) < 3 {
					m.console.AppendLog(styles.WarningStyle.Render("Usage: /auth use <session-id>"))
					return nil
				}
				m.activeAuthSession = strings.TrimSpace(parts[2])
				m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("Authenticated runtime session set: %s", m.activeAuthSession)))
				m.refreshSystemPromptWithFindings()
				return nil
			case "clear":
				m.activeAuthSession = ""
				m.console.AppendLog(styles.WarningStyle.Render("Cleared authenticated runtime session"))
				m.refreshSystemPromptWithFindings()
				return nil
			case "status":
				if m.activeAuthSession == "" {
					m.console.AppendLog(styles.MutedStyle.Render("No authenticated runtime session is active"))
				} else {
					m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("Active authenticated runtime session: %s", m.activeAuthSession)))
				}
				return nil
			case "test":
				if len(parts) < 3 {
					m.console.AppendLog(styles.WarningStyle.Render("Usage: /auth test <url> [idor|sqli|authz] [key=value ...]"))
					return nil
				}
				testType := "idor"
				argStart := 3
				if len(parts) >= 4 && !strings.Contains(parts[3], "=") {
					testType = strings.ToLower(parts[3])
					argStart = 4
				}
				target := parts[2]
				metadata := m.buildAuthTestMetadata(parts[argStart:])
				if _, ok := metadata["session_id"]; !ok && m.activeAuthSession != "" {
					metadata["session_id"] = m.activeAuthSession
				}
				if sessionID, _ := metadata["session_id"].(string); strings.TrimSpace(sessionID) == "" {
					m.console.AppendLog(styles.WarningStyle.Render("Set an authenticated runtime session first with /auth use <session-id> or pass session_id=<value>"))
					return nil
				}
				query := fmt.Sprintf("run authenticated %s checks on %s", mapAuthTestKind(testType), target)
				if method, ok := metadata["method"].(string); ok && method != "" {
					query += fmt.Sprintf(" using method %s", method)
				}
				return m.handleAIChat(query, metadata)
			default:
				m.console.AppendLog(styles.WarningStyle.Render("Usage: /auth use <session-id> | /auth status | /auth clear | /auth test <url> [idor|sqli|authz] [key=value ...]"))
				return nil
			}

		case "/agent":
			m.header = m.header.Update("ai")
			if len(parts) < 2 {
				m.console.AppendLog(styles.WarningStyle.Render("Usage: /agent <description>"))
				m.console.AppendLog(styles.MutedStyle.Render("  Creates a custom AI agent from your description"))
				m.console.AppendLog(styles.MutedStyle.Render("  Example: /agent make an aggressive recon agent that uses all available tools"))
				return nil
			}
			description := strings.Join(parts[1:], " ")
			return m.createAgentFromDescription(description)

		case "/agents":
			m.header = m.header.Update("ai")
			// Handle subcommands: /agents delete <id>, /agents edit <id>, /agents use <id>
			if len(parts) >= 3 {
				subCmd := parts[1]
				agentID := parts[2]
				switch subCmd {
				case "delete", "rm", "remove":
					return m.deleteAgent(agentID)
				case "edit", "open":
					return m.openAgentInEditor(agentID)
				case "use", "run", "activate":
					return m.useAgent(agentID, strings.Join(parts[3:], " "))
				}
			}
			// List all saved agents
			return m.listSavedAgents()

		case "/dork":
			if len(parts) < 2 {
				m.console.AppendLog(styles.WarningStyle.Render("Usage: /dork <query>"))
				return nil
			}
			query := strings.Join(parts[1:], " ")
			return m.startAgentTask("generate search dorks for " + query)

		// === Settings & Config ===
		case "/apis":
			m.console.AppendLog(m.renderPanel("API Configuration", []string{
				"",
				styles.MutedStyle.Render("Configure with:") + " zypheron config set-key <provider>",
				"",
			}, m.renderAPIStatus()))

		case "/settings":
			cfg := config.Get()
			m.console.AppendLog(m.renderPanel("Settings", []string{
				"",
				styles.KeyStyle.Render("  AI Settings:"),
				fmt.Sprintf("    %-14s %s", styles.MutedStyle.Render("Provider:"), cfg.AIProvider),
				fmt.Sprintf("    %-14s %s", styles.MutedStyle.Render("Model:"), cfg.AIModel),
				fmt.Sprintf("    %-14s %.1f", styles.MutedStyle.Render("Temperature:"), cfg.AITemperature),
				"",
				styles.KeyStyle.Render("  Scanning:"),
				fmt.Sprintf("    %-14s %s", styles.MutedStyle.Render("Default Ports:"), cfg.DefaultPorts),
				fmt.Sprintf("    %-14s %ds", styles.MutedStyle.Render("Timeout:"), cfg.ScanTimeoutSec),
				fmt.Sprintf("    %-14s %d", styles.MutedStyle.Render("Max Concurrent:"), cfg.MaxConcurrentScans),
				"",
				styles.KeyStyle.Render("  UI:"),
				fmt.Sprintf("    %-14s %s", styles.MutedStyle.Render("Theme:"), cfg.Theme),
				fmt.Sprintf("    %-14s %s", styles.MutedStyle.Render("Color Scheme:"), cfg.ColorScheme),
				fmt.Sprintf("    %-14s %v", styles.MutedStyle.Render("Show Splash:"), cfg.ShowSplash),
				"",
				styles.KeyStyle.Render("  Session:"),
				fmt.Sprintf("    %-14s %v", styles.MutedStyle.Render("Auto-Save:"), cfg.AutoSaveSession),
				fmt.Sprintf("    %-14s %d days", styles.MutedStyle.Render("History:"), cfg.MaxHistoryDays),
				"",
				styles.MutedStyle.Render("  Config: ~/.zypheron/config.json"),
				styles.MutedStyle.Render("  Press Tab to change AI model"),
				"",
			}, nil))

		case "/providers":
			m.console.AppendLog(m.renderPanel("AI Providers", []string{
				"",
				styles.KeyStyle.Render("  Cloud:"),
				"    Claude    " + styles.MutedStyle.Render("ANTHROPIC_API_KEY"),
				"    GPT-5     " + styles.MutedStyle.Render("OPENAI_API_KEY"),
				"    Gemini    " + styles.MutedStyle.Render("GEMINI_API_KEY"),
				"    DeepSeek  " + styles.MutedStyle.Render("DEEPSEEK_API_KEY"),
				"    Grok      " + styles.MutedStyle.Render("XAI_API_KEY"),
				"",
				styles.KeyStyle.Render("  Local (Ollama):"),
				"    Llama-3, Mistral, DeepSeek-local",
				"",
			}, nil))

		// === Account ===
		case "/account":
			m.console.AppendLog(m.renderPanel("Account", []string{
				"",
				fmt.Sprintf("  %-10s %s", styles.MutedStyle.Render("Status:"), styles.SuccessStyle.Render("Free Tier")),
				fmt.Sprintf("  %-10s %s", styles.MutedStyle.Render("Email:"), "Not linked"),
				"",
				styles.MutedStyle.Render("  Link: zypheron auth login"),
				"",
			}, nil))

		case "/plan":
			m.console.AppendLog(m.renderPanel("Subscription Plan", []string{
				"",
				"  " + styles.SuccessStyle.Render("Current: FREE"),
				"",
			}, m.renderPlanTable()))

		case "/upgrade":
			m.console.AppendLog(m.renderPanel("Upgrade Account", []string{
				"",
				"  " + styles.SuccessStyle.Render("All tiers FREE during beta!"),
				"",
				"  " + styles.KeyStyle.Render("https://zypheron.net/upgrade"),
				"",
			}, nil))

		case "/usage":
			duration := time.Since(time.Unix(m.sessionStart, 0))
			m.console.AppendLog(m.renderPanel("Usage Statistics", []string{
				"",
				fmt.Sprintf("  %-12s %s", styles.MutedStyle.Render("Session:"), styles.KeyStyle.Render(duration.Round(time.Second).String())),
				fmt.Sprintf("  %-12s %s", styles.MutedStyle.Render("Scans:"), fmt.Sprintf("%d", m.summary.ScanCount)),
				fmt.Sprintf("  %-12s %s", styles.MutedStyle.Render("Findings:"), fmt.Sprintf("%d", m.summary.FindingCount)),
				fmt.Sprintf("  %-12s %s", styles.MutedStyle.Render("AI Msgs:"), fmt.Sprintf("%d", len(m.chatHistory))),
				"",
			}, nil))

		// === Tools ===
		case "/tools":
			m.header = m.header.Update("tools")
			m.console.AppendLog(m.renderPanel("Available Tools", nil, m.renderToolsTable()))

		case "/history":
			m.header = m.header.Update("history")
			m.console.AppendLog(m.renderPanel("Scan History", []string{
				"",
				styles.MutedStyle.Render("  No scans in history yet"),
				"",
			}, nil))

		case "/export":
			m.console.AppendLog(m.renderPanel("Export Results", []string{
				"",
				"  " + styles.KeyStyle.Render("Usage:") + " /export <format> [filename]",
				"",
				"  " + styles.MutedStyle.Render("Formats:") + " json, html, pdf, csv",
				"",
			}, nil))

		// === System ===
		case "/help":
			m.showHelp = true
			return nil

		case "/clear":
			m.console = views.NewConsole(m.width, m.height-15)
			m.summary.ResetToIdle()

		case "/context":
			// Show current pentest context
			if m.pentestCtx == nil {
				m.console.AppendLog(styles.WarningStyle.Render("No pentest context loaded"))
				return nil
			}

			// Check for "full" subcommand
			if len(parts) >= 2 && parts[1] == "full" {
				// Show full pentest context (AI-formatted)
				m.console.AppendLog(styles.AIStyle.Render("\n" + m.pentestCtx.BuildAIContext()))
				return nil
			}

			// Show summary view
			stats := m.pentestCtx.GetSummaryStats()
			m.console.AppendLog(styles.AIStyle.Render("\n╭─ Pentest Context " + strings.Repeat("─", 38) + "╮"))
			m.console.AppendLog(fmt.Sprintf("│  Phase: %s", styles.KeyStyle.Render(string(m.pentestCtx.CurrentPhase))))
			m.console.AppendLog(fmt.Sprintf("│  Duration: %s", time.Since(m.pentestCtx.StartTime).Round(time.Minute)))
			m.console.AppendLog("│")
			m.console.AppendLog(fmt.Sprintf("│  Services:       %d", stats["services"]))
			m.console.AppendLog(fmt.Sprintf("│  Endpoints:      %d", stats["endpoints"]))
			m.console.AppendLog(fmt.Sprintf("│  Vulnerabilities: %d (%d critical, %d high)",
				stats["vulns"], stats["vulns_critical"], stats["vulns_high"]))
			m.console.AppendLog(fmt.Sprintf("│  CVEs:           %d", stats["cves"]))
			m.console.AppendLog(fmt.Sprintf("│  Credentials:    %d", stats["credentials"]))
			m.console.AppendLog(fmt.Sprintf("│  Tools Run:      %d", stats["tools_run"]))
			m.console.AppendLog("│")
			if len(m.pentestCtx.PrimaryTargets) > 0 {
				m.console.AppendLog(fmt.Sprintf("│  Targets: %s", strings.Join(m.pentestCtx.PrimaryTargets, ", ")))
			}
			m.console.AppendLog(styles.AIStyle.Render("╰" + strings.Repeat("─", 56) + "╯"))
			m.console.AppendLog(styles.MutedStyle.Render("  Use /context full for detailed view"))

		case "/reset":
			// Reset pentest context for new engagement
			if m.pentestCtx != nil {
				m.pentestCtx.Reset()
				if err := m.pentestCtx.Save(); err != nil {
					m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("[Warning] Failed to save context: %v", err)))
				}
			}
			m.chatHistory = make([]aibridge.Message, 0)
			m.activeAuthSession = ""
			m.summary.ScanCount = 0
			m.summary.FindingCount = 0
			m.console.AppendLog(styles.SuccessStyle.Render("\n[Reset] Pentest context cleared for new engagement"))
			m.console.AppendLog(styles.MutedStyle.Render("  All discovered services, vulns, and CVEs have been cleared"))

		case "/doctor":
			m.console.AppendLog(m.renderDoctorCheck())

		case "/quit", "/exit":
			m.quitting = true
			return beginQuitSequence()

		default:
			m.console.AppendLog(styles.ErrorStyle.Render("Unknown command: " + parts[0]))
			m.console.AppendLog(styles.MutedStyle.Render("  Type / to see available commands"))
		}
		return nil
	}

	// Use rule-based intent classifier
	intent := ClassifyIntent(cmd, m.summary.FindingCount > 0)

	switch intent.Type {
	case IntentCommand:
		// Already handled by slash command routing above
		return nil

	case IntentScan:
		if intent.NeedsTarget {
			m.console.AppendLog(styles.WarningStyle.Render("What target would you like to scan?"))
			m.console.AppendLog(styles.MutedStyle.Render("  Examples: example.com, 192.168.1.1, https://api.example.com"))
			m.awaitingTarget = true
			m.pendingAgentQuery = cmd
			return nil
		}
		return m.startAgentTask(cmd)

	case IntentClarify:
		m.console.AppendLog(styles.MutedStyle.Render("Could you provide more details about what you'd like to do?"))
		m.console.AppendLog(styles.MutedStyle.Render("Examples:"))
		m.console.AppendLog(styles.KeyStyle.Render("  - 'scan example.com' to start a security scan"))
		m.console.AppendLog(styles.KeyStyle.Render("  - 'what vulnerabilities did you find?' to discuss results"))
		m.console.AppendLog(styles.KeyStyle.Render("  - 'explain port 22' for security information"))
		return nil

	case IntentFollowUp:
		// Ensure findings are in context before chatting
		m.refreshSystemPromptWithFindings()
		// Fall through to normal chat with enhanced context
	}

	return m.handleAIChat(cmd, nil)
}

func (m *Model) handleAIChat(cmd string, overrideMetadata map[string]interface{}) tea.Cmd {
	modelName := m.modelSelector.SelectedModel()
	m.aiProcessing = true
	spinnerCmd := m.summary.SetStatus("Processing", fmt.Sprintf("AI: %s (Esc to cancel)", modelName), "THINKING", true)

	if len(m.chatHistory) == 0 {
		m.chatHistory = append(m.chatHistory, aibridge.Message{
			Role:    "system",
			Content: m.buildContextAwareSystemPrompt(),
		})
	} else if m.summary.FindingCount > 0 || m.activeAuthSession != "" {
		m.refreshSystemPromptWithFindings()
	}

	messageMetadata := m.buildRuntimeMessageMetadata(cmd)
	for key, value := range overrideMetadata {
		messageMetadata[key] = value
	}

	m.chatHistory = append(m.chatHistory, aibridge.Message{
		Role:     "user",
		Content:  cmd,
		Metadata: messageMetadata,
	})

	if len(m.chatHistory) > 21 {
		m.chatHistory = append(m.chatHistory[:1], m.chatHistory[len(m.chatHistory)-20:]...)
	}

	cancelCh := m.cancelAI
	messages := make([]aibridge.Message, len(m.chatHistory))
	copy(messages, m.chatHistory)
	sessionID := m.runtimeSessionID

	aiCmd := func() tea.Msg {
		provider := views.ModelToProvider(modelName)
		engineModel := views.ModelToEngineModel(modelName)
		if provider == "" {
			provider = "ollama"
		}

		resultCh := make(chan tea.Msg, 1)

		go func() {
			resp, err := m.bridge.ChatDetailed(messages, provider, engineModel, 0.7, 1500, sessionID)
			if err != nil {
				resultCh <- AIErrorMsg{Err: err}
				return
			}
			resultCh <- AIResponseMsg{
				Content:         resp.Content,
				SessionID:       resp.SessionID,
				TaskID:          resp.TaskID,
				TaskStatus:      resp.TaskStatus,
				ToolResults:     resp.ToolResults,
				ProgressEvents:  resp.ProgressEvents,
				ApprovalRequest: resp.ApprovalRequest,
			}
		}()

		select {
		case result := <-resultCh:
			return result
		case <-cancelCh:
			return AICancelledMsg{}
		}
	}

	return tea.Batch(spinnerCmd, aiCmd)
}

func (m *Model) buildRuntimeMessageMetadata(cmd string) map[string]interface{} {
	metadata := map[string]interface{}{}
	if m.activeAuthSession != "" && queryNeedsAuthenticatedRuntime(cmd) {
		metadata["session_id"] = m.activeAuthSession
	}
	for key, value := range parseInlineRuntimeMetadata(cmd) {
		metadata[key] = value
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

func (m *Model) buildAuthTestMetadata(args []string) map[string]interface{} {
	metadata := map[string]interface{}{}
	for key, value := range parseRuntimeKeyValuePairs(args) {
		metadata[key] = value
	}
	return metadata
}

func queryNeedsAuthenticatedRuntime(cmd string) bool {
	lower := strings.ToLower(cmd)
	keywords := []string{"authenticated", "idor", "bola", "bfla", "authorization", "privilege escalation", "session", "cookie"}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func parseInlineRuntimeMetadata(cmd string) map[string]interface{} {
	return parseRuntimeKeyValuePairs(strings.Fields(cmd))
}

func parseRuntimeKeyValuePairs(tokens []string) map[string]interface{} {
	metadata := map[string]interface{}{}
	headers := map[string]string{}
	for _, token := range tokens {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if value == "" {
			continue
		}

		switch key {
		case "session_id", "auth_session_id":
			metadata["session_id"] = value
		case "method":
			metadata["method"] = strings.ToUpper(value)
		case "data":
			metadata["data"] = value
		case "required_role":
			metadata["required_role"] = value
		case "actual_role":
			metadata["actual_role"] = value
		case "target_user_id":
			metadata["target_user_id"] = value
		default:
			if strings.HasPrefix(key, "header.") {
				headerName := strings.TrimSpace(parts[0][len("header."):])
				if headerName != "" {
					headers[headerName] = value
				}
			}
		}
	}
	if len(headers) > 0 {
		metadata["headers"] = headers
	}
	return metadata
}

func mapAuthTestKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "sqli", "sqlmap", "sql":
		return "sql injection"
	case "authz", "authorization", "bfla":
		return "authorization"
	default:
		return "idor"
	}
}

// startAgentTask initiates an AI agent for a security task
func (m *Model) startAgentTask(userQuery string) tea.Cmd {
	// Extract target from query
	target := extractTarget(userQuery)
	if target == "" {
		// Store the query and ask user for target
		m.pendingAgentQuery = userQuery
		m.awaitingTarget = true
		m.console.AppendLog(styles.WarningStyle.Render("\n[AI Agent] No target detected in your request."))
		m.console.AppendLog(styles.MutedStyle.Render("  Please enter the target (domain, IP, or URL):"))
		m.console.AppendLog(styles.MutedStyle.Render("  Examples: example.com, 192.168.1.1, https://api.example.com"))
		_ = m.summary.SetStatus("Waiting", "Enter target", "INPUT", false)
		return nil
	}

	return m.startAgentWithTarget(userQuery, target)
}

// pendingAgentStart stores agent start info while waiting for sudo
type pendingAgentStart struct {
	userQuery string
	target    string
}

var pendingAgentInfo *pendingAgentStart

// startAgentWithTarget starts an agent with the given target
func (m *Model) startAgentWithTarget(userQuery, target string) tea.Cmd {
	// Agents typically use nmap, masscan, etc. - check for sudo proactively
	if !canSudoWithoutPassword() {
		// Store agent info and show sudo prompt
		pendingAgentInfo = &pendingAgentStart{
			userQuery: userQuery,
			target:    target,
		}
		m.sudoPrompt = components.NewSudoPrompt("security scanning tools", m.width, m.height)
		m.showSudoPrompt = true
		return m.sudoPrompt.Init()
	}

	return m.startAgentWithTargetAfterSudo(userQuery, target)
}

// startAgentWithTargetAfterSudo actually starts the agent (called after sudo auth)
func (m *Model) startAgentWithTargetAfterSudo(userQuery, target string) tea.Cmd {
	m.header = m.header.Update("agents")
	m.agentActive = true

	modelName := m.modelSelector.SelectedModel()
	provider := views.ModelToProvider(modelName)
	engineModel := views.ModelToEngineModel(modelName)
	if provider == "" {
		provider = "ollama"
	}

	m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("\n[AI Agent] Starting task with %s...", modelName)))
	m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  Target: %s", target)))
	m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  Query: %s\n", userQuery)))

	// Create agent and start
	agent := NewAgent(m.bridge, provider, engineModel)
	agent.UserQuery = userQuery
	m.activeAgents[agent.ID] = agent

	return tea.Batch(
		func() tea.Msg {
			go agent.run(target)
			return AgentThinkingMsg{AgentID: agent.ID, Status: "Planning approach..."}
		},
		tickForAgentUpdates(agent),
	)
}

// isSecurityTaskRequest checks if input looks like a security task
// Deprecated: Use ClassifyIntent for better classification
func isSecurityTaskRequest(input string) bool {
	lower := strings.ToLower(input)

	// Keywords that indicate a security task or agent request
	securityKeywords := []string{
		// Agent creation keywords
		"create an agent", "make an agent", "start an agent", "launch an agent",
		"create agent", "make agent", "start agent", "launch agent",
		"be my agent", "act as agent", "agent mode",
		// Security task keywords
		"scan", "test", "check", "find", "look for", "search for",
		"vulnerabilities", "vulns", "exploit", "attack",
		"nmap", "nikto", "nuclei", "gobuster", "sqlmap", "hydra",
		"ports", "services", "directories", "endpoints",
		"pentest", "penetration", "security",
		"use ", "run ", "execute",
		"reconnaissance", "recon ", "enumerate", "discover",
	}

	for _, kw := range securityKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}

	return false
}

// buildContextAwareSystemPrompt creates a system prompt with full pentest engagement context
func (m *Model) buildContextAwareSystemPrompt() string {
	basePrompt := `You are Zypheron, an AI assistant for penetration testing and security operations.

Personality:
- Professional and direct - you get to the point
- Technically precise - accuracy matters in security work
- Occasionally dry humor when appropriate (subtle, not forced)
- Treat users as fellow security professionals

Communication style:
- Concise responses - no fluff or excessive explanations
- Use technical terminology appropriately
- Format output for terminal readability (short lines, clear structure)
- When explaining attacks or techniques, be practical and actionable

Context:
- You're integrated into Zypheron CLI, a penetration testing platform
- Users can execute scans, run tools, and perform security assessments
- You have access to tools like nmap, nikto, nuclei, gobuster, sqlmap, etc.
- Assume authorized testing context (pentest engagement, bug bounty, CTF)

Capabilities:
- Reference any services, endpoints, vulnerabilities, or CVEs discovered in this engagement
- Suggest exploit modifications based on discovered service versions
- Recommend attack paths based on discovered vulnerabilities and CVEs
- Help customize MSF modules or other exploits to match the exact target environment
- Track the full engagement state across multiple scans and tool runs

Remember: Keep responses focused and useful. Security professionals value efficiency.`

	basePrompt += "\n\nWhen recommending recon, OSINT, or vuln-enrichment steps, you may suggest these external analyst resources when they fit the task.\nDo not imply Zypheron can query them directly unless the current workflow or configured integrations support that step:\n" + intel.AnalystPromptBlock() + `

Use them intentionally:
- vuln/CVE enrichment: Vulners, LeakIX, Pulsedive, GreyNoise
- exposed infrastructure: Shodan, Censys, FOFA, ZoomEye, Netlas, BinaryEdge, IVRE
- cert/subdomain pivots: crt.sh, Censys
- code and secret discovery: grep.app, Searchcode, PublicWWW
- broader OSINT and attack surface: Intelligence X, FullHunt, urlscan, Hunter, SOCRadar, Onyphe, WiGLE`

	if m.activeAuthSession != "" {
		basePrompt += fmt.Sprintf("\n\nAuthenticated runtime context:\n- Active session_id: %s\n- If the user asks for authenticated testing, prefer using this stored session unless they override it.\n", m.activeAuthSession)
	}

	// Add deep pentest context if available
	if m.pentestCtx != nil {
		stats := m.pentestCtx.GetSummaryStats()
		hasContent := stats["services"] > 0 || stats["endpoints"] > 0 || stats["vulns"] > 0 ||
			stats["cves"] > 0 || stats["tools_run"] > 0

		if hasContent {
			// Use the comprehensive context from PentestContext
			basePrompt += "\n\n" + m.pentestCtx.BuildAIContext()
			basePrompt += "\n\n---\nWhen the user refers to 'the scan', 'the vulnerability', 'that CVE', 'the API endpoint', etc., use the context above. When they ask about exploits or attack paths, reference the discovered services, CVEs, and their known exploits."
		}
	}

	// Fallback: Also include basic scan progress findings if no deep context
	if m.pentestCtx == nil || m.pentestCtx.GetSummaryStats()["tools_run"] == 0 {
		findings := m.scanProgress.GetAllFindings()
		if m.summary.FindingCount > 0 || len(findings) > 0 {
			basePrompt += "\n\n## Recent Scan Findings\n"
			basePrompt += fmt.Sprintf("- Scans completed: %d\n", m.summary.ScanCount)
			basePrompt += fmt.Sprintf("- Findings discovered: %d\n", m.summary.FindingCount)

			if len(findings) > 0 {
				basePrompt += "\n### Latest Findings:\n"
				for _, f := range findings {
					basePrompt += fmt.Sprintf("- [%s] %s\n", strings.ToUpper(f.Severity), f.Value)
				}
			}
		}
	}

	return basePrompt
}

func (m *Model) ingestRuntimeToolResults(toolResults []map[string]interface{}) {
	if len(toolResults) == 0 {
		return
	}

	findingsAdded := 0
	for _, result := range toolResults {
		toolName, _ := result["tool_name"].(string)
		data, _ := result["data"].(map[string]interface{})
		evidence, _ := data["evidence"].(map[string]interface{})
		target, _ := evidence["target"].(string)
		if target == "" {
			if value, ok := data["url"].(string); ok {
				target = value
			}
		}
		if target != "" && m.pentestCtx != nil {
			m.pentestCtx.AddTarget(target)
		}

		if findings, ok := evidence["findings"].([]interface{}); ok {
			for _, rawFinding := range findings {
				findingMap, ok := rawFinding.(map[string]interface{})
				if !ok {
					continue
				}
				title, _ := findingMap["title"].(string)
				if title == "" {
					continue
				}
				severity, _ := findingMap["severity"].(string)
				description, _ := findingMap["description"].(string)
				findingEvidence, _ := findingMap["evidence"].(string)
				affectedURL, _ := findingMap["url"].(string)
				if affectedURL == "" {
					affectedURL = target
				}

				if m.pentestCtx != nil {
					m.pentestCtx.AddVulnerability(VulnerabilityFinding{
						Type:        toolName,
						Title:       title,
						Description: description,
						Severity:    severity,
						AffectedURL: affectedURL,
						Evidence:    findingEvidence,
						Tool:        toolName,
						Exploitable: strings.EqualFold(severity, "critical") || strings.EqualFold(severity, "high"),
					})
				}
				m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("[Validated %s] %s", strings.ToUpper(severity), title)))
				findingsAdded++
			}
		}
	}

	if findingsAdded > 0 {
		m.summary.AddFindings(findingsAdded)
		m.refreshSystemPromptWithFindings()
	}
}

// refreshSystemPromptWithFindings updates system prompt with current findings
func (m *Model) refreshSystemPromptWithFindings() {
	systemPrompt := m.buildContextAwareSystemPrompt()

	if len(m.chatHistory) > 0 && m.chatHistory[0].Role == "system" {
		m.chatHistory[0].Content = systemPrompt
	} else {
		// Insert at beginning
		m.chatHistory = append([]aibridge.Message{{
			Role:    "system",
			Content: systemPrompt,
		}}, m.chatHistory...)
	}
}

// extractTarget extracts a target from user query
func extractTarget(query string) string {
	lower := strings.ToLower(query)

	// Common patterns
	patterns := []string{
		"scan ", "test ", "attack ", "check ",
		"against ", "on ", "target ",
	}

	for _, pattern := range patterns {
		if idx := strings.Index(lower, pattern); idx != -1 {
			// Get word after pattern
			rest := query[idx+len(pattern):]
			words := strings.Fields(rest)
			if len(words) > 0 {
				target := words[0]
				// Clean up target
				target = strings.Trim(target, ".,!?\"'")
				// Check if it looks like a target (domain, IP, URL)
				if looksLikeTarget(target) {
					return target
				}
			}
		}
	}

	// Try to find domain/IP patterns directly
	words := strings.Fields(query)
	for _, word := range words {
		word = strings.Trim(word, ".,!?\"'")
		if looksLikeTarget(word) {
			return word
		}
	}

	return ""
}

// looksLikeTarget checks if string looks like a valid target
func looksLikeTarget(s string) bool {
	// IP address pattern
	if strings.Count(s, ".") >= 3 {
		parts := strings.Split(s, ".")
		if len(parts) == 4 {
			return true
		}
	}

	// Domain pattern
	if strings.Contains(s, ".") && !strings.Contains(s, " ") {
		// Basic domain check
		parts := strings.Split(s, ".")
		if len(parts) >= 2 && len(parts[len(parts)-1]) >= 2 {
			return true
		}
	}

	// URL pattern
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return true
	}

	return false
}

// tickForAgentUpdates creates a cmd to poll agent messages
func tickForAgentUpdates(agent *Agent) tea.Cmd {
	return func() tea.Msg {
		if agent == nil || agent.msgChan == nil {
			return AgentDoneMsg{AgentID: ""}
		}
		msg, ok := <-agent.msgChan
		if !ok {
			// Channel closed - agent is done
			return AgentDoneMsg{AgentID: agent.ID}
		}
		return msg
	}
}

// pollActiveAgent returns a command to poll the first active agent
func (m *Model) pollActiveAgent() tea.Cmd {
	for _, agent := range m.activeAgents {
		if agent != nil && agent.msgChan != nil {
			return tickForAgentUpdates(agent)
		}
	}
	return nil
}

// ============================================================================
// SAVED AGENT MANAGEMENT
// ============================================================================

// AgentCreatedMsg is sent when an agent is successfully created
type AgentCreatedMsg struct {
	Agent *agents.AgentConfig
}

// AgentCreationErrorMsg is sent when agent creation fails
type AgentCreationErrorMsg struct {
	Err error
}

// createAgentFromDescription uses AI to create an agent config from user description
func (m *Model) createAgentFromDescription(description string) tea.Cmd {
	if m.agentManager == nil {
		m.console.AppendLog(styles.ErrorStyle.Render("Agent manager not initialized"))
		return nil
	}

	m.aiProcessing = true
	modelName := m.modelSelector.SelectedModel()
	_ = m.summary.SetStatus("Creating", "AI generating agent config...", "THINKING", true)
	m.console.AppendLog(styles.AIStyle.Render("\n[Agent Creator] Generating agent from description..."))
	m.console.AppendLog(styles.MutedStyle.Render("  \"" + description + "\""))

	// Capture for closure
	bridge := m.bridge
	provider := views.ModelToProvider(modelName)
	if provider == "" {
		provider = "ollama"
	}

	return func() tea.Msg {
		// Build the prompt to generate agent config
		prompt := `You are an agent configuration generator. Create a JSON configuration for a security/penetration testing AI agent based on the user's description.

Output ONLY valid JSON with this exact structure (no markdown, no explanation):
{
  "name": "short memorable name for the agent",
  "description": "one sentence describing what this agent does",
  "personality": "detailed personality traits and communication style",
  "behavior": "how the agent approaches tasks and makes decisions",
  "tools": ["preferred", "tools", "to", "use"],
  "constraints": ["any limitations or rules the agent should follow"],
  "examples": ["example behaviors or responses"]
}

Available tools: nmap, nikto, nuclei, masscan, sqlmap, hydra, gobuster, ffuf, subfinder, amass, theharvester

User's description: ` + description

		messages := []aibridge.Message{
			{Role: "user", Content: prompt},
		}

		engineModel := views.ModelToEngineModel(modelName)
		resp, err := bridge.ChatDetailed(messages, provider, engineModel, 0.7, 2000, "")
		if err != nil {
			return AgentCreationErrorMsg{Err: err}
		}
		if resp.ApprovalRequest != nil {
			return AgentCreationErrorMsg{Err: fmt.Errorf("agent creation requires runtime approval and cannot continue in JSON mode")}
		}

		// Parse the JSON response
		// Find JSON in response (in case AI adds extra text)
		jsonStart := strings.Index(resp.Content, "{")
		jsonEnd := strings.LastIndex(resp.Content, "}")
		if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
			return AgentCreationErrorMsg{Err: fmt.Errorf("AI did not return valid JSON")}
		}
		jsonStr := resp.Content[jsonStart : jsonEnd+1]

		var agentConfig agents.AgentConfig
		if err := json.Unmarshal([]byte(jsonStr), &agentConfig); err != nil {
			return AgentCreationErrorMsg{Err: fmt.Errorf("failed to parse agent config: %w", err)}
		}

		return AgentCreatedMsg{Agent: &agentConfig}
	}
}

// listSavedAgents displays all saved agent configurations
func (m *Model) listSavedAgents() tea.Cmd {
	if m.agentManager == nil {
		m.console.AppendLog(styles.ErrorStyle.Render("Agent manager not initialized"))
		return nil
	}

	agentList, err := m.agentManager.List()
	if err != nil {
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("Failed to list agents: %v", err)))
		return nil
	}

	m.console.AppendLog(styles.AIStyle.Render("\n╭─ Saved Agents " + strings.Repeat("─", 40) + "╮"))

	if len(agentList) == 0 {
		m.console.AppendLog(styles.MutedStyle.Render("│  No saved agents"))
		m.console.AppendLog(styles.MutedStyle.Render("│"))
		m.console.AppendLog(styles.MutedStyle.Render("│  Create one with:"))
		m.console.AppendLog(styles.KeyStyle.Render("│    /agent <description>"))
		m.console.AppendLog(styles.MutedStyle.Render("│  Example:"))
		m.console.AppendLog(styles.MutedStyle.Render("│    /agent make an aggressive recon agent"))
	} else {
		for i, agent := range agentList {
			// Agent name and ID
			m.console.AppendLog(fmt.Sprintf("│  %s %s",
				styles.SuccessStyle.Render(fmt.Sprintf("%d.", i+1)),
				styles.KeyStyle.Render(agent.Name)))
			m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("│     ID: %s", agent.ID)))

			// Description (truncated)
			desc := agent.Description
			if len(desc) > 45 {
				desc = desc[:42] + "..."
			}
			m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("│     %s", desc)))

			// Tools
			if len(agent.Tools) > 0 {
				toolStr := strings.Join(agent.Tools, ", ")
				if len(toolStr) > 40 {
					toolStr = toolStr[:37] + "..."
				}
				m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("│     Tools: %s", toolStr)))
			}

			m.console.AppendLog("│")
		}

		m.console.AppendLog(styles.MutedStyle.Render("│  Commands:"))
		m.console.AppendLog(styles.KeyStyle.Render("│    /agents use <id> <target>") + styles.MutedStyle.Render(" - Run agent"))
		m.console.AppendLog(styles.KeyStyle.Render("│    /agents edit <id>") + styles.MutedStyle.Render(" - Open in editor"))
		m.console.AppendLog(styles.KeyStyle.Render("│    /agents delete <id>") + styles.MutedStyle.Render(" - Delete agent"))
	}

	m.console.AppendLog(styles.AIStyle.Render("╰" + strings.Repeat("─", 55) + "╯"))
	m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  Agents stored in: %s", m.agentManager.GetAgentsDir())))

	return nil
}

// deleteAgent removes a saved agent
func (m *Model) deleteAgent(agentID string) tea.Cmd {
	if m.agentManager == nil {
		m.console.AppendLog(styles.ErrorStyle.Render("Agent manager not initialized"))
		return nil
	}

	// First check if agent exists
	agent, err := m.agentManager.Load(agentID)
	if err != nil {
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("Agent '%s' not found", agentID)))
		return nil
	}

	if err := m.agentManager.Delete(agentID); err != nil {
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("Failed to delete agent: %v", err)))
		return nil
	}

	m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("\n[Deleted] Agent '%s' (%s) has been removed", agent.Name, agentID)))
	return nil
}

// openAgentInEditor opens the agent config file in VSCode or default editor
func (m *Model) openAgentInEditor(agentID string) tea.Cmd {
	if m.agentManager == nil {
		m.console.AppendLog(styles.ErrorStyle.Render("Agent manager not initialized"))
		return nil
	}

	if err := m.agentManager.OpenInEditor(agentID); err != nil {
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("Failed to open editor: %v", err)))
		return nil
	}

	filepath := m.agentManager.GetFilePath(agentID)
	m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("\n[Editor] Opening %s", filepath)))
	return nil
}

// useAgent activates a saved agent for a task
func (m *Model) useAgent(agentID string, taskDescription string) tea.Cmd {
	if m.agentManager == nil {
		m.console.AppendLog(styles.ErrorStyle.Render("Agent manager not initialized"))
		return nil
	}

	agent, err := m.agentManager.Load(agentID)
	if err != nil {
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("Agent '%s' not found", agentID)))
		return nil
	}

	if taskDescription == "" {
		m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("Usage: /agents use %s <target or task>", agentID)))
		m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  Example: /agents use %s example.com", agentID)))
		return nil
	}

	// Create a custom query that includes the agent's personality
	customQuery := fmt.Sprintf("[Using agent: %s] %s", agent.Name, taskDescription)

	m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("\n[Activating] %s", agent.Name)))
	m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  %s", agent.Description)))

	// Start the agent task with the saved agent's context
	return m.startAgentTask(customQuery)
}

// renderPanel creates a boxed panel with title and content
func (m *Model) renderPanel(title string, lines []string, table []string) string {
	width := 52
	border := styles.ColorBorder

	// Build content
	var content []string
	content = append(content, "") // top padding

	// Add regular lines
	for _, line := range lines {
		content = append(content, line)
	}

	// Add table if provided
	if table != nil {
		content = append(content, table...)
	}

	content = append(content, "") // bottom padding

	// Create the box
	topBorder := styles.AIStyle.Render("╭─ " + title + " " + strings.Repeat("─", width-len(title)-4) + "╮")
	bottomBorder := lipgloss.NewStyle().Foreground(border).Render("╰" + strings.Repeat("─", width) + "╯")

	var result []string
	result = append(result, topBorder)

	for _, line := range content {
		// Pad line to width
		padded := line
		visLen := lipgloss.Width(line)
		if visLen < width {
			padded = line + strings.Repeat(" ", width-visLen)
		}
		result = append(result, lipgloss.NewStyle().Foreground(border).Render("│")+padded+lipgloss.NewStyle().Foreground(border).Render("│"))
	}

	result = append(result, bottomBorder)

	return "\n" + strings.Join(result, "\n")
}

// renderAPIStatus returns formatted API status lines
func (m *Model) renderAPIStatus() []string {
	providers := []struct {
		name   string
		envKey string
	}{
		{"Anthropic", "ANTHROPIC_API_KEY"},
		{"OpenAI", "OPENAI_API_KEY"},
		{"Google", "GEMINI_API_KEY"},
		{"DeepSeek", "DEEPSEEK_API_KEY"},
		{"Groq", "GROQ_API_KEY"},
	}

	var lines []string
	lines = append(lines, "")
	for _, p := range providers {
		status := styles.CriticalStyle.Render("Not Set")
		icon := "○"
		if os.Getenv(p.envKey) != "" {
			status = styles.SuccessStyle.Render("Ready")
			icon = "●"
		}
		lines = append(lines, fmt.Sprintf("  %s %-12s %s", icon, p.name, status))
	}
	lines = append(lines, "")
	return lines
}

// renderPlanTable returns formatted plan comparison
func (m *Model) renderPlanTable() []string {
	return []string{
		"  " + styles.MutedStyle.Render("Plan        Features"),
		"  " + strings.Repeat("─", 40),
		"  " + styles.SuccessStyle.Render("Free") + "        Scanning, recon, AI analysis",
		"  Starter     + Post-exploitation basics",
		"  Pro         + Autopent, team features",
		"  Enterprise  + Compliance, SSO, API",
		"",
	}
}

// renderToolsTable returns formatted tools list
func (m *Model) renderToolsTable() []string {
	toolList := []struct {
		name, cat, desc string
	}{
		{"nmap", "Scan", "Network & service detection"},
		{"masscan", "Scan", "Fast port scanner"},
		{"nikto", "Web", "Web vulnerability scanner"},
		{"nuclei", "Web", "Template-based scanner"},
		{"gobuster", "Web", "Directory bruteforce"},
		{"ffuf", "Web", "Fast fuzzer"},
		{"sqlmap", "Exploit", "SQL injection"},
		{"hydra", "Exploit", "Password cracking"},
		{"amass", "Recon", "Subdomain enumeration"},
	}

	var lines []string
	lines = append(lines, "")
	lines = append(lines, "  "+styles.MutedStyle.Render("Tool      Category   Description"))
	lines = append(lines, "  "+strings.Repeat("─", 44))
	for _, t := range toolList {
		lines = append(lines, fmt.Sprintf("  %-9s %-10s %s",
			styles.KeyStyle.Render(t.name),
			styles.MutedStyle.Render(t.cat),
			t.desc))
	}
	lines = append(lines, "")
	return lines
}

// renderDoctorCheck performs system health check
func (m *Model) renderDoctorCheck() string {
	var lines []string

	// Check all tools
	allTools := tools.CheckAllTools()
	installed := 0
	missing := 0
	var missingTools []tools.ToolInfo

	for _, t := range allTools {
		if t.Installed {
			installed++
		} else {
			missing++
			missingTools = append(missingTools, t.Tool)
		}
	}

	// Header
	lines = append(lines, "")
	lines = append(lines, styles.AIStyle.Render("╭─ System Health Check "+strings.Repeat("─", 34)+"╮"))

	// AI Engine status
	aiStatus := styles.SuccessStyle.Render("● Running")
	if !m.bridge.IsRunning() {
		aiStatus = styles.CriticalStyle.Render("○ Not Running")
	}
	lines = append(lines, fmt.Sprintf("│  %-14s %s%s│", "AI Engine:", aiStatus, strings.Repeat(" ", 25)))

	// Tool summary
	toolSummary := fmt.Sprintf("%d/%d installed", installed, len(allTools))
	if missing > 0 {
		toolSummary = styles.WarningStyle.Render(toolSummary)
	} else {
		toolSummary = styles.SuccessStyle.Render(toolSummary)
	}
	lines = append(lines, fmt.Sprintf("│  %-14s %s%s│", "Tools:", toolSummary, strings.Repeat(" ", 20)))

	lines = append(lines, "│"+strings.Repeat(" ", 56)+"│")
	lines = append(lines, "│  "+styles.MutedStyle.Render("Tool Status:")+strings.Repeat(" ", 42)+"│")
	lines = append(lines, "│  "+strings.Repeat("─", 52)+"│")

	// Individual tools
	for _, t := range allTools {
		icon := styles.SuccessStyle.Render("●")
		status := styles.MutedStyle.Render("ready")
		if !t.Installed {
			icon = styles.CriticalStyle.Render("○")
			status = styles.CriticalStyle.Render("missing")
		}
		req := ""
		if t.Tool.Required {
			req = styles.WarningStyle.Render("*")
		}
		line := fmt.Sprintf("│  %s %-12s %-10s %s", icon, t.Tool.Name+req, status, styles.MutedStyle.Render(t.Tool.Description))
		// Pad to width
		visLen := lipgloss.Width(line)
		if visLen < 57 {
			line += strings.Repeat(" ", 57-visLen)
		}
		lines = append(lines, line+"│")
	}

	lines = append(lines, "│"+strings.Repeat(" ", 56)+"│")

	// Install command if missing
	if missing > 0 {
		lines = append(lines, "│  "+styles.WarningStyle.Render(fmt.Sprintf("%d tools missing", missing))+strings.Repeat(" ", 38)+"│")
		installCmd := tools.GetBulkInstallCommand(missingTools)
		if installCmd != "" {
			lines = append(lines, "│  "+styles.MutedStyle.Render("Install all:")+strings.Repeat(" ", 42)+"│")
			// Truncate command if too long
			if len(installCmd) > 50 {
				installCmd = installCmd[:47] + "..."
			}
			lines = append(lines, "│  "+styles.KeyStyle.Render(installCmd)+strings.Repeat(" ", 52-len(installCmd))+"│")
		}
	} else {
		lines = append(lines, "│  "+styles.SuccessStyle.Render("All tools ready!")+strings.Repeat(" ", 38)+"│")
	}

	lines = append(lines, "│"+strings.Repeat(" ", 56)+"│")
	lines = append(lines, "│  "+styles.MutedStyle.Render("* = required for basic functionality")+strings.Repeat(" ", 17)+"│")
	lines = append(lines, styles.AIStyle.Render("╰"+strings.Repeat("─", 56)+"╯"))

	return strings.Join(lines, "\n")
}

func (m Model) View() string {
	if m.quitting {
		return m.renderClosingScreen()
	}

	if m.state == stateSplash {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.splash.View())
	}

	// Show help overlay if active
	if m.showHelp {
		return m.renderHelp()
	}

	// Show sudo prompt overlay if active
	if m.showSudoPrompt {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.sudoPrompt.View())
	}

	if m.showAPIKeyPrompt {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.apiKeyPrompt.View())
	}

	if m.showApprovalPrompt {
		return m.approvalPrompt.View()
	}

	// Show scan progress when active, otherwise show console
	// Ctrl+O toggles raw output view
	mainArea := m.console.View()
	if m.showRawOutput && (m.scanActive || m.scanProgress.IsActive()) {
		mainArea = m.scanProgress.RenderRawOutputView()
	} else if m.scanActive || m.scanProgress.IsActive() {
		mainArea = m.scanProgress.View()
	}

	// Build input area with optional slash menu
	inputArea := m.input.View()
	if m.slashMenu.IsOpen() {
		inputArea = lipgloss.JoinVertical(lipgloss.Left,
			m.slashMenu.View(),
			m.input.View(),
		)
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		m.header.View(),
		mainArea,
		m.summary.View(),
		inputArea,
		m.renderBottomBar(), // Combined stats + model selector
	)
}

func (m Model) renderClosingScreen() string {
	lines := ui.BannerLines()
	logoStyle := lipgloss.NewStyle().Foreground(styles.ColorAccent).Bold(true)
	for i, line := range lines {
		lines[i] = logoStyle.Render(line)
	}

	logo := strings.Join(lines, "\n")
	width := lipgloss.Width(logo)
	if m.width > 0 && m.width-8 < width {
		width = m.width - 8
	}
	if width < 48 {
		width = 48
	}

	metaStyle := lipgloss.NewStyle().
		Foreground(styles.ColorMuted).
		Width(width).
		Align(lipgloss.Center)

	meta := lipgloss.JoinVertical(
		lipgloss.Center,
		metaStyle.Render("v2.0.0  |  AI-Powered Penetration Testing Platform"),
		metaStyle.Render("by Zero/Harrison"),
	)
	tagline := lipgloss.NewStyle().
		Foreground(styles.ColorAqua).
		Bold(true).
		Width(width).
		Align(lipgloss.Center).
		Render("[ Session secured. Operator exit complete. ]")
	status := lipgloss.NewStyle().
		Foreground(styles.ColorMuted).
		Width(width).
		Align(lipgloss.Center).
		Render("Shutting down Zypheron...")

	content := lipgloss.JoinVertical(
		lipgloss.Center,
		logo,
		lipgloss.NewStyle().Foreground(styles.ColorBorder).Width(width).Align(lipgloss.Center).Render(ui.BannerDivider(width)),
		meta,
		"",
		tagline,
		"",
		status,
	)

	return lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(content)
}

type apiKeyStoredMsg struct {
	Provider string
}

type apiKeyStoreErrorMsg struct {
	Err error
}

func (m *Model) hasAPIKeyForModel(modelName string) bool {
	credentialProvider := views.ModelToCredentialProvider(modelName)
	if credentialProvider == "" {
		return true
	}

	if envVar := views.CredentialProviderEnvVar(credentialProvider); envVar != "" && os.Getenv(envVar) != "" {
		return true
	}

	if !m.bridge.IsRunning() {
		return false
	}

	resp, err := m.bridge.GetConfiguredProviders()
	if err != nil {
		return false
	}

	rawProviders, ok := resp["providers"].([]interface{})
	if !ok {
		return false
	}

	for _, raw := range rawProviders {
		provider, ok := raw.(string)
		if ok && strings.EqualFold(provider, credentialProvider) {
			return true
		}
	}

	return false
}

func (m *Model) confirmModelSelection(idx int) {
	m.modelSelector.SetIndex(idx)
	m.confirmedModelIdx = idx
	m.pendingModelIdx = -1

	modelName := m.modelSelector.SelectedModel()
	m.summary.SetModelName(modelName)

	if err := persistSelectedModel(modelName); err != nil {
		m.console.AppendLog(styles.WarningStyle.Render(fmt.Sprintf("Saved model in-session, but failed to persist settings: %v", err)))
	}
}

func (m *Model) storeAPIKeyAndActivateModel(provider, apiKey string) tea.Cmd {
	return func() tea.Msg {
		if !m.bridge.IsRunning() {
			if err := m.bridge.StartQuiet(); err != nil {
				return apiKeyStoreErrorMsg{Err: err}
			}
		}

		resp, err := m.bridge.StoreAPIKey(map[string]interface{}{
			"provider": provider,
			"api_key":  apiKey,
		})
		if err != nil {
			return apiKeyStoreErrorMsg{Err: err}
		}

		success, _ := resp["success"].(bool)
		if !success {
			if message, ok := resp["message"].(string); ok && strings.TrimSpace(message) != "" {
				return apiKeyStoreErrorMsg{Err: fmt.Errorf("%s", message)}
			}
			return apiKeyStoreErrorMsg{Err: fmt.Errorf("AI engine rejected API key storage")}
		}

		return apiKeyStoredMsg{Provider: provider}
	}
}

func persistSelectedModel(modelName string) error {
	cfg := config.Get()
	provider := views.ModelToProvider(modelName)

	cfg.AIProvider = provider
	cfg.AIModel = modelName

	switch provider {
	case "ollama":
		cfg.AI.Provider = config.AIProviderOllama
		cfg.AI.OllamaModel = views.ModelToEngineModel(modelName)
		cfg.AI.Model = ""
	case "claude":
		cfg.AI.Provider = config.AIProviderAnthropic
		cfg.AI.Model = modelName
	case "openai":
		cfg.AI.Provider = config.AIProviderOpenAI
		cfg.AI.Model = modelName
	case "gemini":
		cfg.AI.Provider = config.AIProviderGemini
		cfg.AI.Model = modelName
	case "kimi":
		cfg.AI.Provider = config.AIProviderKimi
		cfg.AI.Model = modelName
	case "deepseek":
		cfg.AI.Provider = config.AIProviderDeepSeek
		cfg.AI.Model = modelName
	case "grok":
		cfg.AI.Provider = config.AIProviderGrok
		cfg.AI.Model = modelName
	default:
		cfg.AI.Model = modelName
	}

	return cfg.Save()
}

// renderBottomBar combines session stats with model selector
func (m Model) renderBottomBar() string {
	// If model selector is open, just show that
	if m.modelSelector.IsOpen() {
		return m.modelSelector.View()
	}

	// Calculate session duration
	sessionDuration := time.Since(time.Unix(m.sessionStart, 0))
	hours := int(sessionDuration.Hours())
	minutes := int(sessionDuration.Minutes()) % 60

	var sessionStr string
	if hours > 0 {
		sessionStr = fmt.Sprintf("%dh %dm", hours, minutes)
	} else {
		sessionStr = fmt.Sprintf("%dm", minutes)
	}

	// Session stats on the left
	left := fmt.Sprintf("Session: %s  Scans: %d  Findings: %d", sessionStr, m.summary.ScanCount, m.summary.FindingCount)
	right := fmt.Sprintf("Model: [%s ▼] (Tab to change)", m.modelSelector.SelectedModel())

	// Width-aware rendering to avoid wrapping on narrow terminals.
	if m.width <= 0 {
		return styles.MutedStyle.Render(left + "    " + right)
	}

	max := m.width
	left = truncateText(left, max)
	right = truncateText(right, max)

	// Keep at least a small gap between left and right sections.
	const minGap = 2
	needed := len(left) + minGap + len(right)
	if needed > max {
		rightBudget := max / 2
		if rightBudget < 18 {
			rightBudget = 18
		}
		if rightBudget > max-8 {
			rightBudget = max - 8
		}
		right = truncateText(right, rightBudget)
		left = truncateText(left, max-minGap-len(right))
	}

	gap := max - len(left) - len(right)
	if gap < minGap {
		gap = minGap
	}

	return styles.MutedStyle.Render(left) + strings.Repeat(" ", gap) + styles.MutedStyle.Render(right)
}

func (m Model) bottomAreaHeight() int {
	return m.modelSelector.Height()
}

func truncateText(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// renderHelp renders the help overlay
func (m Model) renderHelp() string {
	// Header
	header := styles.AIStyle.Render("╭─────────────────────────────────────────────────────────────────╮\n") +
		styles.AIStyle.Render("│") + styles.TextStyle.Render("              ZYPHERON COMMAND REFERENCE              ") + styles.AIStyle.Render("│\n") +
		styles.AIStyle.Render("╰─────────────────────────────────────────────────────────────────╯")

	// AI Commands section
	aiCmds := lipgloss.JoinVertical(lipgloss.Left,
		styles.AIStyle.Render("\n  🤖 AI Commands"),
		styles.MutedStyle.Render("  ─────────────────────────────────────────────────"),
		fmt.Sprintf("  %s  %s", styles.KeyStyle.Render("<natural language>"), styles.MutedStyle.Render("Ask AI anything - it understands security tasks")),
		fmt.Sprintf("  %s          %s", styles.KeyStyle.Render("ai <question>"), styles.MutedStyle.Render("Direct AI query")),
		fmt.Sprintf("  %s   %s", styles.KeyStyle.Render("autopent <target>"), styles.MutedStyle.Render("Autonomous penetration test")),
		fmt.Sprintf("  %s        %s", styles.KeyStyle.Render("dork <query>"), styles.MutedStyle.Render("AI-enhanced search dorking")),
	)

	// Scan Commands section
	scanCmds := lipgloss.JoinVertical(lipgloss.Left,
		styles.SuccessStyle.Render("\n  🔍 Scanning"),
		styles.MutedStyle.Render("  ─────────────────────────────────────────────────"),
		fmt.Sprintf("  %s     %s", styles.KeyStyle.Render("/scan <target>"), styles.MutedStyle.Render("Start security scan (nmap default)")),
		fmt.Sprintf("  %s    %s", styles.KeyStyle.Render("/recon <domain>"), styles.MutedStyle.Render("Reconnaissance gathering")),
		fmt.Sprintf("  %s  %s", styles.KeyStyle.Render("/scan <t> --tool"), styles.MutedStyle.Render("Specify tool: nmap, nikto, nuclei")),
	)

	// Navigation section
	navCmds := lipgloss.JoinVertical(lipgloss.Left,
		styles.WarningStyle.Render("\n  ⌨️  Navigation"),
		styles.MutedStyle.Render("  ─────────────────────────────────────────────────"),
		fmt.Sprintf("  %s                  %s", styles.KeyStyle.Render("[R]"), styles.MutedStyle.Render("Recon tab")),
		fmt.Sprintf("  %s                  %s", styles.KeyStyle.Render("[S]"), styles.MutedStyle.Render("Scan tab")),
		fmt.Sprintf("  %s                  %s", styles.KeyStyle.Render("[A]"), styles.MutedStyle.Render("AI tab")),
		fmt.Sprintf("  %s                  %s", styles.KeyStyle.Render("[T]"), styles.MutedStyle.Render("Tools tab")),
		fmt.Sprintf("  %s                  %s", styles.KeyStyle.Render("[H]"), styles.MutedStyle.Render("History tab")),
		fmt.Sprintf("  %s                %s", styles.KeyStyle.Render("[Tab]"), styles.MutedStyle.Render("Change AI model")),
		fmt.Sprintf("  %s                %s", styles.KeyStyle.Render("[Esc]"), styles.MutedStyle.Render("Close this help / Cancel")),
		fmt.Sprintf("  %s             %s", styles.KeyStyle.Render("[Ctrl+C]"), styles.MutedStyle.Render("Quit Zypheron")),
	)

	// System commands
	sysCmds := lipgloss.JoinVertical(lipgloss.Left,
		styles.InfoStyle.Render("\n  ⚙️  System"),
		styles.MutedStyle.Render("  ─────────────────────────────────────────────────"),
		fmt.Sprintf("  %s             %s", styles.KeyStyle.Render("/agents"), styles.MutedStyle.Render("View active AI agents")),
		fmt.Sprintf("  %s     %s", styles.KeyStyle.Render("/quit or /exit"), styles.MutedStyle.Render("Exit Zypheron")),
		fmt.Sprintf("  %s                  %s", styles.KeyStyle.Render("?"), styles.MutedStyle.Render("Show this help")),
	)

	// Footer
	footer := styles.MutedStyle.Render("\n\n  Press ") + styles.KeyStyle.Render("Esc") + styles.MutedStyle.Render(" to close")

	content := lipgloss.JoinVertical(lipgloss.Left,
		header,
		aiCmds,
		scanCmds,
		navCmds,
		sysCmds,
		footer,
	)

	// Center the help overlay
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

// Tools that require root/sudo for full functionality
var sudoRequiredTools = map[string]bool{
	"nmap":      true, // SYN scans, OS detection
	"masscan":   true, // Raw packet scanning
	"tcpdump":   true, // Packet capture
	"arpspoof":  true,
	"ettercap":  true,
	"bettercap": true,
	"hping3":    true,
}

// toolNeedsSudo checks if a tool requires root privileges
func toolNeedsSudo(tool string) bool {
	return sudoRequiredTools[tool]
}

// canSudoWithoutPassword checks if sudo credentials are cached
func canSudoWithoutPassword() bool {
	cmd := exec.Command("sudo", "-n", "true")
	return cmd.Run() == nil
}

// startScanWithSudoCheck initiates a scan, prompting for sudo if needed
func (m *Model) startScanWithSudoCheck(req ScanRequest) tea.Cmd {
	// Check if this tool needs sudo
	if toolNeedsSudo(req.Tool) && !canSudoWithoutPassword() {
		// Need sudo - show prompt
		m.pendingScan = &req
		m.sudoPrompt = components.NewSudoPrompt(req.Tool, m.width, m.height)
		m.showSudoPrompt = true
		return m.sudoPrompt.Init()
	}

	// No sudo needed or already cached - start scan directly
	return tea.Batch(
		StartScan(req),
		TickForScanUpdate(),
	)
}

// ============================================================================
// BASH COMMAND EXECUTION
// ============================================================================

// BashOutputMsg delivers bash command output
type BashOutputMsg struct {
	CmdID string
	Line  string
	IsErr bool
}

// BashDoneMsg signals bash command completion
type BashDoneMsg struct {
	CmdID    string
	ExitCode int
	Error    error
}

// executeBashCommand runs a bash command and streams output to console
func (m *Model) executeBashCommand(bashCmd string) tea.Cmd {
	// Handle cd command specially
	if strings.HasPrefix(bashCmd, "cd ") || bashCmd == "cd" {
		return m.handleCdCommand(bashCmd)
	}

	// Add to bash history for pentest context
	m.bashHistory = append(m.bashHistory, bashCmd)
	if len(m.bashHistory) > 100 {
		m.bashHistory = m.bashHistory[1:]
	}

	// Record in pentest context
	if m.pentestCtx != nil {
		m.pentestCtx.AddToolExecution(ToolExecution{
			Tool:      "bash",
			Target:    m.workingDir,
			Args:      []string{bashCmd},
			StartTime: time.Now(),
		})
	}

	// Generate unique command ID
	cmdID := fmt.Sprintf("bash_%d", time.Now().UnixNano())

	m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("$ %s", bashCmd)))
	m.console.AppendLog(styles.MutedStyle.Render(fmt.Sprintf("  [%s] Running in %s", cmdID[:12], m.workingDir)))

	// Capture working dir for closure
	workDir := m.workingDir

	return func() tea.Msg {
		// Create command
		cmd := exec.Command("bash", "-c", bashCmd)
		cmd.Dir = workDir

		// Capture both stdout and stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return BashDoneMsg{CmdID: cmdID, ExitCode: 1, Error: err}
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return BashDoneMsg{CmdID: cmdID, ExitCode: 1, Error: err}
		}

		// Start command
		if err := cmd.Start(); err != nil {
			return BashDoneMsg{CmdID: cmdID, ExitCode: 1, Error: err}
		}

		// Read output
		var wg sync.WaitGroup
		outputChan := make(chan string, 100)

		// Read stdout
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				outputChan <- scanner.Text()
			}
		}()

		// Read stderr
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				outputChan <- "[stderr] " + scanner.Text()
			}
		}()

		// Close channel when done
		go func() {
			wg.Wait()
			close(outputChan)
		}()

		// Collect output
		var output strings.Builder
		for line := range outputChan {
			output.WriteString(line)
			output.WriteString("\n")
		}

		// Wait for command to finish
		exitCode := 0
		if err := cmd.Wait(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				return BashDoneMsg{CmdID: cmdID, ExitCode: 1, Error: err}
			}
		}

		// Return combined result
		return bashResultMsg{
			CmdID:    cmdID,
			Output:   output.String(),
			ExitCode: exitCode,
		}
	}
}

// bashResultMsg carries bash command result back to Update
type bashResultMsg struct {
	CmdID    string
	Output   string
	ExitCode int
}

// handleCdCommand changes the working directory
func (m *Model) handleCdCommand(bashCmd string) tea.Cmd {
	var targetDir string

	if bashCmd == "cd" || bashCmd == "cd ~" {
		// cd with no args goes to home
		home, err := os.UserHomeDir()
		if err != nil {
			m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("Failed to get home directory: %v", err)))
			return nil
		}
		targetDir = home
	} else {
		// Extract directory from "cd <dir>"
		targetDir = strings.TrimPrefix(bashCmd, "cd ")
		targetDir = strings.TrimSpace(targetDir)

		// Handle ~ expansion
		if strings.HasPrefix(targetDir, "~") {
			home, _ := os.UserHomeDir()
			targetDir = strings.Replace(targetDir, "~", home, 1)
		}

		// Handle relative paths
		if !strings.HasPrefix(targetDir, "/") {
			targetDir = filepath.Join(m.workingDir, targetDir)
		}
	}

	// Verify directory exists
	info, err := os.Stat(targetDir)
	if err != nil {
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("cd: %s: %v", targetDir, err)))
		return nil
	}
	if !info.IsDir() {
		m.console.AppendLog(styles.ErrorStyle.Render(fmt.Sprintf("cd: %s: Not a directory", targetDir)))
		return nil
	}

	// Update working directory
	m.workingDir = targetDir
	m.console.AppendLog(styles.SuccessStyle.Render(fmt.Sprintf("Changed directory to: %s", targetDir)))

	// Add to bash history
	m.bashHistory = append(m.bashHistory, bashCmd)

	return nil
}

// GetWorkingDir returns current working directory
func (m *Model) GetWorkingDir() string {
	return m.workingDir
}

// GetBashHistory returns bash command history
func (m *Model) GetBashHistory() []string {
	return m.bashHistory
}
