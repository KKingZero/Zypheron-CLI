package agents

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// AgentConfig represents a saved agent configuration
type AgentConfig struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Personality string    `json:"personality"`
	Behavior    string    `json:"behavior"`
	Tools       []string  `json:"tools,omitempty"`
	Constraints []string  `json:"constraints,omitempty"`
	Examples    []string  `json:"examples,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AgentManager handles agent storage and retrieval
type AgentManager struct {
	agentsDir string
}

// NewAgentManager creates a new agent manager
func NewAgentManager() (*AgentManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	agentsDir := filepath.Join(homeDir, ".zypheron", "agents")
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create agents directory: %w", err)
	}

	return &AgentManager{agentsDir: agentsDir}, nil
}

// GetAgentsDir returns the agents directory path
func (m *AgentManager) GetAgentsDir() string {
	return m.agentsDir
}

// Save saves an agent configuration to disk
func (m *AgentManager) Save(agent *AgentConfig) error {
	if agent.ID == "" {
		agent.ID = generateAgentID(agent.Name)
	}
	if agent.CreatedAt.IsZero() {
		agent.CreatedAt = time.Now()
	}
	agent.UpdatedAt = time.Now()

	filename := filepath.Join(m.agentsDir, agent.ID+".json")
	data, err := json.MarshalIndent(agent, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal agent config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write agent file: %w", err)
	}

	return nil
}

// Load loads an agent configuration by ID
func (m *AgentManager) Load(id string) (*AgentConfig, error) {
	filename := filepath.Join(m.agentsDir, id+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent file: %w", err)
	}

	var agent AgentConfig
	if err := json.Unmarshal(data, &agent); err != nil {
		return nil, fmt.Errorf("failed to parse agent config: %w", err)
	}

	return &agent, nil
}

// List returns all saved agent configurations
func (m *AgentManager) List() ([]*AgentConfig, error) {
	entries, err := os.ReadDir(m.agentsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read agents directory: %w", err)
	}

	var agents []*AgentConfig
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		id := strings.TrimSuffix(entry.Name(), ".json")
		agent, err := m.Load(id)
		if err != nil {
			continue // Skip invalid files
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

// Delete removes an agent configuration
func (m *AgentManager) Delete(id string) error {
	filename := filepath.Join(m.agentsDir, id+".json")
	if err := os.Remove(filename); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("agent '%s' not found", id)
		}
		return fmt.Errorf("failed to delete agent: %w", err)
	}
	return nil
}

// GetFilePath returns the file path for an agent
func (m *AgentManager) GetFilePath(id string) string {
	return filepath.Join(m.agentsDir, id+".json")
}

// OpenInEditor opens the agent file in VSCode or fallback editor
func (m *AgentManager) OpenInEditor(id string) error {
	filepath := m.GetFilePath(id)

	// Check if file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return fmt.Errorf("agent '%s' not found", id)
	}

	// Try VSCode first
	if err := exec.Command("code", filepath).Start(); err == nil {
		return nil
	}

	// Try cursor (VSCode fork)
	if err := exec.Command("cursor", filepath).Start(); err == nil {
		return nil
	}

	// Try generic xdg-open on Linux
	if err := exec.Command("xdg-open", filepath).Start(); err == nil {
		return nil
	}

	return fmt.Errorf("no editor found - file is at: %s", filepath)
}

// generateAgentID creates a URL-safe ID from the agent name
func generateAgentID(name string) string {
	// Convert to lowercase and replace spaces with hyphens
	id := strings.ToLower(name)
	id = strings.ReplaceAll(id, " ", "-")

	// Remove non-alphanumeric characters except hyphens
	reg := regexp.MustCompile(`[^a-z0-9\-]`)
	id = reg.ReplaceAllString(id, "")

	// Remove multiple consecutive hyphens
	reg = regexp.MustCompile(`-+`)
	id = reg.ReplaceAllString(id, "-")

	// Trim hyphens from start/end
	id = strings.Trim(id, "-")

	// Ensure not empty
	if id == "" {
		id = fmt.Sprintf("agent-%d", time.Now().Unix())
	}

	// Truncate if too long
	if len(id) > 50 {
		id = id[:50]
	}

	return id
}

// BuildSystemPrompt generates a system prompt from agent config
func (a *AgentConfig) BuildSystemPrompt() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("You are %s.", a.Name))

	if a.Description != "" {
		parts = append(parts, a.Description)
	}

	if a.Personality != "" {
		parts = append(parts, "\nPersonality:\n"+a.Personality)
	}

	if a.Behavior != "" {
		parts = append(parts, "\nBehavior:\n"+a.Behavior)
	}

	if len(a.Tools) > 0 {
		parts = append(parts, "\nPreferred Tools: "+strings.Join(a.Tools, ", "))
	}

	if len(a.Constraints) > 0 {
		parts = append(parts, "\nConstraints:")
		for _, c := range a.Constraints {
			parts = append(parts, "- "+c)
		}
	}

	if len(a.Examples) > 0 {
		parts = append(parts, "\nExample behaviors:")
		for _, e := range a.Examples {
			parts = append(parts, "- "+e)
		}
	}

	return strings.Join(parts, "\n")
}
