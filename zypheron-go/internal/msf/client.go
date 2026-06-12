// Package msf provides Metasploit Framework RPC API integration.
// It communicates with msfrpcd to execute modules, manage sessions, and retrieve results.
package msf

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// Client represents a connection to the Metasploit RPC daemon.
type Client struct {
	mu sync.RWMutex

	host    string
	port    int
	token   string
	ssl     bool
	client  *http.Client
	timeout time.Duration

	// Callback for progress updates
	onProgress func(module string, progress float64, status string)
	onFinding  func(finding Finding)
}

// Finding represents a Metasploit finding (vuln, session, loot, etc.)
type Finding struct {
	Type        string            `json:"type"` // "vuln", "session", "loot", "host", "service"
	Module      string            `json:"module"`
	Target      string            `json:"target"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Data        map[string]string `json:"data"`
	Timestamp   time.Time         `json:"timestamp"`
}

// ModuleInfo contains information about a Metasploit module.
type ModuleInfo struct {
	Type        string                  `json:"type"`
	Name        string                  `json:"name"`
	FullName    string                  `json:"fullname"`
	Description string                  `json:"description"`
	Author      []string                `json:"author"`
	References  []string                `json:"references"`
	Rank        string                  `json:"rank"`
	Options     map[string]ModuleOption `json:"options"`
}

// ModuleOption represents a module option.
type ModuleOption struct {
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Default  string `json:"default"`
	Desc     string `json:"desc"`
}

// Session represents an active Metasploit session.
type Session struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	TunnelLocal string `json:"tunnel_local"`
	TunnelPeer  string `json:"tunnel_peer"`
	ViaExploit  string `json:"via_exploit"`
	ViaPayload  string `json:"via_payload"`
	Description string `json:"desc"`
	Info        string `json:"info"`
	Workspace   string `json:"workspace"`
	Username    string `json:"username"`
	UUID        string `json:"uuid"`
}

// JobInfo represents a running Metasploit job.
type JobInfo struct {
	ID        int    `json:"jid"`
	Name      string `json:"name"`
	StartTime int64  `json:"start_time"`
}

// ClientConfig holds configuration for the MSF client.
type ClientConfig struct {
	Host               string
	Port               int
	Username           string
	Password           string
	SSL                bool
	Timeout            time.Duration
	InsecureSkipVerify bool // SECURITY: Set to false to enable TLS certificate verification
}

// DefaultConfig returns default client configuration.
func DefaultConfig() ClientConfig {
	return ClientConfig{
		Host:    "127.0.0.1",
		Port:    55553,
		SSL:     true,
		Timeout: 30 * time.Second,
		// SECURITY (M-05): verify TLS certificates by default. Opt out for a
		// self-signed lab msfrpcd with MSF_INSECURE_TLS=1 (mirrors the Empire
		// client's EMPIRE_INSECURE_TLS pattern).
		InsecureSkipVerify: os.Getenv("MSF_INSECURE_TLS") == "1",
	}
}

// hostIsLocalOrPrivate reports whether host is loopback or an RFC1918 address.
func hostIsLocalOrPrivate(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// NewClient creates a new Metasploit RPC client.
func NewClient(config ClientConfig) *Client {
	if config.InsecureSkipVerify && !hostIsLocalOrPrivate(config.Host) {
		fmt.Fprintln(os.Stderr,
			"WARNING: MSF TLS verification disabled (InsecureSkipVerify) for a "+
				"non-local/non-RFC1918 host. msfrpcd traffic is exposed to MITM.")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// SECURITY (M-05): verification is governed by config; default is on.
			InsecureSkipVerify: config.InsecureSkipVerify, //nolint:gosec // opt-in only
		},
	}

	return &Client{
		host:    config.Host,
		port:    config.Port,
		ssl:     config.SSL,
		timeout: config.Timeout,
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
	}
}

// Connect authenticates with the Metasploit RPC daemon.
func (c *Client) Connect(username, password string) error {
	resp, err := c.call("auth.login", username, password)
	if err != nil {
		return fmt.Errorf("failed to connect to msfrpcd: %w", err)
	}

	result, ok := resp["result"].(string)
	if !ok || result != "success" {
		return fmt.Errorf("authentication failed: %v", resp)
	}

	token, ok := resp["token"].(string)
	if !ok {
		return fmt.Errorf("no token in response")
	}

	c.mu.Lock()
	c.token = token
	c.mu.Unlock()

	return nil
}

// Disconnect logs out from the Metasploit RPC daemon.
func (c *Client) Disconnect() error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	if token == "" {
		return nil
	}

	_, err := c.call("auth.logout", token)

	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()

	return err
}

// IsConnected returns whether the client is authenticated.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token != ""
}

// SetProgressCallback sets a callback for progress updates.
func (c *Client) SetProgressCallback(fn func(module string, progress float64, status string)) {
	c.mu.Lock()
	c.onProgress = fn
	c.mu.Unlock()
}

// SetFindingCallback sets a callback for findings.
func (c *Client) SetFindingCallback(fn func(finding Finding)) {
	c.mu.Lock()
	c.onFinding = fn
	c.mu.Unlock()
}

// ListModules returns available modules of the specified type.
func (c *Client) ListModules(moduleType string) ([]string, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	resp, err := c.call("module."+moduleType, token)
	if err != nil {
		return nil, err
	}

	modules, ok := resp["modules"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format")
	}

	result := make([]string, 0, len(modules))
	for _, m := range modules {
		if s, ok := m.(string); ok {
			result = append(result, s)
		}
	}

	return result, nil
}

// GetModuleInfo returns information about a specific module.
func (c *Client) GetModuleInfo(moduleType, moduleName string) (*ModuleInfo, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	resp, err := c.call("module.info", token, moduleType, moduleName)
	if err != nil {
		return nil, err
	}

	// Parse response into ModuleInfo
	info := &ModuleInfo{
		Type:     moduleType,
		FullName: moduleName,
	}

	if name, ok := resp["name"].(string); ok {
		info.Name = name
	}
	if desc, ok := resp["description"].(string); ok {
		info.Description = desc
	}
	if rank, ok := resp["rank"].(string); ok {
		info.Rank = rank
	}

	return info, nil
}

// ExecuteModule runs a Metasploit module with the given options.
func (c *Client) ExecuteModule(moduleType, moduleName string, options map[string]string) (int, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	resp, err := c.call("module.execute", token, moduleType, moduleName, options)
	if err != nil {
		return 0, err
	}

	// Check for job ID
	if jobID, ok := resp["job_id"].(float64); ok {
		return int(jobID), nil
	}

	// Check for UUID (some modules return this instead)
	if uuid, ok := resp["uuid"].(string); ok {
		c.reportProgress(moduleName, 0, fmt.Sprintf("Started: %s", uuid))
		return 0, nil
	}

	return 0, fmt.Errorf("module execution failed: %v", resp)
}

// GetJobStatus returns the status of a running job.
func (c *Client) GetJobStatus(jobID int) (map[string]interface{}, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	resp, err := c.call("job.info", token, jobID)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// ListJobs returns all running jobs.
func (c *Client) ListJobs() ([]JobInfo, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	resp, err := c.call("job.list", token)
	if err != nil {
		return nil, err
	}

	var jobs []JobInfo
	for id, info := range resp {
		if infoMap, ok := info.(map[string]interface{}); ok {
			job := JobInfo{}
			fmt.Sscanf(id, "%d", &job.ID)
			if name, ok := infoMap["name"].(string); ok {
				job.Name = name
			}
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

// StopJob stops a running job.
func (c *Client) StopJob(jobID int) error {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	_, err := c.call("job.stop", token, jobID)
	return err
}

// ListSessions returns all active sessions.
func (c *Client) ListSessions() ([]Session, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	resp, err := c.call("session.list", token)
	if err != nil {
		return nil, err
	}

	var sessions []Session
	for id, info := range resp {
		if infoMap, ok := info.(map[string]interface{}); ok {
			session := Session{}
			fmt.Sscanf(id, "%d", &session.ID)

			if t, ok := infoMap["type"].(string); ok {
				session.Type = t
			}
			if tl, ok := infoMap["tunnel_local"].(string); ok {
				session.TunnelLocal = tl
			}
			if tp, ok := infoMap["tunnel_peer"].(string); ok {
				session.TunnelPeer = tp
			}
			if ve, ok := infoMap["via_exploit"].(string); ok {
				session.ViaExploit = ve
			}
			if info, ok := infoMap["info"].(string); ok {
				session.Info = info
			}

			sessions = append(sessions, session)

			// Report session as finding
			c.reportFinding(Finding{
				Type:        "session",
				Module:      session.ViaExploit,
				Target:      session.TunnelPeer,
				Description: fmt.Sprintf("%s session: %s", session.Type, session.Info),
				Severity:    "critical",
				Timestamp:   time.Now(),
			})
		}
	}

	return sessions, nil
}

// RunAuxiliary runs an auxiliary module and monitors progress.
func (c *Client) RunAuxiliary(moduleName string, options map[string]string) error {
	jobID, err := c.ExecuteModule("auxiliary", moduleName, options)
	if err != nil {
		return err
	}

	// Monitor job progress
	return c.monitorJob(jobID, moduleName)
}

// RunExploit runs an exploit module and monitors for sessions.
func (c *Client) RunExploit(moduleName string, options map[string]string) error {
	jobID, err := c.ExecuteModule("exploit", moduleName, options)
	if err != nil {
		return err
	}

	// Monitor job and check for new sessions
	return c.monitorJob(jobID, moduleName)
}

// monitorJob monitors a running job until completion.
func (c *Client) monitorJob(jobID int, moduleName string) error {
	if jobID == 0 {
		return nil // Some modules don't return job IDs
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	maxDuration := 10 * time.Minute

	for {
		select {
		case <-ticker.C:
			// Check if job is still running
			jobs, err := c.ListJobs()
			if err != nil {
				continue
			}

			found := false
			for _, job := range jobs {
				if job.ID == jobID {
					found = true
					elapsed := time.Since(startTime)
					// Estimate progress based on time (rough)
					progress := (elapsed.Seconds() / maxDuration.Seconds()) * 100
					if progress > 95 {
						progress = 95
					}
					c.reportProgress(moduleName, progress, "Running...")
					break
				}
			}

			if !found {
				// Job completed
				c.reportProgress(moduleName, 100, "Completed")

				// Check for new sessions
				c.ListSessions()
				return nil
			}

			// Timeout check
			if time.Since(startTime) > maxDuration {
				c.StopJob(jobID)
				return fmt.Errorf("job timed out after %v", maxDuration)
			}
		}
	}
}

// call makes an RPC call to msfrpcd.
func (c *Client) call(method string, args ...interface{}) (map[string]interface{}, error) {
	// Build request
	request := append([]interface{}{method}, args...)

	// Encode as msgpack
	data, err := msgpack.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	// Build URL
	scheme := "http"
	if c.ssl {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/api/", scheme, c.host, c.port)

	// Make request
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "binary/message-pack")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RPC request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Decode response
	var result map[string]interface{}
	if err := msgpack.Unmarshal(body, &result); err != nil {
		// Try JSON as fallback
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
	}

	// Check for errors
	if errMsg, ok := result["error"].(string); ok {
		return nil, fmt.Errorf("RPC error: %s", errMsg)
	}

	return result, nil
}

// reportProgress reports progress via callback.
func (c *Client) reportProgress(module string, progress float64, status string) {
	c.mu.RLock()
	fn := c.onProgress
	c.mu.RUnlock()

	if fn != nil {
		fn(module, progress, status)
	}
}

// reportFinding reports a finding via callback.
func (c *Client) reportFinding(finding Finding) {
	c.mu.RLock()
	fn := c.onFinding
	c.mu.RUnlock()

	if fn != nil {
		fn(finding)
	}
}

// Ping checks if msfrpcd is reachable.
func (c *Client) Ping() error {
	resp, err := c.call("core.version")
	if err != nil {
		return err
	}

	if _, ok := resp["version"]; !ok {
		return fmt.Errorf("unexpected response from msfrpcd")
	}

	return nil
}

// GetVersion returns the Metasploit version.
func (c *Client) GetVersion() (string, error) {
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()

	var resp map[string]interface{}
	var err error

	if token != "" {
		resp, err = c.call("core.version", token)
	} else {
		resp, err = c.call("core.version")
	}

	if err != nil {
		return "", err
	}

	if version, ok := resp["version"].(string); ok {
		return version, nil
	}

	return "unknown", nil
}
