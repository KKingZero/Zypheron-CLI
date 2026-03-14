package ui

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
)

// ProgressDisplay provides real-time progress feedback during tool execution.
// It combines a spinner animation, progress bar, findings counter, and heartbeat.
type ProgressDisplay struct {
	mu sync.Mutex

	spinner    *spinner.Spinner
	toolName   string
	target     string
	startTime  time.Time
	lastUpdate time.Time

	// Progress tracking
	percent    float64
	statusText string

	// Findings tracking
	findings     []string
	findingCount int
	maxFindings  int // max findings to display (default 5)

	// Heartbeat
	heartbeatFrame int
	heartbeatChars []string

	// State
	stopped       bool
	heartbeatStop chan struct{} // PERF: Track heartbeat goroutine for cleanup
}

// Tool-specific progress parsing patterns
var ProgressPatterns = map[string]*regexp.Regexp{
	// Network scanners
	"nmap":    regexp.MustCompile(`About (\d+\.?\d*)% done`),
	"masscan": regexp.MustCompile(`rate:\s*[\d.]+[kKmM]?-?pps.*found=(\d+)`),

	// Web scanners
	"nikto":   regexp.MustCompile(`^\+ `), // count-based progress
	"nuclei":  regexp.MustCompile(`\[INF\].*Templates.*?(\d+)`),
	"gobuster": regexp.MustCompile(`Progress:\s*(\d+)\s*/\s*(\d+)`),
	"ffuf":     regexp.MustCompile(`:: Progress: \[(\d+)/(\d+)\]`),
	"dirb":     regexp.MustCompile(`GENERATED WORDS:\s*(\d+)`),

	// SQL injection
	"sqlmap": regexp.MustCompile(`\[(\d+):(\d+):(\d+)\]\s+\[INFO\]`), // timestamp = activity

	// Password cracking
	"hydra": regexp.MustCompile(`\[STATUS\]\s+([\d.]+)\s+tries/min`),
	"john":  regexp.MustCompile(`(\d+)g\s+\d+:\d+:\d+`), // guesses

	// Subdomain enumeration
	"amass":     regexp.MustCompile(`Querying|Average|Discoveries:`),
	"subfinder": regexp.MustCompile(`^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$`), // domain output = count-based progress
	"sublist3r": regexp.MustCompile(`Total Unique Subdomains Found:`),

	// Metasploit (basic output parsing)
	"msfconsole": regexp.MustCompile(`\[\*\]|\[\+\]|\[-\]`),
	"msf":        regexp.MustCompile(`\[\*\]|\[\+\]|\[-\]`),

	// API testing
	"newman": regexp.MustCompile(`iteration:\s*(\d+)/(\d+)|→`),
}

// Tool-specific finding detection patterns
var FindingPatterns = map[string]*regexp.Regexp{
	// Network scanners
	"nmap":    regexp.MustCompile(`(\d+)/(tcp|udp)\s+open\s+(\S+)`),
	"masscan": regexp.MustCompile(`Discovered open port (\d+)/(tcp|udp)`),

	// Web scanners
	"nikto":    regexp.MustCompile(`^\+ .*?(OSVDB-\d+|CVE-\d+-\d+|Server:|Retrieved)`),
	"nuclei":   regexp.MustCompile(`"template-id":\s*"([^"]+)"|^\[.*?\]\s+\[.*?\]\s+(.+)`),
	"gobuster": regexp.MustCompile(`^(/\S+)\s+\(Status:\s*(\d+)\)`),
	"ffuf":     regexp.MustCompile(`^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)`),
	"dirb":     regexp.MustCompile(`\+ (https?://\S+)\s+\(CODE:(\d+)`),

	// SQL injection
	"sqlmap": regexp.MustCompile(`Parameter:\s+'([^']+)'.*is vulnerable|Type:\s+(.+)|injected parameter '([^']+)'`),

	// Password cracking
	"hydra": regexp.MustCompile(`\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)`),
	"john":  regexp.MustCompile(`^(\S+)\s+\((\S+)\)$`), // password (user)

	// Subdomain enumeration
	"amass":     regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$`),
	"subfinder": regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$`),
	"sublist3r": regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$`),

	// Metasploit
	"msfconsole": regexp.MustCompile(`\[\+\]\s+(.+)`), // success messages
	"msf":        regexp.MustCompile(`\[\+\]\s+(.+)`),

	// API testing
	"newman": regexp.MustCompile(`✓|✗|AssertionError|FAIL|PASS`),
}

// Estimated total tests/items for progress calculation
var EstimatedTotals = map[string]float64{
	"nikto":     6500,   // ~6500 tests in default nikto scan
	"nuclei":    10000,  // varies by template count
	"gobuster":  10000,  // depends on wordlist
	"ffuf":      10000,  // depends on wordlist
	"dirb":      4612,   // common.txt default
	"hydra":     1000,   // depends on wordlist
	"subfinder": 100,    // count-based
	"amass":     500,    // estimate
	"newman":    50,     // API test count
}

// ExpectedLineCount provides tool-specific expected output line counts
// Used for line-count based progress estimation when tools don't report progress
var ExpectedLineCount = map[string]int{
	"nmap":       200,  // Typical nmap scan output lines
	"nikto":      500,  // Nikto verbose output
	"nuclei":     300,  // Nuclei template scan
	"gobuster":   1000, // Directory enumeration
	"ffuf":       1000, // Web fuzzer output
	"dirb":       500,  // Directory scanner
	"sqlmap":     400,  // SQL injection testing
	"hydra":      200,  // Password cracking
	"masscan":    150,  // Fast port scanner
	"amass":      300,  // Subdomain enumeration
	"subfinder":  100,  // Subdomain finder
	"sublist3r":  100,  // Subdomain lister
	"msfconsole": 200,  // Metasploit
	"msf":        200,  // Metasploit shorthand
	"newman":     150,  // Postman collection runner
}

// ToolCategories groups tools by type for display purposes
var ToolCategories = map[string]string{
	"nmap":       "Network Scanner",
	"masscan":    "Port Scanner",
	"nikto":      "Web Scanner",
	"nuclei":     "Vuln Scanner",
	"gobuster":   "Dir Buster",
	"ffuf":       "Web Fuzzer",
	"dirb":       "Dir Scanner",
	"sqlmap":     "SQL Injection",
	"hydra":      "Password Cracker",
	"john":       "Password Cracker",
	"amass":      "DNS Enum",
	"subfinder":  "Subdomain Finder",
	"sublist3r":  "Subdomain Finder",
	"msfconsole": "Metasploit",
	"msf":        "Metasploit",
	"newman":     "API Tester",
}

// NewProgressDisplay creates a new progress display for a tool execution.
func NewProgressDisplay(toolName, target string) *ProgressDisplay {
	s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
	s.Suffix = fmt.Sprintf(" Running %s on %s...", toolName, truncateTarget(target, 30))

	return &ProgressDisplay{
		spinner:        s,
		toolName:       toolName,
		target:         target,
		startTime:      time.Now(),
		lastUpdate:     time.Now(),
		maxFindings:    5,
		findings:       make([]string, 0, 10),
		heartbeatChars: []string{".", "..", "...", ""},
	}
}

// Start begins the progress display animation.
func (p *ProgressDisplay) Start() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.stopped {
		p.spinner.Start()
	}
}

// Stop halts the progress display.
func (p *ProgressDisplay) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stopped = true
	p.spinner.Stop()

	// PERF: Stop heartbeat goroutine to prevent leak
	if p.heartbeatStop != nil {
		close(p.heartbeatStop)
		p.heartbeatStop = nil
	}
}

// UpdateProgress updates the progress percentage and optional status text.
func (p *ProgressDisplay) UpdateProgress(percent float64, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}

	p.percent = percent
	p.lastUpdate = time.Now()
	if status != "" {
		p.statusText = status
	}

	p.updateSuffix()
}

// AddFinding records a new finding and displays it.
func (p *ProgressDisplay) AddFinding(finding string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}

	p.findingCount++
	p.lastUpdate = time.Now()

	// Keep only the last maxFindings
	if len(p.findings) >= p.maxFindings {
		p.findings = p.findings[1:]
	}
	p.findings = append(p.findings, finding)

	// Print the finding immediately
	p.spinner.Stop()
	fmt.Printf("  %s %s\n", Success.Sprint("Found:"), finding)
	p.spinner.Start()

	p.updateSuffix()
}

// Tick advances the heartbeat animation (call periodically during idle).
func (p *ProgressDisplay) Tick() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}

	p.heartbeatFrame = (p.heartbeatFrame + 1) % len(p.heartbeatChars)
	p.updateSuffix()
}

// ParseLine processes an output line and extracts progress/findings.
// Returns true if the line contained progress/finding information.
func (p *ProgressDisplay) ParseLine(line string) bool {
	p.mu.Lock()
	tool := p.toolName
	p.mu.Unlock()

	var foundProgress bool

	// Check for progress updates
	if pattern, ok := ProgressPatterns[tool]; ok {
		if matches := pattern.FindStringSubmatch(line); len(matches) > 0 {
			foundProgress = p.parseToolProgress(tool, line, matches)
		}
	}

	// Check for findings
	if pattern, ok := FindingPatterns[tool]; ok {
		if matches := pattern.FindStringSubmatch(line); len(matches) > 0 {
			finding := p.parseToolFinding(tool, line, matches)
			if finding != "" && !p.isDuplicateFinding(finding) {
				p.AddFinding(finding)
				foundProgress = true
			}
		}
	}

	return foundProgress
}

// parseToolProgress handles tool-specific progress parsing.
func (p *ProgressDisplay) parseToolProgress(tool, line string, matches []string) bool {
	switch tool {
	case "nmap":
		var pct float64
		if _, err := fmt.Sscanf(matches[1], "%f", &pct); err == nil {
			p.UpdateProgress(pct, "")
			return true
		}

	case "nikto", "subfinder", "amass":
		// Count-based progress
		p.mu.Lock()
		p.findingCount++
		total := EstimatedTotals[tool]
		if total == 0 {
			total = 100
		}
		pct := (float64(p.findingCount) / total) * 100
		if pct > 99 {
			pct = 99
		}
		p.percent = pct
		p.lastUpdate = time.Now()
		p.mu.Unlock()
		p.updateSuffixLocked()
		return true

	case "masscan":
		if len(matches) > 1 {
			var found int
			if _, err := fmt.Sscanf(matches[1], "%d", &found); err == nil {
				p.mu.Lock()
				p.findingCount = found
				p.lastUpdate = time.Now()
				p.mu.Unlock()
				p.updateSuffixLocked()
				return true
			}
		}

	case "gobuster", "ffuf":
		// Progress: current/total format
		if len(matches) >= 3 {
			var current, total int
			fmt.Sscanf(matches[1], "%d", &current)
			fmt.Sscanf(matches[2], "%d", &total)
			if total > 0 {
				pct := (float64(current) / float64(total)) * 100
				p.UpdateProgress(pct, fmt.Sprintf("%d/%d", current, total))
				return true
			}
		}

	case "sqlmap":
		// Activity indicator - just update timestamp
		p.mu.Lock()
		p.lastUpdate = time.Now()
		p.mu.Unlock()
		return true

	case "hydra":
		// Extract tries/min rate
		if len(matches) > 1 {
			p.mu.Lock()
			p.statusText = fmt.Sprintf("%.1s tries/min", matches[1])
			p.lastUpdate = time.Now()
			p.mu.Unlock()
			p.updateSuffixLocked()
			return true
		}

	case "john":
		// Guesses count
		if len(matches) > 1 {
			var guesses int
			fmt.Sscanf(matches[1], "%d", &guesses)
			p.mu.Lock()
			p.findingCount = guesses
			p.lastUpdate = time.Now()
			p.mu.Unlock()
			p.updateSuffixLocked()
			return true
		}

	case "msfconsole", "msf":
		// Activity indicator
		p.mu.Lock()
		p.lastUpdate = time.Now()
		p.mu.Unlock()
		return true
	}

	return false
}

// parseToolFinding extracts finding information from a matched line.
func (p *ProgressDisplay) parseToolFinding(tool, line string, matches []string) string {
	switch tool {
	case "nmap":
		if len(matches) >= 4 {
			return fmt.Sprintf("%s/%s %s", matches[1], matches[2], matches[3])
		}

	case "nikto":
		return truncateTarget(line, 60)

	case "nuclei":
		if matches[1] != "" {
			return matches[1]
		} else if len(matches) > 2 && matches[2] != "" {
			return truncateTarget(matches[2], 50)
		}

	case "masscan":
		if len(matches) >= 3 {
			return fmt.Sprintf("%s/%s open", matches[1], matches[2])
		}

	case "gobuster":
		if len(matches) >= 3 {
			return fmt.Sprintf("%s (Status: %s)", matches[1], matches[2])
		}

	case "ffuf":
		if len(matches) >= 4 {
			return fmt.Sprintf("%s [%s, %s bytes]", matches[1], matches[2], matches[3])
		}

	case "dirb":
		if len(matches) >= 3 {
			return fmt.Sprintf("%s (CODE: %s)", matches[1], matches[2])
		}

	case "sqlmap":
		// Return the first non-empty match group
		for i := 1; i < len(matches); i++ {
			if matches[i] != "" {
				return fmt.Sprintf("SQLi: %s", truncateTarget(matches[i], 50))
			}
		}

	case "hydra":
		if len(matches) >= 6 {
			return fmt.Sprintf("%s@%s:%s [%s]", matches[4], matches[3], matches[5], matches[2])
		}

	case "john":
		if len(matches) >= 3 {
			return fmt.Sprintf("%s (%s)", matches[1], matches[2])
		}

	case "amass", "subfinder", "sublist3r":
		// The whole line is the subdomain
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 0 && len(trimmed) < 100 {
			return trimmed
		}

	case "msfconsole", "msf":
		if len(matches) > 1 && matches[1] != "" {
			return truncateTarget(matches[1], 60)
		}
	}

	return ""
}

// isDuplicateFinding checks if a finding was already recorded.
func (p *ProgressDisplay) isDuplicateFinding(finding string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, f := range p.findings {
		if f == finding {
			return true
		}
	}
	return false
}

// updateSuffix updates the spinner suffix with current progress.
func (p *ProgressDisplay) updateSuffix() {
	elapsed := time.Since(p.startTime)

	var parts []string

	// Tool and target
	parts = append(parts, fmt.Sprintf(" %s", p.toolName))

	// Progress bar (if we have progress)
	if p.percent > 0 {
		bar := p.getProgressBar(p.percent)
		parts = append(parts, bar)
		parts = append(parts, Accent.Sprintf("%.0f%%", p.percent))
	}

	// Findings count
	if p.findingCount > 0 {
		parts = append(parts, fmt.Sprintf("| %s: %d", Success.Sprint("Found"), p.findingCount))
	}

	// Elapsed time
	parts = append(parts, fmt.Sprintf("| %s", formatDuration(elapsed)))

	// Heartbeat indicator if no recent updates
	if time.Since(p.lastUpdate) > 2*time.Second {
		heartbeat := p.heartbeatChars[p.heartbeatFrame]
		parts = append(parts, Muted.Sprintf("(active%s)", heartbeat))
	}

	p.spinner.Suffix = " " + strings.Join(parts, " ")
}

// updateSuffixLocked calls updateSuffix but expects caller NOT to hold lock.
func (p *ProgressDisplay) updateSuffixLocked() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updateSuffix()
}

// getProgressBar returns an ASCII progress bar.
func (p *ProgressDisplay) getProgressBar(percentage float64) string {
	width := 20
	filled := int(math.Round((percentage / 100) * float64(width)))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	empty := width - filled

	bar := strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", empty)
	return fmt.Sprintf("[%s]", Primary.Sprint(bar))
}

// GetElapsed returns the elapsed time since start.
func (p *ProgressDisplay) GetElapsed() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Since(p.startTime)
}

// GetFindingCount returns the number of findings.
func (p *ProgressDisplay) GetFindingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.findingCount
}

// GetProgress returns the current progress percentage.
func (p *ProgressDisplay) GetProgress() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.percent
}

// truncateTarget shortens a target string if too long.
func truncateTarget(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// formatDuration formats a duration in human-readable format.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// StartHeartbeat starts a background goroutine that ticks the heartbeat.
// Returns a stop channel - close it to stop the heartbeat.
// PERF: Heartbeat is automatically stopped when Stop() is called.
func (p *ProgressDisplay) StartHeartbeat() chan struct{} {
	p.mu.Lock()
	// Stop existing heartbeat if any
	if p.heartbeatStop != nil {
		close(p.heartbeatStop)
	}
	stop := make(chan struct{})
	p.heartbeatStop = stop
	p.mu.Unlock()

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.Tick()
			case <-stop:
				return
			}
		}
	}()

	return stop
}
