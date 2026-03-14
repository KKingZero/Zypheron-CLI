// Package queue provides a scan job queue system for the Zypheron TUI.
// Manages background scan execution with configurable limits, progress tracking,
// and integration with the Bubble Tea message system.
package queue

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/buffer"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tui/scanner"
)

// JobStatus represents the current state of a scan job
type JobStatus int

const (
	JobPending   JobStatus = iota // Waiting in queue
	JobRunning                    // Currently executing
	JobCompleted                  // Successfully completed
	JobFailed                     // Failed with error
	JobCanceled                   // Canceled by user
)

// String returns a human-readable status string
func (s JobStatus) String() string {
	switch s {
	case JobPending:
		return "pending"
	case JobRunning:
		return "running"
	case JobCompleted:
		return "completed"
	case JobFailed:
		return "failed"
	case JobCanceled:
		return "canceled"
	default:
		return "unknown"
	}
}

// ScanJob represents a queued scan operation
type ScanJob struct {
	// ID is a unique identifier for this job
	ID string

	// Target is the scan target (IP, domain, CIDR, URL)
	Target string

	// Tool is the scanner tool to use (nmap, nikto, etc.)
	Tool string

	// Status is the current job state
	Status JobStatus

	// statusAtomic is thread-safe status for concurrent access
	statusAtomic atomic.Int32

	// Progress is the estimated completion percentage (0-100)
	Progress float64

	// progressAtomic is thread-safe progress for concurrent access
	progressAtomic atomic.Int64

	// Output stores streaming output (bounded ring buffer)
	Output *buffer.RingBuffer

	// Result holds the final scan result (nil until complete)
	Result *scanner.ScanResult

	// Error holds any error that occurred (nil on success)
	Error error

	// Phase identifies the recon phase (optional, for recon workflows)
	Phase string

	// CreatedAt records when the job was queued
	CreatedAt time.Time

	// StartedAt records when execution began (zero if pending)
	StartedAt time.Time

	// CompletedAt records when execution finished (zero if not complete)
	CompletedAt time.Time
}

// Duration returns the execution duration (or time since start if running)
func (j *ScanJob) Duration() time.Duration {
	if j.StartedAt.IsZero() {
		return 0
	}
	if j.CompletedAt.IsZero() {
		return time.Since(j.StartedAt)
	}
	return j.CompletedAt.Sub(j.StartedAt)
}

// ManagerConfig configures the queue manager
type ManagerConfig struct {
	// MaxQueueSize is the maximum number of pending jobs
	MaxQueueSize int

	// MaxConcurrent is the maximum number of concurrent scans
	MaxConcurrent int

	// OutputBufferSize is the size of the ring buffer for each job
	OutputBufferSize int

	// DefaultTimeout is the default scan timeout
	DefaultTimeout time.Duration
}

// DefaultManagerConfig returns sensible defaults
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		MaxQueueSize:     5,                  // Max 5 queued (per user requirement)
		MaxConcurrent:    3,                  // Allow 3 concurrent scans
		OutputBufferSize: 10000,              // 10K lines in ring buffer
		DefaultTimeout:   5 * time.Minute,
	}
}

// Manager handles the scan job queue and execution
type Manager struct {
	config   ManagerConfig
	executor *scanner.SandboxedExecutor

	// Job storage
	pending   []*ScanJob          // Pending jobs (FIFO queue)
	active    map[string]*ScanJob // Currently running jobs (by ID)
	completed []*ScanJob          // Completed jobs (most recent first)

	// Synchronization
	mu     sync.RWMutex
	wg     sync.WaitGroup // Track active job goroutines
	ctx    context.Context
	cancel context.CancelFunc

	// Bubble Tea program reference for sending messages
	program *tea.Program
}

// NewManager creates a new queue manager with the given configuration
func NewManager(cfg ManagerConfig) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config:    cfg,
		executor:  scanner.NewSandboxedExecutor(scanner.DefaultExecutorConfig()),
		pending:   make([]*ScanJob, 0, cfg.MaxQueueSize),
		active:    make(map[string]*ScanJob),
		completed: make([]*ScanJob, 0),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// SetProgram sets the Bubble Tea program for sending messages
// Must be called after TUI initialization
func (m *Manager) SetProgram(p *tea.Program) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.program = p
}

// Enqueue adds a new scan job to the queue
// Returns error if queue is full
func (m *Manager) Enqueue(job *ScanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check queue size limit
	if len(m.pending) >= m.config.MaxQueueSize {
		return fmt.Errorf("queue full: maximum %d pending scans allowed", m.config.MaxQueueSize)
	}

	// Initialize job
	job.Status = JobPending
	job.CreatedAt = time.Now()
	job.Output = buffer.NewRingBuffer(m.config.OutputBufferSize)

	// Add to queue
	m.pending = append(m.pending, job)

	// Try to start execution if slots available
	go m.tryStartNext()

	return nil
}

// Cancel cancels a job by ID
// Returns error if job not found or cannot be canceled
func (m *Manager) Cancel(jobID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check pending queue
	for i, job := range m.pending {
		if job.ID == jobID {
			job.Status = JobCanceled
			job.statusAtomic.Store(int32(JobCanceled))
			job.CompletedAt = time.Now()
			// Remove from pending
			m.pending = append(m.pending[:i], m.pending[i+1:]...)
			// Add to completed
			m.completed = append([]*ScanJob{job}, m.completed...)
			return nil
		}
	}

	// Check active jobs
	if job, ok := m.active[jobID]; ok {
		job.Status = JobCanceled
		job.statusAtomic.Store(int32(JobCanceled))
		// Cancellation will be handled by context
		// The worker goroutine will clean up
		return nil
	}

	return fmt.Errorf("job not found: %s", jobID)
}

// CancelActive cancels all active scans
func (m *Manager) CancelActive() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.active {
		job.Status = JobCanceled
		job.statusAtomic.Store(int32(JobCanceled))
	}
}

// GetJob retrieves a job by ID from any state
func (m *Manager) GetJob(jobID string) (*ScanJob, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check pending
	for _, job := range m.pending {
		if job.ID == jobID {
			return job, true
		}
	}

	// Check active
	if job, ok := m.active[jobID]; ok {
		return job, true
	}

	// Check completed
	for _, job := range m.completed {
		if job.ID == jobID {
			return job, true
		}
	}

	return nil, false
}

// GetStatus returns a snapshot of all jobs in the queue
func (m *Manager) GetStatus() []*ScanJob {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var jobs []*ScanJob

	// Active jobs first
	for _, job := range m.active {
		jobs = append(jobs, job)
	}

	// Then pending
	for _, job := range m.pending {
		jobs = append(jobs, job)
	}

	// Then recent completed (limit to 10)
	limit := 10
	if len(m.completed) < limit {
		limit = len(m.completed)
	}
	for i := 0; i < limit; i++ {
		jobs = append(jobs, m.completed[i])
	}

	return jobs
}

// GetPendingCount returns the number of pending jobs
func (m *Manager) GetPendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pending)
}

// GetActiveCount returns the number of active jobs
func (m *Manager) GetActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.active)
}

// QueueSpaceAvailable returns true if the queue has room for more jobs
func (m *Manager) QueueSpaceAvailable() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pending) < m.config.MaxQueueSize
}

// tryStartNext attempts to start the next pending job if slots are available
// Must be called with lock NOT held
func (m *Manager) tryStartNext() {
	m.mu.Lock()

	// Check if we can start more jobs
	if len(m.active) >= m.config.MaxConcurrent {
		m.mu.Unlock()
		return
	}

	// Get next pending job
	if len(m.pending) == 0 {
		m.mu.Unlock()
		return
	}

	job := m.pending[0]
	m.pending = m.pending[1:]

	// Move to active
	job.Status = JobRunning
	job.statusAtomic.Store(int32(JobRunning))
	job.StartedAt = time.Now()
	m.active[job.ID] = job

	m.mu.Unlock()

	// Start execution in goroutine
	go m.executeJob(job)
}

// executeJob runs a scan job and handles completion
func (m *Manager) executeJob(job *ScanJob) {
	m.wg.Add(1)
	defer m.wg.Done()

	// Create job-specific context
	ctx, cancel := context.WithTimeout(m.ctx, m.config.DefaultTimeout)
	defer cancel()

	// Send job started message
	m.sendMessage(ScanStartedMsg{JobID: job.ID, Tool: job.Tool, Target: job.Target})

	// Build scan options
	opts := scanner.ScanOptions{
		Target:       job.Target,
		Timeout:      m.config.DefaultTimeout,
		StreamOutput: true,
		MaxOutputMB:  50, // 50MB max output
	}

	// Execute scanner
	outputChan, err := m.executor.Execute(ctx, job.Tool, opts)
	if err != nil {
		m.completeJob(job, nil, err)
		return
	}

	// Stream output and track progress
	start := time.Now()
	lineCount := 0

	for line := range outputChan {
		// Check for cancellation using atomic read (thread-safe)
		if JobStatus(job.statusAtomic.Load()) == JobCanceled {
			cancel()
			break
		}

		// Add to ring buffer
		category := "info"
		if line.IsError {
			category = "error"
		}
		job.Output.Write(line.Content, category)

		lineCount++

		// Update progress (estimate based on time and output)
		elapsed := time.Since(start)
		estimatedProgress := float64(elapsed) / float64(m.config.DefaultTimeout) * 100
		if estimatedProgress > 95 {
			estimatedProgress = 95 // Cap at 95% until complete
		}
		// Store progress atomically (thread-safe)
		job.progressAtomic.Store(int64(estimatedProgress * 100)) // Store as fixed-point (x100)
		job.Progress = estimatedProgress                         // Also update for UI reads under lock

		// Send progress message every 10 lines
		if lineCount%10 == 0 {
			m.sendMessage(ScanProgressMsg{
				JobID:    job.ID,
				Progress: estimatedProgress,
				Line:     line.Content,
			})
		}
	}

	// Check cancellation status using atomic read
	canceled := JobStatus(job.statusAtomic.Load()) == JobCanceled

	// Collect result
	result := &scanner.ScanResult{
		Success:   !canceled,
		Output:    job.Output.Export(),
		Duration:  time.Since(start),
		BytesRead: int64(job.Output.Len()),
	}

	// Complete the job
	if canceled {
		m.completeJob(job, result, fmt.Errorf("scan canceled"))
	} else {
		m.completeJob(job, result, nil)
	}
}

// completeJob marks a job as complete and moves it to completed list
func (m *Manager) completeJob(job *ScanJob, result *scanner.ScanResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from active
	delete(m.active, job.ID)

	// Update job state
	job.CompletedAt = time.Now()
	job.Progress = 100
	job.Result = result
	job.Error = err

	if err != nil && job.Status != JobCanceled {
		job.Status = JobFailed
	} else if job.Status != JobCanceled {
		job.Status = JobCompleted
	}

	// Add to completed (most recent first)
	m.completed = append([]*ScanJob{job}, m.completed...)

	// Limit completed history to 100 items
	if len(m.completed) > 100 {
		m.completed = m.completed[:100]
	}

	// Send completion message
	if err != nil {
		m.sendMessageLocked(ScanFailedMsg{JobID: job.ID, Error: err.Error()})
	} else {
		m.sendMessageLocked(ScanCompletedMsg{JobID: job.ID, Result: result})
	}

	// Try to start next job (release lock first)
	go m.tryStartNext()
}

// sendMessage sends a message to the Bubble Tea program
// Must be called with lock NOT held
func (m *Manager) sendMessage(msg tea.Msg) {
	m.mu.RLock()
	p := m.program
	m.mu.RUnlock()

	if p != nil {
		p.Send(msg)
	}
}

// sendMessageLocked sends a message to the Bubble Tea program
// Must be called with lock HELD (uses separate goroutine to avoid deadlock)
func (m *Manager) sendMessageLocked(msg tea.Msg) {
	p := m.program
	if p != nil {
		go p.Send(msg)
	}
}

// Shutdown gracefully shuts down the queue manager
func (m *Manager) Shutdown() {
	m.cancel()
	m.wg.Wait() // Wait for all active goroutines to complete
}

// Message types for Bubble Tea integration

// ScanQueuedMsg is sent when a scan is added to the queue
type ScanQueuedMsg struct {
	JobID  string
	Target string
	Tool   string
}

// ScanStartedMsg is sent when a scan starts executing
type ScanStartedMsg struct {
	JobID  string
	Tool   string
	Target string
}

// ScanProgressMsg is sent periodically during scan execution
type ScanProgressMsg struct {
	JobID    string
	Progress float64
	Line     string
}

// ScanCompletedMsg is sent when a scan completes successfully
type ScanCompletedMsg struct {
	JobID  string
	Result *scanner.ScanResult
}

// ScanFailedMsg is sent when a scan fails
type ScanFailedMsg struct {
	JobID string
	Error string
}

// QueueFullMsg is sent when trying to enqueue to a full queue
type QueueFullMsg struct{}

// ToolMissingMsg is sent when a required tool is not installed
type ToolMissingMsg struct {
	Tool       string
	InstallCmd string
}
