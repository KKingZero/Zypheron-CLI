package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/tools"
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/validation"
)

// NmapScanner implements the Scanner interface for nmap
// This is an example implementation demonstrating proper usage
type NmapScanner struct {
	executor *SandboxedExecutor
}

// NewNmapScanner creates a new nmap scanner instance
func NewNmapScanner() *NmapScanner {
	return &NmapScanner{
		executor: NewSandboxedExecutor(DefaultExecutorConfig()),
	}
}

// Name returns the scanner identifier
func (n *NmapScanner) Name() string {
	return "nmap"
}

// Validate performs nmap-specific target validation
func (n *NmapScanner) Validate(target string) error {
	// Use existing validation infrastructure
	if err := validation.ValidateTarget(target); err != nil {
		return fmt.Errorf("nmap target validation failed: %w", err)
	}

	// Additional nmap-specific validation could go here
	// For example, checking if target is a URL (nmap needs IP/domain)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return fmt.Errorf("nmap requires IP address or domain name, not URL")
	}

	return nil
}

// Execute runs nmap with the provided options
func (n *NmapScanner) Execute(ctx context.Context, opts ScanOptions) (<-chan OutputLine, error) {
	// Validate target first
	if err := n.Validate(opts.Target); err != nil {
		return nil, err
	}

	// Build nmap-specific arguments
	// Start with safe defaults
	args := []string{
		"-v",    // Verbose output for better streaming
		"-Pn",   // No ping (more reliable)
		"-T4",   // Timing template (aggressive but safe)
		opts.Target,
	}

	// Append user-provided arguments
	args = append(args, opts.Args...)

	// Update options with nmap arguments
	nmapOpts := opts
	nmapOpts.Args = args

	// Set reasonable defaults if not specified
	if nmapOpts.Timeout == 0 {
		nmapOpts.Timeout = DefaultTimeout
	}
	if nmapOpts.MaxOutputMB == 0 {
		nmapOpts.MaxOutputMB = 10 // 10MB default for nmap
	}

	// Execute via sandboxed executor
	return n.executor.Execute(ctx, n.Name(), nmapOpts)
}

// ParseResult extracts structured data from nmap output
func (n *NmapScanner) ParseResult(output string) (interface{}, error) {
	if strings.TrimSpace(output) == "" {
		return nil, fmt.Errorf("empty nmap output")
	}

	// Use existing nmap parser from tools package
	parsed := tools.ParseNmapOutput(output)

	if parsed == nil {
		return nil, fmt.Errorf("failed to parse nmap output")
	}

	return parsed, nil
}

// NiktoScanner implements the Scanner interface for nikto
// Another example demonstrating the interface
type NiktoScanner struct {
	executor *SandboxedExecutor
}

// NewNiktoScanner creates a new nikto scanner instance
func NewNiktoScanner() *NiktoScanner {
	return &NiktoScanner{
		executor: NewSandboxedExecutor(DefaultExecutorConfig()),
	}
}

// Name returns the scanner identifier
func (n *NiktoScanner) Name() string {
	return "nikto"
}

// Validate performs nikto-specific target validation
func (n *NiktoScanner) Validate(target string) error {
	// Use existing validation
	if err := validation.ValidateTarget(target); err != nil {
		return fmt.Errorf("nikto target validation failed: %w", err)
	}

	// Nikto requires HTTP/HTTPS or will assume HTTP
	// This is fine - no additional validation needed

	return nil
}

// Execute runs nikto with the provided options
func (n *NiktoScanner) Execute(ctx context.Context, opts ScanOptions) (<-chan OutputLine, error) {
	// Validate target
	if err := n.Validate(opts.Target); err != nil {
		return nil, err
	}

	// Build nikto-specific arguments
	args := []string{
		"-h", opts.Target, // Host
		"-output", "-",    // Output to stdout
		"-Format", "txt",  // Text format
		"-ask", "no",      // Non-interactive
	}

	// Only add -nolookup for IP addresses, not domain names
	// DNS lookups are needed for domain scanning to work correctly
	if isIPAddress(opts.Target) {
		args = append(args, "-nolookup")
	}

	// Append user-provided arguments
	args = append(args, opts.Args...)

	// Update options
	niktoOpts := opts
	niktoOpts.Args = args

	// Nikto can be verbose - set higher output limit
	if niktoOpts.MaxOutputMB == 0 {
		niktoOpts.MaxOutputMB = 20 // 20MB default for nikto
	}
	if niktoOpts.Timeout == 0 {
		niktoOpts.Timeout = DefaultTimeout
	}

	// Execute via sandboxed executor
	return n.executor.Execute(ctx, n.Name(), niktoOpts)
}

// ParseResult extracts structured data from nikto output
func (n *NiktoScanner) ParseResult(output string) (interface{}, error) {
	if strings.TrimSpace(output) == "" {
		return nil, fmt.Errorf("empty nikto output")
	}

	// Use existing nikto parser if available
	// The tools package has parseNiktoOutput (private)
	// For now, return raw output - can implement parser later
	findings := []string{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Nikto findings start with "+"
		if strings.HasPrefix(line, "+") {
			findings = append(findings, strings.TrimPrefix(line, "+"))
		}
	}

	if len(findings) == 0 {
		return nil, nil // No findings, but not an error
	}

	return map[string]interface{}{
		"findings": findings,
	}, nil
}

// SimpleScannerFactory implements ScannerFactory for basic scanner creation
type SimpleScannerFactory struct {
	scanners map[string]func() Scanner
}

// NewSimpleScannerFactory creates a scanner factory with default scanners
func NewSimpleScannerFactory() *SimpleScannerFactory {
	factory := &SimpleScannerFactory{
		scanners: make(map[string]func() Scanner),
	}

	// Register default scanners
	factory.scanners["nmap"] = func() Scanner { return NewNmapScanner() }
	factory.scanners["nikto"] = func() Scanner { return NewNiktoScanner() }

	return factory
}

// CreateScanner creates a scanner instance by name
func (f *SimpleScannerFactory) CreateScanner(toolName string) (Scanner, error) {
	// Validate tool name first
	if err := validation.ValidateToolName(toolName); err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	// Look up scanner factory
	scannerFunc, ok := f.scanners[toolName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrScannerNotFound, toolName)
	}

	return scannerFunc(), nil
}

// ListScanners returns all available scanner names
func (f *SimpleScannerFactory) ListScanners() []string {
	scanners := make([]string, 0, len(f.scanners))
	for name := range f.scanners {
		scanners = append(scanners, name)
	}
	return scanners
}

// IsAvailable checks if a scanner binary is installed
func (f *SimpleScannerFactory) IsAvailable(toolName string) bool {
	// Validate tool name
	if err := validation.ValidateToolName(toolName); err != nil {
		return false
	}

	// Check if scanner is registered
	if _, ok := f.scanners[toolName]; !ok {
		return false
	}

	// Try to create scanner and check binary
	scanner, err := f.CreateScanner(toolName)
	if err != nil {
		return false
	}

	// The executor will check if the binary exists during Execute
	// For now, just return true if scanner is registered
	// A more sophisticated implementation could do exec.LookPath here
	_ = scanner // Use scanner to avoid unused variable warning

	return true
}

// RegisterScanner adds a custom scanner to the factory
func (f *SimpleScannerFactory) RegisterScanner(name string, factory func() Scanner) error {
	// Validate scanner name
	if err := validation.ValidateToolName(name); err != nil {
		return fmt.Errorf("cannot register scanner: %w", err)
	}

	// Check if already registered
	if _, exists := f.scanners[name]; exists {
		return fmt.Errorf("scanner %s already registered", name)
	}

	f.scanners[name] = factory
	return nil
}

// isIPAddress checks if a string is a valid IP address (IPv4 or IPv6)
func isIPAddress(target string) bool {
	// Remove port if present
	host := target
	if strings.Contains(target, ":") {
		// Could be IPv6 or host:port
		// Try parsing as is first
		if ip := net.ParseIP(target); ip != nil {
			return true
		}
		// Try splitting on last colon for host:port format
		lastColon := strings.LastIndex(target, ":")
		if lastColon != -1 {
			host = target[:lastColon]
		}
	}

	// Try parsing as IP address
	return net.ParseIP(host) != nil
}
