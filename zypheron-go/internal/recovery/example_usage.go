package recovery

import (
	"errors"
	"fmt"
	"log"
	"time"
)

// Example: Wrapping a risky operation with panic recovery
func ExampleRecover() {
	// Wrap potentially panicking code
	Recover(func() {
		// Simulate risky operation that might panic
		processScanResults(nil) // This might panic on nil pointer
	})

	// Execution continues here even if panic occurred
	fmt.Println("Application continues running")
}

// Example: AI API call with retry mechanism
func ExampleWithRetry_AICall() {
	// Configure retry for AI API calls (transient failures are common)
	config := RetryConfig{
		MaxRetries:   5,
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Multiplier:   2.0, // Exponential backoff
		OnRetry: func(attempt int, err error) {
			log.Printf("AI API call failed (attempt %d): %v", attempt, err)
		},
	}

	err := WithRetry(func() error {
		// Call AI service (DeepSeek, OpenAI, etc.)
		return callAIService("analyze vulnerability", "CVE-2024-1234")
	}, config)

	if err != nil {
		log.Printf("AI service unavailable after retries: %v", err)
	}
}

// Example: Network request with retry and exponential backoff
func ExampleWithRetry_NetworkRequest() {
	config := RetryConfig{
		MaxRetries:   3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   2.0,
	}

	err := WithRetry(func() error {
		// Perform network request (scanning, reconnaissance, etc.)
		return performNetworkScan("192.168.1.0/24")
	}, config)

	if err != nil {
		log.Printf("Network scan failed: %v", err)
	}
}

// Example: Circuit breaker for external vulnerability database
func ExampleCircuitBreaker_VulnDB() {
	// Create circuit breaker for vulnerability database API
	vulnDBCircuit := NewCircuitBreaker(CircuitBreakerConfig{
		Name:      "vuln-db-api",
		Threshold: 5,                // Open after 5 consecutive failures
		Timeout:   30 * time.Second, // Try again after 30 seconds
		ResetTime: 60 * time.Second, // Full reset after 60 seconds of success
		OnStateChange: func(from, to CircuitState) {
			log.Printf("VulnDB circuit: %s -> %s", from, to)
		},
	})

	// Use circuit breaker for all vulnerability database queries
	for _, cve := range []string{"CVE-2024-1234", "CVE-2024-5678"} {
		err := vulnDBCircuit.Execute(func() error {
			return queryVulnerabilityDatabase(cve)
		})

		if errors.Is(err, ErrCircuitOpen) {
			log.Printf("VulnDB temporarily unavailable, using cached data")
			// Fallback to cached vulnerability data
			useCachedVulnData(cve)
		} else if err != nil {
			log.Printf("VulnDB query failed: %v", err)
		}
	}
}

// Example: Circuit breaker for Metasploit RPC
func ExampleCircuitBreaker_Metasploit() {
	// Create circuit breaker for Metasploit RPC connection
	msfCircuit := NewCircuitBreaker(CircuitBreakerConfig{
		Name:      "metasploit-rpc",
		Threshold: 3,
		Timeout:   20 * time.Second,
		OnStateChange: func(from, to CircuitState) {
			if to == StateOpen {
				log.Println("Metasploit RPC is down, disabling exploit modules")
			} else if to == StateClosed {
				log.Println("Metasploit RPC recovered, exploit modules available")
			}
		},
	})

	// Execute exploit through circuit breaker
	err := msfCircuit.Execute(func() error {
		return executeMetasploitExploit("exploit/multi/handler")
	})

	if errors.Is(err, ErrCircuitOpen) {
		log.Println("Metasploit unavailable, skipping exploitation phase")
	}
}

// Example: Combined retry + circuit breaker for reliable API calls
func ExampleCombinedRetryAndCircuitBreaker() {
	// Circuit breaker for the external service
	apiCircuit := NewCircuitBreaker(CircuitBreakerConfig{
		Name:      "external-api",
		Threshold: 5,
		Timeout:   30 * time.Second,
	})

	// Retry configuration for transient errors
	retryConfig := RetryConfig{
		MaxRetries:   3,
		InitialDelay: 200 * time.Millisecond,
		MaxDelay:     2 * time.Second,
		Multiplier:   2.0,
	}

	// Combine both patterns for maximum reliability
	err := WithRetry(func() error {
		return apiCircuit.Execute(func() error {
			// Your API call here
			return callExternalSecurityAPI()
		})
	}, retryConfig)

	if err != nil {
		log.Printf("API call failed with retry and circuit breaker: %v", err)
	}
}

// Example: RecoveryMiddleware for CLI command handlers
func ExampleRecoveryMiddleware_CLICommand() {
	// Wrap CLI command handler with panic recovery
	scanCommand := RecoveryMiddleware(func() error {
		// Parse and validate scan target
		target := parseScanTarget()

		// Execute scan (might panic on invalid input)
		results := performScan(target)

		// Display results
		displayResults(results)

		return nil
	})

	// Execute command safely
	if err := scanCommand(); err != nil {
		log.Printf("Scan command failed: %v", err)
	}
}

// Example: RecoveryMiddleware for tool execution
func ExampleRecoveryMiddleware_ToolExecution() {
	tools := []string{"nmap", "nikto", "sqlmap", "dirb"}

	for _, toolName := range tools {
		// Wrap each tool execution with recovery
		wrapped := RecoveryMiddleware(func() error {
			return executeTool(toolName, []string{"--target", "example.com"})
		})

		if err := wrapped(); err != nil {
			log.Printf("Tool %s failed: %v", toolName, err)
			// Continue with next tool instead of crashing
		}
	}
}

// Example: Protecting TUI updates from panics
func ExampleRecover_TUIUpdate() {
	// Wrap TUI update logic with panic recovery
	Recover(func() {
		// Update progress bar
		updateProgressBar(calculateProgress())

		// Update scan results table
		updateResultsTable(fetchLatestResults())

		// Refresh AI recommendations
		recs, _ := getAIRecommendations()
		updateAIPanel(recs)
	})
}

// Example: Circuit breaker with health check monitoring
func ExampleCircuitBreaker_HealthCheck() {
	// Create circuit breaker for external service
	serviceCircuit := NewCircuitBreaker(CircuitBreakerConfig{
		Name:      "external-service",
		Threshold: 3,
		Timeout:   15 * time.Second,
	})

	// Periodically check circuit state and log health
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		state := serviceCircuit.GetState()
		failures := serviceCircuit.GetFailures()

		log.Printf("Service health - State: %s, Failures: %d", state, failures)

		// Alert if circuit is open
		if state == StateOpen {
			sendAlert("External service is down")
		}
	}
}

// Example: Graceful degradation with circuit breaker
func ExampleCircuitBreaker_GracefulDegradation() {
	aiCircuit := NewCircuitBreaker(CircuitBreakerConfig{
		Name:      "ai-service",
		Threshold: 3,
		Timeout:   20 * time.Second,
	})

	// Try to get AI-powered recommendations
	var recommendations []string
	err := aiCircuit.Execute(func() error {
		var err error
		recommendations, err = getAIRecommendations()
		return err
	})

	if errors.Is(err, ErrCircuitOpen) || err != nil {
		// Gracefully degrade to rule-based recommendations
		log.Println("AI service unavailable, using rule-based fallback")
		recommendations = getRuleBasedRecommendations()
	}

	// Use recommendations regardless of source
	applyRecommendations(recommendations)
}

// Example: Rate-limited API calls with circuit breaker
func ExampleCircuitBreaker_RateLimiting() {
	apiCircuit := NewCircuitBreaker(CircuitBreakerConfig{
		Name:      "rate-limited-api",
		Threshold: 10, // Higher threshold for rate-limited APIs
		Timeout:   60 * time.Second,
	})

	// Process batch of requests
	requests := []string{"req1", "req2", "req3"}
	for _, req := range requests {
		err := apiCircuit.Execute(func() error {
			return processAPIRequest(req)
		})

		if errors.Is(err, ErrCircuitOpen) {
			log.Println("API rate limit reached, pausing requests")
			break
		}

		// Small delay to respect rate limits
		time.Sleep(100 * time.Millisecond)
	}
}

// Mock functions for examples (not part of actual implementation)

func processScanResults(data interface{}) {
	// Mock implementation
}

func callAIService(action, data string) error {
	// Mock implementation
	return nil
}

func performNetworkScan(target string) error {
	// Mock implementation
	return nil
}

func queryVulnerabilityDatabase(cve string) error {
	// Mock implementation
	return nil
}

func useCachedVulnData(cve string) {
	// Mock implementation
}

func executeMetasploitExploit(module string) error {
	// Mock implementation
	return nil
}

func callExternalSecurityAPI() error {
	// Mock implementation
	return nil
}

func parseScanTarget() string {
	// Mock implementation
	return "example.com"
}

func performScan(target string) interface{} {
	// Mock implementation
	return nil
}

func displayResults(results interface{}) {
	// Mock implementation
}

func executeTool(name string, args []string) error {
	// Mock implementation
	return nil
}

func calculateProgress() int {
	// Mock implementation
	return 50
}

func fetchLatestResults() interface{} {
	// Mock implementation
	return nil
}

func getAIRecommendations() ([]string, error) {
	// Mock implementation
	return []string{"recommendation1", "recommendation2"}, nil
}

func getRuleBasedRecommendations() []string {
	// Mock implementation
	return []string{"fallback1", "fallback2"}
}

func applyRecommendations(recs []string) {
	// Mock implementation
}

func updateProgressBar(progress int) {
	// Mock implementation
}

func updateResultsTable(results interface{}) {
	// Mock implementation
}

func updateAIPanel(recommendations []string) {
	// Mock implementation
}

func sendAlert(message string) {
	// Mock implementation
}

func processAPIRequest(req string) error {
	// Mock implementation
	return nil
}
