package recovery

import (
	"errors"
	"testing"
	"time"
)

// TestRecover verifies panic recovery functionality
func TestRecover(t *testing.T) {
	// Test that panic is recovered
	recovered := false
	Recover(func() {
		defer func() {
			if r := recover(); r == nil {
				recovered = true
			}
		}()
		panic("test panic")
	})

	// If we reach here, panic was recovered
	if recovered {
		t.Error("Panic should have been recovered by Recover()")
	}
}

// TestRecoverNoPanic verifies normal execution without panic
func TestRecoverNoPanic(t *testing.T) {
	executed := false
	Recover(func() {
		executed = true
	})

	if !executed {
		t.Error("Function should have executed normally")
	}
}

// TestRetryConfigValidate verifies retry configuration validation
func TestRetryConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		config   RetryConfig
		expected RetryConfig
	}{
		{
			name: "negative max retries",
			config: RetryConfig{
				MaxRetries:   -1,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   2.0,
			},
			expected: RetryConfig{
				MaxRetries:   maxRetries,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   2.0,
			},
		},
		{
			name: "excessive max retries",
			config: RetryConfig{
				MaxRetries:   1000,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   2.0,
			},
			expected: RetryConfig{
				MaxRetries:   maxRetries,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   2.0,
			},
		},
		{
			name: "invalid multiplier",
			config: RetryConfig{
				MaxRetries:   3,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   0.5,
			},
			expected: RetryConfig{
				MaxRetries:   3,
				InitialDelay: 100 * time.Millisecond,
				MaxDelay:     5 * time.Second,
				Multiplier:   2.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.Validate()

			if tt.config.MaxRetries != tt.expected.MaxRetries {
				t.Errorf("MaxRetries = %d, want %d", tt.config.MaxRetries, tt.expected.MaxRetries)
			}
			if tt.config.Multiplier != tt.expected.Multiplier {
				t.Errorf("Multiplier = %f, want %f", tt.config.Multiplier, tt.expected.Multiplier)
			}
		})
	}
}

// TestWithRetry verifies retry mechanism
func TestWithRetry(t *testing.T) {
	// Test successful execution on first attempt
	t.Run("success on first attempt", func(t *testing.T) {
		attempts := 0
		config := RetryConfig{
			MaxRetries:   3,
			InitialDelay: 10 * time.Millisecond,
			MaxDelay:     100 * time.Millisecond,
			Multiplier:   2.0,
		}

		err := WithRetry(func() error {
			attempts++
			return nil
		}, config)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if attempts != 1 {
			t.Errorf("Expected 1 attempt, got %d", attempts)
		}
	})

	// Test retry on transient failure
	t.Run("success after retries", func(t *testing.T) {
		attempts := 0
		config := RetryConfig{
			MaxRetries:   3,
			InitialDelay: 10 * time.Millisecond,
			MaxDelay:     100 * time.Millisecond,
			Multiplier:   2.0,
		}

		err := WithRetry(func() error {
			attempts++
			if attempts < 3 {
				return errors.New("transient error")
			}
			return nil
		}, config)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
	})

	// Test exhausted retries
	t.Run("exhausted retries", func(t *testing.T) {
		attempts := 0
		config := RetryConfig{
			MaxRetries:   2,
			InitialDelay: 10 * time.Millisecond,
			MaxDelay:     100 * time.Millisecond,
			Multiplier:   2.0,
		}

		err := WithRetry(func() error {
			attempts++
			return errors.New("persistent error")
		}, config)

		if err == nil {
			t.Error("Expected error after exhausting retries")
		}
		if attempts != 3 { // MaxRetries + 1
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
	})
}

// TestCircuitBreaker verifies circuit breaker functionality
func TestCircuitBreaker(t *testing.T) {
	// Test circuit transitions
	t.Run("circuit state transitions", func(t *testing.T) {
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:      "test",
			Threshold: 2,
			Timeout:   100 * time.Millisecond,
			ResetTime: 50 * time.Millisecond,
		})

		// Initially closed
		if cb.GetState() != StateClosed {
			t.Errorf("Expected StateClosed, got %v", cb.GetState())
		}

		// First failure
		_ = cb.Execute(func() error {
			return errors.New("error")
		})

		if cb.GetState() != StateClosed {
			t.Error("Should remain closed after first failure")
		}

		// Second failure - should open
		_ = cb.Execute(func() error {
			return errors.New("error")
		})

		if cb.GetState() != StateOpen {
			t.Errorf("Expected StateOpen, got %v", cb.GetState())
		}

		// Should fail fast while open
		err := cb.Execute(func() error {
			t.Error("Should not execute while circuit is open")
			return nil
		})

		if !errors.Is(err, ErrCircuitOpen) {
			t.Errorf("Expected ErrCircuitOpen, got %v", err)
		}
	})

	// Test half-open transition
	t.Run("half-open transition", func(t *testing.T) {
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:      "test",
			Threshold: 1,
			Timeout:   50 * time.Millisecond,
			ResetTime: 50 * time.Millisecond,
		})

		// Open the circuit
		_ = cb.Execute(func() error {
			return errors.New("error")
		})

		if cb.GetState() != StateOpen {
			t.Errorf("Expected StateOpen, got %v", cb.GetState())
		}

		// Wait for timeout
		time.Sleep(60 * time.Millisecond)

		// Next attempt should transition to half-open
		_ = cb.Execute(func() error {
			return nil
		})

		// After successful execution and reset time, should be closed
		time.Sleep(60 * time.Millisecond)
		_ = cb.Execute(func() error {
			return nil
		})

		if cb.GetState() != StateClosed {
			t.Errorf("Expected StateClosed after recovery, got %v", cb.GetState())
		}
	})

	// Test reset
	t.Run("manual reset", func(t *testing.T) {
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			Name:      "test",
			Threshold: 1,
			Timeout:   1 * time.Second,
		})

		// Open the circuit
		_ = cb.Execute(func() error {
			return errors.New("error")
		})

		if cb.GetState() != StateOpen {
			t.Error("Circuit should be open")
		}

		// Manual reset
		cb.Reset()

		if cb.GetState() != StateClosed {
			t.Error("Circuit should be closed after reset")
		}
	})
}

// TestRecoveryMiddleware verifies middleware functionality
func TestRecoveryMiddleware(t *testing.T) {
	// Test normal execution
	t.Run("normal execution", func(t *testing.T) {
		wrapped := RecoveryMiddleware(func() error {
			return nil
		})

		err := wrapped()
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})

	// Test error propagation
	t.Run("error propagation", func(t *testing.T) {
		expectedErr := errors.New("test error")
		wrapped := RecoveryMiddleware(func() error {
			return expectedErr
		})

		err := wrapped()
		if err != expectedErr {
			t.Errorf("Expected %v, got %v", expectedErr, err)
		}
	})

	// Test panic recovery
	t.Run("panic recovery", func(t *testing.T) {
		wrapped := RecoveryMiddleware(func() error {
			panic("test panic")
		})

		err := wrapped()
		if err == nil {
			t.Error("Expected error from panic recovery")
		}
	})
}

// TestSetLogDirectory verifies log directory configuration
func TestSetLogDirectory(t *testing.T) {
	// Test absolute path
	t.Run("absolute path", func(t *testing.T) {
		originalDir := getLogDirectory()
		defer SetLogDirectory(originalDir)

		newDir := "/tmp/test-recovery-logs"
		SetLogDirectory(newDir)

		if getLogDirectory() != newDir {
			t.Errorf("Expected %s, got %s", newDir, getLogDirectory())
		}
	})

	// Test relative path (should be ignored)
	t.Run("relative path ignored", func(t *testing.T) {
		originalDir := getLogDirectory()
		defer SetLogDirectory(originalDir)

		SetLogDirectory("relative/path")

		if getLogDirectory() != originalDir {
			t.Error("Relative path should be ignored")
		}
	})
}
