package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestNewTokenBucket tests bucket creation
func TestNewTokenBucket(t *testing.T) {
	tests := []struct {
		name             string
		config           Config
		expectedCapacity float64
	}{
		{
			name:             "default config",
			config:           DefaultConfig(),
			expectedCapacity: 10,
		},
		{
			name:             "custom config",
			config:           Config{RequestsPerMinute: 120, BurstSize: 20},
			expectedCapacity: 20,
		},
		{
			name:             "zero rpm uses defaults",
			config:           Config{RequestsPerMinute: 0, BurstSize: 5},
			expectedCapacity: 10, // Falls back to default
		},
		{
			name:             "zero burst",
			config:           Config{RequestsPerMinute: 60, BurstSize: 0},
			expectedCapacity: 10, // Falls back to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tb := NewTokenBucket(tt.config)

			if tb.capacity != tt.expectedCapacity {
				t.Errorf("Expected capacity %f, got %f", tt.expectedCapacity, tb.capacity)
			}

			// Should start with full bucket
			if tb.tokens != tb.capacity {
				t.Errorf("Expected tokens %f, got %f", tb.capacity, tb.tokens)
			}

			if tb.closed {
				t.Error("New bucket should not be closed")
			}
		})
	}
}

// TestNewProviderLimiter tests provider-specific limiters
func TestNewProviderLimiter(t *testing.T) {
	providers := []string{"anthropic", "openai", "google", "deepseek", "grok", "ollama", "unknown"}

	for _, provider := range providers {
		t.Run(provider, func(t *testing.T) {
			tb := NewProviderLimiter(provider)

			if tb == nil {
				t.Fatal("Limiter should not be nil")
			}

			if tb.capacity <= 0 {
				t.Errorf("Capacity should be positive, got %f", tb.capacity)
			}

			if tb.refillRate <= 0 {
				t.Errorf("Refill rate should be positive, got %f", tb.refillRate)
			}
		})
	}
}

// TestAllow tests basic allow functionality
func TestAllow(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 3})

	// Should allow first 3 requests (burst capacity)
	for i := 0; i < 3; i++ {
		if !tb.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 4th request should be denied (bucket empty)
	if tb.Allow() {
		t.Error("4th request should be denied")
	}

	// Check stats
	stats := tb.Stats()
	if stats["accepted"].(int64) != 3 {
		t.Errorf("Expected 3 accepted, got %v", stats["accepted"])
	}
	if stats["rejected"].(int64) != 1 {
		t.Errorf("Expected 1 rejected, got %v", stats["rejected"])
	}
}

// TestAllowN tests consuming multiple tokens
func TestAllowN(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 10})

	// Should allow 5 tokens
	if !tb.AllowN(5) {
		t.Error("Should allow 5 tokens")
	}

	// Should allow another 5
	if !tb.AllowN(5) {
		t.Error("Should allow another 5 tokens")
	}

	// Should deny any more
	if tb.AllowN(1) {
		t.Error("Should deny when bucket is empty")
	}

	// AllowN(0) should always succeed
	if !tb.AllowN(0) {
		t.Error("AllowN(0) should always succeed")
	}

	// AllowN(-1) should always succeed
	if !tb.AllowN(-1) {
		t.Error("AllowN with negative should succeed")
	}
}

// TestRefill tests token refill over time
func TestRefill(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping refill test in short mode")
	}

	// 60 requests/minute = 1 per second
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 3})

	// Drain the bucket
	for i := 0; i < 3; i++ {
		tb.Allow()
	}

	// Should be empty
	if tb.Allow() {
		t.Error("Bucket should be empty")
	}

	// Wait for 1 second (should refill 1 token)
	time.Sleep(1100 * time.Millisecond)

	// Should now have 1 token
	if !tb.Allow() {
		t.Error("Should have 1 token after 1 second")
	}
}

// TestWait tests blocking wait
func TestWait(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping wait test in short mode")
	}

	tb := NewTokenBucket(Config{RequestsPerMinute: 600, BurstSize: 1}) // Fast refill for testing

	// Use the one token
	tb.Allow()

	// Wait should block and eventually succeed
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := tb.Wait(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Wait should succeed, got error: %v", err)
	}

	// Should have waited at least some time
	if elapsed < 50*time.Millisecond {
		t.Logf("Wait returned quickly: %v (this may be ok if tokens were available)", elapsed)
	}
}

// TestWaitContextCancellation tests wait with cancelled context
func TestWaitContextCancellation(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 1, BurstSize: 1}) // Very slow refill

	// Use the one token
	tb.Allow()

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := tb.Wait(ctx)
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}

// TestWaitTimeout tests wait with timeout
func TestWaitTimeout(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 1, BurstSize: 1}) // Very slow refill

	// Use the one token
	tb.Allow()

	// Short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := tb.Wait(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded, got: %v", err)
	}
}

// TestReserve tests reservation calculation
func TestReserve(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 5})

	// With full bucket, should return 0
	duration := tb.Reserve(3)
	if duration != 0 {
		t.Errorf("Expected 0 wait time, got %v", duration)
	}

	// Drain bucket
	for i := 0; i < 5; i++ {
		tb.Allow()
	}

	// Should need to wait for tokens
	duration = tb.Reserve(1)
	if duration <= 0 {
		t.Errorf("Expected positive wait time, got %v", duration)
	}

	// Reserve 0 should return 0
	if tb.Reserve(0) != 0 {
		t.Error("Reserve(0) should return 0")
	}

	// Reserve negative should return 0
	if tb.Reserve(-1) != 0 {
		t.Error("Reserve(-1) should return 0")
	}
}

// TestAvailable tests available token count
func TestAvailable(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 10})

	// Initially full
	if available := tb.Available(); int(available) != 10 {
		t.Errorf("Expected 10 tokens available, got %f", available)
	}

	// After consuming 3
	tb.AllowN(3)
	if available := tb.Available(); int(available) != 7 {
		t.Errorf("Expected 7 tokens available, got %f", available)
	}
}

// TestStats tests statistics tracking
func TestStats(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 5})

	// Make some requests
	tb.Allow() // Accepted
	tb.Allow() // Accepted
	tb.Allow() // Accepted
	tb.Allow() // Accepted
	tb.Allow() // Accepted
	tb.Allow() // Rejected (bucket empty)

	stats := tb.Stats()

	if stats["total_requests"].(int64) != 6 {
		t.Errorf("Expected 6 total requests, got %v", stats["total_requests"])
	}

	if stats["accepted"].(int64) != 5 {
		t.Errorf("Expected 5 accepted, got %v", stats["accepted"])
	}

	if stats["rejected"].(int64) != 1 {
		t.Errorf("Expected 1 rejected, got %v", stats["rejected"])
	}

	rate := stats["acceptance_rate"].(float64)
	expectedRate := 5.0 / 6.0
	if rate < expectedRate-0.01 || rate > expectedRate+0.01 {
		t.Errorf("Expected acceptance rate ~%f, got %f", expectedRate, rate)
	}
}

// TestReset tests bucket reset
func TestReset(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 10})

	// Use all tokens and track stats
	for i := 0; i < 10; i++ {
		tb.Allow()
	}
	tb.Allow() // Rejected

	// Reset
	tb.Reset()

	// Should be back to full capacity
	if tb.tokens != tb.capacity {
		t.Errorf("Expected full capacity after reset, got %f", tb.tokens)
	}

	// Stats should be cleared
	stats := tb.Stats()
	if stats["total_requests"].(int64) != 0 {
		t.Errorf("Expected 0 total requests after reset, got %v", stats["total_requests"])
	}
}

// TestClose tests limiter closure
func TestClose(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 10})

	// Close the limiter
	tb.Close()

	// Allow should return false
	if tb.Allow() {
		t.Error("Allow should return false after close")
	}

	// Wait should return error
	err := tb.Wait(context.Background())
	if err != ErrLimiterClosed {
		t.Errorf("Expected ErrLimiterClosed, got %v", err)
	}

	// Reserve should return -1
	if tb.Reserve(1) != -1 {
		t.Error("Reserve should return -1 after close")
	}
}

// TestSetRate tests dynamic rate adjustment
func TestSetRate(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 10})

	originalRate := tb.refillRate

	// Double the rate
	tb.SetRate(120)

	if tb.refillRate != originalRate*2 {
		t.Errorf("Expected rate to double, got %f", tb.refillRate)
	}

	// Invalid rate should be ignored
	tb.SetRate(0)
	if tb.refillRate != originalRate*2 {
		t.Error("Invalid rate should be ignored")
	}

	tb.SetRate(-10)
	if tb.refillRate != originalRate*2 {
		t.Error("Negative rate should be ignored")
	}
}

// TestSetCapacity tests dynamic capacity adjustment
func TestSetCapacity(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 60, BurstSize: 10})

	// Increase capacity
	tb.SetCapacity(20)
	if tb.capacity != 20 {
		t.Errorf("Expected capacity 20, got %f", tb.capacity)
	}

	// Decrease capacity (tokens should be capped)
	tb.SetCapacity(5)
	if tb.capacity != 5 {
		t.Errorf("Expected capacity 5, got %f", tb.capacity)
	}
	if tb.tokens > 5 {
		t.Errorf("Tokens should be capped at capacity, got %f", tb.tokens)
	}

	// Invalid capacity should be ignored
	tb.SetCapacity(0)
	if tb.capacity != 5 {
		t.Error("Zero capacity should be ignored")
	}

	tb.SetCapacity(-5)
	if tb.capacity != 5 {
		t.Error("Negative capacity should be ignored")
	}
}

// TestConcurrency tests thread safety
func TestConcurrency(t *testing.T) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 6000, BurstSize: 100})

	var wg sync.WaitGroup
	acceptedCount := int64(0)
	rejectedCount := int64(0)
	var mu sync.Mutex

	// Launch many goroutines
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if tb.Allow() {
					mu.Lock()
					acceptedCount++
					mu.Unlock()
				} else {
					mu.Lock()
					rejectedCount++
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	// Verify stats match our counts
	stats := tb.Stats()
	if stats["total_requests"].(int64) != 500 {
		t.Errorf("Expected 500 total requests, got %v", stats["total_requests"])
	}

	if stats["accepted"].(int64) != acceptedCount {
		t.Errorf("Stats accepted mismatch: stats=%v, counted=%d",
			stats["accepted"], acceptedCount)
	}
}

// TestGlobalLimiter tests singleton global limiter
func TestGlobalLimiter(t *testing.T) {
	limiter1 := GetGlobalLimiter()
	limiter2 := GetGlobalLimiter()

	if limiter1 != limiter2 {
		t.Error("GetGlobalLimiter should return same instance")
	}

	if limiter1 == nil {
		t.Error("Global limiter should not be nil")
	}
}

// TestRateLimitConvenience tests convenience functions
func TestRateLimitConvenience(t *testing.T) {
	// Reset global limiter for clean test
	globalLimiter = nil
	globalLimiterOnce = sync.Once{}

	// RateLimit should work
	result := RateLimit()
	// First call should succeed (fresh bucket)
	if !result {
		t.Error("First RateLimit call should succeed")
	}

	// RateLimitWait with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := RateLimitWait(ctx)
	// Should either succeed or timeout, not panic
	_ = err
}

// TestProviderConfigs tests provider configurations
func TestProviderConfigs(t *testing.T) {
	expectedProviders := []string{"anthropic", "openai", "google", "deepseek", "kimi", "ollama"}

	for _, provider := range expectedProviders {
		config, ok := ProviderConfigs[provider]
		if !ok {
			t.Errorf("Missing config for provider: %s", provider)
			continue
		}

		if config.RequestsPerMinute <= 0 {
			t.Errorf("Provider %s has invalid RequestsPerMinute: %f",
				provider, config.RequestsPerMinute)
		}

		if config.BurstSize <= 0 {
			t.Errorf("Provider %s has invalid BurstSize: %d",
				provider, config.BurstSize)
		}
	}
}

// TestErrorMessages tests error message strings
func TestErrorMessages(t *testing.T) {
	if ErrRateLimitExceeded.Error() != "rate limit exceeded" {
		t.Errorf("Unexpected ErrRateLimitExceeded message: %s", ErrRateLimitExceeded.Error())
	}

	if ErrLimiterClosed.Error() != "rate limiter is closed" {
		t.Errorf("Unexpected ErrLimiterClosed message: %s", ErrLimiterClosed.Error())
	}
}

// ===== BENCHMARK TESTS =====

// BenchmarkAllow benchmarks the Allow operation
func BenchmarkAllow(b *testing.B) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 1000000, BurstSize: 1000000})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.Allow()
	}
}

// BenchmarkAllowConcurrent benchmarks concurrent Allow operations
func BenchmarkAllowConcurrent(b *testing.B) {
	tb := NewTokenBucket(Config{RequestsPerMinute: 1000000, BurstSize: 1000000})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tb.Allow()
		}
	})
}

// BenchmarkStats benchmarks stats collection
func BenchmarkStats(b *testing.B) {
	tb := NewTokenBucket(DefaultConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tb.Stats()
	}
}

// BenchmarkAvailable benchmarks available token check
func BenchmarkAvailable(b *testing.B) {
	tb := NewTokenBucket(DefaultConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tb.Available()
	}
}

// BenchmarkReserve benchmarks reservation calculation
func BenchmarkReserve(b *testing.B) {
	tb := NewTokenBucket(DefaultConfig())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tb.Reserve(1)
	}
}
