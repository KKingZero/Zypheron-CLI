package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrRateLimitExceeded is returned when rate limit is exceeded
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	// ErrLimiterClosed is returned when limiter is closed
	ErrLimiterClosed = errors.New("rate limiter is closed")
)

// TokenBucket implements a token bucket rate limiter
// Tokens are added at a fixed rate and consumed on each request
type TokenBucket struct {
	capacity       float64       // Maximum tokens in bucket
	tokens         float64       // Current tokens available
	refillRate     float64       // Tokens added per second
	lastRefill     time.Time     // Last time tokens were refilled
	mu             sync.Mutex
	closed         bool

	// Stats tracking
	totalRequests  int64
	acceptedCount  int64
	rejectedCount  int64
	waitCount      int64
}

// Config holds rate limiter configuration
type Config struct {
	// RequestsPerMinute is the sustained request rate
	RequestsPerMinute float64
	// BurstSize is the maximum burst capacity
	BurstSize int
}

// DefaultConfig returns sensible defaults for AI API rate limiting
func DefaultConfig() Config {
	return Config{
		RequestsPerMinute: 60,  // 1 request per second average
		BurstSize:         10,  // Allow bursts of 10 requests
	}
}

// ProviderConfigs contains rate limits for different AI providers
var ProviderConfigs = map[string]Config{
	"anthropic": {RequestsPerMinute: 60, BurstSize: 10},
	"openai":    {RequestsPerMinute: 60, BurstSize: 20},
	"google":    {RequestsPerMinute: 60, BurstSize: 10},
	"deepseek":  {RequestsPerMinute: 30, BurstSize: 5},
	"kimi":      {RequestsPerMinute: 30, BurstSize: 5},
	"ollama":    {RequestsPerMinute: 120, BurstSize: 30}, // Local, more lenient
}

// NewTokenBucket creates a new token bucket rate limiter
func NewTokenBucket(config Config) *TokenBucket {
	if config.RequestsPerMinute <= 0 {
		config = DefaultConfig()
	}

	capacity := float64(config.BurstSize)
	if capacity <= 0 {
		capacity = 10
	}

	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity, // Start with full bucket
		refillRate: config.RequestsPerMinute / 60.0, // Convert to per-second
		lastRefill: time.Now(),
	}
}

// NewGlobalLimiter creates a limiter with global defaults
func NewGlobalLimiter() *TokenBucket {
	return NewTokenBucket(DefaultConfig())
}

// NewProviderLimiter creates a limiter for a specific provider
func NewProviderLimiter(provider string) *TokenBucket {
	config, ok := ProviderConfigs[provider]
	if !ok {
		config = DefaultConfig()
	}
	return NewTokenBucket(config)
}

// refill adds tokens based on time elapsed since last refill
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	// Add tokens based on time elapsed
	tb.tokens += elapsed * tb.refillRate

	// Cap at capacity
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	tb.lastRefill = now
}

// Allow checks if a request can proceed immediately
// Returns true if allowed, false if rate limited
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.closed {
		return false
	}

	tb.totalRequests++
	tb.refill()

	if tb.tokens >= 1 {
		tb.tokens--
		tb.acceptedCount++
		return true
	}

	tb.rejectedCount++
	return false
}

// AllowN checks if N tokens can be consumed
func (tb *TokenBucket) AllowN(n int) bool {
	if n <= 0 {
		return true
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.closed {
		return false
	}

	tb.totalRequests++
	tb.refill()

	needed := float64(n)
	if tb.tokens >= needed {
		tb.tokens -= needed
		tb.acceptedCount++
		return true
	}

	tb.rejectedCount++
	return false
}

// Wait blocks until a token is available or context is cancelled
func (tb *TokenBucket) Wait(ctx context.Context) error {
	tb.mu.Lock()
	if tb.closed {
		tb.mu.Unlock()
		return ErrLimiterClosed
	}
	tb.totalRequests++
	tb.waitCount++
	tb.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tb.mu.Lock()
		if tb.closed {
			tb.mu.Unlock()
			return ErrLimiterClosed
		}

		tb.refill()

		if tb.tokens >= 1 {
			tb.tokens--
			tb.acceptedCount++
			tb.mu.Unlock()
			return nil
		}

		// Calculate wait time for next token
		tokensNeeded := 1 - tb.tokens
		waitTime := time.Duration(tokensNeeded/tb.refillRate*1000) * time.Millisecond
		if waitTime < 10*time.Millisecond {
			waitTime = 10 * time.Millisecond
		}
		tb.mu.Unlock()

		// Wait before retry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Continue loop
		}
	}
}

// WaitN blocks until N tokens are available
func (tb *TokenBucket) WaitN(ctx context.Context, n int) error {
	if n <= 0 {
		return nil
	}

	for i := 0; i < n; i++ {
		if err := tb.Wait(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Reserve returns how long to wait before n tokens will be available
func (tb *TokenBucket) Reserve(n int) time.Duration {
	if n <= 0 {
		return 0
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.closed {
		return -1 // Indicates error
	}

	tb.refill()

	needed := float64(n)
	if tb.tokens >= needed {
		return 0
	}

	tokensNeeded := needed - tb.tokens
	return time.Duration(tokensNeeded/tb.refillRate*1000) * time.Millisecond
}

// Available returns the current number of tokens available
func (tb *TokenBucket) Available() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	return tb.tokens
}

// Stats returns rate limiter statistics
func (tb *TokenBucket) Stats() map[string]interface{} {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	return map[string]interface{}{
		"capacity":        tb.capacity,
		"tokens":          tb.tokens,
		"refill_rate":     tb.refillRate,
		"total_requests":  tb.totalRequests,
		"accepted":        tb.acceptedCount,
		"rejected":        tb.rejectedCount,
		"waited":          tb.waitCount,
		"acceptance_rate": func() float64 {
			if tb.totalRequests == 0 {
				return 1.0
			}
			return float64(tb.acceptedCount) / float64(tb.totalRequests)
		}(),
	}
}

// Reset resets the limiter to full capacity
func (tb *TokenBucket) Reset() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.tokens = tb.capacity
	tb.lastRefill = time.Now()
	tb.totalRequests = 0
	tb.acceptedCount = 0
	tb.rejectedCount = 0
	tb.waitCount = 0
}

// Close closes the rate limiter
func (tb *TokenBucket) Close() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.closed = true
}

// SetRate dynamically updates the refill rate
func (tb *TokenBucket) SetRate(requestsPerMinute float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if requestsPerMinute > 0 {
		tb.refillRate = requestsPerMinute / 60.0
	}
}

// SetCapacity dynamically updates the bucket capacity
func (tb *TokenBucket) SetCapacity(capacity int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if capacity > 0 {
		tb.capacity = float64(capacity)
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
	}
}

// GlobalRateLimiter is the singleton global rate limiter instance
var (
	globalLimiter     *TokenBucket
	globalLimiterOnce sync.Once
)

// GetGlobalLimiter returns the singleton global rate limiter
func GetGlobalLimiter() *TokenBucket {
	globalLimiterOnce.Do(func() {
		globalLimiter = NewGlobalLimiter()
	})
	return globalLimiter
}

// RateLimit is a convenience function that uses the global limiter
func RateLimit() bool {
	return GetGlobalLimiter().Allow()
}

// RateLimitWait is a convenience function that waits using the global limiter
func RateLimitWait(ctx context.Context) error {
	return GetGlobalLimiter().Wait(ctx)
}
