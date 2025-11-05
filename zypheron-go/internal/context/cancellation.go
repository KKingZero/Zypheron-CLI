package context

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/ui"
)

// GlobalContext provides application-wide context with cancellation support
var (
	globalCtx    context.Context
	globalCancel context.CancelFunc
	once         sync.Once
)

// SetupGlobalContext initializes the global context with signal handling
func SetupGlobalContext() context.Context {
	once.Do(func() {
		globalCtx, globalCancel = context.WithCancel(context.Background())

		// Setup signal handling for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			sig := <-sigChan
			ui.Warning.Printf("\nReceived signal: %v. Shutting down gracefully...\n", sig)
			globalCancel()
		}()
	})

	return globalCtx
}

// GetGlobalContext returns the global context
func GetGlobalContext() context.Context {
	if globalCtx == nil {
		return SetupGlobalContext()
	}
	return globalCtx
}

// CancelGlobalContext cancels the global context
func CancelGlobalContext() {
	if globalCancel != nil {
		globalCancel()
	}
}

// WithTimeout creates a context with timeout from global context
func WithTimeout(timeout int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(GetGlobalContext(), timeout)
}

