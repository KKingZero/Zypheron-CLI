package kali

import (
	"github.com/KKingZero/Cobra-AI/zypheron-go/internal/platform"
)

// Environment represents the security Linux environment.
// It is kept in this package for backwards compatibility with older callers.
type Environment = platform.Environment

// DetectEnvironment detects if running on a supported security Linux distro and/or WSL.
func DetectEnvironment() (*Environment, error) {
	return platform.DetectEnvironment()
}
