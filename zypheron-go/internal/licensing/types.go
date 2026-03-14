// Package licensing provides license validation and feature gating for Zypheron CLI
package licensing

import (
	"time"
)

// Tier represents subscription tiers
type Tier string

const (
	TierFree       Tier = "free"
	TierStarter    Tier = "starter"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
)

// Feature represents gated features
type Feature string

const (
	FeatureCloudAI         Feature = "cloud_ai"
	FeatureAutopent        Feature = "autopent"
	FeatureExploitation    Feature = "exploitation"
	FeaturePostExploit     Feature = "post_exploitation"
	FeatureTeams           Feature = "teams"
	FeatureCompliance      Feature = "compliance"
	FeatureAuditLogs       Feature = "audit_logs"
	FeatureAPIAccess       Feature = "api_access"
	FeatureSSO             Feature = "sso"
	FeatureNetworkScan     Feature = "network_scan"
	FeatureWebScan         Feature = "web_scan"
	FeatureLocalAI         Feature = "local_ai"
	FeaturePrioritySupport Feature = "priority_support"
)

// License represents a user's license state
type License struct {
	UserID           string    `json:"user_id"`
	Email            string    `json:"email"`
	Tier             Tier      `json:"tier"`
	Features         []Feature `json:"features"`
	TokensRemaining  int64     `json:"tokens_remaining"`
	TokensUsed       int64     `json:"tokens_used"`
	TokensLimit      int64     `json:"tokens_limit"`
	ResetDate        time.Time `json:"reset_date"`
	ExpiresAt        time.Time `json:"expires_at"`
	IssuedAt         time.Time `json:"issued_at"`
	DeviceID         string    `json:"device_id"`
	TeamID           string    `json:"team_id,omitempty"`
	TeamRole         string    `json:"team_role,omitempty"`
	OfflineDays      int       `json:"offline_days"`
	Signature        string    `json:"signature"`
	LicenseID        string    `json:"license_id"`
	Valid            bool      `json:"valid"`
	CreatedAt        time.Time `json:"created_at"`
	RefreshedAt      time.Time `json:"refreshed_at"`
	DevicesUsed      int       `json:"devices_used"`
	DevicesLimit     int       `json:"devices_limit"`
	OfflineMode      bool      `json:"offline_mode"`
	OfflineToken     string    `json:"offline_token"`
	OfflineGraceDays int       `json:"offline_grace_days"`
}

// TierConfig defines token limits and features per tier
type TierConfig struct {
	TokenLimit   int64
	Features     []Feature
	DeviceLimit  int
	OfflineDays  int
	Description  string
}

// TierConfigs maps tiers to their configurations
var TierConfigs = map[Tier]TierConfig{
	TierFree: {
		TokenLimit:  0,
		Features:    []Feature{},
		DeviceLimit: 1,
		OfflineDays: -1, // Unlimited — free tier has no license to expire
		Description: "Free - Scanning & Self-hosted AI",
	},
	TierStarter: {
		TokenLimit:  1_000_000,
		Features:    []Feature{FeatureCloudAI, FeatureAutopent, FeatureExploitation, FeaturePostExploit},
		DeviceLimit: 2,
		OfflineDays: 7,
		Description: "Starter - 1M tokens/month",
	},
	TierPro: {
		TokenLimit:  3_000_000,
		Features:    []Feature{FeatureCloudAI, FeatureAutopent, FeatureExploitation, FeaturePostExploit},
		DeviceLimit: 3,
		OfflineDays: 7,
		Description: "Pro - 3M tokens/month",
	},
	TierEnterprise: {
		TokenLimit:  15_000_000,
		Features:    []Feature{FeatureCloudAI, FeatureAutopent, FeatureExploitation, FeaturePostExploit, FeatureTeams, FeatureCompliance, FeatureAuditLogs, FeatureAPIAccess, FeatureSSO},
		DeviceLimit: -1, // Unlimited
		OfflineDays: 7,  // Default, configurable
		Description: "Enterprise - 15M tokens/user/month",
	},
}

// OfflineDaysOptions available for enterprise configuration
var OfflineDaysOptions = []int{1, 7, 30, 90, -1} // -1 = never expire

// TokenUsage tracks token consumption
type TokenUsage struct {
	Action    string    `json:"action"`
	Tokens    int64     `json:"tokens"`
	Provider  string    `json:"provider,omitempty"`
	Feature   string    `json:"feature,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// AuthSession represents an authenticated session
type AuthSession struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
}

// Device represents a registered device
type Device struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

// FeatureLockedError is returned when accessing a gated feature
type FeatureLockedError struct {
	Feature     Feature
	RequiredTier Tier
	CurrentTier  Tier
	Message     string
}

func (e *FeatureLockedError) Error() string {
	return e.Message
}

// InsufficientTokensError is returned when token balance is too low
type InsufficientTokensError struct {
	Required  int64
	Available int64
	ResetDate time.Time
}

func (e *InsufficientTokensError) Error() string {
	return "insufficient tokens"
}

// NotAuthenticatedError is returned when no valid session exists
type NotAuthenticatedError struct {
	Message string
}

func (e *NotAuthenticatedError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "not authenticated"
}
