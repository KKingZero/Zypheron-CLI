package licensing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

// UpgradeURL is the URL for upgrading a Zypheron subscription
const UpgradeURL = "https://zypheron.net/upgrade"

var (
	instance *LicenseManager
	once     sync.Once
)

// Init initializes the licensing subsystem (lazy singleton).
func Init() {
	GetManager()
}

// LicenseManager handles license validation and caching
type LicenseManager struct {
	license      *License
	session      *AuthSession
	storage      *Storage
	mu           sync.RWMutex
	offlineMode  bool
	lastSync     time.Time
}

// GetManager returns the singleton license manager instance
func GetManager() *LicenseManager {
	once.Do(func() {
		storage, err := NewStorage()
		if err != nil {
			// Fall back to free tier if storage fails
			instance = &LicenseManager{
				license: &License{Tier: TierFree},
				storage: nil,
			}
			return
		}
		instance = &LicenseManager{
			storage: storage,
		}
		instance.loadFromCache()
	})
	return instance
}

// GetLicense returns the current license (for convenience)
func GetLicense() *License {
	return GetManager().License()
}

// License returns the current license state
func (m *LicenseManager) License() *License {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.license == nil {
		return &License{Tier: TierFree}
	}
	return m.license
}

// IsAuthenticated checks if user is logged in
func (m *LicenseManager) IsAuthenticated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.session != nil && m.session.AccessToken != ""
}

// HasFeature checks if the current license includes a feature
func (m *LicenseManager) HasFeature(feature Feature) bool {
	license := m.License()

	// Check direct feature list
	for _, f := range license.Features {
		if f == feature {
			return true
		}
	}

	// Check tier defaults
	if config, ok := TierConfigs[license.Tier]; ok {
		for _, f := range config.Features {
			if f == feature {
				return true
			}
		}
	}

	return false
}

// RequireFeature returns an error if feature is not available
func (m *LicenseManager) RequireFeature(feature Feature) error {
	if isDevModeEnabled() || os.Getenv("ZYPHERON_DEV") != "" || os.Getenv("ZYPHERON_DEV_MODE") == "1" {
		return nil
	}
	if m.HasFeature(feature) {
		return nil
	}

	license := m.License()
	requiredTier := getMinTierForFeature(feature)

	return &FeatureLockedError{
		Feature:      feature,
		RequiredTier: requiredTier,
		CurrentTier:  license.Tier,
		Message:      formatFeatureLockedMessage(feature, license.Tier),
	}
}

// HasTokens checks if enough tokens are available
func (m *LicenseManager) HasTokens(required int64) bool {
	license := m.License()
	return license.TokensRemaining >= required
}

// DeductTokens reduces token balance (call after successful AI operation)
func (m *LicenseManager) DeductTokens(tokens int64, usage TokenUsage) error {
	if isDevModeEnabled() || os.Getenv("ZYPHERON_DEV") != "" || os.Getenv("ZYPHERON_DEV_MODE") == "1" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.license == nil {
		return &NotAuthenticatedError{}
	}

	if m.license.TokensRemaining < tokens {
		return &InsufficientTokensError{
			Required:  tokens,
			Available: m.license.TokensRemaining,
			ResetDate: m.license.ResetDate,
		}
	}

	m.license.TokensRemaining -= tokens
	m.license.TokensUsed += tokens
	usage.Tokens = tokens
	usage.Timestamp = time.Now()

	// Save to local cache
	if m.storage != nil {
		m.storage.SaveLicense(m.license)
		m.storage.AddUsage(usage)
	}

	return nil
}

// GetTokensRemaining returns current token balance
func (m *LicenseManager) GetTokensRemaining() int64 {
	return m.License().TokensRemaining
}

// GetTier returns current subscription tier
func (m *LicenseManager) GetTier() Tier {
	return m.License().Tier
}

// IsPaidTier returns true if user has a paid subscription
func (m *LicenseManager) IsPaidTier() bool {
	tier := m.GetTier()
	return tier == TierStarter || tier == TierPro || tier == TierEnterprise
}

// IsOffline returns true if operating in offline mode
func (m *LicenseManager) IsOffline() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.offlineMode
}

// SetLicense updates the current license (called after API sync)
func (m *LicenseManager) SetLicense(license *License) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.license = license
	m.lastSync = time.Now()
	if m.storage != nil {
		m.storage.SaveLicense(license)
	}
}

// SetSession updates the auth session
func (m *LicenseManager) SetSession(session *AuthSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = session
	if m.storage != nil {
		m.storage.SaveSession(session)
	}
}

// GetSession returns the current auth session
func (m *LicenseManager) GetSession() *AuthSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.session
}

// ClearSession logs out the user
func (m *LicenseManager) ClearSession() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = nil
	m.license = &License{Tier: TierFree}
	if m.storage != nil {
		m.storage.ClearAll()
	}
}

// IsLicenseValid checks if cached license is still valid for offline use
func (m *LicenseManager) IsLicenseValid() bool {
	license := m.License()

	if license.Tier == TierFree {
		return true // Free tier always valid
	}

	// Check expiration
	if time.Now().After(license.ExpiresAt) {
		return false
	}

	// Check offline duration
	offlineDays := license.OfflineDays
	if offlineDays == -1 {
		return true // Never expire offline
	}

	offlineDeadline := license.IssuedAt.AddDate(0, 0, offlineDays)
	return time.Now().Before(offlineDeadline)
}

// IsLicenseValidForOffline checks if cached license is still valid for offline use,
// considering both subscription expiry and offline grace period.
func (m *LicenseManager) IsLicenseValidForOffline() bool {
	license := m.License()

	if license.Tier == TierFree {
		return true // Free tier always valid offline
	}

	// Check subscription expiration
	if !license.ExpiresAt.IsZero() && time.Now().After(license.ExpiresAt) {
		return false
	}

	// Check offline grace period
	offlineDays := license.OfflineDays
	if offlineDays == 0 {
		if cfg, ok := TierConfigs[license.Tier]; ok {
			offlineDays = cfg.OfflineDays
		}
	}
	if offlineDays == -1 {
		return true // Never expire offline
	}

	last := license.RefreshedAt
	if last.IsZero() {
		last = license.IssuedAt
	}
	if last.IsZero() {
		return true
	}

	return time.Since(last) <= (time.Duration(offlineDays) * 24 * time.Hour)
}

// CheckOfflineGracePeriod is a package-level convenience that returns true if
// the cached license is within its offline grace period or user is on free tier.
func CheckOfflineGracePeriod() bool {
	return GetManager().IsLicenseValidForOffline()
}

// DegradeLicenseGracefully downgrades to free tier while preserving basic validity.
func (m *LicenseManager) DegradeLicenseGracefully(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setFreeTier()
	if m.storage != nil {
		m.storage.SaveLicense(m.license)
	}
}

// setFreeTier resets the license to free tier defaults.
func (m *LicenseManager) setFreeTier() {
	m.license = &License{
		Tier:        TierFree,
		Features:    []Feature{},
		Valid:       true,
		ExpiresAt:   time.Now().AddDate(100, 0, 0),
		RefreshedAt: time.Now(),
		IssuedAt:    time.Now(),
	}
	m.offlineMode = false
}

// ValidateLicenseOnStartup checks cached license freshness and offline grace period.
func ValidateLicenseOnStartup() error {
	m := GetManager()
	license := m.License()
	if license == nil || license.Tier == TierFree {
		return nil
	}

	// Subscription expiration check
	if !license.ExpiresAt.IsZero() && time.Now().After(license.ExpiresAt) {
		m.DegradeLicenseGracefully("license expired")
		return fmt.Errorf("license expired")
	}

	// Offline grace period check
	offlineDays := license.OfflineDays
	if offlineDays == 0 {
		if cfg, ok := TierConfigs[license.Tier]; ok {
			offlineDays = cfg.OfflineDays
		}
	}
	if offlineDays == -1 {
		return nil // never expire offline
	}

	last := license.RefreshedAt
	if last.IsZero() {
		last = license.IssuedAt
	}
	if last.IsZero() {
		last = time.Now()
	}

	if time.Since(last) > (time.Duration(offlineDays) * 24 * time.Hour) {
		m.DegradeLicenseGracefully("offline grace period expired")
		return fmt.Errorf("offline grace period expired")
	}

	return nil
}

// GetDeviceID returns a unique identifier for this device
func (m *LicenseManager) GetDeviceID() string {
	hostname, _ := os.Hostname()
	homeDir, _ := os.UserHomeDir()

	// Create a hash from machine-specific info
	data := fmt.Sprintf("%s:%s:%s:%s", hostname, homeDir, runtime.GOOS, runtime.GOARCH)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16])
}

// loadFromCache loads license and session from local storage
func (m *LicenseManager) loadFromCache() {
	if m.storage == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Load session
	if session, err := m.storage.LoadSession(); err == nil {
		m.session = session
	}

	// Load license
	if license, err := m.storage.LoadLicense(); err == nil {
		m.license = license
		m.offlineMode = true
	} else {
		m.license = &License{Tier: TierFree}
	}
}

// SyncWithServer synchronizes license state with backend
func (m *LicenseManager) SyncWithServer() error {
	if !m.IsAuthenticated() {
		return nil
	}
	err := SyncLicense()
	if err == nil {
		m.mu.Lock()
		m.offlineMode = false
		m.lastSync = time.Now()
		m.mu.Unlock()
	}
	return err
}

// Refresh refreshes the license from the backend server
func (m *LicenseManager) Refresh() error {
	// Sync with server to get latest license state
	if err := m.SyncWithServer(); err != nil {
		return err
	}

	// Reload from cache in case of updates
	m.loadFromCache()

	m.mu.Lock()
	m.license.RefreshedAt = time.Now()
	m.mu.Unlock()

	return nil
}

// getMinTierForFeature returns the minimum tier required for a feature
func getMinTierForFeature(feature Feature) Tier {
	switch feature {
	case FeatureCloudAI, FeatureAutopent, FeatureExploitation, FeaturePostExploit:
		return TierStarter
	case FeatureTeams, FeatureCompliance, FeatureAuditLogs, FeatureAPIAccess, FeatureSSO:
		return TierEnterprise
	default:
		return TierFree
	}
}

// formatFeatureLockedMessage creates a user-friendly error message
func formatFeatureLockedMessage(feature Feature, currentTier Tier) string {
	featureNames := map[Feature]string{
		FeatureCloudAI:      "Cloud AI",
		FeatureAutopent:     "Automated Penetration Testing",
		FeatureExploitation: "Exploitation",
		FeaturePostExploit:  "Post-Exploitation",
		FeatureTeams:        "Team Management",
		FeatureCompliance:   "Compliance Reporting",
		FeatureAuditLogs:    "Audit Logging",
		FeatureAPIAccess:    "API Access",
		FeatureSSO:          "SSO/SAML",
	}

	name := featureNames[feature]
	if name == "" {
		name = string(feature)
	}

	minTier := getMinTierForFeature(feature)

	return fmt.Sprintf(`
╔═══════════════════════════════════════════════════════════════════╗
║                      FEATURE LOCKED                                ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  %s requires a paid subscription.
║                                                                    ║
║  Your current plan: %s
║  Required plan: %s or higher
║                                                                    ║
║  Upgrade options:                                                  ║
║    Starter     $29/mo       →  1M AI tokens + Exploitation        ║
║    Pro         $149/mo      →  3M AI tokens + All features        ║
║    Enterprise  $500/mo/seat →  15M tokens + Teams (min 5 seats)   ║
║                                                                    ║
║  Upgrade: zypheron upgrade                                         ║
║  Online:  %s
║  Login:   zypheron login                                           ║
║                                                                    ║
╚═══════════════════════════════════════════════════════════════════╝
`, name, currentTier, minTier, UpgradeURL)
}

// FormatInsufficientTokensMessage creates a user-friendly error message
func FormatInsufficientTokensMessage(required, available int64, resetDate time.Time) string {
	daysUntilReset := int(time.Until(resetDate).Hours() / 24)

	return fmt.Sprintf(`
╔═══════════════════════════════════════════════════════════════════╗
║                    INSUFFICIENT TOKENS                             ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  This request requires approximately %s tokens.
║  Your remaining balance: %s tokens
║                                                                    ║
║  Options:                                                          ║
║    1. Wait for reset: %d days (%s)
║    2. Upgrade plan: zypheron upgrade                               ║
║    3. Use local AI: --provider ollama                              ║
║                                                                    ║
╚═══════════════════════════════════════════════════════════════════╝
`, formatTokens(required), formatTokens(available), daysUntilReset, resetDate.Format("Jan 2, 2006"))
}

func formatTokens(n int64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

// ExportLicenseInfo returns license info as JSON (for debugging)
func (m *LicenseManager) ExportLicenseInfo() ([]byte, error) {
	license := m.License()
	return json.MarshalIndent(map[string]interface{}{
		"tier":             license.Tier,
		"tokens_remaining": license.TokensRemaining,
		"tokens_used":      license.TokensUsed,
		"tokens_limit":     license.TokensLimit,
		"reset_date":       license.ResetDate,
		"expires_at":       license.ExpiresAt,
		"features":         license.Features,
		"is_authenticated": m.IsAuthenticated(),
		"is_offline":       m.IsOffline(),
		"device_id":        m.GetDeviceID(),
	}, "", "  ")
}
