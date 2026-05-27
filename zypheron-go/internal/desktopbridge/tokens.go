package desktopbridge

import (
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

// We reuse the existing "zypheron" service entry already used by
// internal/config/keyring.go for AI provider keys. Token entries live under
// distinct accounts so they don't collide with API-key entries.
const (
	keyringService     = "zypheron"
	accessTokenAccount = "desktop-bridge-access-token"
	refreshTokenAccount = "desktop-bridge-refresh-token"
	clientIDAccount    = "desktop-bridge-client-id"

	// Env fallbacks for headless / CI environments where libsecret/keychain
	// aren't available. Per CLAUDE.md security guidelines: never store
	// credentials in plaintext; these env vars are caller-supplied at runtime.
	envAccessToken  = "ZYPHERON_DESKTOP_ACCESS_TOKEN"
	envRefreshToken = "ZYPHERON_DESKTOP_REFRESH_TOKEN"
	envClientID     = "ZYPHERON_DESKTOP_CLIENT_ID"
)

// TokenPair holds the freshly-issued credentials returned by /v1/auth/pair
// or /v1/auth/refresh.
type TokenPair struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	AccessExpiresIn  int    `json:"access_expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

var ErrNoCredentials = errors.New("no desktop-bridge credentials stored — run `zypheron login`")

// SaveTokens writes the access + refresh pair to the OS keyring. If the
// keyring is unavailable (typical on headless servers), this returns the
// underlying error so the caller can decide whether to instruct the user to
// set env-var fallbacks.
func SaveTokens(pair TokenPair) error {
	if err := keyring.Set(keyringService, accessTokenAccount, pair.AccessToken); err != nil {
		return fmt.Errorf("store access token: %w", err)
	}
	if err := keyring.Set(keyringService, refreshTokenAccount, pair.RefreshToken); err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	return nil
}

// SaveClientID records the per-CLI client identifier returned at pair time so
// later /v1/auth/revoke calls can identify themselves.
func SaveClientID(clientID string) error {
	if err := keyring.Set(keyringService, clientIDAccount, clientID); err != nil {
		return fmt.Errorf("store client id: %w", err)
	}
	return nil
}

// LoadAccessToken returns the stored access token, preferring the env-var
// override for headless environments. Returns ErrNoCredentials if neither
// source has a value.
func LoadAccessToken() (string, error) {
	if v := os.Getenv(envAccessToken); v != "" {
		return v, nil
	}
	v, err := keyring.Get(keyringService, accessTokenAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNoCredentials
		}
		return "", fmt.Errorf("load access token: %w", err)
	}
	return v, nil
}

// LoadRefreshToken behaves like LoadAccessToken but for the refresh token.
func LoadRefreshToken() (string, error) {
	if v := os.Getenv(envRefreshToken); v != "" {
		return v, nil
	}
	v, err := keyring.Get(keyringService, refreshTokenAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNoCredentials
		}
		return "", fmt.Errorf("load refresh token: %w", err)
	}
	return v, nil
}

// LoadClientID returns the per-CLI client id captured at pair time.
func LoadClientID() (string, error) {
	if v := os.Getenv(envClientID); v != "" {
		return v, nil
	}
	v, err := keyring.Get(keyringService, clientIDAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNoCredentials
		}
		return "", fmt.Errorf("load client id: %w", err)
	}
	return v, nil
}

// DeleteTokens wipes all desktop-bridge credentials. Used on logout, revoke,
// or when refresh fails permanently so the user is prompted to re-pair.
func DeleteTokens() error {
	var firstErr error
	for _, account := range []string{accessTokenAccount, refreshTokenAccount, clientIDAccount} {
		if err := keyring.Delete(keyringService, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete %s: %w", account, err)
			}
		}
	}
	return firstErr
}
