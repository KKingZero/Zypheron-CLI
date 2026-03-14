# Zypheron CLI - Quick Reference Guide

## For Developers

### Authentication & Licensing Quick Reference

---

## File Structure

```
zypheron-go/
├── cmd/zypheron/
│   └── main.go                    # Calls InitWithValidation()
├── internal/
│   ├── licensing/
│   │   ├── api_client.go          # Device code OAuth, token refresh
│   │   ├── license.go             # 7-day grace, validation, caching
│   │   ├── middleware.go          # Cobra PreRunE for feature gating
│   │   ├── gates.go               # Helper functions (RequireX)
│   │   ├── types.go               # Tier, Feature, License structs
│   │   └── storage.go             # Local cache in ~/.config/zypheron/
│   └── commands/
│       ├── auth.go                # login, logout, whoami, account
│       ├── autopent.go            # PAID: Starter+
│       ├── pwn.go                 # PAID: Starter+
│       ├── compliance.go          # PAID: Enterprise
│       ├── scan.go                # FREE
│       └── ...
```

---

## How to Add a New Paid Command

### Option 1: Use Existing Helper Functions (Recommended)

```go
package commands

import (
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
    "github.com/spf13/cobra"
)

func NewPaidCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "new-feature [args]",
        Short: "New paid feature (Starter+)",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Check license BEFORE doing work
            if err := licensing.RequireExploitation(); err != nil {
                if licErr, ok := err.(*licensing.FeatureLockedError); ok {
                    fmt.Println(licErr.Message)
                    return nil
                }
                return err
            }

            // Feature implementation here
            return nil
        },
    }
    return cmd
}
```

### Option 2: Use Middleware (Cleaner, Recommended for New Code)

```go
package commands

import (
    "github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
    "github.com/spf13/cobra"
)

func NewPaidCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "new-feature [args]",
        Short: "New paid feature (Starter+)",
        // PreRunE runs before RunE - perfect for validation
        PreRunE: licensing.RequireExploitationMiddleware(),
        RunE: func(cmd *cobra.Command, args []string) error {
            // Feature implementation here
            // License already validated by PreRunE
            return nil
        },
    }
    return cmd
}
```

### Option 3: Custom Middleware with Token Check

```go
cmd.PreRunE = licensing.NewLicenseMiddleware().
    RequireFeature(licensing.FeatureCloudAI).
    RequireTokens(10000).  // Require 10k tokens available
    PreRunE()
```

---

## Available Helper Functions

### Feature Gates

```go
// These return error if feature not available
licensing.RequireCloudAI()         // Cloud AI providers (Starter+)
licensing.RequireAutopent()        // Autonomous pentesting (Starter+)
licensing.RequireExploitation()    // Exploitation framework (Starter+)
licensing.RequirePostExploit()     // Post-exploitation (Starter+)
licensing.RequireCompliance()      // Compliance reporting (Enterprise)
licensing.RequireTeams()           // Team management (Enterprise)
licensing.RequireAuditLogs()       // Audit logging (Enterprise)

// Check if feature is available (returns bool)
licensing.CanUseCloudAI()
licensing.CanUseAutopent()
licensing.CanUseExploitation()
```

### Provider Gating

```go
// Check if specific AI provider can be used
licensing.RequireProviderAccess("claude")    // Requires paid tier
licensing.RequireProviderAccess("ollama")    // Always allowed (free)
licensing.RequireProviderAccess("openai")    // Requires paid tier

// Check provider + token balance
licensing.CheckProviderAndTokens("claude", 5000)  // Requires 5k tokens
```

### License Manager

```go
manager := licensing.GetManager()

// Check authentication
manager.IsAuthenticated()  // bool

// Check tier
manager.GetTier()          // licensing.Tier (free, starter, pro, enterprise)
manager.IsPaidTier()       // bool

// Check tokens
manager.GetTokensRemaining()      // int64
manager.HasTokens(1000)           // bool
manager.DeductTokens(500, usage)  // Deduct after AI operation

// Check features
manager.HasFeature(licensing.FeatureCloudAI)  // bool
manager.RequireFeature(licensing.FeatureCloudAI)  // error if not available

// Get license
license := manager.License()  // *licensing.License
```

---

## Tier & Feature Definitions

### Tiers

```go
licensing.TierFree         // "free"
licensing.TierStarter      // "starter"
licensing.TierPro          // "pro"
licensing.TierEnterprise   // "enterprise"
```

### Features

```go
licensing.FeatureCloudAI         // Cloud AI providers
licensing.FeatureAutopent        // Autonomous pentesting
licensing.FeatureExploitation    // Exploitation framework
licensing.FeaturePostExploit     // Post-exploitation
licensing.FeatureTeams           // Team management
licensing.FeatureCompliance      // Compliance reporting
licensing.FeatureAuditLogs       // Audit logging
licensing.FeatureAPIAccess       // API access
licensing.FeatureSSO             // SSO/SAML
```

---

## License Struct

```go
type License struct {
    UserID           string       // User's unique ID
    Email            string       // User's email
    Tier             Tier         // free, starter, pro, enterprise
    Features         []Feature    // List of available features
    TokensRemaining  int64        // Tokens left this billing period
    TokensUsed       int64        // Tokens used this billing period
    TokensLimit      int64        // Total tokens per billing period
    ResetDate        time.Time    // When tokens reset
    ExpiresAt        time.Time    // License expiration
    IssuedAt         time.Time    // When license was issued
    RefreshedAt      time.Time    // Last sync with server
    DeviceID         string       // This device's ID
    TeamID           string       // Team ID (if Enterprise)
    TeamRole         string       // Team role (if Enterprise)
    OfflineDays      int          // Offline grace period (7 days default)
}
```

---

## Authentication Flow

### Login Command

```bash
$ zypheron login
```

**What happens:**
1. CLI requests device code from API: `POST /auth/device/code`
2. API returns user_code (e.g., "WXYZ-ABCD") and device_code
3. CLI displays user code prominently
4. CLI auto-opens browser to verification URL
5. User enters code in web app and authorizes
6. CLI polls API every 5 seconds: `POST /auth/device/login`
7. When authorized:
   - Stores access_token and refresh_token
   - Registers device: `POST /users/devices`
   - Fetches license: `GET /licenses/validate`
   - Saves to `~/.config/zypheron/`

### Token Refresh

**Automatic on 401:**
- Any API call returns 401
- CLI auto-refreshes token: `POST /auth/refresh`
- Retries original request
- Seamless to user

**Manual:**
```go
client := licensing.NewAPIClient()
err := client.RefreshToken()
```

---

## Offline Mode

### Grace Period: 7 Days

**How it works:**
1. User logs in → license cached with `RefreshedAt` timestamp
2. CLI starts → validates `time.Now() < RefreshedAt + 7 days`
3. If valid → background sync attempts to refresh
4. If invalid → degrades to free tier

**Validation on startup:**
```go
// In main.go
licensing.InitWithValidation()

// Under the hood:
// 1. Loads cached license
// 2. Checks offline grace period
// 3. If expired: degrades to free tier
// 4. If valid: starts background sync
```

**Background sync:**
- Runs 200ms after CLI starts
- Non-blocking (goroutine)
- Attempts to fetch fresh license
- Updates `RefreshedAt` on success
- Marks offline/online accordingly

---

## Common Patterns

### Pattern 1: Paid Command with Manual Check

```go
func MyPaidCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "paid-feature",
        Short: "Paid feature (Starter+)",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Check license
            if err := licensing.RequireExploitation(); err != nil {
                if licErr, ok := err.(*licensing.FeatureLockedError); ok {
                    fmt.Println(licErr.Message)  // Shows upgrade prompt
                    return nil
                }
                return err
            }

            // Do work
            fmt.Println("Feature unlocked!")
            return nil
        },
    }
}
```

### Pattern 2: Paid Command with Middleware

```go
func MyPaidCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "paid-feature",
        Short: "Paid feature (Starter+)",
        RunE: func(cmd *cobra.Command, args []string) error {
            // License already validated
            fmt.Println("Feature unlocked!")
            return nil
        },
    }
    cmd.PreRunE = licensing.RequireExploitationMiddleware()
    return cmd
}
```

### Pattern 3: Cloud AI with Token Check

```go
func AICmd() *cobra.Command {
    var provider string

    cmd := &cobra.Command{
        Use:   "ai-analyze [target]",
        Short: "AI-powered analysis (Starter+)",
        RunE: func(cmd *cobra.Command, args []string) error {
            // Check provider access + token balance
            estimatedTokens := int64(5000)
            if err := licensing.CheckProviderAndTokens(provider, estimatedTokens); err != nil {
                if licErr, ok := err.(*licensing.FeatureLockedError); ok {
                    fmt.Println(licErr.Message)
                    return nil
                }
                if tokErr, ok := err.(*licensing.InsufficientTokensError); ok {
                    fmt.Printf("Insufficient tokens: need %d, have %d\n",
                        tokErr.Required, tokErr.Available)
                    return nil
                }
                return err
            }

            // Call AI provider
            result := callAI(args[0], provider)

            // Deduct tokens after successful operation
            usage := licensing.TokenUsage{
                Action:   "ai_analyze",
                Provider: provider,
                Feature:  "cloud_ai",
            }
            licensing.GetManager().DeductTokens(estimatedTokens, usage)

            fmt.Println(result)
            return nil
        },
    }
    cmd.Flags().StringVarP(&provider, "provider", "p", "claude", "AI provider")
    return cmd
}
```

### Pattern 4: Free Tier Command (No Gating)

```go
func ScanCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "scan [target]",
        Short: "Network scanning (FREE)",
        RunE: func(cmd *cobra.Command, args []string) error {
            // No license check needed
            // Anyone can use this
            runScan(args[0])
            return nil
        },
    }
}
```

---

## Error Handling

### FeatureLockedError

```go
if err := licensing.RequireFeature(feature); err != nil {
    if licErr, ok := err.(*licensing.FeatureLockedError); ok {
        // User-friendly upgrade prompt
        fmt.Println(licErr.Message)
        return nil  // Don't propagate error, already shown to user
    }
    return err  // Other error, propagate
}
```

### InsufficientTokensError

```go
manager := licensing.GetManager()
license := manager.License()
if license.TokensRemaining < requiredTokens {
    // Show error with reset date
    fmt.Printf("Insufficient tokens: need %d, have %d\n",
        requiredTokens, license.TokensRemaining)
    fmt.Printf("Tokens reset on: %s\n",
        license.ResetDate.Format("January 2, 2006"))
    return nil
}
```

### NotAuthenticatedError

```go
if !licensing.GetManager().IsAuthenticated() {
    fmt.Println("Not logged in. Run: zypheron login")
    return nil
}
```

---

## Testing Your Feature

### Test Free Tier Access

```bash
# Logout first
$ zypheron logout

# Try your paid feature
$ zypheron your-paid-command
# Should show upgrade prompt
```

### Test Starter Tier Access

```bash
# Login
$ zypheron login

# Try your paid feature
$ zypheron your-paid-command
# Should work if user has Starter+
```

### Test Token Deduction

```bash
# Check token balance
$ zypheron whoami
# Note tokens remaining

# Use your feature
$ zypheron your-ai-command

# Check balance again
$ zypheron whoami
# Should be reduced
```

### Test Offline Mode

```bash
# Login
$ zypheron login

# Stop API server
# (simulate offline)

# Use CLI
$ zypheron your-paid-command
# Should work from cache (< 7 days)

# Simulate > 7 days offline
# (manually edit ~/.config/zypheron/license.json - set RefreshedAt to 8 days ago)

$ zypheron your-paid-command
# Should degrade to free tier
```

---

## Debugging

### Enable Debug Mode

```bash
export ZYPHERON_DEBUG=1
zypheron your-command
```

### Check License Status

```bash
# View current license
zypheron whoami

# View license JSON
cat ~/.config/zypheron/license.json | jq

# View session
cat ~/.config/zypheron/session.json | jq
```

### Force Re-Login

```bash
zypheron logout
zypheron login
```

---

## Constants & Configuration

### API URL

```go
// Default (production)
licensing.DefaultAPIURL = "http://localhost:8000/api/v1"

// Override via environment
export ZYPHERON_API_URL="https://api.zypheron.io/api/v1"
```

### Offline Grace Period

```go
licensing.OfflineGracePeriodDays = 7  // Constant

// Enterprise can override per-license
license.OfflineDays = 30  // Or 1, 7, 90, -1 (never)
```

### Storage Location

```bash
~/.config/zypheron/
├── session.json      # Access + refresh tokens
├── license.json      # Cached license
└── usage.jsonl       # Token usage log
```

---

## Best Practices

### 1. Always Check License Before Expensive Operations

```go
// BAD: Do work, then check
result := expensiveOperation()
if err := licensing.RequireFeature(feature); err != nil {
    return err  // Too late, already did work
}

// GOOD: Check first, then do work
if err := licensing.RequireFeature(feature); err != nil {
    return err
}
result := expensiveOperation()
```

### 2. Deduct Tokens After Success

```go
// BAD: Deduct before operation
manager.DeductTokens(5000, usage)
result, err := callAI()  // What if this fails?

// GOOD: Deduct after success
result, err := callAI()
if err != nil {
    return err
}
manager.DeductTokens(5000, usage)
```

### 3. Show User-Friendly Errors

```go
// BAD: Return raw error
if err := licensing.RequireFeature(feature); err != nil {
    return err  // User sees: "feature locked: cloud_ai"
}

// GOOD: Show upgrade prompt
if err := licensing.RequireFeature(feature); err != nil {
    if licErr, ok := err.(*licensing.FeatureLockedError); ok {
        fmt.Println(licErr.Message)  // Shows nice upgrade prompt
        return nil
    }
    return err
}
```

### 4. Use Middleware for Commands

```go
// BAD: Manual check in every command
func Cmd1() { checkLicense() }
func Cmd2() { checkLicense() }
func Cmd3() { checkLicense() }

// GOOD: Use middleware once
cmd.PreRunE = licensing.RequireExploitationMiddleware()
```

### 5. Non-Blocking Startup

```go
// GOOD: Current implementation
if err := licensing.InitWithValidation(); err != nil {
    // Log but don't block
    if os.Getenv("ZYPHERON_DEBUG") != "" {
        fmt.Fprintf(os.Stderr, "License validation warning: %v\n", err)
    }
}

// BAD: Block startup on error
if err := licensing.InitWithValidation(); err != nil {
    panic(err)  // Don't do this!
}
```

---

## Common Gotchas

### 1. Don't Forget to Import

```go
import "github.com/KKingZero/Cobra-AI/zypheron-go/internal/licensing"
```

### 2. Type Assertions

```go
// Always check type assertion
if licErr, ok := err.(*licensing.FeatureLockedError); ok {
    // Safe to use licErr
} else {
    // Not a FeatureLockedError
}
```

### 3. Free Features Don't Need Checks

```go
// Scan is FREE - no license check needed
func ScanCmd() *cobra.Command {
    // Just do the work
}
```

### 4. Ollama is Always Free

```go
// Self-hosted AI is free
licensing.RequireProviderAccess("ollama")  // Always returns nil
```

---

## Need Help?

- **Documentation**: See `PHASE2_PHASE3_IMPLEMENTATION.md`
- **Examples**: Check `internal/commands/autopent.go`, `pwn.go`, `compliance.go`
- **Debug**: `export ZYPHERON_DEBUG=1`

---

**Happy coding!** 🚀
