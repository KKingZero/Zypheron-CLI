# GitHub OAuth Authentication Setup Guide

This guide explains how to set up and use the GitHub OAuth authentication flow in the Zypheron API.

## Overview

The Zypheron API now supports GitHub OAuth as an authentication method alongside traditional email/password authentication. Users can:
- Sign up with their GitHub account
- Link their existing email/password account with GitHub
- Log in using GitHub OAuth

## Features

- **CSRF Protection**: State parameter validation prevents cross-site request forgery attacks
- **Email Verification**: Handles both public and private GitHub emails
- **Account Linking**: Automatically links GitHub accounts with existing email-based accounts
- **Secure Token Storage**: OAuth tokens are not stored; only user profile information is persisted
- **Comprehensive Error Handling**: Detailed error messages for debugging OAuth flow issues

## Setup Instructions

### 1. Register a GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **"New OAuth App"** or **"New GitHub App"**
3. Fill in the application details:
   - **Application name**: Zypheron API (or your preferred name)
   - **Homepage URL**: `http://localhost:8000` (for development) or your production domain
   - **Authorization callback URL**: `http://localhost:8000/auth/github/callback`
   - **Description**: Optional description of your application

4. Click **"Register application"**
5. Copy the **Client ID** and generate a **Client Secret**

### 2. Configure Environment Variables

Add the following to your `.env` file:

```bash
# GitHub OAuth Configuration
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
BASE_URL=http://localhost:8000  # API base URL (change for production)
FRONTEND_URL=http://localhost:3000  # Web app URL (optional, for device flow)
```

**Security Note**: Never commit your `.env` file or expose your `GITHUB_CLIENT_SECRET` in client-side code or API responses.

### 3. Production Configuration

For production environments:

```bash
GITHUB_CLIENT_ID=your_production_client_id
GITHUB_CLIENT_SECRET=your_production_client_secret
BASE_URL=https://api.yourdomain.com
FRONTEND_URL=https://app.yourdomain.com
ENVIRONMENT=production  # Enables HTTPS-only cookies
```

## OAuth Flow

### Endpoints

#### 1. `GET /auth/github`
Initiates the GitHub OAuth flow.

**Response**: Redirects to GitHub's authorization page
**Cookies Set**: `oauth_state` (HttpOnly, 10-minute expiry) for CSRF protection

**Example**:
```bash
curl -X GET http://localhost:8000/auth/github
```

#### 2. `GET /auth/github/callback`
Handles the OAuth callback from GitHub.

**Query Parameters**:
- `code` (required): Authorization code from GitHub
- `state` (required): CSRF state token
- `error` (optional): Error code if authorization failed
- `error_description` (optional): Human-readable error description

**Response**: Returns JWT access token and user information

**Example Response**:
```json
{
  "user": {
    "id": 1,
    "email": "user@example.com",
    "tier": "free",
    "is_active": true,
    "is_verified": true,
    "github_username": "octocat",
    "github_avatar_url": "https://avatars.githubusercontent.com/u/123456"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### Flow Diagram

```
┌──────────┐                ┌──────────────┐                ┌────────────┐
│  Client  │                │  Zypheron    │                │   GitHub   │
│          │                │     API      │                │            │
└────┬─────┘                └──────┬───────┘                └─────┬──────┘
     │                             │                              │
     │ 1. GET /auth/github         │                              │
     ├────────────────────────────>│                              │
     │                             │                              │
     │ 2. Set oauth_state cookie   │                              │
     │    Redirect to GitHub       │                              │
     │<────────────────────────────┤                              │
     │                             │                              │
     │ 3. User authorizes app                                     │
     ├────────────────────────────────────────────────────────────>│
     │                             │                              │
     │ 4. Redirect to callback with code & state                  │
     │<────────────────────────────────────────────────────────────┤
     │                             │                              │
     │ 5. GET /auth/github/callback?code=XXX&state=YYY            │
     ├────────────────────────────>│                              │
     │                             │                              │
     │                             │ 6. Validate state (CSRF)     │
     │                             │ 7. Exchange code for token   │
     │                             ├─────────────────────────────>│
     │                             │                              │
     │                             │ 8. Access token              │
     │                             │<─────────────────────────────┤
     │                             │                              │
     │                             │ 9. Fetch user profile        │
     │                             ├─────────────────────────────>│
     │                             │                              │
     │                             │ 10. User data                │
     │                             │<─────────────────────────────┤
     │                             │                              │
     │                             │ 11. Fetch user emails        │
     │                             ├─────────────────────────────>│
     │                             │                              │
     │                             │ 12. Email list               │
     │                             │<─────────────────────────────┤
     │                             │                              │
     │                             │ 13. Create/update user       │
     │                             │ 14. Generate JWT token       │
     │                             │                              │
     │ 15. Return JWT & user info  │                              │
     │<────────────────────────────┤                              │
     │                             │                              │
```

## Security Features

### 1. CSRF Protection
- Generates a random 32-byte state token using `secrets.token_urlsafe(32)`
- Stores state in HttpOnly cookie with 10-minute expiry
- Validates state parameter in callback matches the cookie value
- Rejects requests with missing or mismatched state

### 2. Secure Cookie Configuration
- `HttpOnly`: Prevents JavaScript access (XSS protection)
- `Secure`: HTTPS-only in production environments
- `SameSite=Lax`: Protects against CSRF while allowing OAuth redirects
- Short expiry: 10-minute window for OAuth flow completion

### 3. Email Verification
- Prioritizes primary verified emails from GitHub
- Falls back to any verified email if no primary email exists
- Rejects accounts without verified emails
- Handles private GitHub email configurations

### 4. OAuth Token Security
- GitHub access token is used only for fetching user data
- Token is never stored in the database
- Token is not returned to the client
- Only user profile information is persisted

### 5. Account Linking
- Links GitHub accounts to existing email/password accounts
- Prevents duplicate accounts for the same email
- Updates GitHub profile information on each login
- Maintains user identity across authentication methods

### 6. Error Handling
- Does not expose client secret in any response
- Provides user-friendly error messages
- Handles GitHub API failures gracefully
- Validates all OAuth responses before processing

## User Account Types

### 1. GitHub OAuth Only
- Created when user signs up via GitHub
- `password_hash` is `NULL`
- `is_verified` is `True` (GitHub emails are pre-verified)
- Cannot use email/password login

### 2. Email/Password with GitHub Linked
- User registers with email/password first
- Later links GitHub account via OAuth
- Can use either authentication method
- GitHub profile info is synced on each GitHub login

### 3. Email/Password Only
- Traditional registration
- No GitHub fields populated
- Can link GitHub account later

## API Integration Examples

### Frontend Integration (React)

```typescript
// Redirect user to GitHub OAuth
const handleGitHubLogin = () => {
  window.location.href = 'http://localhost:8000/auth/github';
};

// Handle OAuth callback (if implementing custom callback page)
useEffect(() => {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('access_token');

  if (token) {
    // Store token in localStorage or state management
    localStorage.setItem('auth_token', token);
    // Redirect to dashboard
    navigate('/dashboard');
  }
}, []);
```

### CLI Integration

```python
import webbrowser
import http.server
from urllib.parse import urlparse, parse_qs

# Open browser for OAuth
webbrowser.open('http://localhost:8000/auth/github')

# Listen for callback (simplified example)
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if 'access_token' in query:
            token = query['access_token'][0]
            print(f"Received token: {token}")
            # Save token to config
```

### Direct API Testing

```bash
# 1. Open in browser (cannot test with curl due to redirect)
open http://localhost:8000/auth/github

# 2. After authorization, GitHub redirects to callback
# The callback endpoint returns JSON with user data and token

# 3. Use the token for authenticated requests
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/auth/me
```

## Troubleshooting

### Error: "GitHub OAuth not configured"
**Solution**: Ensure `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are set in your `.env` file.

### Error: "Invalid state parameter"
**Causes**:
- Cookie was deleted or expired (10-minute timeout)
- Browser doesn't support cookies
- CSRF attack attempt

**Solution**: Restart the OAuth flow from `/auth/github`

### Error: "No verified email found"
**Causes**:
- GitHub account has no verified email addresses
- All emails are marked as private and user hasn't granted email permission

**Solution**:
1. Verify an email address in GitHub settings
2. Make at least one email public or verify it
3. Try OAuth flow again

### Error: "Failed to exchange code for access token"
**Causes**:
- Invalid client ID or secret
- Authorization code already used (codes are single-use)
- Code expired (10-minute timeout)

**Solution**:
1. Verify environment variables
2. Check callback URL matches registered OAuth app
3. Restart OAuth flow

### Production Issues
**Callback URL Mismatch**: Ensure your GitHub OAuth app's callback URL exactly matches `{BASE_URL}/auth/github/callback`

**Cookie Not Set**: Check that `Secure` cookie attribute matches your HTTPS configuration. In production with HTTPS, cookies require `Secure=True`.

## Database Schema

The implementation uses existing User model fields:

```sql
-- GitHub OAuth fields in users table
github_id VARCHAR(100) UNIQUE,  -- GitHub user ID (string)
github_username VARCHAR(100),   -- GitHub login name
github_avatar_url VARCHAR(500), -- Profile picture URL
```

## Rate Limiting & Quotas

GitHub OAuth endpoints respect the same rate limiting as other authentication endpoints. Consider implementing:
- Rate limiting on `/auth/github` to prevent abuse
- Logging failed OAuth attempts for security monitoring
- Monitoring GitHub API rate limits (5000 requests/hour for authenticated requests)

## Future Enhancements

Potential improvements to consider:
1. Store GitHub OAuth token for API access (with encryption)
2. Add refresh token support
3. Support additional OAuth scopes (repos, gists, etc.)
4. Implement account unlinking endpoint
5. Add webhook support for profile updates
6. Support GitHub Enterprise Server

## References

- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps)
- [GitHub REST API - Users](https://docs.github.com/en/rest/users)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
