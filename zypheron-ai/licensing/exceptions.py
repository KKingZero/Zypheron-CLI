"""
Licensing exceptions for Zypheron AI engine.
"""


class LicenseError(Exception):
    """Base class for licensing errors."""
    pass


class FeatureLockedError(LicenseError):
    """Raised when accessing a feature that requires a higher tier."""

    def __init__(self, feature: str, required_tier: str, current_tier: str, message: str = None):
        self.feature = feature
        self.required_tier = required_tier
        self.current_tier = current_tier
        self.message = message or self._format_message()
        super().__init__(self.message)

    def _format_message(self) -> str:
        return f"""
╔═══════════════════════════════════════════════════════════════════╗
║                      FEATURE LOCKED                                ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  {self.feature} requires a paid subscription.
║                                                                    ║
║  Your current plan: {self.current_tier}
║  Required plan: {self.required_tier} or higher
║                                                                    ║
║  Upgrade options:                                                  ║
║    Starter   $29/mo   →  1M AI tokens + Exploitation              ║
║    Pro       $149/mo  →  5M AI tokens + Priority Support          ║
║    Enterprise $499/mo/user → Teams + Compliance                   ║
║                                                                    ║
║  Upgrade: zypheron upgrade                                         ║
║                                                                    ║
╚═══════════════════════════════════════════════════════════════════╝
"""


class InsufficientTokensError(LicenseError):
    """Raised when token balance is too low for an operation."""

    def __init__(self, required: int, available: int, reset_date: str = None):
        self.required = required
        self.available = available
        self.reset_date = reset_date
        self.message = self._format_message()
        super().__init__(self.message)

    def _format_message(self) -> str:
        reset_info = f"Resets: {self.reset_date}" if self.reset_date else "Check your account for reset date"
        return f"""
╔═══════════════════════════════════════════════════════════════════╗
║                    INSUFFICIENT TOKENS                             ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  This request requires approximately {self.required:,} tokens.
║  Your remaining balance: {self.available:,} tokens
║                                                                    ║
║  {reset_info}
║                                                                    ║
║  Options:                                                          ║
║    1. Wait for token reset                                         ║
║    2. Upgrade plan: zypheron upgrade                               ║
║    3. Use local AI: --provider ollama                              ║
║                                                                    ║
╚═══════════════════════════════════════════════════════════════════╝
"""


class NotAuthenticatedError(LicenseError):
    """Raised when operation requires authentication but user is not logged in."""

    def __init__(self, message: str = None):
        self.message = message or "Not authenticated. Please login: zypheron login"
        super().__init__(self.message)


class LicenseExpiredError(LicenseError):
    """Raised when the cached license has expired and needs refresh."""

    def __init__(self, expired_at: str = None):
        self.expired_at = expired_at
        self.message = f"License expired{f' at {expired_at}' if expired_at else ''}. Please reconnect: zypheron login"
        super().__init__(self.message)
