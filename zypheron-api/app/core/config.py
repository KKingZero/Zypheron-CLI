"""Application configuration with environment variable support."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Zypheron API"
    app_version: str = "2.0.0"
    debug: bool = False
    environment: Literal["development", "staging", "production"] = "development"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    frontend_url: str = "http://localhost:3000"
    cors_allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:5173",
        ],
        description="Explicit allowed origins for local and self-hosted frontends",
    )
    # SECURITY (H-02): IP ranges of reverse proxies we trust to set
    # X-Forwarded-For / X-Real-IP. Empty by default => never trust those headers
    # (use the direct socket peer). Set this to your load balancer's CIDR(s) when
    # running behind a proxy. Otherwise an attacker can spoof their source IP and
    # bypass rate limiting.
    trusted_proxy_cidrs: list[str] = Field(
        default_factory=list,
        description="CIDRs of trusted reverse proxies allowed to set forwarded-IP headers",
    )

    # Database - SQLite by default, optional self-hosted PostgreSQL
    database_type: Literal["sqlite", "postgresql"] = "sqlite"
    database_url: str = "sqlite+aiosqlite:///./zypheron.db"

    # PostgreSQL (optional self-hosted)
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "zypheron"
    postgres_password: str = "zypheron_dev_password"
    postgres_db: str = "zypheron"
    postgres_url_override: str | None = None  # Override auto-generated URL if needed

    # Legacy hosted database settings retained for compatibility with older configs
    supabase_url: str | None = None
    supabase_key: str | None = None  # anon/public key
    supabase_service_key: str | None = None  # service_role key (bypasses RLS) - server only

    # Dashboard webapp (app.zypheron.net) integration
    # SECURITY: supabase_jwt_secret verifies tokens minted by Supabase Auth for
    # the dashboard + desktop sync. This is the project's JWT secret (Supabase
    # dashboard -> Settings -> API -> JWT Secret), distinct from jwt_secret_key
    # which signs this API's own CLI sessions.
    supabase_jwt_secret: str | None = None
    webapp_url: str = "https://app.zypheron.net"  # used for portal links + report render
    report_render_secret: str | None = None  # short-lived token gate for /report-render

    # Dashboard entitlement gate. The web dashboard is the $499/mo platform tier.
    # Access is granted when the user's (or their firm owner's) active plan
    # exposes this feature flag, OR via a free-access grant / developer access.
    # The $499 "Mid" plan + Enterprise carry web_dashboard=true in launch.sql.
    dashboard_required_feature: str = "web_dashboard"

    # Redis (optional for caching and rate limiting)
    redis_url: str | None = None
    redis_enabled: bool = False
    redis_ssl: bool = False
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str | None = None
    redis_db: int = 0

    # JWT Authentication
    # SECURITY: JWT secret must be set via environment variable in production
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"
    jwt_secret_key: str = Field(
        default="dev-secret-UNSAFE-FOR-PRODUCTION",
        description="JWT signing key - MUST be set via JWT_SECRET_KEY env var in production"
    )
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 10080  # 7 days

    def model_post_init(self, __context) -> None:
        """Validate critical security settings after initialization."""
        # SECURITY (H-07): reject the known-unsafe default JWT secret in ANY
        # non-development environment. The default is published in this
        # open-source repo, so accepting it outside local dev allows token
        # forgery. Previously this only fired for "production", leaving "staging"
        # exposed.
        if self.environment != "development":
            if "UNSAFE" in self.jwt_secret_key or self.jwt_secret_key == "dev-secret-UNSAFE-FOR-PRODUCTION":
                raise ValueError(
                    f"CRITICAL: JWT_SECRET_KEY must be set in {self.environment}! "
                    "The default secret is public in this open-source repo. "
                    "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
            if len(self.jwt_secret_key) < 32:
                raise ValueError(
                    f"CRITICAL: JWT_SECRET_KEY must be at least 32 characters in {self.environment}"
                )

    # API Keys for AI Providers (server-side pool)
    openai_api_keys: list[str] = Field(default_factory=list)
    anthropic_api_keys: list[str] = Field(default_factory=list)
    grok_api_keys: list[str] = Field(default_factory=list)
    deepseek_api_keys: list[str] = Field(default_factory=list)

    # Ollama (Local LLM server - no API key required)
    enable_ollama: bool = True  # Enable Ollama provider (runs locally)
    ollama_base_url: str = "http://localhost:11434"  # Ollama server URL

    # Rate Limiting
    enable_rate_limiting: bool = True  # Master switch for rate limiting
    rate_limit_free: int = 10  # requests per minute
    rate_limit_starter: int = 60
    rate_limit_pro: int = 120
    rate_limit_enterprise: int = 300

    # Token Limits (monthly)
    token_limit_free: int = 0  # BYOK only
    token_limit_starter: int = 1_000_000
    token_limit_pro: int = 3_000_000
    token_limit_enterprise: int = 15_000_000  # per 5 users

    # Cache TTL (seconds) - Aggressive strategy for ~35-40% cost savings
    cache_ttl_prompt: int = 3600  # 1 hour for identical prompts
    cache_ttl_vuln_desc: int = 86400  # 24 hours for vulnerability descriptions (CVE lookups)
    cache_ttl_general: int = 21600  # 6 hours for general security info

    # Legacy Stripe settings retained for compatibility with older configs
    stripe_secret_key: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_publishable_key: str | None = None
    # Monthly price IDs
    stripe_price_id_starter_monthly: str | None = None
    stripe_price_id_pro_monthly: str | None = None
    stripe_price_id_enterprise_monthly: str | None = None
    # Annual price IDs
    stripe_price_id_starter_annual: str | None = None
    stripe_price_id_pro_annual: str | None = None
    stripe_price_id_enterprise_annual: str | None = None
    stripe_payment_grace_period_days: int = 3

    # Legacy pricing values retained for compatibility with older configs
    price_starter_monthly: int = 2900  # $29
    price_starter_annual: int = 26100  # $261 (25% off $348)
    price_pro_monthly: int = 14900  # $149
    price_pro_annual: int = 134100  # $1,341 (25% off $1,788)
    price_enterprise_monthly: int = 49900  # $499 per user
    price_enterprise_annual: int = 449100  # $4,491 per user (25% off $5,988)
    enterprise_min_seats: int = 3

    # Metrics endpoint security
    metrics_secret_token: str | None = None  # Bearer token for /metrics access

    # Legacy redirect allowlist retained for older hosted flows
    allowed_redirect_domains: list[str] = Field(
        default_factory=lambda: ["localhost"],
        description="Allowed redirect domains for optional local web flows",
    )

    # GitHub OAuth Integration
    github_client_id: str | None = None
    github_client_secret: str | None = None
    base_url: str = "http://localhost:8000"

    # BYOK (Bring Your Own Key) Encryption
    # SECURITY: Encryption keys for BYOK API key storage
    # CRYPTO-H1: AES-256-GCM is recommended (stronger than Fernet)
    # Generate AES-256 key: python -c "import secrets; print(secrets.token_hex(32))"
    # Generate Fernet key: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

    # NEW: AES-256-GCM keys (recommended for production)
    byok_encryption_key_gcm_v1: str | None = Field(
        default=None,
        description="AES-256-GCM encryption key version 1 (64-char hex string)"
    )
    byok_encryption_key_gcm_v2: str | None = Field(
        default=None,
        description="AES-256-GCM encryption key version 2 (64-char hex string)"
    )
    byok_encryption_key_gcm_v3: str | None = Field(
        default=None,
        description="AES-256-GCM encryption key version 3 (64-char hex string)"
    )
    byok_encryption_key_gcm_v4: str | None = Field(
        default=None,
        description="AES-256-GCM encryption key version 4 (64-char hex string)"
    )
    byok_encryption_key_gcm_v5: str | None = Field(
        default=None,
        description="AES-256-GCM encryption key version 5 (64-char hex string)"
    )

    # LEGACY: Fernet keys (AES-128-CBC) - kept for backward compatibility read-only
    byok_encryption_key: str | None = Field(
        default=None,
        description="Legacy Fernet encryption key (deprecated - use GCM keys)"
    )
    byok_encryption_key_v1: str | None = Field(
        default=None,
        description="Legacy Fernet encryption key version 1 (read-only for migration)"
    )
    byok_encryption_key_v2: str | None = Field(
        default=None,
        description="Legacy Fernet encryption key version 2 (read-only for migration)"
    )
    byok_encryption_key_v3: str | None = Field(
        default=None,
        description="Legacy Fernet encryption key version 3 (read-only for migration)"
    )
    byok_encryption_key_v4: str | None = Field(
        default=None,
        description="Legacy Fernet encryption key version 4 (read-only for migration)"
    )
    byok_encryption_key_v5: str | None = Field(
        default=None,
        description="Legacy Fernet encryption key version 5 (read-only for migration)"
    )

    byok_encryption_key_current: int | None = Field(
        default=None,
        description="Current key version to use for new encryptions (1-5). Defaults to highest available version."
    )

    @computed_field
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @computed_field
    @property
    def postgres_url(self) -> str | None:
        """Generate PostgreSQL URL from configuration.

        Priority:
        1. postgres_url_override (if set)
        2. Legacy hosted database credentials
        3. Local PostgreSQL settings
        """
        # Allow manual override
        if self.postgres_url_override:
            return self.postgres_url_override

        # Supabase connection (production)
        if self.supabase_url and self.supabase_service_key:
            # Extract host from Supabase URL
            host = self.supabase_url.replace("https://", "").split(".")[0]
            return f"postgresql+asyncpg://postgres:{self.supabase_service_key}@db.{host}.supabase.co:5432/postgres"

        # Local PostgreSQL connection (development)
        if self.database_type == "postgresql":
            return (
                f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
                f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
            )

        return None


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
