"""Prometheus metrics for Zypheron API monitoring.

Provides counters, histograms, and gauges for:
- HTTP request tracking
- AI proxy usage
- Cache performance
- Rate limiting
- Subscription status
"""

from prometheus_client import Counter, Gauge, Histogram

# HTTP metrics
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)

http_request_duration = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# AI proxy metrics
ai_requests_total = Counter(
    "ai_requests_total",
    "Total AI proxy requests",
    ["provider", "model", "tier", "is_byok"],
)

ai_request_duration = Histogram(
    "ai_request_duration_seconds",
    "AI request duration in seconds",
    ["provider"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)

ai_tokens_used_total = Counter(
    "ai_tokens_used_total",
    "Total AI tokens consumed",
    ["provider", "model", "token_type"],
)

# Cache metrics
cache_hits_total = Counter(
    "cache_hits_total",
    "Total cache hits",
    ["backend"],
)

cache_misses_total = Counter(
    "cache_misses_total",
    "Total cache misses",
    ["backend"],
)

# Rate limiting metrics
rate_limit_exceeded_total = Counter(
    "rate_limit_exceeded_total",
    "Total rate limit exceeded events",
    ["tier", "limit_type"],
)

# Subscription metrics
active_subscriptions = Gauge(
    "active_subscriptions",
    "Number of active subscriptions",
    ["tier"],
)
