"""Pytest configuration and shared fixtures for Zypheron API tests.

Provides:
- Test database setup with SQLite in-memory
- Mock Stripe client
- Authenticated test client
- Test user and license fixtures
- Auth token fixtures
"""

import asyncio
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import stripe
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base, get_db
from app.core.security import create_access_token, hash_password
from app.main import app
from app.routers.auth import hash_token
from app.models.device_code import DeviceCode
from app.models.license import License
from app.models.session import Session
from app.models.user import User


# Configure pytest-asyncio
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Test database engine (SQLite in-memory for speed)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)

TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest.fixture(scope="function")
async def test_db() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session with tables created and cleaned up.

    Each test gets a fresh database with all tables created.
    Tables are dropped after each test.
    """
    # Create all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create session
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    # Drop all tables after test
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def override_get_db(test_db: AsyncSession):
    """Override the get_db dependency to use test database."""
    async def _get_test_db() -> AsyncGenerator[AsyncSession, None]:
        yield test_db

    app.dependency_overrides[get_db] = _get_test_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
async def client(override_get_db) -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing the API.

    Uses HTTPX AsyncClient with ASGI transport for fast in-process testing.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def test_user(test_db: AsyncSession) -> User:
    """Create a test user with email/password authentication.

    Returns:
        User with email test@example.com and password "testpass123"
    """
    user = User(
        email="test@example.com",
        password_hash=hash_password("testpass123"),
        tier="free",
        is_active=True,
        is_verified=False,
    )
    test_db.add(user)
    await test_db.commit()
    await test_db.refresh(user)
    return user


@pytest.fixture
async def test_user_with_license(test_db: AsyncSession) -> tuple[User, License]:
    """Create a test user with an active free-tier license.

    Returns:
        Tuple of (User, License)
    """
    user = User(
        email="licensed@example.com",
        password_hash=hash_password("testpass123"),
        tier="free",
        is_active=True,
        is_verified=True,
    )
    test_db.add(user)
    await test_db.flush()

    license = License(
        user_id=user.id,
        tier="free",
        status="active",
    )
    test_db.add(license)
    await test_db.commit()
    await test_db.refresh(user)
    await test_db.refresh(license)

    return user, license


@pytest.fixture
async def test_paid_user(test_db: AsyncSession) -> tuple[User, License]:
    """Create a test user with an active pro-tier subscription.

    Returns:
        Tuple of (User, License) with pro tier
    """
    user = User(
        email="pro@example.com",
        password_hash=hash_password("testpass123"),
        tier="pro",
        is_active=True,
        is_verified=True,
    )
    test_db.add(user)
    await test_db.flush()

    license = License(
        user_id=user.id,
        tier="pro",
        status="active",
        stripe_customer_id="cus_test123",
        stripe_subscription_id="sub_test123",
        stripe_price_id="price_pro_monthly",
    )
    test_db.add(license)
    await test_db.commit()
    await test_db.refresh(user)
    await test_db.refresh(license)

    return user, license


@pytest.fixture
def auth_token(test_user: User) -> str:
    """Generate a JWT token for the test user.

    Returns:
        Bearer token string (without "Bearer " prefix)
    """
    token_data = {"sub": str(test_user.id), "email": test_user.email}
    return create_access_token(token_data)


@pytest.fixture
async def auth_headers(test_user: User, test_db: AsyncSession) -> dict[str, str]:
    """Generate authentication headers with valid JWT token and session.

    Creates a session record in the database for token validation.

    Returns:
        Dictionary with Authorization header
    """
    token_data = {"sub": str(test_user.id), "email": test_user.email}
    token = create_access_token(token_data)

    # Create session record (tokens are stored as SHA-256 hashes)
    session = Session(
        user_id=test_user.id,
        token=hash_token(token),
    )
    test_db.add(session)
    await test_db.commit()

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def paid_user_headers(test_paid_user: tuple[User, License], test_db: AsyncSession) -> dict[str, str]:
    """Generate authentication headers for paid user.

    Returns:
        Dictionary with Authorization header for pro-tier user
    """
    user, _ = test_paid_user
    token_data = {"sub": str(user.id), "email": user.email}
    token = create_access_token(token_data)

    # Create session record (tokens are stored as SHA-256 hashes)
    session = Session(
        user_id=user.id,
        token=hash_token(token),
    )
    test_db.add(session)
    await test_db.commit()

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def mock_stripe_customer() -> MagicMock:
    """Mock Stripe Customer object.

    Returns:
        MagicMock configured as Stripe Customer
    """
    mock = MagicMock()
    mock.id = "cus_mock123"
    mock.email = "test@example.com"
    mock.metadata = {"user_id": "1", "environment": "test"}
    return mock


@pytest.fixture
def mock_stripe_subscription() -> dict[str, Any]:
    """Mock Stripe Subscription object as dictionary.

    Returns:
        Dictionary representing a Stripe subscription
    """
    return {
        "id": "sub_mock123",
        "customer": "cus_mock123",
        "status": "active",
        "current_period_end": int(datetime(2025, 2, 1, tzinfo=timezone.utc).timestamp()),
        "cancel_at_period_end": False,
        "items": {
            "data": [
                {
                    "price": {
                        "id": "price_pro_monthly",
                    }
                }
            ]
        },
        "metadata": {
            "user_id": "1",
            "tier": "pro",
        },
    }


@pytest.fixture
def mock_stripe_checkout_session() -> MagicMock:
    """Mock Stripe Checkout Session object.

    Returns:
        MagicMock configured as Stripe Checkout Session
    """
    mock = MagicMock()
    mock.id = "cs_mock123"
    mock.url = "https://checkout.stripe.com/pay/cs_mock123"
    mock.customer = "cus_mock123"
    mock.mode = "subscription"
    mock.status = "open"
    return mock


@pytest.fixture
def mock_stripe_webhook_event() -> dict[str, Any]:
    """Mock Stripe webhook event structure.

    Returns:
        Dictionary representing a Stripe webhook event
    """
    return {
        "id": "evt_mock123",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_mock123",
                "customer": "cus_mock123",
                "status": "active",
                "metadata": {"user_id": "1", "tier": "pro"},
            }
        },
    }


@pytest.fixture
def mock_stripe_client(mocker, mock_stripe_customer, mock_stripe_checkout_session):
    """Mock the Stripe API client for all Stripe operations.

    Mocks:
    - stripe.Customer.create
    - stripe.Customer.retrieve
    - stripe.checkout.Session.create
    - stripe.Subscription.retrieve
    - stripe.Subscription.modify
    - stripe.Subscription.delete
    - stripe.Webhook.construct_event

    Returns:
        Dictionary of mocked Stripe methods
    """
    # Mock Customer operations
    mock_customer_create = mocker.patch(
        "stripe.Customer.create",
        return_value=mock_stripe_customer
    )
    mock_customer_retrieve = mocker.patch(
        "stripe.Customer.retrieve",
        return_value=mock_stripe_customer
    )

    # Mock Checkout Session
    mock_checkout_create = mocker.patch(
        "stripe.checkout.Session.create",
        return_value=mock_stripe_checkout_session
    )

    # Mock Subscription operations
    mock_sub_retrieve = mocker.patch(
        "stripe.Subscription.retrieve",
        return_value=MagicMock(
            id="sub_mock123",
            status="active",
            cancel_at_period_end=False,
            current_period_end=int(datetime(2025, 2, 1, tzinfo=timezone.utc).timestamp()),
            items=MagicMock(
                data=[
                    MagicMock(price=MagicMock(id="price_pro_monthly"))
                ]
            ),
        )
    )
    mock_sub_modify = mocker.patch(
        "stripe.Subscription.modify",
        return_value=MagicMock(
            id="sub_mock123",
            cancel_at_period_end=True,
            current_period_end=int(datetime(2025, 2, 1, tzinfo=timezone.utc).timestamp()),
        )
    )
    mock_sub_delete = mocker.patch("stripe.Subscription.delete")

    # Mock Webhook verification
    mock_webhook_construct = mocker.patch(
        "stripe.Webhook.construct_event",
        side_effect=lambda payload, sig, secret: {
            "id": "evt_mock123",
            "type": "customer.subscription.created",
            "data": {"object": {}},
        }
    )

    return {
        "customer_create": mock_customer_create,
        "customer_retrieve": mock_customer_retrieve,
        "checkout_create": mock_checkout_create,
        "subscription_retrieve": mock_sub_retrieve,
        "subscription_modify": mock_sub_modify,
        "subscription_delete": mock_sub_delete,
        "webhook_construct": mock_webhook_construct,
    }


@pytest.fixture
async def test_device_code(test_db: AsyncSession) -> DeviceCode:
    """Create a test device code in pending status.

    Returns:
        DeviceCode with status='pending'
    """
    device_code = DeviceCode(
        device_code="test_device_code_123456",
        user_code="TEST-1234",
        device_info={
            "os": "Linux",
            "platform": "Ubuntu 22.04",
            "hostname": "test-machine",
        },
        status="pending",
        expires_at=DeviceCode.generate_expiration(minutes=5),
    )
    test_db.add(device_code)
    await test_db.commit()
    await test_db.refresh(device_code)
    return device_code


@pytest.fixture
async def expired_device_code(test_db: AsyncSession) -> DeviceCode:
    """Create an expired device code for testing expiry scenarios.

    Returns:
        DeviceCode with status='expired' and past expiration time
    """
    from datetime import timedelta

    device_code = DeviceCode(
        device_code="expired_device_code_123",
        user_code="EXPR-5678",
        device_info={"os": "Linux"},
        status="pending",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
    )
    test_db.add(device_code)
    await test_db.commit()
    await test_db.refresh(device_code)
    return device_code


@pytest.fixture
async def test_annual_user(test_db: AsyncSession) -> tuple[User, License]:
    """Create a test user with an annual pro subscription."""
    user = User(
        email="annual@example.com",
        password_hash=hash_password("testpass123"),
        tier="pro",
        is_active=True,
        is_verified=True,
    )
    test_db.add(user)
    await test_db.flush()

    license = License(
        user_id=user.id,
        tier="pro",
        status="active",
        stripe_customer_id="cus_annual123",
        stripe_subscription_id="sub_annual123",
        stripe_price_id="price_pro_annual",
        billing_interval="annual",
    )
    test_db.add(license)
    await test_db.commit()
    await test_db.refresh(user)
    await test_db.refresh(license)
    return user, license


@pytest.fixture
def mock_stripe_portal_session():
    """Mock Stripe billing portal session."""
    mock = MagicMock()
    mock.url = "https://billing.stripe.com/session/test_portal"
    return mock


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for idempotency tests."""
    mock = AsyncMock()
    mock.is_available = True
    mock._client = AsyncMock()
    mock._client.get = AsyncMock(return_value=None)
    mock._client.setex = AsyncMock()
    return mock


@pytest.fixture
def mock_load_balancer():
    """Mock AILoadBalancer for AI proxy tests."""
    from app.services.load_balancer import AILoadBalancer
    mock = MagicMock(spec=AILoadBalancer)
    mock.get_available_providers.return_value = ["openai", "anthropic", "ollama"]
    mock.get_pool_stats.return_value = {
        "openai": {"total_keys": 2, "healthy_keys": 2, "unhealthy_keys": 0, "total_failures": 0},
    }
    return mock


@pytest.fixture
def mock_cache_service():
    """Mock CacheService for testing."""
    from app.services.cache import CacheService
    mock = AsyncMock(spec=CacheService)
    mock.get_cached_response = AsyncMock(return_value=None)
    mock.cache_response = AsyncMock()
    mock.get_stats = AsyncMock(return_value={"backend": "mock", "size": 0, "metrics": {}})
    return mock


@pytest.fixture
def mock_redis():
    """Mock Redis client for tests requiring Redis."""
    mock = AsyncMock()
    mock.is_available = True
    mock._client = AsyncMock()
    mock._client.eval = AsyncMock(return_value=[1, 1, 9999999999])  # allowed, count, reset_time
    mock._client.get = AsyncMock(return_value=None)
    mock._client.setex = AsyncMock()
    return mock


@pytest.fixture
async def user_with_quota(test_db: AsyncSession) -> tuple:
    """Create a user with a quota record for AI proxy tests."""
    from app.models.token_usage import UserQuota
    from datetime import timedelta

    user = User(
        email="quota@example.com",
        password_hash=hash_password("testpass123"),
        tier="pro",
        is_active=True,
        is_verified=True,
    )
    test_db.add(user)
    await test_db.flush()

    license = License(
        user_id=user.id,
        tier="pro",
        status="active",
        stripe_customer_id="cus_quota123",
        stripe_subscription_id="sub_quota123",
    )
    test_db.add(license)

    now = datetime.now(timezone.utc)
    quota = UserQuota(
        user_id=user.id,
        tier="pro",
        period_start=now.replace(day=1),
        period_end=(now.replace(day=1) + timedelta(days=31)),
        tokens_used_period=100000,
        token_limit=3000000,
        byok_enabled=False,
    )
    test_db.add(quota)
    await test_db.commit()
    await test_db.refresh(user)
    await test_db.refresh(license)
    await test_db.refresh(quota)
    return user, license, quota
