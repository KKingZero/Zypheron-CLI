"""Tests for authentication endpoints (registration, login, logout).

Tests cover:
- User registration
- Email/password login
- Session management
- Logout
- Current user retrieval
- Authentication middleware
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.license import License
from app.models.session import Session
from app.models.user import User


class TestUserRegistration:
    """Tests for POST /auth/register endpoint."""

    async def test_register_success(
        self,
        client: AsyncClient,
        test_db: AsyncSession,
    ):
        """Test successful user registration."""
        response = await client.post(
            "/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == 201
        data = response.json()

        # Verify response structure
        assert "user" in data
        assert "access_token" in data
        assert "token_type" in data

        # Verify user data
        user_data = data["user"]
        assert user_data["email"] == "newuser@example.com"
        assert user_data["tier"] == "free"
        assert user_data["is_active"] is True

        # Verify JWT token provided
        assert data["access_token"] is not None
        assert data["token_type"] == "bearer"

        # Verify user created in database
        stmt = select(User).where(User.email == "newuser@example.com")
        result = await test_db.execute(stmt)
        user = result.scalar_one_or_none()
        assert user is not None
        assert user.tier == "free"

    async def test_register_creates_free_license(
        self,
        client: AsyncClient,
        test_db: AsyncSession,
    ):
        """Test that registration creates default free license."""
        response = await client.post(
            "/auth/register",
            json={
                "email": "licensed@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == 201
        user_id = response.json()["user"]["id"]

        # Verify license created
        stmt = select(License).where(License.user_id == user_id)
        result = await test_db.execute(stmt)
        license = result.scalar_one_or_none()

        assert license is not None
        assert license.tier == "free"
        assert license.status == "active"

    async def test_register_creates_session(
        self,
        client: AsyncClient,
        test_db: AsyncSession,
    ):
        """Test that registration creates active session."""
        response = await client.post(
            "/auth/register",
            json={
                "email": "session@example.com",
                "password": "SecurePass123!",
            },
        )

        assert response.status_code == 201
        token = response.json()["access_token"]
        user_id = response.json()["user"]["id"]

        # Verify session created
        stmt = select(Session).where(
            Session.user_id == user_id,
            Session.token == token,
        )
        result = await test_db.execute(stmt)
        session = result.scalar_one_or_none()

        assert session is not None
        assert session.is_active is True

    async def test_register_duplicate_email(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        """Test registration with existing email fails."""
        response = await client.post(
            "/auth/register",
            json={
                "email": test_user.email,
                "password": "AnotherPass456!",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert "already registered" in data["detail"].lower()

    async def test_register_invalid_email(
        self,
        client: AsyncClient,
    ):
        """Test registration with invalid email format."""
        response = await client.post(
            "/auth/register",
            json={
                "email": "not-an-email",
                "password": "SecurePass123!",
            },
        )

        # Should fail validation
        assert response.status_code == 422


class TestUserLogin:
    """Tests for POST /auth/login endpoint."""

    async def test_login_success(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test successful login with correct credentials."""
        response = await client.post(
            "/auth/login",
            json={
                "email": test_user.email,
                "password": "testpass123",  # Password from fixture
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Verify response structure
        assert "user" in data
        assert "access_token" in data
        assert "token_type" in data

        # Verify user data
        assert data["user"]["email"] == test_user.email
        assert data["user"]["id"] == test_user.id

        # Verify token provided
        assert data["access_token"] is not None

        # Verify last_login updated
        await test_db.refresh(test_user)
        assert test_user.last_login is not None

    async def test_login_wrong_password(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        """Test login with incorrect password fails."""
        response = await client.post(
            "/auth/login",
            json={
                "email": test_user.email,
                "password": "wrongpassword",
            },
        )

        assert response.status_code == 401
        data = response.json()
        assert "invalid" in data["detail"].lower()

    async def test_login_nonexistent_user(
        self,
        client: AsyncClient,
    ):
        """Test login with non-existent email fails."""
        response = await client.post(
            "/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "anypassword",
            },
        )

        assert response.status_code == 401
        data = response.json()
        assert "invalid" in data["detail"].lower()

    async def test_login_inactive_user(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test login with inactive user account fails."""
        # Deactivate user
        test_user.is_active = False
        await test_db.commit()

        response = await client.post(
            "/auth/login",
            json={
                "email": test_user.email,
                "password": "testpass123",
            },
        )

        assert response.status_code == 401


class TestUserLogout:
    """Tests for POST /auth/logout endpoint."""

    async def test_logout_success(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test successful logout invalidates session."""
        response = await client.post(
            "/auth/logout",
            headers=auth_headers,
        )

        assert response.status_code == 204

        # Verify session invalidated
        token = auth_headers["Authorization"].replace("Bearer ", "")
        stmt = select(Session).where(
            Session.token == token,
            Session.user_id == test_user.id,
        )
        result = await test_db.execute(stmt)
        session = result.scalar_one_or_none()

        assert session is not None
        assert session.is_active is False

    async def test_logout_without_auth(
        self,
        client: AsyncClient,
    ):
        """Test logout without authentication fails."""
        response = await client.post("/auth/logout")

        assert response.status_code == 401


class TestCurrentUser:
    """Tests for GET /auth/me endpoint."""

    async def test_get_current_user_success(
        self,
        client: AsyncClient,
        auth_headers: dict[str, str],
        test_user: User,
    ):
        """Test retrieving current authenticated user."""
        response = await client.get(
            "/auth/me",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["id"] == test_user.id
        assert data["email"] == test_user.email
        assert data["tier"] == test_user.tier

    async def test_get_current_user_without_auth(
        self,
        client: AsyncClient,
    ):
        """Test retrieving current user without authentication fails."""
        response = await client.get("/auth/me")

        assert response.status_code == 401


class TestAuthenticationMiddleware:
    """Tests for JWT authentication and middleware."""

    async def test_invalid_token_format(
        self,
        client: AsyncClient,
    ):
        """Test request with invalid token format."""
        response = await client.get(
            "/auth/me",
            headers={"Authorization": "InvalidFormat token123"},
        )

        assert response.status_code == 401

    async def test_missing_bearer_prefix(
        self,
        client: AsyncClient,
    ):
        """Test request with missing Bearer prefix."""
        response = await client.get(
            "/auth/me",
            headers={"Authorization": "sometoken123"},
        )

        assert response.status_code == 401

    async def test_expired_session(
        self,
        client: AsyncClient,
        test_user: User,
        test_db: AsyncSession,
    ):
        """Test request with expired/invalidated session."""
        from app.core.security import create_access_token

        # Create token but don't create session (simulates expired)
        token = create_access_token({
            "sub": str(test_user.id),
            "email": test_user.email,
        })

        response = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401
        data = response.json()
        assert "invalid" in data["detail"].lower() or "expired" in data["detail"].lower()


class TestHealthEndpoints:
    """Tests for health check and root endpoints."""

    async def test_health_check(self, client: AsyncClient):
        """Test health check endpoint."""
        response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert "service" in data
        assert "version" in data
        assert "environment" in data

    async def test_root_endpoint(self, client: AsyncClient):
        """Test root endpoint returns API info."""
        response = await client.get("/")

        assert response.status_code == 200
        data = response.json()

        assert "service" in data
        assert "version" in data
        assert "docs" in data
        assert data["docs"] == "/docs"
