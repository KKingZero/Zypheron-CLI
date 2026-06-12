"""Authentication router for user registration, login, and OAuth.

Supports:
- Email/password registration and login
- GitHub OAuth flow
- Session management and logout
- Current user retrieval

Security Features:
- AUTH-H2: Generic error messages to prevent email enumeration
- AUTH-H3: Account lockout after 5 failed attempts (15 min)
- AUTH-H4: Session limits per tier (Free:2, Starter:5, Pro:10, Enterprise:unlimited)
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    generate_device_code,
    generate_user_code,
    hash_password,
    verify_password,
)
from app.models.device_code import DeviceCode
from app.models.license import License
from app.models.session import Session
from app.models.user import User
from app.services.token_tracking import TokenTrackingService
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.schemas.device_auth import (
    DeviceAuthorizeRequest,
    DeviceAuthorizeResponse,
    DeviceCodeRequest,
    DeviceCodeResponse,
    DeviceTokenRequest,
    DeviceTokenResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()

# AUTH-H3: Account lockout configuration
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# AUTH-H4: Session limits per tier
SESSION_LIMITS = {
    "free": 2,
    "starter": 5,
    "pro": 10,
    "enterprise": None,  # Unlimited
}


def get_session_limit(tier: str) -> int | None:
    """Get session limit for a user tier.

    Args:
        tier: User subscription tier

    Returns:
        Maximum number of sessions allowed, or None for unlimited
    """
    return SESSION_LIMITS.get(tier.lower(), SESSION_LIMITS["free"])


async def enforce_session_limit(user_id: int, tier: str, db: AsyncSession) -> None:
    """Enforce session limit by invalidating oldest sessions if limit exceeded.

    AUTH-H4: Limits concurrent sessions per tier to prevent session fixation attacks.

    Args:
        user_id: User ID
        tier: User's subscription tier
        db: Database session
    """
    limit = get_session_limit(tier)

    # Enterprise tier has no limit
    if limit is None:
        return

    # Count active sessions
    count_stmt = select(func.count(Session.id)).where(
        Session.user_id == user_id,
        Session.is_active == True,
    )
    result = await db.execute(count_stmt)
    active_count = result.scalar_one()

    # If at or over limit, invalidate oldest sessions
    if active_count >= limit:
        # Get oldest sessions to invalidate (keep limit - 1 to make room for new one)
        sessions_to_invalidate = active_count - limit + 1

        oldest_stmt = (
            select(Session)
            .where(Session.user_id == user_id, Session.is_active == True)
            .order_by(Session.created_at.asc())
            .limit(sessions_to_invalidate)
        )
        result = await db.execute(oldest_stmt)
        old_sessions = result.scalars().all()

        for session in old_sessions:
            session.invalidate()


def hash_token(token: str) -> str:
    """Create SHA-256 hash of token for secure storage.

    JWT tokens are hashed before storing in the database to prevent plaintext exposure.
    This mitigates the risk of token compromise if the database is breached.

    Args:
        token: The JWT token to hash

    Returns:
        Hexadecimal string representation of the SHA-256 hash
    """
    return hashlib.sha256(token.encode()).hexdigest()


# Dependency to get current user from JWT token
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate JWT token from Authorization header.

    Args:
        request: FastAPI request object
        db: Database session

    Returns:
        Current authenticated user

    Raises:
        HTTPException: If token is missing, invalid, or user not found
    """
    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.replace("Bearer ", "")

    # Hash the token for database lookup (tokens are stored as SHA-256 hashes)
    # SECURITY: This change invalidates all existing sessions due to hash format change
    token_hash = hash_token(token)

    # Validate token exists in sessions table and is active
    stmt = select(Session).where(
        Session.token == token_hash,
        Session.is_active == True,
    )
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()

    if not session or not session.is_valid():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update session activity
    session.update_activity()

    # Get user
    stmt = select(User).where(User.id == session.user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return user


# Type alias for current user dependency
CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Register a new user with email and password.

    Creates user account, default free-tier license, and returns JWT token.

    AUTH-H2: Returns generic error message to prevent email enumeration.

    Args:
        request: Registration request with email and password
        db: Database session

    Returns:
        LoginResponse with user info and access token

    Raises:
        HTTPException: If registration fails (generic message)
    """
    # Check if user already exists
    stmt = select(User).where(User.email == request.email)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()

    # AUTH-H2: Generic error message to prevent email enumeration
    # Don't reveal whether the email exists in our system
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed. Please check your input and try again.",
        )

    # Create new user
    hashed_pw = hash_password(request.password)
    new_user = User(
        email=request.email,
        password_hash=hashed_pw,
        tier="free",
        is_active=True,
        is_verified=False,
    )
    db.add(new_user)
    await db.flush()  # Get user.id without committing

    # Create default free license
    free_license = License(
        user_id=new_user.id,
        tier="free",
        status="active",
    )
    db.add(free_license)

    # Initialize user quota for token tracking
    token_service = TokenTrackingService(db)
    await token_service.initialize_user_quota(
        user_id=new_user.id,
        tier="free",
        byok_enabled=False,
    )

    # Update last login
    new_user.update_last_login()

    # Create JWT token
    token_data = {"sub": str(new_user.id), "email": new_user.email}
    access_token = create_access_token(token_data)

    # Create session record with hashed token for security
    new_session = Session(
        user_id=new_user.id,
        token=hash_token(access_token),
    )
    db.add(new_session)

    await db.commit()
    await db.refresh(new_user)

    return LoginResponse(
        user=UserResponse.model_validate(new_user),
        access_token=access_token,
        token_type="bearer",
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Login with email and password.

    Validates credentials and returns JWT token.

    Security features:
    - AUTH-H2: Generic error messages to prevent email enumeration
    - AUTH-H3: Account lockout after 5 failed attempts (15 min)
    - AUTH-H4: Session limits per tier

    Args:
        request: Login request with email and password
        db: Database session

    Returns:
        LoginResponse with user info and access token

    Raises:
        HTTPException: If credentials are invalid or account is locked
    """
    # Find user by email
    stmt = select(User).where(User.email == request.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    # AUTH-H2: Generic error message for non-existent user
    # Use constant-time-ish check to prevent timing attacks
    if not user:
        # Still hash something to prevent timing attacks
        verify_password(request.password, "$2b$12$dummyhashtopreventtimingattacks")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # AUTH-H3: Check if account is locked
    if user.is_locked():
        remaining = user.get_lockout_remaining_seconds()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked. Try again in {remaining // 60 + 1} minutes.",
            headers={"Retry-After": str(remaining)},
        )

    # Verify user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Verify password
    if not user.password_hash or not verify_password(request.password, user.password_hash):
        # AUTH-H3: Record failed login attempt
        is_now_locked = user.record_failed_login(
            max_attempts=MAX_FAILED_ATTEMPTS,
            lockout_minutes=LOCKOUT_DURATION_MINUTES,
        )
        await db.commit()

        if is_now_locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed attempts. Account locked for {LOCKOUT_DURATION_MINUTES} minutes.",
                headers={"Retry-After": str(LOCKOUT_DURATION_MINUTES * 60)},
            )

        # SECURITY (H-01): return a generic error. Leaking the remaining attempt
        # count gives an attacker a precise lockout oracle for credential
        # stuffing (rotate IPs just before lockout). The count is still tracked
        # server-side for lockout enforcement above.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    # AUTH-H3: Reset failed login counter on successful login
    user.reset_failed_logins()

    # Update last login
    user.update_last_login()

    # AUTH-H4: Enforce session limits before creating new session
    await enforce_session_limit(user.id, user.tier, db)

    # Ensure user has a quota record (handles legacy users created before quota system)
    token_service = TokenTrackingService(db)
    quota_info = await token_service.get_quota_info(user.id)
    if quota_info["tier"] == "unknown":
        await token_service.initialize_user_quota(
            user_id=user.id,
            tier=user.tier or "free",
            byok_enabled=False,
        )

    # Create JWT token
    token_data = {"sub": str(user.id), "email": user.email}
    access_token = create_access_token(token_data)

    # Create session record with hashed token for security
    new_session = Session(
        user_id=user.id,
        token=hash_token(access_token),
    )
    db.add(new_session)

    await db.commit()

    return LoginResponse(
        user=UserResponse.model_validate(user),
        access_token=access_token,
        token_type="bearer",
    )


@router.get("/github")
async def github_oauth_redirect(
    response: Response,
) -> RedirectResponse:
    """Redirect to GitHub OAuth authorization page.

    Initiates the GitHub OAuth flow by redirecting to GitHub's authorize endpoint.
    Generates a CSRF state token and stores it in a secure cookie.

    Returns:
        Redirect response to GitHub OAuth page

    Raises:
        HTTPException: If GitHub OAuth is not configured
    """
    # Validate GitHub OAuth configuration
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.",
        )

    # Generate CSRF protection state token
    state = secrets.token_urlsafe(32)

    # Store state in secure cookie for validation in callback
    # Cookie expires in 10 minutes (enough time for OAuth flow)
    # Security: Always use secure flag (requires HTTPS even in dev), strict SameSite for CSRF protection
    # Using __Host- prefix for additional security (prevents subdomain hijacking)
    response.set_cookie(
        key="__Host-oauth_state",
        value=state,
        max_age=600,  # 10 minutes
        httponly=True,
        secure=True,  # ALWAYS secure, even in dev - use HTTPS locally
        samesite="strict",  # Strict for CSRF protection on state tokens
        path="/",  # Required for __Host- prefix
    )

    # Build GitHub authorization URL
    redirect_uri = f"{settings.base_url}/auth/github/callback"
    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.github_client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=user:email"
        f"&state={state}"
    )

    return RedirectResponse(url=github_auth_url)


@router.get("/github/callback", response_model=LoginResponse)
async def github_oauth_callback(
    request: Request,
    response: Response,
    code: str,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Handle GitHub OAuth callback and create/login user.

    Exchanges authorization code for access token, fetches user info from GitHub,
    and creates or logs in the user.

    Args:
        request: FastAPI request object (to access cookies)
        code: Authorization code from GitHub
        state: CSRF protection state parameter
        error: Error code from GitHub (if authorization failed)
        error_description: Human-readable error description
        db: Database session

    Returns:
        LoginResponse with user info and access token

    Raises:
        HTTPException: If OAuth flow fails or is not configured
    """
    # Check if GitHub returned an error
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"GitHub OAuth error: {error_description or error}",
        )

    # Validate GitHub OAuth configuration
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.",
        )

    # Validate CSRF state parameter with constant-time comparison to prevent timing attacks
    stored_state = request.cookies.get("__Host-oauth_state")

    # Check if state parameters exist first
    if not state or not stored_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter. Possible CSRF attack detected. Please try logging in again.",
        )

    # Use constant-time comparison to prevent timing attacks
    # secrets.compare_digest requires both strings to be the same type and will handle length mismatches safely
    if not secrets.compare_digest(state, stored_state):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter. Possible CSRF attack detected. Please try logging in again.",
        )

    # Clear the state cookie immediately after successful validation (single-use token)
    response.delete_cookie(
        key="__Host-oauth_state",
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )

    try:
        # Step 1: Exchange authorization code for access token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                },
                timeout=10.0,
            )

            if token_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to exchange code for access token with GitHub.",
                )

            token_data = token_response.json()

            # Check for error in token response
            if "error" in token_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"GitHub token error: {token_data.get('error_description', token_data['error'])}",
                )

            access_token = token_data.get("access_token")
            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="No access token received from GitHub.",
                )

            # Step 2: Fetch user profile from GitHub
            user_response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
                timeout=10.0,
            )

            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to fetch user profile from GitHub.",
                )

            github_user = user_response.json()

            # Step 3: Fetch user emails from GitHub
            # GitHub email might be private, so we need to fetch from the emails endpoint
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
                timeout=10.0,
            )

            if emails_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to fetch user emails from GitHub.",
                )

            github_emails = emails_response.json()

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="GitHub API request timed out. Please try again.",
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to communicate with GitHub API: {str(e)}",
        )

    # Extract GitHub user information
    github_id = str(github_user.get("id"))
    github_username = github_user.get("login")
    github_avatar_url = github_user.get("avatar_url")

    # Find primary verified email
    primary_email = None
    for email_obj in github_emails:
        if email_obj.get("primary") and email_obj.get("verified"):
            primary_email = email_obj.get("email")
            break

    # If no primary verified email, try to find any verified email
    if not primary_email:
        for email_obj in github_emails:
            if email_obj.get("verified"):
                primary_email = email_obj.get("email")
                break

    # If still no email, use the public email from profile (might be None)
    if not primary_email:
        primary_email = github_user.get("email")

    if not primary_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No verified email found in GitHub account. Please add and verify an email address on GitHub.",
        )

    # Step 4: Find or create user in database
    # First, try to find user by GitHub ID
    stmt = select(User).where(User.github_id == github_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user:
        # Existing GitHub OAuth user - update their info
        user.github_username = github_username
        user.github_avatar_url = github_avatar_url
        user.email = primary_email  # Update email in case it changed on GitHub
        user.update_last_login()
    else:
        # Try to find user by email (they might have registered with email/password)
        stmt = select(User).where(User.email == primary_email)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user:
            # Link existing email/password account with GitHub
            user.github_id = github_id
            user.github_username = github_username
            user.github_avatar_url = github_avatar_url
            user.update_last_login()
        else:
            # Create new user with GitHub OAuth
            user = User(
                email=primary_email,
                github_id=github_id,
                github_username=github_username,
                github_avatar_url=github_avatar_url,
                password_hash=None,  # OAuth users don't have password
                tier="free",
                is_active=True,
                is_verified=True,  # GitHub emails are already verified
            )
            db.add(user)
            await db.flush()  # Get user.id without committing

            # Create default free license for new users
            free_license = License(
                user_id=user.id,
                tier="free",
                status="active",
            )
            db.add(free_license)

            user.update_last_login()

    # Step 5: Create JWT token and session (same as email login flow)
    token_data = {"sub": str(user.id), "email": user.email}
    access_token = create_access_token(token_data)

    # Create session record with hashed token for security
    new_session = Session(
        user_id=user.id,
        token=hash_token(access_token),
    )
    db.add(new_session)

    await db.commit()
    await db.refresh(user)

    return LoginResponse(
        user=UserResponse.model_validate(user),
        access_token=access_token,
        token_type="bearer",
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def logout(
    current_user: CurrentUser,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Logout and invalidate current session.

    Marks the current JWT token as inactive in the sessions table.

    Args:
        current_user: Currently authenticated user
        request: FastAPI request object
        db: Database session

    Returns:
        Empty 204 response

    Raises:
        HTTPException: If session not found
    """
    # Extract token from header
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")

    # Hash the token for database lookup (tokens are stored as SHA-256 hashes)
    token_hash = hash_token(token)

    # Invalidate session
    stmt = select(Session).where(
        Session.token == token_hash,
        Session.user_id == current_user.id,
    )
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()

    if session:
        session.invalidate()
        await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: CurrentUser) -> UserResponse:
    """Get current authenticated user information.

    Returns the current user's profile data.

    Args:
        current_user: Currently authenticated user

    Returns:
        UserResponse with current user data
    """
    return UserResponse.model_validate(current_user)


# Helper function for cleanup
async def cleanup_expired_codes(db: AsyncSession) -> int:
    """Delete expired device codes from the database.

    This function should be called periodically or before inserting new codes
    to keep the database clean.

    Args:
        db: Database session

    Returns:
        Number of expired codes deleted
    """
    now = datetime.now(timezone.utc)
    stmt = delete(DeviceCode).where(DeviceCode.expires_at < now)
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount


# Device Code Authentication Endpoints (OAuth 2.0 Device Authorization Grant - RFC 8628)


@router.post("/device/code", response_model=DeviceCodeResponse, status_code=status.HTTP_201_CREATED)
async def create_device_code(
    request: DeviceCodeRequest,
    db: AsyncSession = Depends(get_db),
) -> DeviceCodeResponse:
    """Initiate device code authentication flow.

    The CLI calls this endpoint to get a device_code (for polling) and
    a user_code (for the user to enter on the web app).

    Flow:
    1. CLI calls this endpoint with device info
    2. API generates device_code (32 chars) and user_code (8 chars, XXXX-XXXX format)
    3. API stores in device_codes table with 5-minute expiry
    4. API returns both codes and verification URL
    5. CLI displays user_code and verification_url to user
    6. CLI starts polling /device/token with device_code

    Args:
        request: Device information from CLI
        db: Database session

    Returns:
        DeviceCodeResponse with codes and verification URL

    Raises:
        HTTPException: If code generation fails
    """
    # Clean up expired codes (optional optimization)
    await cleanup_expired_codes(db)

    # Generate unique codes
    max_attempts = 10
    device_code = None
    user_code = None

    for _ in range(max_attempts):
        device_code = generate_device_code()
        user_code = generate_user_code()

        # Check if codes are unique
        stmt = select(DeviceCode).where(
            (DeviceCode.device_code == device_code) | (DeviceCode.user_code == user_code)
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        if not existing:
            break
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate unique device codes. Please try again.",
        )

    # Create device code record with 5-minute expiry (300 seconds)
    expiry_minutes = 5
    new_device_code = DeviceCode(
        device_code=device_code,
        user_code=user_code,
        device_info=request.device_info,
        status="pending",
        expires_at=DeviceCode.generate_expiration(minutes=expiry_minutes),
    )
    db.add(new_device_code)
    await db.commit()

    # Build verification URL
    verification_url = f"{settings.frontend_url}/device?code={user_code}"

    return DeviceCodeResponse(
        device_code=device_code,
        user_code=user_code,
        verification_url=verification_url,
        expires_in=expiry_minutes * 60,  # Convert to seconds
        interval=5,  # Recommend 5-second polling interval
    )


@router.post("/device/authorize", response_model=DeviceAuthorizeResponse)
async def authorize_device_code(
    request: DeviceAuthorizeRequest,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> DeviceAuthorizeResponse:
    """Authorize a device code after user authentication.

    This endpoint is called by the web app after the user:
    1. Logs in on the web
    2. Navigates to /device?code=XXXX-XXXX
    3. Confirms they want to authorize the device

    The web app must include the user's JWT token in the Authorization header.

    Args:
        request: Contains the user_code to authorize
        current_user: Authenticated user from JWT token
        db: Database session

    Returns:
        DeviceAuthorizeResponse with success status

    Raises:
        HTTPException: If user_code is invalid, expired, or already used
    """
    # Find device code by user_code
    stmt = select(DeviceCode).where(DeviceCode.user_code == request.user_code)
    result = await db.execute(stmt)
    device_code_record = result.scalar_one_or_none()

    if not device_code_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid device code. Please check the code and try again.",
        )

    # Check if expired
    if device_code_record.is_expired():
        device_code_record.mark_expired()
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code has expired. Please request a new code from your CLI.",
        )

    # Check if already authorized or denied
    if device_code_record.status == "authorized":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code has already been authorized.",
        )

    if device_code_record.status == "denied":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device code was denied. Please request a new code.",
        )

    # Authorize the device code
    device_code_record.authorize(current_user.id)
    await db.commit()

    return DeviceAuthorizeResponse(
        success=True,
        message="Device authorized successfully. You can now return to your CLI.",
        device_info=device_code_record.device_info,
    )


@router.post("/device/token", response_model=DeviceTokenResponse)
async def poll_device_token(
    request: DeviceTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> DeviceTokenResponse:
    """Poll for device code authorization status.

    The CLI calls this endpoint repeatedly (every 5 seconds) to check if
    the user has authorized the device code.

    Possible responses:
    - status='pending': User hasn't authorized yet, keep polling
    - status='authorized': User authorized, returns JWT token and user info
    - status='expired': Device code expired, need to start over
    - status='denied': User explicitly denied authorization

    Args:
        request: Contains device_code to check
        db: Database session

    Returns:
        DeviceTokenResponse with status and tokens (if authorized)

    Raises:
        HTTPException: If device_code is invalid
    """
    # Find device code
    stmt = select(DeviceCode).where(DeviceCode.device_code == request.device_code)
    result = await db.execute(stmt)
    device_code_record = result.scalar_one_or_none()

    if not device_code_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid device code.",
        )

    # Check if expired
    if device_code_record.is_expired():
        if device_code_record.status != "expired":
            device_code_record.mark_expired()
            await db.commit()
        return DeviceTokenResponse(status="expired")

    # Check status
    if device_code_record.status == "denied":
        return DeviceTokenResponse(status="denied")

    if device_code_record.status == "pending":
        return DeviceTokenResponse(status="pending")

    if device_code_record.status == "authorized" and device_code_record.user_id:
        # Get user information
        stmt = select(User).where(User.id == device_code_record.user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account not found or inactive.",
            )

        # Update user's last login
        user.update_last_login()

        # Ensure user has a quota record (handles legacy users created before quota system)
        token_service = TokenTrackingService(db)
        quota_info = await token_service.get_quota_info(user.id)
        if quota_info["tier"] == "unknown":
            await token_service.initialize_user_quota(
                user_id=user.id,
                tier=user.tier or "free",
                byok_enabled=False,
            )

        # Create JWT token
        token_data = {"sub": str(user.id), "email": user.email}
        access_token = create_access_token(token_data)

        # Create session record with hashed token for security
        new_session = Session(
            user_id=user.id,
            token=hash_token(access_token),
        )
        db.add(new_session)

        # Mark device code as used by deleting it (or you could keep it for audit)
        # For now, we'll keep it for audit trail but could delete it
        # await db.delete(device_code_record)

        await db.commit()

        return DeviceTokenResponse(
            status="authorized",
            access_token=access_token,
            refresh_token=None,  # Reserved for future use
            user_id=str(user.id),  # Convert to string for Go CLI compatibility
            email=user.email,
            tier=user.tier,
            token_type="bearer",
            expires_in=None,  # No expiry (until logout)
        )

    # Fallback for unexpected status
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Unexpected device code status.",
    )
