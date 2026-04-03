# Database Quick Reference

Fast reference for common database operations in Zypheron API.

## Quick Start Commands

```bash
# SQLite (default - no setup needed)
python -m uvicorn app.main:app --reload

# PostgreSQL (Docker)
./scripts/db-manager.sh start
./scripts/db-manager.sh init
python -m uvicorn app.main:app --reload
```

## Database Manager Script

```bash
# Start/Stop PostgreSQL
./scripts/db-manager.sh start
./scripts/db-manager.sh stop
./scripts/db-manager.sh restart

# Initialize database
./scripts/db-manager.sh init
./scripts/db-manager.sh init --drop  # Drop all tables first

# Switch database type
./scripts/db-manager.sh switch-sqlite
./scripts/db-manager.sh switch-postgres

# Utilities
./scripts/db-manager.sh status      # Show current status
./scripts/db-manager.sh backup      # Backup database
./scripts/db-manager.sh logs        # View PostgreSQL logs
./scripts/db-manager.sh shell       # Open psql shell
./scripts/db-manager.sh pgadmin     # Start pgAdmin UI
```

## Environment Variables

```env
# SQLite (default)
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db

# Local PostgreSQL
DATABASE_TYPE=postgresql
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=zypheron
POSTGRES_PASSWORD=zypheron_dev_password
POSTGRES_DB=zypheron

# Supabase
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_KEY=your_service_key
```

## Docker Compose

```bash
# PostgreSQL only
docker-compose up -d postgres

# With pgAdmin
docker-compose --profile tools up -d

# With Redis
docker-compose --profile cache up -d

# Everything
docker-compose --profile tools --profile cache up -d

# View logs
docker-compose logs -f postgres

# Stop all
docker-compose down

# Stop and remove volumes (DESTRUCTIVE!)
docker-compose down -v
```

## Database Operations (Python)

```python
# Get database session (in FastAPI route)
from app.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

@app.get("/users")
async def get_users(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User))
    return result.scalars().all()

# Use context manager (outside FastAPI)
from app.core.database import get_db_context

async def some_function():
    async with get_db_context() as db:
        result = await db.execute(select(User))
        users = result.scalars().all()
    # Session automatically committed/closed

# Initialize database
from app.core.database import init_db
await init_db()  # Creates all tables

# Close connections
from app.core.database import close_db
await close_db()
```

## DeviceCode Model Usage

```python
from app.models import DeviceCode, User
from sqlalchemy import select
from datetime import datetime, timezone

# Create a device code
device_code = DeviceCode(
    device_code="random_device_code_abc123",
    user_code="ABC-DEF",
    device_info={
        "os": "Linux",
        "version": "1.0.0",
        "hardware_id": "unique-device-id"
    },
    status="pending",
    expires_at=DeviceCode.generate_expiration(10)  # 10 minutes
)
db.add(device_code)
await db.commit()

# Find by user code
result = await db.execute(
    select(DeviceCode).where(DeviceCode.user_code == "ABC-DEF")
)
device_code = result.scalar_one_or_none()

# Check status
if device_code and device_code.is_pending():
    print("Waiting for user authorization...")

# Authorize device
device_code.authorize(user_id=123)
await db.commit()

# Check expiration
if device_code.is_expired():
    device_code.mark_expired()
    await db.commit()

# Deny authorization
device_code.deny()
await db.commit()
```

## Common Queries

```python
from sqlalchemy import select, and_, or_

# Get all pending device codes
result = await db.execute(
    select(DeviceCode)
    .where(DeviceCode.status == "pending")
    .order_by(DeviceCode.created_at.desc())
)
pending_codes = result.scalars().all()

# Get device codes expiring soon
from datetime import timedelta
soon = datetime.now(timezone.utc) + timedelta(minutes=5)
result = await db.execute(
    select(DeviceCode)
    .where(
        and_(
            DeviceCode.status == "pending",
            DeviceCode.expires_at <= soon
        )
    )
)
expiring_codes = result.scalars().all()

# Get user with their device codes
result = await db.execute(
    select(User)
    .where(User.id == user_id)
    .options(selectinload(User.device_codes))
)
user = result.scalar_one_or_none()
if user:
    for code in user.device_codes:
        print(f"{code.user_code}: {code.status}")

# Clean up expired codes
from sqlalchemy import delete
await db.execute(
    delete(DeviceCode)
    .where(
        and_(
            DeviceCode.status == "pending",
            DeviceCode.expires_at < datetime.now(timezone.utc)
        )
    )
)
await db.commit()
```

## Validation & Testing

```bash
# Validate schema
python scripts/validate_schema.py

# Initialize database
python scripts/init_db.py

# Drop and recreate
python scripts/init_db.py --drop
```

## PostgreSQL Commands (psql)

```bash
# Open shell
./scripts/db-manager.sh shell
# or
docker exec -it zypheron-postgres psql -U zypheron -d zypheron

# Useful psql commands
\dt                    # List all tables
\d device_codes        # Describe device_codes table
\di                    # List indexes
\df                    # List functions
\l                     # List databases
\du                    # List users
\q                     # Quit

# SQL queries
SELECT * FROM device_codes WHERE status = 'pending';
SELECT COUNT(*) FROM users;
SELECT user_code, status, expires_at FROM device_codes ORDER BY created_at DESC LIMIT 10;
```

## Backup & Restore

```bash
# Backup (using script)
./scripts/db-manager.sh backup

# Manual SQLite backup
cp zypheron.db backups/zypheron_$(date +%Y%m%d).db

# Manual PostgreSQL backup
docker exec zypheron-postgres pg_dump -U zypheron zypheron > backup.sql

# Restore PostgreSQL
docker exec -i zypheron-postgres psql -U zypheron zypheron < backup.sql
```

## Troubleshooting

```bash
# Check database status
./scripts/db-manager.sh status

# View PostgreSQL logs
./scripts/db-manager.sh logs

# Restart PostgreSQL
./scripts/db-manager.sh restart

# Verify schema
python scripts/validate_schema.py

# Reinitialize database (DESTRUCTIVE!)
./scripts/db-manager.sh init --drop

# Check for port conflicts
sudo lsof -i :5432

# Fix SQLite permissions
chmod 644 zypheron.db
```

## Performance Tips

```python
# Use eager loading to avoid N+1 queries
from sqlalchemy.orm import selectinload

result = await db.execute(
    select(User).options(
        selectinload(User.devices),
        selectinload(User.device_codes),
        selectinload(User.licenses)
    )
)

# Use indexes for filtering
# Indexes are automatically created on:
# - Primary keys (id)
# - Unique fields (device_code, user_code, email)
# - Foreign keys (user_id)
# - Status fields (status)

# Batch operations
from sqlalchemy import update

await db.execute(
    update(DeviceCode)
    .where(DeviceCode.expires_at < datetime.now(timezone.utc))
    .values(status="expired")
)

# Use connection pooling (already configured)
# pool_size=10, max_overflow=20
```

## Migration Path to Alembic

```bash
# Install Alembic
pip install alembic

# Initialize
alembic init alembic

# Configure alembic.ini
# Edit: sqlalchemy.url = postgresql+asyncpg://...

# Create migration
alembic revision --autogenerate -m "Initial schema"

# Apply migration
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Resources

- Full guide: `DATABASE_SETUP.md`
- Models: `app/models/`
- Config: `app/core/config.py`
- Database: `app/core/database.py`
- Scripts: `scripts/`
