# Zypheron API - Database Setup Guide

This guide covers setting up the database infrastructure for the Zypheron API, supporting both SQLite (development) and PostgreSQL (development/production).

## Quick Start

### Option 1: SQLite (Default - Easiest)

SQLite is the default database and requires no additional setup:

```bash
# Just run the API - SQLite database will be created automatically
python -m uvicorn app.main:app --reload
```

The database file `zypheron.db` will be created in the project root.

### Option 2: Local PostgreSQL (Docker)

For development with PostgreSQL (recommended for production-like environment):

```bash
# 1. Start PostgreSQL with Docker Compose
docker-compose up -d postgres

# 2. Update your .env file
DATABASE_TYPE=postgresql
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=zypheron
POSTGRES_PASSWORD=zypheron_dev_password
POSTGRES_DB=zypheron

# 3. Initialize the database
python scripts/init_db.py

# 4. Run the API
python -m uvicorn app.main:app --reload
```

### Option 3: Supabase (Production Cloud)

For production deployment with Supabase:

```bash
# 1. Create a project at https://app.supabase.com

# 2. Update your .env file with Supabase credentials
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
SUPABASE_KEY=your_anon_key
SUPABASE_SERVICE_KEY=your_service_role_key

# 3. Initialize the database
python scripts/init_db.py

# 4. Deploy and run
```

---

## Docker Compose Services

The `docker-compose.yml` provides several services:

### Core Services

**PostgreSQL** (always available):
```bash
docker-compose up -d postgres
```
- PostgreSQL 15 Alpine
- Port: 5432
- Persistent volume: `postgres_data`
- Health checks enabled

### Optional Services (Profiles)

**pgAdmin** (database management UI):
```bash
docker-compose --profile tools up -d pgadmin
```
- Access: http://localhost:5050
- Login: admin@zypheron.local / admin
- Useful for inspecting database schema and running queries

**Redis** (caching and rate limiting):
```bash
docker-compose --profile cache up -d redis
```
- Port: 6379
- Password: zypheron_redis_password
- Persistent volume: `redis_data`

**All services**:
```bash
docker-compose --profile tools --profile cache up -d
```

---

## Database Models

The following tables are created by SQLAlchemy:

### Core Tables

1. **users** - User accounts and authentication
   - Email/password and GitHub OAuth support
   - User metadata and status flags
   - Timestamps and activity fields

2. **devices** - Registered devices per user
   - Device fingerprinting
   - License assignment
   - Activation tracking

3. **device_codes** - OAuth 2.0 Device Authorization Grant
   - Device code flow for CLI authentication
   - User code for manual entry
   - Status tracking (pending, authorized, expired, denied)
   - Device metadata (JSONB in PostgreSQL)

4. **licenses** - Software licenses
   - License keys and types
   - Activation limits
   - Expiration tracking

5. **sessions** - Active user sessions
   - JWT token tracking
   - Device association
   - Session expiration

6. **token_usage** - AI token consumption tracking
   - Per-request token counts
   - Provider and model tracking
   - Usage accounting

7. **user_quota** - Usage quotas
   - Limit tracking
   - Reset tracking
   - Overage monitoring

---

## Database Configuration

### Environment Variables

All database configuration is done via environment variables in `.env`:

#### SQLite (Development)
```env
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

#### Local PostgreSQL (Docker)
```env
DATABASE_TYPE=postgresql
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=zypheron
POSTGRES_PASSWORD=zypheron_dev_password
POSTGRES_DB=zypheron
```

#### PostgreSQL URL Override
```env
DATABASE_TYPE=postgresql
POSTGRES_URL_OVERRIDE=postgresql+asyncpg://user:pass@host:5432/db
```

#### Supabase (Production)
```env
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Connection Pool Settings

PostgreSQL connections are pooled for optimal performance:

- **pool_size**: 10 connections
- **max_overflow**: 20 additional connections
- **pool_timeout**: 30 seconds
- **pool_recycle**: 3600 seconds (1 hour)
- **command_timeout**: 60 seconds
- **connection_timeout**: 10 seconds

These settings are optimized for production use and can be adjusted in `app/core/database.py`.

---

## Database Initialization

### Using the init_db.py Script

The initialization script creates all tables and verifies the setup:

```bash
# Create all tables
python scripts/init_db.py

# Drop existing tables and recreate (DESTRUCTIVE!)
python scripts/init_db.py --drop
```

The script will:
1. Display current database configuration
2. Create all tables from SQLAlchemy models
3. Verify that all expected tables exist
4. Report any issues

### Manual Initialization

You can also initialize the database programmatically:

```python
from app.core.database import init_db
import asyncio

asyncio.run(init_db())
```

Or via the API's startup event (already configured in `app/main.py`).

---

## PostgreSQL Extensions

The following PostgreSQL extensions are automatically enabled (see `scripts/init-db.sql`):

- **uuid-ossp**: UUID generation functions
- **pgcrypto**: Cryptographic functions
- **pg_trgm**: Fuzzy text search (for searching user codes, emails, etc.)

These extensions are only available in PostgreSQL (not SQLite).

---

## Database Migrations

### Current Approach

Currently using SQLAlchemy's `create_all()` for automatic table creation. This works well for development but has limitations:

- No migration history
- Cannot handle schema changes to existing tables
- All tables recreated on each deployment

### Future: Alembic Migrations

For production, consider using Alembic for proper database migrations:

```bash
# Install Alembic
pip install alembic

# Initialize Alembic
alembic init alembic

# Create a migration
alembic revision --autogenerate -m "Add device_codes table"

# Apply migrations
alembic upgrade head
```

This will provide:
- Version-controlled schema changes
- Rollback capability
- Safe production deployments
- Migration history tracking

---

## Switching Between Databases

You can easily switch between SQLite and PostgreSQL by changing the `DATABASE_TYPE` environment variable:

### SQLite → PostgreSQL

```bash
# 1. Start PostgreSQL
docker-compose up -d postgres

# 2. Update .env
DATABASE_TYPE=postgresql

# 3. Initialize PostgreSQL database
python scripts/init_db.py

# 4. Optional: Migrate data from SQLite
# (Manual process - export from SQLite, import to PostgreSQL)

# 5. Restart API
```

### PostgreSQL → SQLite

```bash
# 1. Update .env
DATABASE_TYPE=sqlite

# 2. Restart API (SQLite will be created automatically)
```

---

## Backup and Restore

### SQLite Backup

```bash
# Backup
cp zypheron.db zypheron.db.backup

# Restore
cp zypheron.db.backup zypheron.db
```

### PostgreSQL Backup (Docker)

```bash
# Backup
docker exec zypheron-postgres pg_dump -U zypheron zypheron > backup.sql

# Restore
docker exec -i zypheron-postgres psql -U zypheron zypheron < backup.sql
```

### Supabase Backup

Use Supabase dashboard or CLI:
```bash
# Using Supabase CLI
supabase db dump -f backup.sql
```

---

## Troubleshooting

### PostgreSQL Connection Issues

**Error: "connection refused"**
```bash
# Check if PostgreSQL is running
docker-compose ps

# View PostgreSQL logs
docker-compose logs postgres

# Restart PostgreSQL
docker-compose restart postgres
```

**Error: "authentication failed"**
- Verify credentials in `.env` match `docker-compose.yml`
- Default: user=zypheron, password=zypheron_dev_password

### Database Not Initialized

**Error: "relation 'users' does not exist"**
```bash
# Run initialization script
python scripts/init_db.py
```

### Port Conflicts

**Error: "port 5432 already in use"**
```bash
# Check what's using port 5432
sudo lsof -i :5432

# Option 1: Stop conflicting service
sudo systemctl stop postgresql

# Option 2: Change port in docker-compose.yml
ports:
  - "5433:5432"  # Use 5433 on host
```

### SQLite Permission Issues

**Error: "unable to open database file"**
```bash
# Check file permissions
ls -l zypheron.db

# Fix permissions
chmod 644 zypheron.db
```

---

## Performance Optimization

### PostgreSQL Tuning

For production deployments, consider tuning PostgreSQL settings:

```yaml
# docker-compose.yml
environment:
  POSTGRES_INITDB_ARGS: >-
    -c shared_buffers=256MB
    -c effective_cache_size=1GB
    -c maintenance_work_mem=64MB
    -c checkpoint_completion_target=0.9
    -c wal_buffers=16MB
    -c default_statistics_target=100
```

### Index Optimization

The models define indexes on frequently queried fields:
- User email, GitHub ID
- Device codes, user codes
- License keys
- Session tokens
- User IDs (foreign keys)

### Query Optimization

Use SQLAlchemy's eager loading to avoid N+1 queries:
```python
# Bad: N+1 queries
users = await session.execute(select(User))
for user in users.scalars():
    print(user.devices)  # Separate query for each user!

# Good: Single query with join
users = await session.execute(
    select(User).options(selectinload(User.devices))
)
```

---

## Security Considerations

### PostgreSQL Security

- **Never commit passwords**: Use `.env` file (in `.gitignore`)
- **Strong passwords**: Change default passwords in production
- **SSL/TLS**: Enable for production databases
- **Row Level Security**: Consider enabling RLS in Supabase
- **Firewall rules**: Restrict database access to known IPs

### SQLite Security

- **File permissions**: Ensure database file is not world-readable
- **Encryption**: Consider using SQLCipher for encrypted SQLite
- **Not for production**: SQLite is single-user and not suitable for production

### Connection String Security

Never log or expose database URLs:
```python
# Bad
print(f"Connecting to {db_url}")

# Good
print("Connecting to database...")
```

---

## Next Steps

1. **Set up Redis** for caching (optional but recommended)
2. **Configure Alembic** for production migrations
3. **Set up automated backups** for production database
4. **Enable monitoring** with tools like pganalyze or Datadog
5. **Implement connection pooling** with PgBouncer for high-traffic scenarios

---

## Resources

- [SQLAlchemy 2.0 Documentation](https://docs.sqlalchemy.org/en/20/)
- [asyncpg Documentation](https://magicstack.github.io/asyncpg/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Supabase Documentation](https://supabase.com/docs)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
