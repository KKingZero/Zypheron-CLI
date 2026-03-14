# PostgreSQL Infrastructure - Phase 1 Complete

## Overview

Phase 1 of the Zypheron API database infrastructure is now complete. The API supports both SQLite (for easy development) and PostgreSQL (for production deployment), with seamless switching between the two.

## What's New

### Database Support

- **SQLite**: Default, no setup required
- **Local PostgreSQL**: Docker-based, production-like environment
- **Supabase**: Cloud PostgreSQL for production
- **Custom PostgreSQL**: Support for any PostgreSQL instance

### New DeviceCode Model

OAuth 2.0 Device Authorization Grant (RFC 8628) implementation:

```python
device_code = DeviceCode(
    device_code="secret_device_code",
    user_code="ABC-DEF",  # User-friendly code
    device_info={"os": "Linux", "version": "1.0.0"},
    status="pending",
    expires_at=DeviceCode.generate_expiration(10)
)
```

### Management Tools

- `./scripts/db-manager.sh` - Complete database management CLI
- `./scripts/init_db.py` - Database initialization
- `./scripts/validate_schema.py` - Schema validation
- `docker-compose.yml` - PostgreSQL + pgAdmin + Redis

## Quick Start

### Option 1: SQLite (Default)

```bash
# No setup needed
python -m uvicorn app.main:app --reload
```

### Option 2: PostgreSQL (Recommended)

```bash
# Start PostgreSQL
./scripts/db-manager.sh start

# Initialize database
./scripts/db-manager.sh init

# Run API
python -m uvicorn app.main:app --reload
```

## Documentation

Choose your guide:

### 📚 Full Documentation

- **[DATABASE_SETUP.md](./DATABASE_SETUP.md)** - Comprehensive setup guide (400+ lines)
  - All database options
  - Configuration details
  - Performance tuning
  - Security best practices
  - Troubleshooting

### ⚡ Quick Reference

- **[DATABASE_QUICK_REF.md](./DATABASE_QUICK_REF.md)** - Fast reference
  - Common commands
  - Code snippets
  - Quick troubleshooting
  - One-liner solutions

### 🔄 Migration Guide

- **[POSTGRES_MIGRATION_GUIDE.md](./POSTGRES_MIGRATION_GUIDE.md)** - Migration help
  - SQLite → PostgreSQL migration
  - Production deployment
  - Rollback procedures
  - Data migration scripts

### 📊 Implementation Summary

- **[PHASE1_IMPLEMENTATION_SUMMARY.md](./PHASE1_IMPLEMENTATION_SUMMARY.md)** - Complete details
  - What was implemented
  - Files created/modified
  - Testing results
  - Next steps

## Common Tasks

### Database Management

```bash
# Start/Stop PostgreSQL
./scripts/db-manager.sh start
./scripts/db-manager.sh stop

# Switch database type
./scripts/db-manager.sh switch-sqlite
./scripts/db-manager.sh switch-postgres

# Initialize/Reset database
./scripts/db-manager.sh init
./scripts/db-manager.sh init --drop  # DESTRUCTIVE!

# Utilities
./scripts/db-manager.sh status   # Check status
./scripts/db-manager.sh backup   # Backup database
./scripts/db-manager.sh shell    # Open psql
./scripts/db-manager.sh pgadmin  # Start web UI
```

### Docker Services

```bash
# PostgreSQL only
docker-compose up -d postgres

# With pgAdmin (http://localhost:5050)
docker-compose --profile tools up -d

# With Redis
docker-compose --profile cache up -d

# Everything
docker-compose --profile tools --profile cache up -d

# Stop all
docker-compose down
```

### Validation

```bash
# Validate schema
python scripts/validate_schema.py

# Check database structure
./scripts/db-manager.sh shell
\dt  # List tables
\d device_codes  # Describe table
```

## Environment Configuration

### SQLite (Default)

```env
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

### Local PostgreSQL

```env
DATABASE_TYPE=postgresql
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=zypheron
POSTGRES_PASSWORD=zypheron_dev_password
POSTGRES_DB=zypheron
```

### Supabase (Production)

```env
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_KEY=your_service_key
```

## Database Schema

### New Table: device_codes

```sql
CREATE TABLE device_codes (
    id INTEGER PRIMARY KEY,
    device_code VARCHAR(255) UNIQUE NOT NULL,
    user_code VARCHAR(20) UNIQUE NOT NULL,
    device_info JSON,
    user_id INTEGER REFERENCES users(id),
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    authorized_at TIMESTAMP WITH TIME ZONE
);
```

Indexes on: device_code, user_code, user_id, status, expires_at

### All Tables

1. `users` - User accounts
2. `devices` - Registered devices
3. `device_codes` - OAuth device codes (NEW)
4. `licenses` - Software licenses
5. `sessions` - Active sessions
6. `token_usage` - AI token tracking
7. `user_quota` - Monthly quotas

## DeviceCode Usage

```python
from app.models import DeviceCode
from sqlalchemy import select

# Create device code
code = DeviceCode(
    device_code="dc_abc123",
    user_code="ABC-DEF",
    device_info={"os": "Linux"},
    status="pending",
    expires_at=DeviceCode.generate_expiration(10)
)
db.add(code)
await db.commit()

# Find by user code
result = await db.execute(
    select(DeviceCode).where(DeviceCode.user_code == "ABC-DEF")
)
code = result.scalar_one_or_none()

# Check status
if code and code.is_pending():
    # Authorize
    code.authorize(user_id=123)
    await db.commit()

# Helper methods
code.is_pending()      # Check if waiting
code.is_expired()      # Check expiration
code.is_authorized()   # Check authorization
code.authorize(123)    # Authorize device
code.deny()            # Deny authorization
code.mark_expired()    # Mark expired
```

## Production Deployment

### Supabase

```bash
# 1. Create project at https://app.supabase.com
# 2. Get credentials from Project Settings → API
# 3. Configure .env with credentials
# 4. Initialize database
python scripts/init_db.py
```

### Self-Hosted PostgreSQL

```bash
# 1. Set up PostgreSQL server
# 2. Configure connection in .env
# 3. Initialize database
python scripts/init_db.py
```

### Docker Production

```bash
# Use docker-compose in production
docker-compose -f docker-compose.prod.yml up -d
```

## Monitoring

### Connection Pool

```python
from app.core.database import engine

# Check pool status
print(engine.pool.status())
```

### Database Metrics

```sql
-- Active connections
SELECT count(*) FROM pg_stat_activity;

-- Table sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Query performance
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
```

## Troubleshooting

### PostgreSQL Won't Start

```bash
# Check Docker
docker ps

# View logs
./scripts/db-manager.sh logs

# Restart
./scripts/db-manager.sh restart
```

### Connection Failed

```bash
# Check credentials in .env
cat .env | grep POSTGRES

# Test connection
./scripts/db-manager.sh shell
```

### Tables Not Created

```bash
# Run initialization
./scripts/db-manager.sh init

# Or with Python
python scripts/init_db.py
```

### Performance Issues

```python
# In database.py, increase pool size:
pool_size=20,        # from 10
max_overflow=40,     # from 20
```

## Security

### Production Checklist

- [ ] Change default passwords
- [ ] Use strong JWT secret
- [ ] Enable SSL/TLS for database
- [ ] Restrict database access by IP
- [ ] Enable Row Level Security (Supabase)
- [ ] Regular backups
- [ ] Monitor for suspicious activity

### Secure Passwords

```bash
# Generate secure password
openssl rand -base64 32

# Update in .env
POSTGRES_PASSWORD=your-secure-password
JWT_SECRET_KEY=your-secure-jwt-secret
```

## Backup & Restore

### Automatic Backups

```bash
# Manual backup
./scripts/db-manager.sh backup

# Automated (cron)
0 2 * * * /path/to/scripts/db-manager.sh backup
```

### Restore

```bash
# SQLite
cp backups/zypheron_YYYYMMDD.db zypheron.db

# PostgreSQL
docker exec -i zypheron-postgres psql -U zypheron zypheron < backup.sql
```

## Performance Tuning

### Connection Pooling

Already configured with optimal settings:
- Pool size: 10
- Max overflow: 20
- Pool timeout: 30s
- Connection recycling: 1 hour

### Query Optimization

```python
# Use eager loading
from sqlalchemy.orm import selectinload

result = await db.execute(
    select(User).options(selectinload(User.device_codes))
)
```

### Indexes

All critical fields are indexed:
- Primary keys
- Foreign keys
- Unique constraints
- Status fields
- Search fields

## Next Steps

### Phase 2: Device Code API

1. Device code generation endpoint
2. User authorization endpoint
3. Device polling endpoint
4. Device code validation
5. Token issuance

### Future Enhancements

- [ ] Alembic migrations
- [ ] Read replicas
- [ ] PgBouncer for connection pooling
- [ ] Database monitoring (Datadog, New Relic)
- [ ] Automated backups
- [ ] Point-in-time recovery

## Support

### Issues

If you encounter issues:

1. Check [DATABASE_SETUP.md](./DATABASE_SETUP.md) troubleshooting
2. Validate schema: `python scripts/validate_schema.py`
3. Check logs: `./scripts/db-manager.sh logs`
4. Verify status: `./scripts/db-manager.sh status`

### Resources

- **PostgreSQL Docs**: https://www.postgresql.org/docs/
- **Supabase Docs**: https://supabase.com/docs
- **SQLAlchemy Docs**: https://docs.sqlalchemy.org/
- **asyncpg Docs**: https://magicstack.github.io/asyncpg/

## Summary

✅ **Phase 1 Complete**

- PostgreSQL support implemented
- DeviceCode model created and validated
- Comprehensive tooling and documentation
- Production-ready infrastructure
- Easy switching between SQLite and PostgreSQL
- Docker containerization
- Schema validation passing
- Migration guides available

Ready for Phase 2: Device Code API Implementation!
