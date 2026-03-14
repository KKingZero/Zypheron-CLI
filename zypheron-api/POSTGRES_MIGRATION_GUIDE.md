# PostgreSQL Migration Guide

This guide helps you migrate from SQLite to PostgreSQL or set up PostgreSQL for a new installation.

## Table of Contents

1. [New Installation (PostgreSQL from start)](#new-installation-postgresql)
2. [Migrating from SQLite to PostgreSQL](#migrating-sqlite-to-postgresql)
3. [Rollback to SQLite](#rollback-to-sqlite)
4. [Production Deployment](#production-deployment)

---

## New Installation (PostgreSQL)

If you're starting fresh with PostgreSQL:

### Step 1: Start PostgreSQL

```bash
# Start PostgreSQL container
cd zypheron-api
docker-compose up -d postgres

# Verify it's running
docker-compose ps postgres
```

### Step 2: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env and set:
DATABASE_TYPE=postgresql
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=zypheron
POSTGRES_PASSWORD=zypheron_dev_password
POSTGRES_DB=zypheron
```

Or use the helper script:

```bash
./scripts/db-manager.sh switch-postgres
```

### Step 3: Initialize Database

```bash
# Initialize all tables
./scripts/db-manager.sh init

# Or manually:
source .venv/bin/activate
python scripts/init_db.py
```

### Step 4: Verify Setup

```bash
# Validate schema
source .venv/bin/activate
python scripts/validate_schema.py

# Or check with psql
./scripts/db-manager.sh shell
\dt  # List tables
\q   # Quit
```

### Step 5: Start API

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --reload
```

Done! Your API is now running on PostgreSQL.

---

## Migrating SQLite to PostgreSQL

### Prerequisites

- Existing SQLite database (`zypheron.db`)
- Docker installed
- No active API server

### Migration Strategy

There are two approaches:

#### Option A: Fresh Start (Recommended for Development)

**Pros:** Clean, simple, no data migration needed
**Cons:** Loses existing data

```bash
# 1. Backup SQLite (just in case)
cp zypheron.db backups/zypheron_backup_$(date +%Y%m%d).db

# 2. Switch to PostgreSQL
./scripts/db-manager.sh switch-postgres

# 3. Start PostgreSQL
./scripts/db-manager.sh start

# 4. Initialize database
./scripts/db-manager.sh init

# 5. Start API
source .venv/bin/activate
python -m uvicorn app.main:app --reload
```

Note: You'll need to recreate users, licenses, etc.

#### Option B: Data Migration (For Production)

**Pros:** Preserves all data
**Cons:** More complex, requires migration script

**Step 1: Backup SQLite**

```bash
cp zypheron.db backups/zypheron_backup_$(date +%Y%m%d).db
```

**Step 2: Export SQLite Data**

```bash
# Install sqlite3 if not available
sudo apt-get install sqlite3  # Ubuntu/Debian
# or
brew install sqlite3  # macOS

# Export data to SQL
sqlite3 zypheron.db .dump > sqlite_dump.sql
```

**Step 3: Start PostgreSQL**

```bash
./scripts/db-manager.sh start
```

**Step 4: Create Migration Script**

Create `scripts/migrate_sqlite_to_postgres.py`:

```python
#!/usr/bin/env python3
"""Migrate data from SQLite to PostgreSQL."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.models import User, Device, License, Session, TokenUsage, UserQuota


async def migrate():
    """Migrate data from SQLite to PostgreSQL."""
    # SQLite source
    sqlite_engine = create_async_engine("sqlite+aiosqlite:///./zypheron.db")

    # PostgreSQL target (update with your credentials)
    postgres_engine = create_async_engine(
        "postgresql+asyncpg://zypheron:zypheron_dev_password@localhost:5432/zypheron"
    )

    # Create sessions
    sqlite_session_maker = sessionmaker(
        sqlite_engine, class_=AsyncSession, expire_on_commit=False
    )
    postgres_session_maker = sessionmaker(
        postgres_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with sqlite_session_maker() as src_db, postgres_session_maker() as dst_db:
        # Migrate users
        print("Migrating users...")
        result = await src_db.execute(select(User))
        users = result.scalars().all()
        for user in users:
            dst_db.add(user)
        await dst_db.commit()
        print(f"  ✓ Migrated {len(users)} users")

        # Migrate devices
        print("Migrating devices...")
        result = await src_db.execute(select(Device))
        devices = result.scalars().all()
        for device in devices:
            dst_db.add(device)
        await dst_db.commit()
        print(f"  ✓ Migrated {len(devices)} devices")

        # Migrate licenses
        print("Migrating licenses...")
        result = await src_db.execute(select(License))
        licenses = result.scalars().all()
        for license in licenses:
            dst_db.add(license)
        await dst_db.commit()
        print(f"  ✓ Migrated {len(licenses)} licenses")

        # Add other models as needed...

    print("\n✓ Migration completed!")


if __name__ == "__main__":
    asyncio.run(migrate())
```

**Step 5: Run Migration**

```bash
# Switch to PostgreSQL
./scripts/db-manager.sh switch-postgres

# Initialize PostgreSQL tables
./scripts/db-manager.sh init

# Run migration
source .venv/bin/activate
python scripts/migrate_sqlite_to_postgres.py
```

**Step 6: Verify Migration**

```bash
# Check row counts
./scripts/db-manager.sh shell

SELECT 'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 'devices', COUNT(*) FROM devices
UNION ALL
SELECT 'licenses', COUNT(*) FROM licenses;

\q
```

**Step 7: Test API**

```bash
source .venv/bin/activate
python -m uvicorn app.main:app --reload

# Test authentication, device registration, etc.
```

**Step 8: Keep SQLite as Backup**

```bash
# Move SQLite to backup
mv zypheron.db backups/zypheron_pre_postgres_$(date +%Y%m%d).db
```

---

## Rollback to SQLite

If you need to go back to SQLite:

### Quick Rollback

```bash
# 1. Stop API if running
pkill -f uvicorn

# 2. Switch to SQLite
./scripts/db-manager.sh switch-sqlite

# 3. Restore backup (if needed)
cp backups/zypheron_backup_YYYYMMDD.db zypheron.db

# 4. Stop PostgreSQL
./scripts/db-manager.sh stop

# 5. Restart API
source .venv/bin/activate
python -m uvicorn app.main:app --reload
```

### Keep PostgreSQL Running

You can keep PostgreSQL running and still use SQLite:

```bash
# Just switch the database type in .env
DATABASE_TYPE=sqlite
```

The API will use SQLite while PostgreSQL keeps running in the background.

---

## Production Deployment

### Supabase Setup

1. **Create Supabase Project**
   - Go to https://app.supabase.com
   - Create new project
   - Wait for provisioning (~2 minutes)

2. **Get Credentials**
   - Project Settings → API
   - Copy:
     - Project URL (SUPABASE_URL)
     - anon/public key (SUPABASE_KEY)
     - service_role key (SUPABASE_SERVICE_KEY)

3. **Configure Environment**

```bash
# Production .env
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Important: Set strong JWT secret
JWT_SECRET_KEY=your-super-secret-key-change-this
```

4. **Initialize Database**

```bash
# Run locally or in CI/CD
python scripts/init_db.py
```

5. **Enable Row Level Security (Optional)**

In Supabase dashboard:
- Go to Table Editor
- Select each table
- Enable RLS
- Add policies as needed

### Self-Hosted PostgreSQL

For self-hosted production PostgreSQL:

1. **Configure Connection**

```bash
# Option 1: Individual settings
DATABASE_TYPE=postgresql
POSTGRES_HOST=your-postgres-host.com
POSTGRES_PORT=5432
POSTGRES_USER=zypheron
POSTGRES_PASSWORD=very-strong-password
POSTGRES_DB=zypheron

# Option 2: Connection string override
DATABASE_TYPE=postgresql
POSTGRES_URL_OVERRIDE=postgresql+asyncpg://user:pass@host:5432/db?ssl=require
```

2. **Enable SSL**

For production, always use SSL:

```python
# In your connection string:
postgresql+asyncpg://user:pass@host:5432/db?ssl=require

# Or configure in database.py:
connect_args={
    "ssl": "require",
    # Or with certificate validation:
    "ssl": {
        "ca": "/path/to/ca-cert.pem"
    }
}
```

3. **Connection Pooling**

For high traffic, consider PgBouncer:

```yaml
# docker-compose.yml
pgbouncer:
  image: pgbouncer/pgbouncer
  environment:
    DATABASES_HOST: postgres
    DATABASES_PORT: 5432
    DATABASES_USER: zypheron
    DATABASES_PASSWORD: password
    DATABASES_DBNAME: zypheron
    PGBOUNCER_POOL_MODE: transaction
    PGBOUNCER_MAX_CLIENT_CONN: 1000
    PGBOUNCER_DEFAULT_POOL_SIZE: 20
  ports:
    - "6432:6432"
```

Then connect via PgBouncer:
```
POSTGRES_HOST=pgbouncer
POSTGRES_PORT=6432
```

---

## Troubleshooting

### Migration Issues

**Problem: Foreign key constraint errors**

```sql
-- Disable foreign key checks during migration
SET session_replication_role = 'replica';

-- Run migration

-- Re-enable
SET session_replication_role = 'origin';
```

**Problem: Different SQLite and PostgreSQL syntax**

Some SQLite features don't work in PostgreSQL:
- `AUTOINCREMENT` → `SERIAL` or `IDENTITY`
- JSON stored as text → `JSONB` type
- Date/time formatting differences

Solution: Let SQLAlchemy handle it (already done in models).

### Performance Issues After Migration

**Problem: Slow queries**

```sql
-- Check missing indexes
SELECT schemaname, tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public';

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM device_codes WHERE user_code = 'ABC-DEF';
```

**Problem: Connection pool exhausted**

Increase pool size in `database.py`:
```python
pool_size=20,      # Instead of 10
max_overflow=40,   # Instead of 20
```

### Data Integrity Checks

```sql
-- Check for orphaned records
SELECT COUNT(*) FROM device_codes WHERE user_id NOT IN (SELECT id FROM users);

-- Check for duplicates
SELECT user_code, COUNT(*) FROM device_codes GROUP BY user_code HAVING COUNT(*) > 1;

-- Verify foreign keys
SELECT
    tc.table_name,
    kcu.column_name,
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name
FROM information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
    ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
    ON ccu.constraint_name = tc.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY';
```

---

## Best Practices

### Development

1. **Use SQLite for quick local development**
   - Fast setup
   - No dependencies
   - Easy to reset

2. **Use PostgreSQL for production-like testing**
   - Test migrations
   - Verify performance
   - Check PostgreSQL-specific features

### Production

1. **Always use PostgreSQL**
   - Better concurrency
   - Advanced features
   - Scalability

2. **Enable automated backups**
   ```bash
   # Cron job: Daily backup at 2 AM
   0 2 * * * /path/to/scripts/db-manager.sh backup
   ```

3. **Monitor database health**
   - Connection pool usage
   - Query performance
   - Disk space
   - Replication lag (if applicable)

4. **Use connection pooling**
   - Already configured in `database.py`
   - Consider PgBouncer for very high traffic

5. **Implement proper error handling**
   - Already done in `database.py`
   - Automatic rollback on errors
   - Connection health checks

---

## Next Steps

After successful migration:

1. ✓ Verify all data migrated correctly
2. ✓ Test all API endpoints
3. ✓ Update deployment scripts
4. ✓ Configure automated backups
5. ✓ Set up monitoring
6. ✓ Document any custom configuration
7. ✓ Train team on new database
8. ✓ Update README with production setup

---

## Resources

- [DATABASE_SETUP.md](./DATABASE_SETUP.md) - Full setup guide
- [DATABASE_QUICK_REF.md](./DATABASE_QUICK_REF.md) - Quick reference
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Supabase Documentation](https://supabase.com/docs)
- [SQLAlchemy Migration Guide](https://docs.sqlalchemy.org/en/20/changelog/migration_20.html)
