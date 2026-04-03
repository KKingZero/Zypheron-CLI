# Database

Zypheron API supports SQLite (default) and PostgreSQL (optional). SQLite requires no setup; PostgreSQL is recommended for production.

## SQLite (Default)

No setup required. The database file is created automatically on first run.

```bash
# .env
DATABASE_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///./zypheron.db
```

```bash
python -m uvicorn app.main:app --reload
```

### Backup / Restore

```bash
cp zypheron.db zypheron.db.backup
cp zypheron.db.backup zypheron.db
```

## PostgreSQL (Docker)

```bash
# Start PostgreSQL container
docker-compose up -d postgres

# Initialize tables
python scripts/init_db.py

# Start the API
python -m uvicorn app.main:app --reload
```

### Environment Variables

```bash
DATABASE_TYPE=postgresql
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=zypheron
POSTGRES_PASSWORD=zypheron_dev_password
POSTGRES_DB=zypheron
```

Or use a connection string override:

```bash
DATABASE_TYPE=postgresql
POSTGRES_URL_OVERRIDE=postgresql+asyncpg://user:pass@host:5432/db
```

### Supabase (Cloud)

```bash
DATABASE_TYPE=postgresql
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_KEY=your_anon_key
SUPABASE_SERVICE_KEY=your_service_key
```

Initialize with `python scripts/init_db.py`.

## Database Manager Script

```bash
./scripts/db-manager.sh start          # Start PostgreSQL
./scripts/db-manager.sh stop           # Stop PostgreSQL
./scripts/db-manager.sh restart        # Restart
./scripts/db-manager.sh init           # Initialize tables
./scripts/db-manager.sh init --drop    # Drop and recreate (DESTRUCTIVE)
./scripts/db-manager.sh switch-sqlite  # Switch to SQLite
./scripts/db-manager.sh switch-postgres # Switch to PostgreSQL
./scripts/db-manager.sh status         # Current status
./scripts/db-manager.sh backup         # Backup database
./scripts/db-manager.sh shell          # Open psql shell
./scripts/db-manager.sh pgadmin        # Start pgAdmin UI
./scripts/db-manager.sh logs           # View PostgreSQL logs
```

## Docker Compose Services

```bash
docker-compose up -d postgres                              # PostgreSQL only
docker-compose --profile tools up -d                       # + pgAdmin (localhost:5050)
docker-compose --profile cache up -d                       # + Redis
docker-compose --profile tools --profile cache up -d       # Everything
docker-compose down                                        # Stop all
docker-compose down -v                                     # Stop + remove volumes (DESTRUCTIVE)
```

## Migrating SQLite to PostgreSQL

### Option A: Fresh Start (Development)

```bash
cp zypheron.db backups/zypheron_backup_$(date +%Y%m%d).db
./scripts/db-manager.sh switch-postgres
./scripts/db-manager.sh start
./scripts/db-manager.sh init
```

### Option B: Data Migration (Production)

```bash
# 1. Backup SQLite
cp zypheron.db backups/zypheron_backup_$(date +%Y%m%d).db

# 2. Export data
sqlite3 zypheron.db .dump > sqlite_dump.sql

# 3. Switch and init PostgreSQL
./scripts/db-manager.sh switch-postgres
./scripts/db-manager.sh start
./scripts/db-manager.sh init

# 4. Run migration script (create scripts/migrate_sqlite_to_postgres.py)
python scripts/migrate_sqlite_to_postgres.py

# 5. Verify row counts
./scripts/db-manager.sh shell
```

### Rolling Back to SQLite

```bash
# Set DATABASE_TYPE=sqlite in .env and restart the API.
```

## Database Tables

| Table | Description |
|-------|-------------|
| `users` | User accounts (email/password + GitHub OAuth) |
| `devices` | Registered CLI devices per user |
| `device_codes` | OAuth 2.0 Device Authorization Grant codes |
| `licenses` | Software licenses and activation tracking |
| `sessions` | Active JWT sessions |
| `token_usage` | AI token consumption per request |
| `user_quota` | Monthly usage quotas |

## Python Usage

```python
# In a FastAPI route
from app.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

@app.get("/users")
async def get_users(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User))
    return result.scalars().all()

# Outside FastAPI
from app.core.database import get_db_context

async with get_db_context() as db:
    result = await db.execute(select(User))
```

## PostgreSQL Backup / Restore

```bash
# Backup
docker exec zypheron-postgres pg_dump -U zypheron zypheron > backup.sql

# Restore
docker exec -i zypheron-postgres psql -U zypheron zypheron < backup.sql
```

## Connection Pool Settings

| Setting | Value |
|---------|-------|
| `pool_size` | 10 |
| `max_overflow` | 20 |
| `pool_timeout` | 30s |
| `pool_recycle` | 3600s |

Adjust in `app/core/database.py` for high-traffic deployments.

## Useful psql Commands

```bash
./scripts/db-manager.sh shell
# or: docker exec -it zypheron-postgres psql -U zypheron -d zypheron

\dt                     # List tables
\d device_codes         # Describe table
\di                     # List indexes
\l                      # List databases
\q                      # Quit
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "connection refused" | `docker-compose ps` / `docker-compose restart postgres` |
| "authentication failed" | Check credentials in `.env` match `docker-compose.yml` |
| "relation does not exist" | Run `python scripts/init_db.py` |
| Port 5432 in use | `sudo lsof -i :5432` or change port in docker-compose.yml |
| SQLite permission error | `chmod 644 zypheron.db` |

## Key Files

- Models: `app/models/`
- Database config: `app/core/database.py`
- Settings: `app/core/config.py`
- Scripts: `scripts/init_db.py`, `scripts/validate_schema.py`, `scripts/db-manager.sh`
