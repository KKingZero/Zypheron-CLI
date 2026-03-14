-- Zypheron Database Initialization Script
-- This script is executed when PostgreSQL container starts for the first time
-- It sets up extensions and optimizations for the Zypheron database

-- Enable UUID extension (useful for generating unique identifiers)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto for cryptographic functions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enable pg_trgm for fuzzy text search (useful for searching user codes, emails, etc.)
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create indexes will be handled by SQLAlchemy migrations
-- This file only sets up extensions and database-level configurations

-- Set default timezone to UTC
ALTER DATABASE zypheron SET timezone TO 'UTC';

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'Zypheron database initialized successfully';
    RAISE NOTICE 'Extensions enabled: uuid-ossp, pgcrypto, pg_trgm';
    RAISE NOTICE 'Default timezone: UTC';
END $$;
