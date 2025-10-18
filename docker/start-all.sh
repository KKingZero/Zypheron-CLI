#!/bin/bash

echo "🐍 Starting COBRA AI All-in-One Container..."

# Create log directories
mkdir -p /var/log/supervisor

# Initialize database schema if needed
echo "📊 Checking database connection..."
if [ ! -z "$DATABASE_URL" ]; then
    echo "Database configured: $DATABASE_URL"
fi

# Start supervisor to manage all processes
echo "🚀 Starting all services with supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf 