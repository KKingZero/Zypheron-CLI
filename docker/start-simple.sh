#!/bin/bash

echo "🐍 Starting COBRA AI Core Services..."

# Create log directories
mkdir -p /var/log/supervisor

# Initialize database schema if needed
echo "📊 Core services ready to start..."

# Start supervisor to manage all processes
echo "🚀 Starting core services with supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf 