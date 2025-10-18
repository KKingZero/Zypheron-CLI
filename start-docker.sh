#!/bin/bash

echo "====================================================="
echo "     🐍 COBRA AI - Docker Setup                    "
echo "====================================================="
echo

# Check if docker is available
if ! command -v docker >/dev/null 2>&1; then
  echo "❌ Docker is not installed or not in PATH"
  echo "Install Docker: https://docs.docker.com/engine/install/"
  exit 1
fi

# Check if docker daemon is running
if ! docker info >/dev/null 2>&1; then
  echo "❌ Docker daemon is not running"
  exit 1
fi

echo "🔧 Stopping any existing containers..."
docker compose down --remove-orphans || docker-compose down --remove-orphans

echo
echo "🚀 Starting COBRA AI services..."
echo "This may take several minutes on first run (downloading/building images)"
echo

# Prefer docker compose v2; fallback to v1
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose up --build -d
else
  docker-compose up --build -d
fi

if [ $? -ne 0 ]; then
  echo
  echo "❌ Failed to start services!"
  echo "Check the error messages above."
  exit 1
fi

echo
echo "⏳ Waiting for services to start..."
sleep 30

echo
echo "✅ COBRA AI is starting up!"
echo
echo "📍 Access Points:"
echo "  🌐 Frontend: http://localhost"
echo "  🔧 Backend API: http://localhost:3001"
echo "  📊 OSINT Service: http://localhost:8001"
echo "  🔍 Scanner Service: http://localhost:8002"
echo "  📦 Packet Service: http://localhost:8003"
echo "  🕷️  Crawler Service: http://localhost:8004"
echo "  🛡️  Vulnerability Scanner: http://localhost:8005"
echo "  🗄️  Database: localhost:5432"
echo
echo "🎯 To stop all services, run: docker compose down (or docker-compose down)"
echo

