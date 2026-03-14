#!/bin/bash
# Zypheron API Development Server Runner

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}===========================================${NC}"
echo -e "${BLUE}   Zypheron API Development Server${NC}"
echo -e "${BLUE}===========================================${NC}"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${RED}Error: .env file not found${NC}"
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo -e "${GREEN}Created .env file. Please configure it before running.${NC}"
    echo "Edit .env and set at minimum:"
    echo "  - JWT_SECRET_KEY (use: openssl rand -hex 32)"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d ".venv" ] && [ ! -d "venv" ]; then
    echo -e "${RED}Warning: No virtual environment found${NC}"
    echo "Consider creating one with: python -m venv .venv"
    echo ""
fi

# Check if dependencies are installed
if ! python -c "import fastapi" 2>/dev/null; then
    echo -e "${RED}Error: Dependencies not installed${NC}"
    echo "Install with: pip install -r requirements.txt"
    echo "Or with Poetry: poetry install"
    exit 1
fi

# Run the server
echo -e "${GREEN}Starting Zypheron API...${NC}"
echo ""
echo -e "API Docs: ${BLUE}http://localhost:8000/docs${NC}"
echo -e "ReDoc: ${BLUE}http://localhost:8000/redoc${NC}"
echo -e "Health: ${BLUE}http://localhost:8000/health${NC}"
echo ""

# Use uvicorn with auto-reload for development
exec uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
