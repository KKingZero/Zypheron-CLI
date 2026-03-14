#!/usr/bin/env bash
# Zypheron API - Podman/Docker Compose helper script
# Usage: ./scripts/podman-up.sh [--profile tools|monitoring] [--build] [--down]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
API_DIR="$PROJECT_ROOT/zypheron-api"
ENV_FILE="$API_DIR/.env"
COMPOSE_FILE="$API_DIR/docker-compose.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Detect compose command (podman-compose or docker compose)
detect_compose() {
    if command -v podman-compose &>/dev/null; then
        echo "podman-compose"
    elif command -v docker &>/dev/null && docker compose version &>/dev/null; then
        echo "docker compose"
    elif command -v docker-compose &>/dev/null; then
        echo "docker-compose"
    else
        error "Neither podman-compose nor docker compose found."
        error "Install one of: podman-compose, docker compose, docker-compose"
        exit 1
    fi
}

# Validate .env file exists and has required variables
validate_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        warn ".env file not found at $ENV_FILE"
        info "Copying from .env.example..."
        if [[ -f "$API_DIR/.env.example" ]]; then
            cp "$API_DIR/.env.example" "$ENV_FILE"
            warn "Please edit $ENV_FILE with your configuration before running in production."
        else
            error "No .env.example found. Create $ENV_FILE manually."
            exit 1
        fi
    fi

    # Check critical variables
    local missing=0
    local required_vars=("JWT_SECRET_KEY")

    for var in "${required_vars[@]}"; do
        local val
        val=$(grep "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
        if [[ -z "$val" || "$val" == "GENERATE_A_SECURE_SECRET_HERE" ]]; then
            warn "  $var is not configured (or still default)."
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        warn "Some environment variables need attention. This is fine for local dev."
    else
        info "Environment validation passed."
    fi
}

# Parse arguments
ACTION="up"
PROFILES=()
BUILD_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILES+=("$2")
            shift 2
            ;;
        --build)
            BUILD_FLAG="--build"
            shift
            ;;
        --down)
            ACTION="down"
            shift
            ;;
        --logs)
            ACTION="logs"
            shift
            ;;
        --status)
            ACTION="status"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --profile <name>   Enable a compose profile (tools, monitoring)"
            echo "  --build            Force rebuild of containers"
            echo "  --down             Stop and remove containers"
            echo "  --logs             Tail container logs"
            echo "  --status           Show container status"
            echo "  -h, --help         Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                          # Start core services (api, postgres, redis)"
            echo "  $0 --profile tools          # Include pgAdmin"
            echo "  $0 --profile monitoring     # Include Prometheus"
            echo "  $0 --build                  # Rebuild and start"
            echo "  $0 --down                   # Stop all services"
            exit 0
            ;;
        *)
            error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

COMPOSE_CMD=$(detect_compose)
info "Using: $COMPOSE_CMD"

# Build profile flags
PROFILE_FLAGS=""
for p in "${PROFILES[@]+"${PROFILES[@]}"}"; do
    PROFILE_FLAGS="$PROFILE_FLAGS --profile $p"
done

cd "$API_DIR"

case "$ACTION" in
    up)
        validate_env
        info "Starting Zypheron services..."
        # shellcheck disable=SC2086
        $COMPOSE_CMD -f "$COMPOSE_FILE" $PROFILE_FLAGS up -d $BUILD_FLAG
        echo ""
        info "Services started. Checking health..."
        sleep 3
        $COMPOSE_CMD -f "$COMPOSE_FILE" ps
        echo ""
        info "API:      http://localhost:8000"
        info "Health:   http://localhost:8000/health"
        info "Metrics:  http://localhost:8000/metrics"
        if [[ " ${PROFILES[*]+"${PROFILES[*]}"} " == *" tools "* ]]; then
            info "pgAdmin:  http://localhost:5050"
        fi
        if [[ " ${PROFILES[*]+"${PROFILES[*]}"} " == *" monitoring "* ]]; then
            info "Prometheus: http://localhost:9090"
        fi
        ;;
    down)
        info "Stopping Zypheron services..."
        # shellcheck disable=SC2086
        $COMPOSE_CMD -f "$COMPOSE_FILE" $PROFILE_FLAGS down
        info "All services stopped."
        ;;
    logs)
        # shellcheck disable=SC2086
        $COMPOSE_CMD -f "$COMPOSE_FILE" $PROFILE_FLAGS logs -f --tail=100
        ;;
    status)
        $COMPOSE_CMD -f "$COMPOSE_FILE" ps
        ;;
esac
