#!/bin/bash
# Database Manager Script for Zypheron API
# Simplifies common database operations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}ℹ ${1}${NC}"
}

print_success() {
    echo -e "${GREEN}✓ ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ ${1}${NC}"
}

print_error() {
    echo -e "${RED}✗ ${1}${NC}"
}

print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  ${1}${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}\n"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
}

# Function to start PostgreSQL
start_postgres() {
    print_header "Starting PostgreSQL"
    check_docker

    cd "$PROJECT_DIR"
    docker-compose up -d postgres

    print_info "Waiting for PostgreSQL to be ready..."
    sleep 5

    if docker-compose ps postgres | grep -q "Up"; then
        print_success "PostgreSQL is running"
        print_info "Connection details:"
        echo "  Host: localhost"
        echo "  Port: 5432"
        echo "  User: zypheron"
        echo "  Password: zypheron_dev_password"
        echo "  Database: zypheron"
    else
        print_error "PostgreSQL failed to start"
        docker-compose logs postgres
        exit 1
    fi
}

# Function to stop PostgreSQL
stop_postgres() {
    print_header "Stopping PostgreSQL"
    cd "$PROJECT_DIR"
    docker-compose stop postgres
    print_success "PostgreSQL stopped"
}

# Function to start pgAdmin
start_pgadmin() {
    print_header "Starting pgAdmin"
    check_docker

    cd "$PROJECT_DIR"
    docker-compose --profile tools up -d pgadmin

    print_info "Waiting for pgAdmin to be ready..."
    sleep 5

    if docker-compose ps pgadmin | grep -q "Up"; then
        print_success "pgAdmin is running"
        print_info "Access pgAdmin at: http://localhost:5050"
        echo "  Email: admin@zypheron.local"
        echo "  Password: admin"
    else
        print_error "pgAdmin failed to start"
        exit 1
    fi
}

# Function to initialize database
init_db() {
    print_header "Initializing Database"
    cd "$PROJECT_DIR"

    if [ "$1" == "--drop" ]; then
        print_warning "This will DROP all existing tables!"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            print_info "Aborted"
            exit 0
        fi
        python scripts/init_db.py --drop
    else
        python scripts/init_db.py
    fi

    print_success "Database initialized"
}

# Function to switch to SQLite
switch_sqlite() {
    print_header "Switching to SQLite"
    cd "$PROJECT_DIR"

    # Update .env file
    if [ -f .env ]; then
        # Backup .env
        cp .env .env.backup
        print_info "Backed up .env to .env.backup"

        # Update DATABASE_TYPE
        if grep -q "^DATABASE_TYPE=" .env; then
            sed -i 's/^DATABASE_TYPE=.*/DATABASE_TYPE=sqlite/' .env
        else
            echo "DATABASE_TYPE=sqlite" >> .env
        fi

        print_success "Updated .env to use SQLite"
        print_info "Restart the API to apply changes"
    else
        print_error ".env file not found. Copy .env.example to .env first."
        exit 1
    fi
}

# Function to switch to PostgreSQL
switch_postgres() {
    print_header "Switching to PostgreSQL"
    cd "$PROJECT_DIR"

    # Update .env file
    if [ -f .env ]; then
        # Backup .env
        cp .env .env.backup
        print_info "Backed up .env to .env.backup"

        # Update DATABASE_TYPE
        if grep -q "^DATABASE_TYPE=" .env; then
            sed -i 's/^DATABASE_TYPE=.*/DATABASE_TYPE=postgresql/' .env
        else
            echo "DATABASE_TYPE=postgresql" >> .env
        fi

        # Ensure PostgreSQL settings are present
        if ! grep -q "^POSTGRES_HOST=" .env; then
            echo "POSTGRES_HOST=localhost" >> .env
            echo "POSTGRES_PORT=5432" >> .env
            echo "POSTGRES_USER=zypheron" >> .env
            echo "POSTGRES_PASSWORD=zypheron_dev_password" >> .env
            echo "POSTGRES_DB=zypheron" >> .env
        fi

        print_success "Updated .env to use PostgreSQL"
        print_info "Make sure PostgreSQL is running: ./scripts/db-manager.sh start"
        print_info "Then restart the API to apply changes"
    else
        print_error ".env file not found. Copy .env.example to .env first."
        exit 1
    fi
}

# Function to show database status
status() {
    print_header "Database Status"
    cd "$PROJECT_DIR"

    # Check .env DATABASE_TYPE
    if [ -f .env ]; then
        db_type=$(grep "^DATABASE_TYPE=" .env | cut -d= -f2)
        print_info "Configured database type: $db_type"
    else
        print_warning ".env file not found"
    fi

    # Check Docker services
    echo ""
    print_info "Docker services:"
    docker-compose ps
}

# Function to backup database
backup() {
    print_header "Backing Up Database"
    cd "$PROJECT_DIR"

    timestamp=$(date +%Y%m%d_%H%M%S)

    # Check which database type is configured
    db_type=$(grep "^DATABASE_TYPE=" .env | cut -d= -f2 || echo "sqlite")

    if [ "$db_type" == "sqlite" ]; then
        if [ -f zypheron.db ]; then
            backup_file="backups/zypheron_${timestamp}.db"
            mkdir -p backups
            cp zypheron.db "$backup_file"
            print_success "SQLite backup created: $backup_file"
        else
            print_warning "SQLite database file not found"
        fi
    else
        # PostgreSQL backup
        backup_file="backups/zypheron_${timestamp}.sql"
        mkdir -p backups
        docker exec zypheron-postgres pg_dump -U zypheron zypheron > "$backup_file"
        print_success "PostgreSQL backup created: $backup_file"
    fi
}

# Function to show help
show_help() {
    cat << EOF
Zypheron Database Manager

Usage: $0 <command>

Commands:
    start           Start PostgreSQL (Docker)
    stop            Stop PostgreSQL
    restart         Restart PostgreSQL
    pgadmin         Start pgAdmin (web UI for PostgreSQL)

    init            Initialize database (create tables)
    init --drop     Drop all tables and reinitialize (DESTRUCTIVE!)

    switch-sqlite   Switch to SQLite database
    switch-postgres Switch to PostgreSQL database

    status          Show current database status
    backup          Backup current database

    logs            Show PostgreSQL logs
    shell           Open PostgreSQL shell (psql)

    help            Show this help message

Examples:
    # Start PostgreSQL and initialize database
    $0 start
    $0 init

    # Switch to PostgreSQL
    $0 switch-postgres
    $0 start
    $0 init

    # Backup database
    $0 backup

    # View PostgreSQL logs
    $0 logs

EOF
}

# Main script
main() {
    case "$1" in
        start)
            start_postgres
            ;;
        stop)
            stop_postgres
            ;;
        restart)
            stop_postgres
            start_postgres
            ;;
        pgadmin)
            start_pgadmin
            ;;
        init)
            init_db "$2"
            ;;
        switch-sqlite)
            switch_sqlite
            ;;
        switch-postgres)
            switch_postgres
            ;;
        status)
            status
            ;;
        backup)
            backup
            ;;
        logs)
            cd "$PROJECT_DIR"
            docker-compose logs -f postgres
            ;;
        shell)
            print_info "Opening PostgreSQL shell..."
            docker exec -it zypheron-postgres psql -U zypheron -d zypheron
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
