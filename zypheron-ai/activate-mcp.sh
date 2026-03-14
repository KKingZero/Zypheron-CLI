#!/bin/bash
#
# Zypheron MCP Virtual Environment Activation Script
#
# This script activates the virtual environment and provides instructions
# for running the MCP server.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/mcp-venv"

echo "🔴 Zypheron MCP Interface"
echo "========================="
echo ""

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    echo "❌ Virtual environment not found at: $VENV_DIR"
    echo ""
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    
    echo "Installing dependencies..."
    source "$VENV_DIR/bin/activate"
    pip install -r "$SCRIPT_DIR/requirements-mcp.txt"
    echo ""
    echo "✅ Virtual environment created and dependencies installed!"
    echo ""
fi

# Activate virtual environment
echo "⚡ Activating virtual environment..."
source "$VENV_DIR/bin/activate"

echo "✅ Virtual environment activated!"
echo ""
echo "📋 Available commands:"
echo "  python3 mcp_interface/server.py          # Start MCP server"
echo "  python3 mcp_interface/server.py --debug  # Start with debug logging"
echo "  deactivate                               # Exit virtual environment"
echo ""
echo "🔧 Or use the Zypheron CLI:"
echo "  zypheron mcp start                       # Start MCP server"
echo "  zypheron mcp status                      # Check MCP status"
echo "  zypheron mcp config                      # Generate config"
echo ""

# Start a new shell with the venv activated
exec $SHELL

