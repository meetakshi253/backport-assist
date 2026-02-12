#!/usr/bin/env bash
# Quick start script for MCP server

set -e

echo "Linux Kernel Backport Assistant - MCP Server Setup"
echo "===================================================="
echo

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Found Python: $python_version"

# Install dependencies
echo
echo "Installing dependencies..."
pip install -q -r requirements.txt
pip install -q -r mcp/requirements.txt
echo "✓ Dependencies installed"

# Run server
echo
echo "Starting MCP server..."
echo "The server will communicate via stdio (standard input/output)"
echo "Press Ctrl+C to stop"
echo
python3 mcp/server.py
