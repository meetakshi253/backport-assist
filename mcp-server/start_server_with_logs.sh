#!/usr/bin/env bash
# Start MCP server with logs redirected to a file for monitoring

set -e

LOG_DIR="/home/sprasad/repo/meetakshi253/backport-assist/mcp-server/logs"
LOG_FILE="$LOG_DIR/mcp-server-$(date +%Y%m%d-%H%M%S).log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

echo "Linux Kernel Backport Assistant - MCP Server"
echo "============================================="
echo
echo "Logs will be written to: $LOG_FILE"
echo "You can monitor progress with: tail -f $LOG_FILE"
echo
echo "Starting MCP server..."

# Run server with stderr redirected to log file
# Keep stdout for MCP protocol communication
cd /home/sprasad/repo/meetakshi253/backport-assist
python3 mcp-server/server.py 2>> "$LOG_FILE"
