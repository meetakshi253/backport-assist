#!/usr/bin/env bash
# Monitor the latest MCP server log file

LOG_DIR="/home/sprasad/repo/meetakshi253/backport-assist/mcp-server/logs"

if [ ! -d "$LOG_DIR" ]; then
    echo "No logs directory found at: $LOG_DIR"
    echo "Run the server first to create logs."
    exit 1
fi

LATEST_LOG=$(ls -t "$LOG_DIR"/mcp-server-*.log 2>/dev/null | head -1)

if [ -z "$LATEST_LOG" ]; then
    echo "No log files found in $LOG_DIR"
    exit 1
fi

echo "Monitoring: $LATEST_LOG"
echo "Press Ctrl+C to stop"
echo "=========================================="
tail -f "$LATEST_LOG"
