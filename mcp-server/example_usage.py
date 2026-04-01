#!/usr/bin/env python3
"""
Example script showing how to configure and use the MCP server.
This is for documentation purposes - actual MCP clients will handle the protocol.
"""

import json

# Example tool calls that an MCP client can make:

# 1. Scan commits
scan_request = {
    "tool": "scan_commits",
    "arguments": {
        "repo_path": "/path/to/linux",
        "start_version": "6.6",
        "end_version": "6.15",
        "emails": ["maintainer@example.com"],
        "keywords": ["CVE", "regression", "crash"],
        "paths": ["fs/cifs/", "fs/smb/client/"]
    }
}

# 2. Compare commits
compare_request = {
    "tool": "compare_commits",
    "arguments": {
        "commits_data": "[{\"commit\": \"abc123...\", ...}]",  # JSON from scan_commits
        "mainline_repo": "/path/to/linux",
        "target_repo": "/path/to/linux-stable:linux-6.6.y"
    }
}

# 3. Get commit info
info_request = {
    "tool": "get_commit_info",
    "arguments": {
        "repo_path": "/path/to/linux",
        "commit_hash": "abc123def456"
    }
}

# 4. List releases
releases_request = {
    "tool": "list_releases",
    "arguments": {
        "repo_path": "/path/to/linux"
    }
}

print("Example MCP Tool Requests")
print("=" * 60)
print()
print("1. Scan Commits:")
print(json.dumps(scan_request, indent=2))
print()
print("2. Compare Commits:")
print(json.dumps(compare_request, indent=2))
print()
print("3. Get Commit Info:")
print(json.dumps(info_request, indent=2))
print()
print("4. List Releases:")
print(json.dumps(releases_request, indent=2))
print()
print("Note: These requests use the MCP protocol's tool calling format.")
print("Actual MCP clients will wrap these in the full JSON-RPC 2.0 protocol.")
