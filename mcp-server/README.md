# Linux Kernel Backport Assistant - MCP Server

This directory contains the Model Context Protocol (MCP) server implementation for the Linux Kernel Backport Assistant. The MCP server allows AI agents to query and analyze patches in Linux kernel trees.

## Overview

The MCP server exposes the backport-assist tool functionality through a standardized protocol that AI agents can use to:

- **Scan commits** in kernel repositories by version range
- **Compare commits** between mainline and target trees
- **Get commit details** including metadata and release information
- **List releases** available in kernel repositories

## Installation

### Prerequisites

- Python 3.8 or higher
- Git installed and accessible in PATH
- Linux kernel git repositories cloned locally

### Install Dependencies

```bash
cd mcp
pip install -r requirements.txt
```

Or install in the parent directory:

```bash
pip install -r requirements.txt
pip install -r mcp/requirements.txt
```

## Usage

### Running the Server

The MCP server communicates via stdio (standard input/output):

```bash
python mcp/server.py
```

### Using with VS Code

Add the MCP server to your VS Code configuration:

1. Open VS Code settings
2. Add the MCP server configuration to `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "kernel-backport": {
      "command": "python",
      "args": ["mcp/server.py"],
      "cwd": "/path/to/backport-assist"
    }
  }
}
```

3. Reload VS Code to activate the server

### Using with AI Clients

The MCP server can be used with any MCP-compatible AI client. Configure your client to run:

```bash
python /path/to/backport-assist/mcp/server.py
```

## Available Tools

### 1. scan_and_compare (Recommended)

**NEW:** Combined operation that scans commits in mainline and immediately compares with target repository. This is more efficient than using `scan_commits` and `compare_commits` separately, as it avoids transferring potentially huge commit lists between operations.

**Parameters:**
- `mainline_repo` (required): Path to mainline repository to scan (can use `PATH:TAG` format)
- `target_repo` (required): Path to target repository to check against (can use `PATH:TAG` format)
- `start_version` (required): Start version (exclusive), e.g., "6.6", "v6.14"
- `end_version` (optional): End version (inclusive), defaults to "HEAD"
- `emails` (optional): List of important author email addresses
- `keywords` (optional): List of keywords to search for (e.g., ["CVE", "regression", "crash"])
- `paths` (optional): List of paths to track (e.g., ["fs/cifs/", "fs/smb/client/"])
- `no_filter` (optional): If true, return all commits without filtering

**Example:**
```json
{
  "mainline_repo": "/home/user/linux",
  "target_repo": "/home/user/linux-stable:linux-6.6.y",
  "start_version": "6.6",
  "end_version": "6.15",
  "emails": ["maintainer@example.com"],
  "keywords": ["CVE", "regression"],
  "paths": ["fs/cifs/", "fs/smb/client/"]
}
```

**Returns:** Backport analysis with:
- Number of commits scanned
- Number already in target (exact match)
- Number likely in target (title match)
- Number needing backport
- Detailed JSON array with status for each commit

**Benefits over separate tools:**
- More efficient for large commit sets
- Reduces data transfer between agent and server
- Single operation instead of two-step process
- Immediate results without intermediate storage

### 2. scan_commits

Scan Linux kernel commits in a specified version range and filter by importance.

**Parameters:**
- `repo_path` (required): Absolute path to Linux kernel repository (can use `PATH:TAG` format)
- `start_version` (required): Start version (exclusive), e.g., "6.6", "v6.14"
- `end_version` (optional): End version (inclusive), defaults to "HEAD"
- `emails` (optional): List of important author email addresses
- `keywords` (optional): List of keywords to search for (e.g., ["CVE", "regression", "crash"])
- `paths` (optional): List of paths to track (e.g., ["fs/cifs/", "fs/smb/client/"])
- `no_filter` (optional): If true, return all commits without filtering

**Example:**
```json
{
  "repo_path": "/home/user/linux",
  "start_version": "6.6",
  "end_version": "6.15",
  "emails": ["maintainer@example.com"],
  "keywords": ["CVE", "regression", "crash"],
  "paths": ["fs/cifs/", "fs/smb/client/"]
}
```

**Returns:** JSON array of important commits with metadata including release version.

### 3. compare_commits

Compare commits between mainline and target repositories to check backport status.

**Parameters:**
- `commits_data` (required): JSON string containing commits to check (output from scan_commits)
- `mainline_repo` (required): Path to mainline repository (can use `PATH:TAG` format)
- `target_repo` (required): Path to target repository (can use `PATH:TAG` format)
- `paths` (optional): List of paths to track (should match those used in scan)

**Example:**
```json
{
  "commits_data": "[{\"commit\": \"abc123...\", ...}]",
  "mainline_repo": "/home/user/linux",
  "target_repo": "/home/user/linux-stable:linux-6.6.y"
}
```

**Returns:** JSON array with comparison results showing which commits exist in target.

### 4. get_commit_info

Get detailed information about a specific commit.

**Parameters:**
- `repo_path` (required): Absolute path to Linux kernel repository
- `commit_hash` (required): Commit hash to get information for

**Example:**
```json
{
  "repo_path": "/home/user/linux",
  "commit_hash": "abc123def456"
}
```

**Returns:** JSON object with commit details including hash, author, date, subject, body, and release.

### 5. list_releases

List all release tags in a kernel repository.

**Parameters:**
- `repo_path` (required): Absolute path to Linux kernel repository

**Example:**
```json
{
  "repo_path": "/home/user/linux"
}
```

**Returns:** List of version tags (e.g., v6.14, v6.15.1).

### 6. analyze_team_contributions

Analyze kernel contributions by a team of developers, tracking all contribution types.

**Parameters:**
- `repo_path` (required): Absolute path to kernel repository
- `team_emails` (required): Array of team member email addresses
- `since_date` (optional): Start date in YYYY-MM-DD format
- `until_date` (optional): End date in YYYY-MM-DD format
- `paths` (optional): Array of paths to analyze (defaults to SMB paths)
- `include_commit_details` (optional): Include detailed commit lists (default: true)

**Tracks:**
- Commits authored by team members
- Reviewed-by tags
- Tested-by tags
- Reported-by tags
- Acked-by tags
- Suggested-by tags
- Signed-off-by tags

**Example:**
```json
{
  "repo_path": "/home/user/linux",
  "team_emails": [
    "dev1@example.com",
    "dev2@example.com",
    "dev3@example.com"
  ],
  "since_date": "2024-04-01",
  "until_date": "2026-04-01",
  "paths": ["fs/smb/client/", "fs/cifs/"]
}
```

**Returns:** 
- Overall statistics (total unique commits, breakdown by type)
- Individual statistics per team member
- Optional: Detailed commit hash lists grouped by contribution type

**Use cases:**
- Track team productivity and contributions
- Generate contribution reports
- Identify review patterns and collaboration
- Measure different types of contributions beyond just authorship

### 7. get_team_commit_details

Get detailed commit messages for team contributions grouped by contribution type.

**Parameters:**
- `repo_path` (required): Absolute path to kernel repository
- `team_emails` (required): Array of team member email addresses
- `since_date` (optional): Start date in YYYY-MM-DD format
- `until_date` (optional): End date in YYYY-MM-DD format
- `paths` (optional): Array of paths to analyze (defaults to SMB paths)

**Example:**
```json
{
  "repo_path": "/home/user/linux",
  "team_emails": ["dev1@example.com", "dev2@example.com"],
  "since_date": "2024-04-01",
  "until_date": "2026-04-01"
}
```

**Returns:** Commit hashes and one-line subjects organized by contribution type:
- Authored commits
- Reviewed commits
- Tested commits
- Reported issues
- Acked commits
- Suggested changes

**Use cases:**
- Generate detailed contribution reports
- Create documentation of team's work
- Verify contribution counts
- Export commit lists for further analysis

### 8. analyze_subsystem_contributions

Analyze what percentage of commits to a specific kernel subsystem came from a team.

**Parameters:**
- `repo_path` (required): Absolute path to kernel repository
- `subsystem_paths` (required): Array of paths to analyze (e.g., `["fs/smb/client/", "fs/cifs/"]`)
- `team_emails` (required): Array of team member email addresses
- `since_date` (optional): Start date in YYYY-MM-DD format
- `until_date` (optional): End date in YYYY-MM-DD format

**Example:**
```json
{
  "repo_path": "/home/user/linux",
  "subsystem_paths": ["fs/smb/client/", "fs/cifs/"],
  "team_emails": [
    "sprasad@microsoft.com",
    "bharathsm@microsoft.com",
    "msetiya@microsoft.com"
  ],
  "since_date": "2024-04-01",
  "until_date": "2026-04-01"
}
```

**Returns:** 
- Total commits to the subsystem
- Number of commits with team involvement (any contribution type)
- Percentage of team contributions
- Breakdown by contribution type (authored, reviewed, etc.)
- Individual contributions per team member

**Use cases:**
- Measure team ownership of a subsystem
- Calculate contribution percentages for reports
- Understand team's impact on specific kernel areas
- Compare team vs. community contributions
- Track subsystem maintenance responsibility

### 8. categorize_commits

Categorize commits from backport analysis results into fixes vs features.

**Parameters:**
- `analysis_file` (required): Path to JSON file with scan_and_compare or compare_commits results
- `db_path` (required): Path to SQLite database file (will be created)
- `mainline_repo` (required): Path to mainline kernel repository for fetching commit messages

**Categorizes:**
- Fix vs Feature
- Issue types (memory_leak, crash, corruption, use_after_free, etc.)
- Feature areas (multichannel, lease, encryption, caching, etc.)
- Keywords extraction

**Returns:** Summary statistics of categorized commits stored in SQLite database

### 9-13. Query Tools

Query categorized commits from the SQLite database:

- **query_by_feature_area**: Query commits by feature (e.g., 'multichannel', 'lease')
- **query_by_issue_type**: Query fixes by issue type (e.g., 'memory_leak', 'crash')
- **query_by_keyword**: Search by keyword in commit messages
- **get_critical_missing**: Get critical fixes missing from stable
- **get_stats**: Get overall database statistics

## Resources

The server provides documentation resources:

- `kernel://docs/overview` - Overview of capabilities
- `kernel://docs/usage` - Usage guide

## Repository Path Formats

The server supports two formats for specifying repositories:

1. **Simple path**: `/path/to/repository`
   - Uses the current HEAD or default branch

2. **Path with reference**: `/path/to/repository:TAG`
   - Uses the specified git tag or commit hash
   - Examples:
     - `/home/user/linux:v6.15` - Use tag v6.15
     - `/home/user/linux-stable:linux-6.6.y` - Use branch linux-6.6.y
     - `/home/user/linux:abc123def` - Use commit abc123def

## Examples

### Quick Backport Analysis (Recommended)

Ask your AI agent:
> "Use scan_and_compare to analyze commits in /home/user/linux from v6.6 to v6.15 for CIFS subsystem and check which ones need backporting to /home/user/linux-stable:linux-6.6.y. Filter by maintainer@example.com and keywords CVE, regression."

This single operation will:
1. Scan mainline commits in the version range
2. Immediately compare them with the target repository
3. Return only the backport status summary

### Scan for Important CIFS Commits

Ask your AI agent:
> "Scan commits in /home/user/linux from v6.6 to v6.15 for CIFS subsystem, filtering by emails ['maintainer@example.com'] and keywords ['CVE', 'regression']"

### Check Backport Status

Ask your AI agent:
> "Compare the scanned commits between mainline at /home/user/linux and stable tree at /home/user/linux-stable:linux-6.6.y"

Note: For large result sets (hundreds/thousands of commits), prefer using `scan_and_compare` instead of the two-step `scan_commits` + `compare_commits` approach.

### Get Commit Details

Ask your AI agent:
> "Get detailed information about commit abc123def in /home/user/linux"

### List Available Releases

Ask your AI agent:
> "List all release tags in /home/user/linux"

### Analyze Team Contributions

Ask your AI agent:
> "Analyze kernel contributions by my team in the last 2 years. The team consists of: dev1@example.com, dev2@example.com, dev3@example.com. Count commits not just by authorship, but also Reviewed-by, Tested-by, Reported-by, Acked-by, and Suggested-by tags in /home/user/linux."

Or for a specific date range:
> "Get team contributions from 2024-04-01 to 2026-04-01 for emails: dev1@example.com, dev2@example.com in /home/user/linux for fs/smb/client/ paths"

### Get Detailed Team Commit Lists

Ask your AI agent:
> "Get detailed commit messages for team contributions grouped by type (authored, reviewed, tested, etc.) for team members: dev1@example.com, dev2@example.com from 2024-04-01 to 2026-04-01"

This can be used to generate reports with actual commit hashes and one-line summaries.

## Architecture

```
mcp/
├── server.py          # Main MCP server implementation
├── requirements.txt   # MCP-specific dependencies
├── __init__.py        # Package initialization
└── README.md          # This file

Parent directory:
├── common.py          # Shared utilities
├── commit_scanner.py  # Commit scanning logic
└── compare_trees.py   # Tree comparison logic
```

The MCP server imports and uses the core functionality from the parent directory, wrapping it in the MCP protocol.

## Logging

The server logs to stderr by default, which includes:
- Progress updates during long-running operations
- Performance metrics and timing information
- Error messages and debugging info

### Viewing Logs in VS Code

When using the MCP server with GitHub Copilot Chat in VS Code:

1. Open the **Output** panel: `View → Output` or `Ctrl+Shift+U`
2. Select **"GitHub Copilot Chat - MCP"** from the dropdown
3. Real-time logs including progress updates will appear here

### Logging to File

For long-running operations or detailed debugging, use the log file script:

```bash
# Start server with logs redirected to file
./mcp-server/start_server_with_logs.sh

# In another terminal, monitor progress in real-time
./mcp-server/monitor_logs.sh
```

Log files are stored in `mcp-server/logs/` with timestamps.

### Verbose Logging

To enable debug-level logging, set the logging level:

```bash
export PYTHONLOGLEVEL=DEBUG
python mcp-server/server.py
```

### Progress Tracking

Long-running operations like `scan_and_compare` log progress every 5%:
- Percentage complete
- Processing rate (commits/second)
- Estimated time remaining (ETA)
- Timing breakdowns for each phase

Example progress log:
```
INFO: Starting comparison: 1,234 commits to check against 4,523 target commits
INFO: Estimated comparisons: 5,581,782 (this may take a while for large datasets)
INFO: Progress: 62/1234 commits checked (5.0%, 3.2 commits/s, ETA: 6.1m)
INFO: Progress: 123/1234 commits checked (10.0%, 3.5 commits/s, ETA: 5.3m)
...
INFO: Comparison complete in 485.23s (8.09m)
```

## Troubleshooting

### Server Not Starting

- Ensure all dependencies are installed: `pip install -r mcp-server/requirements.txt`
- Check that Python 3.8+ is being used: `python --version`
- Verify the server script is executable: `chmod +x mcp-server/server.py`

### Git Repository Errors

- Ensure git repositories exist at the specified paths
- Verify git is installed and accessible: `git --version`
- Check that the specified tags/commits exist in the repository

### Invalid Commit Data

- Ensure commits_data parameter in compare_commits is valid JSON
- Verify the JSON structure matches the output from scan_commits

## Development

### Testing the Server

You can test the server manually using the MCP protocol:

```bash
# Start the server
python mcp/server.py

# Send test requests via stdin (in JSON-RPC 2.0 format)
```

### Adding New Tools

To add new tools:

1. Add the tool definition in `list_tools()`
2. Create a handler function `handle_<tool_name>(args)`
3. Add the handler to `call_tool()`

### Debugging

Enable DEBUG logging to see detailed information:

```python
# In server.py
logger.setLevel(logging.DEBUG)
```

## License

Same as the parent backport-assist tool.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the parent tool's README.md
3. Check the MCP protocol documentation at https://modelcontextprotocol.io
