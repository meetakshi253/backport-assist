#!/usr/bin/env python3
"""
MCP Server for Linux Kernel Backport Assistant

This MCP server exposes the backport-assist tool functionality to AI agents,
allowing them to query and analyze patches in Linux kernel trees.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Optional
from datetime import datetime

# Add parent directory to path to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import DEFAULT_COMMIT_PATHS, parse_repo_spec, GitRepo, setup_logging
from commit_scanner import CommitScanner, get_cifs_commits
from compare_trees import load_commits_from_file, process_commits
from categorize_commits import populate_database, init_database
from query_commits import CommitDatabase

# MCP SDK imports
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)

# Configure logging
logger = setup_logging(__name__)

# Initialize MCP server
app = Server("kernel-backport-assistant")


def serialize_datetime(obj):
    """Helper to serialize datetime objects to ISO format."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available resources (kernel repositories)."""
    return [
        Resource(
            uri="kernel://docs/overview",
            name="Backport Assistant Overview",
            mimeType="text/plain",
            description="Overview of the Linux Kernel Backport Assistant capabilities"
        ),
        Resource(
            uri="kernel://docs/usage",
            name="Usage Guide",
            mimeType="text/plain",
            description="Guide for using the backport assistant tools"
        )
    ]


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read resource content."""
    if uri == "kernel://docs/overview":
        return """# Linux Kernel Backport Assistant

This tool helps analyze and track important commits in Linux kernel trees,
particularly useful for backporting patches between mainline and stable kernels.

## Capabilities:

1. **Combined Backport Analysis** (Recommended): Single operation to scan mainline
   commits and compare with target repository, avoiding large data transfers

2. **Commit Scanning**: Scan kernel commits by version range, filtering by:
   - Important author emails
   - Keywords (CVE, regression, crash, etc.)
   - Commits marked for stable
   - Fixes for important commits

3. **Tree Comparison**: Compare commits between mainline and target repositories:
   - Check which commits exist in target
   - Identify commits needing backport
   - Determine backport status

4. **Release Tracking**: Track which release version each commit belongs to

5. **Flexible Path Configuration**: Track any kernel subsystem (CIFS, btrfs, networking, etc.)
"""
    
    elif uri == "kernel://docs/usage":
        return """# Usage Guide

## Quick Backport Analysis (Recommended)

Use the `scan_and_compare` tool for efficient backport analysis:
- Scans mainline commits in one operation
- Immediately compares with target repository  
- Returns only the comparison results
- Avoids transferring large intermediate commit lists

## Scanning Commits

Use the `scan_commits` tool to find important commits in a kernel tree:
- Specify version range (start and end)
- Provide repository path
- Optional: filter by emails, keywords, or paths
- Optional: specify git tag/commit to use instead of HEAD

## Comparing Trees

Use the `compare_commits` tool to check backport status:
- Provide commits file (from scan_commits)
- Specify mainline and target repositories
- Get status of each commit (exists, needs backport, etc.)

## Query Commit Details

Use the `get_commit_info` tool to get detailed information about specific commits.
"""
    
    raise ValueError(f"Unknown resource: {uri}")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="scan_commits",
            description="""Scan Linux kernel commits in a specified version range.
            
            Filters commits by importance based on:
            - Author emails (important maintainers)
            - Keywords (CVE, regression, crash, etc.)
            - Commits marked for stable (cc: stable@vger.kernel.org)
            - Fixes for important commits
            
            Returns a list of important commits with metadata including release version.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute path to Linux kernel repository. Can use PATH:TAG format to specify a git tag or commit instead of HEAD"
                    },
                    "start_version": {
                        "type": "string",
                        "description": "Start version (exclusive) e.g., '6.6', 'v6.14'"
                    },
                    "end_version": {
                        "type": "string",
                        "description": "End version (inclusive) e.g., '6.15', 'HEAD'. Defaults to HEAD",
                        "default": "HEAD"
                    },
                    "emails": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Important author email addresses to filter by",
                        "default": []
                    },
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Keywords to search for in commit messages (e.g., ['CVE', 'regression', 'crash'])",
                        "default": []
                    },
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to track in repository (e.g., ['fs/cifs/', 'fs/smb/client/']). Defaults to CIFS/SMB paths",
                        "default": None
                    },
                    "no_filter": {
                        "type": "boolean",
                        "description": "If true, return all commits without filtering",
                        "default": False
                    }
                },
                "required": ["repo_path", "start_version"]
            }
        ),
        Tool(
            name="compare_commits",
            description="""Compare commits between mainline and target repositories.
            
            Checks which commits from the input list exist in the target repository,
            helping identify commits that need backporting.
            
            Returns detailed status for each commit including whether it exists in target.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "commits_data": {
                        "type": "string",
                        "description": "JSON string containing commits to check (output from scan_commits)"
                    },
                    "mainline_repo": {
                        "type": "string",
                        "description": "Path to mainline Linux kernel repository. Can use PATH:TAG format"
                    },
                    "target_repo": {
                        "type": "string",
                        "description": "Path to target repository to check commits against. Can use PATH:TAG format"
                    },
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to track (should match those used in scan). Defaults to CIFS/SMB paths",
                        "default": None
                    }
                },
                "required": ["commits_data", "mainline_repo", "target_repo"]
            }
        ),
        Tool(
            name="get_commit_info",
            description="""Get detailed information about a specific commit.
            
            Returns commit metadata including hash, author, date, subject, body, and release version.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute path to Linux kernel repository"
                    },
                    "commit_hash": {
                        "type": "string",
                        "description": "Commit hash to get information for"
                    }
                },
                "required": ["repo_path", "commit_hash"]
            }
        ),
        Tool(
            name="list_releases",
            description="""List all release tags in a kernel repository.
            
            Returns a list of version tags matching the pattern v*.*.* (e.g., v6.14, v6.15.1).""",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute path to Linux kernel repository"
                    }
                },
                "required": ["repo_path"]
            }
        ),
        Tool(
            name="scan_and_compare",
            description="""Combined operation: Scan commits in mainline repo and immediately compare with target repo.
            
            This is more efficient than calling scan_commits and compare_commits separately,
            as it avoids transferring potentially huge commit lists between operations.
            
            Scans for important commits in the specified version range and immediately
            checks which ones exist in the target repository.
            
            Returns only the comparison results with backport status.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "mainline_repo": {
                        "type": "string",
                        "description": "Path to mainline Linux kernel repository to scan. Can use PATH:TAG format"
                    },
                    "target_repo": {
                        "type": "string",
                        "description": "Path to target repository to check commits against. Can use PATH:TAG format"
                    },
                    "start_version": {
                        "type": "string",
                        "description": "Start version (exclusive) e.g., '6.6', 'v6.14'"
                    },
                    "end_version": {
                        "type": "string",
                        "description": "End version (inclusive) e.g., '6.15', 'HEAD'. Defaults to HEAD",
                        "default": "HEAD"
                    },
                    "emails": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Important author email addresses to filter by",
                        "default": []
                    },
                    "keywords": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Keywords to search for in commit messages (e.g., ['CVE', 'regression', 'crash'])",
                        "default": []
                    },
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Paths to track in repository (e.g., ['fs/cifs/', 'fs/smb/client/']). Defaults to CIFS/SMB paths",
                        "default": None
                    },
                    "no_filter": {
                        "type": "boolean",
                        "description": "If true, return all commits without filtering",
                        "default": False
                    }
                },
                "required": ["mainline_repo", "target_repo", "start_version"]
            }
        ),
        Tool(
            name="categorize_commits",
            description="""Categorize commits from backport analysis results.
            
            Analyzes commit messages to categorize as fixes vs features,
            identifies issue types (memory_leak, crash, corruption, etc.),
            identifies feature areas (multichannel, lease, encryption, etc.),
            and stores results in SQLite database for future queries.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "analysis_file": {
                        "type": "string",
                        "description": "Path to JSON file with scan_and_compare or compare_commits results"
                    },
                    "db_path": {
                        "type": "string",
                        "description": "Path to SQLite database file (will be created if doesn't exist)"
                    },
                    "mainline_repo": {
                        "type": "string",
                        "description": "Path to mainline kernel repository for fetching commit messages"
                    }
                },
                "required": ["analysis_file", "db_path", "mainline_repo"]
            }
        ),
        Tool(
            name="query_by_feature_area",
            description="""Query commits by feature area (e.g., 'multichannel', 'lease', 'encryption').
            
            Returns all commits related to a specific feature area.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to SQLite database file"
                    },
                    "area": {
                        "type": "string",
                        "description": "Feature area to search for (e.g., 'multichannel', 'lease', 'directory')"
                    },
                    "missing_only": {
                        "type": "boolean",
                        "description": "If true, only return commits missing from stable",
                        "default": False
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return",
                        "default": 50
                    }
                },
                "required": ["db_path", "area"]
            }
        ),
        Tool(
            name="query_by_issue_type",
            description="""Query fixes by issue type (e.g., 'memory_leak', 'crash', 'corruption').
            
            Returns all fixes for a specific type of issue.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to SQLite database file"
                    },
                    "issue_type": {
                        "type": "string",
                        "description": "Issue type to search for (e.g., 'memory_leak', 'crash', 'use_after_free')"
                    },
                    "missing_only": {
                        "type": "boolean",
                        "description": "If true, only return commits missing from stable",
                        "default": False
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return",
                        "default": 50
                    }
                },
                "required": ["db_path", "issue_type"]
            }
        ),
        Tool(
            name="query_by_keyword",
            description="""Search commits by keyword in message, patch name, or keywords.
            
            Returns all commits matching the search term.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to SQLite database file"
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to search for in commit messages"
                    },
                    "missing_only": {
                        "type": "boolean",
                        "description": "If true, only return commits missing from stable",
                        "default": False
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return",
                        "default": 50
                    }
                },
                "required": ["db_path", "keyword"]
            }
        ),
        Tool(
            name="get_critical_missing",
            description="""Get critical fixes missing from stable.
            
            Returns fixes marked for stable, security issues, crashes, or corruption
            that are not yet in the stable branch.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to SQLite database file"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return",
                        "default": 50
                    }
                },
                "required": ["db_path"]
            }
        ),
        Tool(
            name="get_stats",
            description="""Get overall statistics from the commit database.
            
            Returns summary of total commits, category breakdown, top issue types,
            top feature areas, and backport status.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to SQLite database file"
                    }
                },
                "required": ["db_path"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    
    try:
        if name == "scan_commits":
            return await handle_scan_commits(arguments)
        elif name == "compare_commits":
            return await handle_compare_commits(arguments)
        elif name == "get_commit_info":
            return await handle_get_commit_info(arguments)
        elif name == "list_releases":
            return await handle_list_releases(arguments)
        elif name == "scan_and_compare":
            return await handle_scan_and_compare(arguments)
        elif name == "categorize_commits":
            return await handle_categorize_commits(arguments)
        elif name == "query_by_feature_area":
            return await handle_query_by_feature_area(arguments)
        elif name == "query_by_issue_type":
            return await handle_query_by_issue_type(arguments)
        elif name == "query_by_keyword":
            return await handle_query_by_keyword(arguments)
        elif name == "get_critical_missing":
            return await handle_get_critical_missing(arguments)
        elif name == "get_stats":
            return await handle_get_stats(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")
    
    except Exception as e:
        logger.error(f"Error in tool {name}: {e}", exc_info=True)
        return [TextContent(
            type="text",
            text=f"Error: {str(e)}"
        )]


async def handle_scan_commits(args: dict) -> list[TextContent]:
    """Handle scan_commits tool call."""
    repo_path_spec = args["repo_path"]
    start_version = args["start_version"]
    end_version = args.get("end_version", "HEAD")
    emails = args.get("emails", [])
    keywords = args.get("keywords", [])
    paths = args.get("paths")
    no_filter = args.get("no_filter", False)
    
    # Parse repository specification
    repo_path, repo_ref = parse_repo_spec(repo_path_spec)
    
    # Validate repository exists
    if not os.path.isdir(repo_path):
        raise ValueError(f"Repository path does not exist: {repo_path}")
    
    # Build config
    config = {
        "start": start_version,
        "end": end_version,
        "mainline_repo": repo_path,
        "mainline_repo_ref": repo_ref,
        "default_branch": None,  # Don't require clean state - just read commits
        "emails": emails,
        "keywords": keywords,
        "paths": paths if paths else DEFAULT_COMMIT_PATHS
    }
    
    # Create scanner
    scanner = CommitScanner(config)
    
    # Temporarily set NOFILTER if requested
    import commit_scanner as cs
    original_nofilter = cs.NOFILTER
    try:
        if no_filter or (not emails and not keywords):
            cs.NOFILTER = True
        
        # Scan commits
        commits_df = scanner.scan_commits()
        
        # Convert to JSON
        result = commits_df.to_json(orient='records', indent=2, default_handler=str)
        
        return [TextContent(
            type="text",
            text=f"Found {len(commits_df)} important commits:\n\n{result}"
        )]
    finally:
        cs.NOFILTER = original_nofilter


async def handle_compare_commits(args: dict) -> list[TextContent]:
    """Handle compare_commits tool call."""
    commits_json = args["commits_data"]
    mainline_spec = args["mainline_repo"]
    target_spec = args["target_repo"]
    paths = args.get("paths")
    
    # Parse repository specifications
    mainline_path, mainline_ref = parse_repo_spec(mainline_spec)
    target_path, target_ref = parse_repo_spec(target_spec)
    
    # Validate repositories exist
    if not os.path.isdir(mainline_path):
        raise ValueError(f"Mainline repository does not exist: {mainline_path}")
    if not os.path.isdir(target_path):
        raise ValueError(f"Target repository does not exist: {target_path}")
    
    # Validate JSON format
    try:
        json.loads(commits_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in commits_data: {e}")
    
    # Write JSON directly to temporary file for process_commits to read
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        tmp_path = tmp.name
        tmp.write(commits_json)
    
    try:
        # Process commits using the file path
        repo_paths = paths if paths else DEFAULT_COMMIT_PATHS
        result_commits = process_commits(
            input_path=tmp_path,
            ref_repo_spec=mainline_spec,
            target_repo_spec=target_spec,
            paths=repo_paths
        )
        
        # Convert CommitInfo list to dict for JSON serialization
        result_data = []
        for commit in result_commits:
            result_data.append({
                'commit': commit.hash,
                'patch_name': commit.title,
                'release': commit.release,
                'priority': commit.importance,
                'comments': commit.comments,
                'date': commit.date.isoformat() if commit.date else None,
                'exists_in_target': 'yes' if commit.found_in_target else ('maybe' if commit.found_by_title else 'no'),
                'matching_target_hash': commit.matching_target_hash or ''
            })
        
        # Create summary
        total = len(result_commits)
        found_exact = sum(1 for c in result_commits if c.found_in_target)
        found_title = sum(1 for c in result_commits if not c.found_in_target and c.found_by_title)
        not_found = sum(1 for c in result_commits if not c.found_in_target and not c.found_by_title)
        
        result_json = json.dumps(result_data, indent=2)
        
        summary = f"""Comparison complete:
- Total commits: {total}
- Found by hash: {found_exact}
- Found by title: {found_title}
- Not found: {not_found}

Details:
{result_json}"""
        
        return [TextContent(
            type="text",
            text=summary
        )]
    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


async def handle_get_commit_info(args: dict) -> list[TextContent]:
    """Handle get_commit_info tool call."""
    repo_path = args["repo_path"]
    commit_hash = args["commit_hash"]
    
    # Validate repository exists
    if not os.path.isdir(repo_path):
        raise ValueError(f"Repository path does not exist: {repo_path}")
    
    # Create repo instance
    repo = GitRepo(repo_path, "master")
    
    # Validate commit exists
    if not repo.check_commit_exists(commit_hash):
        raise ValueError(f"Commit does not exist: {commit_hash}")
    
    # Get detailed commit info
    format_str = "%H%x00%an%x00%ae%x00%at%x00%s%x00%b"
    info = repo.run_git(["show", "-s", f"--format={format_str}", commit_hash])
    
    parts = info.split("\x00")
    if len(parts) >= 6:
        commit_info = {
            "hash": parts[0].strip(),
            "author_name": parts[1].strip(),
            "author_email": parts[2].strip(),
            "date": datetime.fromtimestamp(int(parts[3])).isoformat(),
            "subject": parts[4].strip(),
            "body": parts[5].strip(),
            "release": repo.get_release_tag(commit_hash)
        }
        
        result = json.dumps(commit_info, indent=2)
        return [TextContent(
            type="text",
            text=f"Commit information:\n{result}"
        )]
    
    raise ValueError("Failed to parse commit information")


async def handle_list_releases(args: dict) -> list[TextContent]:
    """Handle list_releases tool call."""
    repo_path = args["repo_path"]
    
    # Validate repository exists
    if not os.path.isdir(repo_path):
        raise ValueError(f"Repository path does not exist: {repo_path}")
    
    # Create repo instance
    repo = GitRepo(repo_path, "master")
    
    # Get all tags matching version pattern
    import re
    tags_output = repo.run_git(["tag", "-l", "v*"])
    version_pattern = re.compile(r'^v[1-9][0-9]*\.[0-9]+(\.[0-9]+)*$')
    
    tags = []
    for tag in tags_output.strip().split('\n'):
        tag = tag.strip()
        if tag and version_pattern.match(tag):
            tags.append(tag)
    
    # Sort tags
    tags.sort(key=lambda t: [int(x) for x in t[1:].split('.')])
    
    result = f"Found {len(tags)} release tags:\n\n" + "\n".join(tags)
    
    return [TextContent(
        type="text",
        text=result
    )]


async def handle_scan_and_compare(args: dict) -> list[TextContent]:
    """Handle scan_and_compare tool call - combines scan and compare in one operation."""
    mainline_spec = args["mainline_repo"]
    target_spec = args["target_repo"]
    start_version = args["start_version"]
    end_version = args.get("end_version", "HEAD")
    emails = args.get("emails", [])
    keywords = args.get("keywords", [])
    paths = args.get("paths")
    no_filter = args.get("no_filter", False)
    
    # Parse repository specifications
    mainline_path, mainline_ref = parse_repo_spec(mainline_spec)
    target_path, target_ref = parse_repo_spec(target_spec)
    
    # Validate repositories exist
    if not os.path.isdir(mainline_path):
        raise ValueError(f"Mainline repository does not exist: {mainline_path}")
    if not os.path.isdir(target_path):
        raise ValueError(f"Target repository does not exist: {target_path}")
    
    # Build config for scanning
    config = {
        "start": start_version,
        "end": end_version,
        "mainline_repo": mainline_path,
        "mainline_repo_ref": mainline_ref,
        "default_branch": None,  # Don't require clean state - just read commits
        "emails": emails,
        "keywords": keywords,
        "paths": paths if paths else DEFAULT_COMMIT_PATHS
    }
    
    # Create scanner
    scanner = CommitScanner(config)
    
    # Temporarily set NOFILTER if requested
    import commit_scanner as cs
    original_nofilter = cs.NOFILTER
    try:
        if no_filter or (not emails and not keywords):
            cs.NOFILTER = True
        
        # Step 1: Scan commits
        logger.info(f"Scanning commits in {mainline_path} from {start_version} to {end_version}")
        commits_df = scanner.scan_commits()
        scanned_count = len(commits_df)
        logger.info(f"Found {scanned_count} commits to check")
        
        # Convert to JSON for processing
        commits_json = commits_df.to_json(orient='records', indent=2, default_handler=str)
        
        # Step 2: Compare commits with target repo
        # Write JSON to temporary file for process_commits
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(commits_json)
        
        try:
            logger.info(f"Comparing commits with target repo {target_path}")
            repo_paths = paths if paths else DEFAULT_COMMIT_PATHS
            result_commits = process_commits(
                input_path=tmp_path,
                ref_repo_spec=mainline_spec,
                target_repo_spec=target_spec,
                paths=repo_paths
            )
            
            # Convert CommitInfo list to dict for JSON serialization
            result_data = []
            for commit in result_commits:
                result_data.append({
                    'commit': commit.hash,
                    'patch_name': commit.title,
                    'release': commit.release,
                    'priority': commit.importance,
                    'comments': commit.comments,
                    'date': commit.date.isoformat() if commit.date else None,
                    'exists_in_target': 'yes' if commit.found_in_target else ('maybe' if commit.found_by_title else 'no'),
                    'matching_target_hash': commit.matching_target_hash or ''
                })
            
            # Create summary
            total = len(result_commits)
            found_exact = sum(1 for c in result_commits if c.found_in_target)
            found_title = sum(1 for c in result_commits if not c.found_in_target and c.found_by_title)
            not_found = sum(1 for c in result_commits if not c.found_in_target and not c.found_by_title)
            
            result_json = json.dumps(result_data, indent=2)
            
            summary = f"""Backport analysis complete:

Scanned: {scanned_count} commits in mainline ({start_version}..{end_version})
Analyzed: {total} commits

Backport Status:
- Already in target (exact match): {found_exact}
- Likely in target (title match): {found_title}
- Needs backport: {not_found}

Detailed Results:
{result_json}"""
            
            return [TextContent(
                type="text",
                text=summary
            )]
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    finally:
        cs.NOFILTER = original_nofilter


async def handle_categorize_commits(args: dict) -> list[TextContent]:
    """Handle categorize_commits tool call."""
    analysis_file = args["analysis_file"]
    db_path = args["db_path"]
    mainline_repo = args["mainline_repo"]
    
    # Validate analysis file exists
    if not os.path.isfile(analysis_file):
        raise ValueError(f"Analysis file does not exist: {analysis_file}")
    
    # Validate mainline repo exists
    if not os.path.isdir(mainline_repo):
        raise ValueError(f"Mainline repository does not exist: {mainline_repo}")
    
    logger.info(f"Starting categorization: {analysis_file} -> {db_path}")
    
    # Run categorization
    try:
        populate_database(db_path, analysis_file, mainline_repo)
        
        # Get stats for summary
        db = CommitDatabase(db_path)
        stats = db.get_stats()
        
        summary = f"""Categorization complete!

Database: {db_path}

Statistics:
- Total commits: {stats['total_commits']}
- Fixes: {stats['by_category'].get('fix', 0)}
- Features: {stats['by_category'].get('feature', 0)}

Backport Status:
- In stable: {stats['backport_status']['in_stable']}
- Likely in stable: {stats['backport_status']['likely_in_stable']}
- Missing from stable: {stats['backport_status']['missing']}

Top Issue Types:
{chr(10).join(f'  - {name}: {count}' for name, count in stats['top_issue_types'][:5])}

Top Feature Areas:
{chr(10).join(f'  - {name}: {count}' for name, count in stats['top_feature_areas'][:5])}
"""
        
        return [TextContent(type="text", text=summary)]
    
    except Exception as e:
        logger.error(f"Categorization failed: {e}", exc_info=True)
        raise


async def handle_query_by_feature_area(args: dict) -> list[TextContent]:
    """Handle query_by_feature_area tool call."""
    db_path = args["db_path"]
    area = args["area"]
    missing_only = args.get("missing_only", False)
    limit = args.get("limit", 50)
    
    if not os.path.isfile(db_path):
        raise ValueError(f"Database file does not exist: {db_path}")
    
    db = CommitDatabase(db_path)
    results = db.query_by_feature_area(area, missing_only)
    
    total = len(results)
    results = results[:limit]
    
    # Format results
    result_list = []
    for row in results:
        result_list.append({
            'commit': row['commit_hash'][:12],
            'patch_name': row['patch_name'],
            'category': row['category'],
            'feature_area': row['feature_area'],
            'issue_type': row['issue_type'],
            'date': row['commit_date'],
            'in_stable': row['in_stable'] or row['likely_in_stable']
        })
    
    result_json = json.dumps(result_list, indent=2)
    
    summary = f"""Found {total} commits for feature area '{area}'"""
    if missing_only:
        summary += " (missing from stable only)"
    if total > limit:
        summary += f"\nShowing first {limit} results"
    summary += f":\n\n{result_json}"
    
    return [TextContent(type="text", text=summary)]


async def handle_query_by_issue_type(args: dict) -> list[TextContent]:
    """Handle query_by_issue_type tool call."""
    db_path = args["db_path"]
    issue_type = args["issue_type"]
    missing_only = args.get("missing_only", False)
    limit = args.get("limit", 50)
    
    if not os.path.isfile(db_path):
        raise ValueError(f"Database file does not exist: {db_path}")
    
    db = CommitDatabase(db_path)
    results = db.query_by_issue_type(issue_type, missing_only)
    
    total = len(results)
    results = results[:limit]
    
    # Format results
    result_list = []
    for row in results:
        result_list.append({
            'commit': row['commit_hash'][:12],
            'patch_name': row['patch_name'],
            'issue_type': row['issue_type'],
            'date': row['commit_date'],
            'cc_stable': bool(row['cc_stable']),
            'in_stable': row['in_stable'] or row['likely_in_stable']
        })
    
    result_json = json.dumps(result_list, indent=2)
    
    summary = f"""Found {total} fixes for issue type '{issue_type}'"""
    if missing_only:
        summary += " (missing from stable only)"
    if total > limit:
        summary += f"\nShowing first {limit} results"
    summary += f":\n\n{result_json}"
    
    return [TextContent(type="text", text=summary)]


async def handle_query_by_keyword(args: dict) -> list[TextContent]:
    """Handle query_by_keyword tool call."""
    db_path = args["db_path"]
    keyword = args["keyword"]
    missing_only = args.get("missing_only", False)
    limit = args.get("limit", 50)
    
    if not os.path.isfile(db_path):
        raise ValueError(f"Database file does not exist: {db_path}")
    
    db = CommitDatabase(db_path)
    results = db.query_by_keyword(keyword, missing_only)
    
    total = len(results)
    results = results[:limit]
    
    # Format results
    result_list = []
    for row in results:
        result_list.append({
            'commit': row['commit_hash'][:12],
            'patch_name': row['patch_name'],
            'category': row['category'],
            'issue_type': row['issue_type'],
            'feature_area': row['feature_area'],
            'date': row['commit_date'],
            'in_stable': row['in_stable'] or row['likely_in_stable']
        })
    
    result_json = json.dumps(result_list, indent=2)
    
    summary = f"""Found {total} commits matching keyword '{keyword}'"""
    if missing_only:
        summary += " (missing from stable only)"
    if total > limit:
        summary += f"\nShowing first {limit} results"
    summary += f":\n\n{result_json}"
    
    return [TextContent(type="text", text=summary)]


async def handle_get_critical_missing(args: dict) -> list[TextContent]:
    """Handle get_critical_missing tool call."""
    db_path = args["db_path"]
    limit = args.get("limit", 50)
    
    if not os.path.isfile(db_path):
        raise ValueError(f"Database file does not exist: {db_path}")
    
    db = CommitDatabase(db_path)
    results = db.get_critical_missing()
    
    total = len(results)
    results = results[:limit]
    
    # Format results
    result_list = []
    for row in results:
        result_list.append({
            'commit': row['commit_hash'][:12],
            'patch_name': row['patch_name'],
            'issue_type': row['issue_type'],
            'date': row['commit_date'],
            'cc_stable': bool(row['cc_stable']),
            'fixes_commit': row['fixes_commit'][:12] if row['fixes_commit'] else None
        })
    
    result_json = json.dumps(result_list, indent=2)
    
    summary = f"""⚠️  Found {total} critical fixes missing from stable"""
    if total > limit:
        summary += f"\nShowing first {limit} results"
    summary += f":\n\n{result_json}"
    
    return [TextContent(type="text", text=summary)]


async def handle_get_stats(args: dict) -> list[TextContent]:
    """Handle get_stats tool call."""
    db_path = args["db_path"]
    
    if not os.path.isfile(db_path):
        raise ValueError(f"Database file does not exist: {db_path}")
    
    db = CommitDatabase(db_path)
    stats = db.get_stats()
    
    # Format stats as readable text
    summary = f"""Commit Database Statistics
{'=' * 50}

Total Commits: {stats['total_commits']}

By Category:
{chr(10).join(f'  - {cat}: {count}' for cat, count in stats['by_category'].items())}

Backport Status:
  - In stable: {stats['backport_status']['in_stable']}
  - Likely in stable: {stats['backport_status']['likely_in_stable']}
  - Missing from stable: {stats['backport_status']['missing']}

Top Issue Types:
{chr(10).join(f'  {i+1}. {name}: {count}' for i, (name, count) in enumerate(stats['top_issue_types']))}

Top Feature Areas:
{chr(10).join(f'  {i+1}. {name}: {count}' for i, (name, count) in enumerate(stats['top_feature_areas']))}
"""
    
    return [TextContent(type="text", text=summary)]


async def main():
    """Run the MCP server."""
    logger.info("Starting Linux Kernel Backport Assistant MCP Server")
    
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
