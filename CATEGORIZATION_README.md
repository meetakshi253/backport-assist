# SMB Client Commit Categorization System

This system analyzes commits in the SMB client code, categorizes them, and stores the information in a SQLite database for easy querying.

## Quick Start

### 1. Run Analysis (already done)

The analysis has been completed and the database is ready at `smb_commits.db`.

### 2. Query the Database

Use `query_commits.py` to search for specific commits:

```bash
# Get all changes relevant to directory leases
python3 query_commits.py smb_commits.db --keyword "directory" --limit 20

# Get missing changes for multichannel
python3 query_commits.py smb_commits.db --feature-area "multichannel" --missing-only

# Get all memory leak fixes
python3 query_commits.py smb_commits.db --issue-type "memory_leak"

# Get all data corruption fixes
python3 query_commits.py smb_commits.db --issue-type "data_corruption"

# Get all critical fixes missing from stable-6.6
python3 query_commits.py smb_commits.db --critical-missing

# Get overall statistics
python3 query_commits.py smb_commits.db --stats

# Search for any keyword
python3 query_commits.py smb_commits.db --keyword "close_shroot"
python3 query_commits.py smb_commits.db --keyword "lease"
python3 query_commits.py smb_commits.db --keyword "reconnect"

# Show full commit messages
python3 query_commits.py smb_commits.db --keyword "corruption" --show-message
```

## Database Schema

The SQLite database (`smb_commits.db`) contains:

### Commit Information
- `commit_hash`: Full commit hash
- `patch_name`: Commit title/subject
- `commit_date`: When the commit was made
- `release_version`: Which kernel version it's in
- `commit_message`: Full commit message

### Backport Status
- `in_stable`: Exact match found in stable-6.6 (by hash)
- `likely_in_stable`: Similar commit found (by title)
- `matching_stable_hash`: Hash of matching commit in stable

### Categorization
- `category`: "fix" or "feature"
- `issue_type`: For fixes - type of issue (memory_leak, crash, corruption, etc.)
- `feature_area`: Area of functionality (multichannel, lease, encryption, etc.)
- `keywords`: JSON array of important keywords
- `fixes_commit`: Hash of commit this fixes (from Fixes: tag)
- `cc_stable`: Whether marked for stable backport

## Current Statistics

From the latest analysis (2026-02-27):

- **Total commits analyzed**: 1,387
- **Fixes**: 582 (42%)
- **Features**: 805 (58%)
- **In stable-6.6**: 0 (exact hash match)
- **Likely in stable-6.6**: 367 (title match)
- **Missing from stable-6.6**: 1,020 (74%)
- **Critical fixes missing**: 76

### Top Issue Types (Fixes)
1. performance: 35
2. null_pointer + crash: 18
3. regression: 16
4. race_condition: 16
5. memory_leak: 13
6. buffer_overflow: 9
7. use_after_free: 6
8. refcount: 5
9. deadlock: 5

### Top Feature Areas
1. io_operations: 80
2. protocol: 58
3. symlink: 43
4. smb_direct: 38
5. mount: 36
6. multichannel: 18
7. locking: 19
8. metadata: 19
9. caching: 17
10. dfs: 17

## Issue Type Categories

The system recognizes these issue types for fixes:

- `memory_leak`: Memory leaks and memory management issues
- `use_after_free`: Use-after-free vulnerabilities
- `null_pointer`: NULL pointer dereferences and crashes
- `buffer_overflow`: Buffer overflows and out-of-bounds access
- `data_corruption`: Data corruption issues
- `deadlock`: Deadlocks and locking issues
- `race_condition`: Race conditions and concurrency bugs
- `refcount`: Reference counting issues
- `resource_leak`: Resource leaks (file descriptors, handles)
- `crash`: Kernel crashes and panics
- `permission`: Permission and access control issues
- `performance`: Performance problems
- `regression`: Regressions from previous changes
- `security`: Security vulnerabilities (CVEs)

## Feature Area Categories

The system recognizes these feature areas:

- `directory_lease`: Directory leasing/caching
- `file_lease`: File leasing and oplocks
- `multichannel`: SMB multichannel support
- `authentication`: Authentication (Kerberos, NTLM, etc.)
- `encryption`: Encryption and signing
- `compression`: Compression support
- `caching`: File and directory caching
- `dfs`: DFS (Distributed File System)
- `symlink`: Symbolic links and reparse points
- `mount`: Mount/unmount operations
- `reconnect`: Reconnection and persistent handles
- `smb_direct`: RDMA/SMB Direct support
- `protocol`: Protocol negotiation and SMB2/SMB3
- `metadata`: Metadata operations (getattr, setattr, etc.)
- `io_operations`: I/O operations (read/write)
- `locking`: File locking
- `xattr`: Extended attributes

## Re-running Analysis

To update the database with new commits:

```bash
# Step 1: Run scan and compare
python3 << 'SCRIPT'
# ... (see the scan script in this file)
SCRIPT

# Step 2: Categorize and update database
source .venv/bin/activate
python3 categorize_commits.py \
  --analysis-file smb_backport_analysis.json \
  --db-path smb_commits.db \
  --mainline-repo /home/sprasad/repo/kernels/mainline
```

## Query Examples for Common Use Cases

### Find all directory lease related changes
```bash
python3 query_commits.py smb_commits.db --keyword "directory.*lease" --missing-only
```

### Find all multichannel fixes missing from stable
```bash
python3 query_commits.py smb_commits.db --feature-area "multichannel" --missing-only --issue-type "fix"
```

### Find all data corruption issues
```bash
python3 query_commits.py smb_commits.db --issue-type "corruption"
```

### Find reconnect-related issues
```bash
python3 query_commits.py smb_commits.db --keyword "reconnect" --show-message
```

## Direct SQL Queries

You can also query the database directly with SQL:

```bash
sqlite3 smb_commits.db
```

```sql
-- Get all fixes for a specific commit
SELECT * FROM commits WHERE fixes_commit LIKE '1234567%';

-- Find all commits in a date range missing from stable
SELECT commit_hash, patch_name, commit_date, issue_type
FROM commits
WHERE commit_date BETWEEN '2025-01-01' AND '2025-12-31'
AND NOT in_stable
AND NOT likely_in_stable
ORDER BY commit_date DESC;

-- Count commits by issue type
SELECT issue_type, COUNT(*) as cnt
FROM commits
WHERE category = 'fix'
GROUP BY issue_type
ORDER BY cnt DESC;

-- Find commits with specific keywords
SELECT commit_hash, patch_name, keywords
FROM commits
WHERE keywords LIKE '%leak%'
OR keywords LIKE '%crash%';
```

## Files

- `smb_commits.db`: SQLite database with all commit information
- `smb_backport_analysis.json`: Raw analysis results (JSON)
- `categorize_commits.py`: Script to analyze and categorize commits
- `query_commits.py`: Interactive query interface
- `CATEGORIZATION_README.md`: This file

## Notes

- The categorization is based on pattern matching in commit messages
- Multiple categories can apply to a single commit
- The "likely in stable" status is based on title similarity (not guaranteed)
- Critical fixes include those marked for stable, security fixes, crash fixes, and corruption fixes
- The database is updated incrementally - re-running won't duplicate commits
