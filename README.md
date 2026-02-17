# Backport Assist

A tool to help identify backport status using commit scanning and tree comparison.

## Setup

1. Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Components

### `commit_scanner.py`
Scans the commit history of the Linux kernel to identify important CIFS/SMB commits.

**Usage with config file:**
```bash
python commit_scanner.py --config config.json
python commit_scanner.py --config config.json --no-filter

# Override config file options with command-line arguments
python commit_scanner.py --config config.json --start 6.8 --output-file custom.json
python commit_scanner.py --config config.json --mainline-repo /different/path:v6.15
```

**Usage with command-line arguments:**
```bash
python commit_scanner.py --start 6.6 --end HEAD \
    --mainline-repo /path/to/linux \
    --emails user@example.com \
    --keywords CVE regression "memory leak" \
    --output-file out/mainline.json

# Without filtering, output as CSV
python commit_scanner.py --start 6.6 --mainline-repo /path/to/linux \
    --emails user@example.com --keywords CVE \
    --no-filter --output-format csv

# Use specific git tag or commit as endpoint
python commit_scanner.py --start 6.6 --mainline-repo /path/to/linux:v6.15
python commit_scanner.py --start 6.6 --mainline-repo /path/to/linux:abc123def

# Track different subsystem (e.g., btrfs filesystem)
python commit_scanner.py --start 6.6 --mainline-repo /path/to/linux \
    --paths "fs/btrfs/" --emails btrfs-maintainer@example.com

# Track multiple networking subsystems
python commit_scanner.py --start 6.6 --mainline-repo /path/to/linux \
    --paths "net/core/" "drivers/net/ethernet/" --emails netdev@example.com
```

**Options:**
- `--config CONFIG_FILE`: Path to JSON configuration file. Command-line arguments override config file values
- `--no-filter`: Return all CIFS commits without filtering
- `--start VERSION`: Start version (exclusive) - required if not using --config
- `--end VERSION`: End version (inclusive), defaults to HEAD
- `--mainline-repo PATH[:TAG]`: Path to mainline Linux kernel repository - required if not using --config. Can specify PATH:TAG format where TAG is a git tag or commit hash to use instead of HEAD
- `--output-file PATH`: Output file path
- `--output-format FORMAT`: Output format: csv or json (default: json)
- `--default-branch BRANCH`: Default git branch (defaults to master)
- `--emails EMAIL [EMAIL ...]`: Important author email addresses
- `--keywords KEYWORD [KEYWORD ...]`: Keywords to search for in commit messages
- `--paths PATH [PATH ...]`: Paths to track in the repository (defaults to CIFS/SMB paths: fs/cifs/, fs/smb/client/, fs/netfs/)
- `--verbose`, `-v`: Enable verbose debug logging

Run `python commit_scanner.py --help` for more details.

### `compare_trees.py`
Compares commits between mainline and target kernel repositories to identify backport status. Reads commit data from a file or stdin, checks if commits exist in the target repository, and outputs the backport status.

**Usage with config file:**
```bash
python compare_trees.py --config config.json

# Override config file options with command-line arguments
python compare_trees.py --config config.json --output-file custom-results.json
python compare_trees.py --config config.json --target-repo /different/stable:linux-6.6.y
```

**Usage with input file:**
```bash
python compare_trees.py --input-file commits.json \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable

# With custom output file and format
python compare_trees.py --input-file commits.csv \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable \
    --output-file results.json --output-format json

# Use specific git tags or commits for comparison
python compare_trees.py --input-file commits.json \
    --mainline-repo /path/to/mainline:v6.15 \
    --target-repo /path/to/stable:linux-6.6.y

# With verbose logging
python compare_trees.py --input-file commits.json \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable --verbose

# Track different subsystem paths
python compare_trees.py --input-file commits.json \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable \
    --paths "fs/btrfs/"
```

**Usage with stdin (pipeline):**
```bash
# Read from stdin
cat commits.json | python compare_trees.py \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable

# Pipeline from commit_scanner.py
python commit_scanner.py --start 6.6 --mainline-repo ~/mainline | \
    python compare_trees.py --mainline-repo ~/mainline --target-repo ~/stable

# Pipeline with specific refs
python commit_scanner.py --start 6.6 --mainline-repo ~/mainline:v6.15 | \
    python compare_trees.py --mainline-repo ~/mainline:v6.15 \
    --target-repo ~/stable:abc123
```

**Options:**
- `--config FILE`: Path to JSON configuration file. Command-line arguments override config file values
- `--input-file FILE`: Input file containing commits (JSON or CSV format). If not specified, reads from stdin
- `--mainline-repo PATH[:TAG]`: Path to mainline/reference Linux kernel repository - required if not using --config. Can specify PATH:TAG format where TAG is a git tag or commit hash to use instead of current HEAD
- `--target-repo PATH[:TAG]`: Path to target Linux kernel repository, e.g., stable branch - required if not using --config. Can specify PATH:TAG format where TAG is a git tag or commit hash to use instead of current HEAD
- `--output-file PATH`: Output file path (prints to stdout if not specified)
- `--output-format FORMAT`: Output format: csv or json (default: json)
- `--paths PATH [PATH ...]`: Paths to track in the repository (defaults to CIFS/SMB paths: fs/cifs/, fs/smb/client/, fs/netfs/)
- `--verbose`: Enable verbose/debug logging

Run `python compare_trees.py --help` for more details.

## Using Git Worktrees

Git worktrees are particularly useful for this workflow, as they allow you to maintain multiple branches in separate directories without needing to clone the repository multiple times.

Example usage:

```bash
# Setup repositories
git clone <stable-repo-url>
git worktree add ../linux-6.12-stable linux-6.12.y
git worktree add ../linux-6.6-stable linux-6.6.y
git worktree add ../linux-mainline mainline # can use Linus' repo

# Setup Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Scan commits
python commit_scanner.py --config config.json --no-filter
# Or use command-line arguments
python commit_scanner.py --start 6.6 --mainline-repo ../linux-mainline \
    --emails user@example.com --keywords CVE \
    --output-file out/mainline.json

# Compare trees
python compare_trees.py --input-file out/mainline.json \
    --mainline-repo ../linux-mainline --target-repo ../linux-6.6-stable

# Or use a pipeline (both default to JSON on stdout/stdin)
python commit_scanner.py --start 6.6 --mainline-repo ../linux-mainline \
    --emails user@example.com --keywords CVE | \
    python compare_trees.py --mainline-repo ../linux-mainline \
    --target-repo ../linux-6.6-stable --output-file backport-status.json

# Use specific tags/commits for comparison
python commit_scanner.py --start 6.6 --mainline-repo ../linux-mainline:v6.15 | \
    python compare_trees.py --mainline-repo ../linux-mainline:v6.15 \
    --target-repo ../linux-6.6-stable:linux-6.6.y --output-file backport-status.json
```
