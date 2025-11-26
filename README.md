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
```

**Options:**
- `--config CONFIG_FILE`: Path to JSON configuration file
- `--no-filter`: Return all CIFS commits without filtering
- `--start VERSION`: Start version (exclusive) - required if not using --config
- `--end VERSION`: End version (inclusive), defaults to HEAD
- `--mainline-repo PATH`: Path to mainline Linux kernel repository - required if not using --config
- `--output-file PATH`: Output file path
- `--output-format FORMAT`: Output format: csv or json (default: json)
- `--default-branch BRANCH`: Default git branch (defaults to master)
- `--emails EMAIL [EMAIL ...]`: Important author email addresses
- `--keywords KEYWORD [KEYWORD ...]`: Keywords to search for in commit messages

Run `python commit_scanner.py --help` for more details.

### `compare_trees.py`
Compares commits between mainline and target kernel repositories to identify backport status. Reads commit data from a file or stdin, checks if commits exist in the target repository, and outputs the backport status.

**Usage with input file:**
```bash
python compare_trees.py --input-file commits.json \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable

# With custom output file and format
python compare_trees.py --input-file commits.csv \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable \
    --output-file results.json --output-format json

# With verbose logging
python compare_trees.py --input-file commits.json \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable --verbose
```

**Usage with stdin (pipeline):**
```bash
# Read from stdin
cat commits.json | python compare_trees.py \
    --mainline-repo /path/to/mainline --target-repo /path/to/stable

# Pipeline from commit_scanner.py
python commit_scanner.py --start 6.6 --mainline-repo ~/mainline | \
    python compare_trees.py --mainline-repo ~/mainline --target-repo ~/stable
```

**Options:**
- `--input-file FILE`: Input file containing commits (JSON or CSV format). If not specified, reads from stdin
- `--mainline-repo PATH`: Path to mainline/reference Linux kernel repository (required)
- `--target-repo PATH`: Path to target Linux kernel repository, e.g., stable branch (required)
- `--output-file PATH`: Output file path (prints to stdout if not specified)
- `--output-format FORMAT`: Output format: csv or json (default: json)
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
```
