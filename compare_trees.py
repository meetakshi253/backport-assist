#!/usr/bin/env python3

import os
import sys
import json
import re
import argparse
import logging
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import pandas as pd

from common import DEFAULT_COMMIT_PATHS, parse_repo_spec, GitRepo, setup_logging, get_repo_name

# Configure logging
logger = setup_logging(__name__)


@dataclass
class CommitInfo:
    hash: str
    title: str
    importance: str
    release: str
    comments: str
    date: datetime = None
    found_in_target: bool = False
    found_by_title: bool = False
    matching_target_hash: str = None


def title_similarity(title1: str, title2: str) -> float:
    """Compare two commit titles - exact match only."""
    # Simple exact match - kernel commit messages should be identical when backported
    return 1.0 if title1.strip() == title2.strip() else 0.0


def load_commits_from_file(file_path: str = None) -> List[Dict]:
    """Load commits from JSON or CSV file, or from stdin if file_path is None."""
    
    if file_path is None:
        # Read from stdin
        logger.info("Reading commits from stdin...")
        try:
            input_data = sys.stdin.read()
            # Try JSON first
            try:
                data = json.loads(input_data)
                logger.info("Successfully parsed commits from stdin as JSON")
                return data
            except json.JSONDecodeError:
                logger.debug("Failed to parse stdin as JSON, trying CSV...")
                # Try CSV
                import io
                df = pd.read_csv(io.StringIO(input_data))
                commits = df.to_dict('records')
                logger.info("Successfully parsed commits from stdin as CSV")
                return commits
        except Exception as e:
            logger.error(f"Failed to read from stdin: {e}")
            sys.exit(1)
    
    # Read from file
    # Try JSON first
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            logger.info(f"Successfully loaded commits from JSON file: {file_path}")
            return data
    except (json.JSONDecodeError, ValueError):
        logger.debug("Failed to parse as JSON, trying CSV...")
    
    # Fall back to CSV
    try:
        df = pd.read_csv(file_path)
        commits = df.to_dict('records')
        logger.info(f"Successfully loaded commits from CSV file: {file_path}")
        return commits
    except Exception as e:
        logger.error(f"Failed to load file as JSON or CSV: {e}")
        sys.exit(1)


def process_commits(input_path: str = None, ref_repo_spec: str = None, target_repo_spec: str = None, paths: List[str] = None, similarity_threshold: float = 0.8) -> List[CommitInfo]:
    # Parse repo specifications
    ref_repo_path, ref_repo_ref = parse_repo_spec(ref_repo_spec)
    target_repo_path, target_repo_ref = parse_repo_spec(target_repo_spec)
    
    # Use provided paths or defaults
    commit_paths = paths if paths else DEFAULT_COMMIT_PATHS
    
    ref_repo = GitRepo(ref_repo_path, ref=ref_repo_ref, paths=commit_paths)
    target_repo = GitRepo(target_repo_path, ref=target_repo_ref, paths=commit_paths)
    commits = []
    earliest_date = None

    def validate_commit_hash(hash_str: str) -> str:
        """Validate and normalize commit hash."""
        # Remove any whitespace
        hash_str = str(hash_str).strip()

        # Check if it's in scientific notation (e.g., 7.614E+11)
        try:
            if 'e+' in hash_str.lower():
                return None
        except Exception:
            return None

        # Basic validation: should be hexadecimal and at least 7 chars
        if not re.match(r'^[0-9a-f]{7,}$', hash_str, re.IGNORECASE):
            return None

        return hash_str

    # Read and validate commits from input file
    logger.info("Reading commits from input file...")
    rows = load_commits_from_file(input_path)
    earliest_commit = ""
    
    for row in rows:
        commit_hash = validate_commit_hash(row['commit'])
        if not commit_hash:
            logger.warning(f"Skipping invalid commit hash: {row['commit']}")
            continue

        commit = CommitInfo(
            hash=commit_hash,
            title=row['patch_name'].strip(),
            importance=row.get('priority', '').strip(),
            release=row.get('release', '').strip(),
            comments=row.get('comments', '').strip()
        )
        
        # Get commit date from reference repo
        commit.date = ref_repo.get_commit_date(commit.hash)
        if commit.date:
            if earliest_date is None or commit.date < earliest_date:
                earliest_date = commit.date
                earliest_commit = commit.hash

        commits.append(commit)

    if not earliest_date:
        logger.error("Could not determine earliest commit date")
        sys.exit(1)

    logger.info(f"Earliest commit date: {earliest_date.isoformat()}, commit id: {earliest_commit}")
    logger.info(f"Total commits to check: {len(commits)}")

    # First pass: Check for exact commit hashes in target
    # print("First pass: Checking for exact commit hashes...")
    # for commit in commits:
    #     if target_repo.check_commit_exists(commit.hash):
    #         commit.found_in_target = True
    #         commit.matching_target_hash = commit.hash

    # Second pass: Look for similar commit titles in target tree
    target_branch = target_repo.get_current_branch()
    logger.debug(f"Target branch: {target_branch}")
    target_commits = target_repo.get_commits_since(earliest_date, target_branch)
    logger.info(f"Found {len(target_commits)} commits in target tree since {earliest_date.isoformat()}")

    logger.info("First pass checks for the 12 digit hash, second pass checks for the title match")
    for commit in commits:
        if commit.found_in_target:
            continue

        for target_hash, target_title in target_commits:
            if target_hash[:12] == commit.hash[:12]:
                commit.found_in_target = True
                commit.matching_target_hash = target_hash
                # print(f"\nExact commit match found:")
                # print(
                #     f"Reference: {commit.hash} - {commit.title}")
                # print(
                #     f"Target   : {target_hash} - {target_title}")
                break

            similarity = title_similarity(commit.title, target_title)
            if similarity >= similarity_threshold:
                commit.found_by_title = True
                commit.matching_target_hash = target_hash
                # print(f"\nPotential title match found:")
                # print(
                #     f"Reference: {commit.hash} - {commit.title}")
                # print(
                #     f"Target   : {target_hash} - {target_title}")
                # print(f"Similarity: {similarity:.2f}")
                break

    # Print summary
    found_exact = sum(1 for c in commits if c.found_in_target)
    found_title = sum(
        1 for c in commits if not c.found_in_target and c.found_by_title)
    not_found = sum(
        1 for c in commits if not c.found_in_target and not c.found_by_title)

    logger.info("Summary:")
    logger.info(f"Commits found by hash: {found_exact}")
    logger.info(f"Additional commits found by title: {found_title}")
    logger.info(f"Commits not found: {not_found}")

    return commits


def parse_args():
    parser = argparse.ArgumentParser(
        description='Compare commits between mainline and target kernel repositories to identify backport status.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Usage Patterns:
  
  Using a configuration file:
  %(prog)s --config config.json
  %(prog)s --config config.json --output-file custom-output.json
  
  Compare commits from input file:
  %(prog)s --input-file commits.json --mainline-repo /path/to/mainline --target-repo /path/to/stable
  
  Using specific git tag or commit in repositories:
  %(prog)s --input-file commits.json --mainline-repo /path/to/mainline:v6.15 \\
           --target-repo /path/to/stable:linux-6.6.y
  %(prog)s --input-file commits.json --mainline-repo /path/to/mainline:abc123 \\
           --target-repo /path/to/stable:def456
  
  Read commits from stdin:
  cat commits.json | %(prog)s --mainline-repo /path/to/mainline --target-repo /path/to/stable
  python commit_scanner.py --start 6.6 --mainline-repo ~/mainline | \\
      %(prog)s --mainline-repo ~/mainline --target-repo ~/stable
  
  With custom output file and format:
  %(prog)s --input-file commits.csv --mainline-repo /path/to/mainline \\
           --target-repo /path/to/stable --output-file results.json --output-format json
  
  With verbose logging:
  %(prog)s --input-file commits.json --mainline-repo /path/to/mainline \\
           --target-repo /path/to/stable --verbose
  
  Track different subsystem paths:
  %(prog)s --input-file commits.json --mainline-repo /path/to/mainline \\
           --target-repo /path/to/stable --paths "fs/btrfs/"
  %(prog)s --config config.json --paths "net/core/" "drivers/net/"

Examples:
  # Compare commits from file (auto-detect JSON/CSV input)
  %(prog)s --input-file out/mainline.json --mainline-repo ~/linux-mainline \\
           --target-repo ~/linux-6.6-stable
  
  # Use specific tags/commits for comparison
  %(prog)s --input-file commits.json --mainline-repo ~/linux:v6.15 \\
           --target-repo ~/stable:linux-6.6.y
  
  # Read from stdin and output as JSON
  cat commits.json | %(prog)s --mainline-repo ~/mainline \\
      --target-repo ~/stable --output-format json
  
  # Pipeline from commit_scanner.py with specific refs
  python commit_scanner.py --start 6.6 --mainline-repo ~/mainline:v6.15 | \\
      %(prog)s --mainline-repo ~/mainline:v6.15 --target-repo ~/stable:abc123 --verbose
  
  # Specify output file
  %(prog)s --input-file commits.json --mainline-repo ~/mainline \\
           --target-repo ~/stable --output-file backport-status.json
        ''')
    
    parser.add_argument('--config', type=str, metavar='FILE',
                        help='path to JSON configuration file')
    parser.add_argument('--input-file', type=str, metavar='FILE',
                        help='input file containing commits (JSON or CSV format). If not specified, reads from stdin')
    parser.add_argument('--mainline-repo', type=str, metavar='PATH',
                        help='path to mainline/reference Linux kernel repository - required if not using --config. '
                             'Can specify PATH:TAG format where TAG is a git tag or commit hash to use instead of current HEAD')
    parser.add_argument('--target-repo', type=str, metavar='PATH',
                        help='path to target Linux kernel repository (e.g., stable branch) - required if not using --config. '
                             'Can specify PATH:TAG format where TAG is a git tag or commit hash to use instead of current HEAD')
    parser.add_argument('--output-file', type=str, metavar='PATH',
                        help='output file path (prints to stdout if not specified)')
    parser.add_argument('--output-format', type=str, choices=['csv', 'json'], default='json', metavar='FORMAT',
                        help='output format: csv or json (default: json)')
    parser.add_argument('--paths', nargs='+', type=str, metavar='PATH',
                        help='paths to track in the repository (space-separated, e.g., "fs/cifs/" "fs/smb/client/"). '
                             'Defaults to CIFS/SMB paths if not specified')
    parser.add_argument('--verbose', action='store_true',
                        help='enable verbose/debug logging')
    
    return parser.parse_args()


def load_config(args) -> Dict:
    """Load configuration from file or command-line arguments.
    Command-line arguments override config file values.
    
    Returns:
        config dict
    """
    if args.config:
        # Load from config file
        with open(args.config) as f:
            config = json.load(f)
        
        # Override config file values with command-line arguments if provided
        if args.input_file:
            config['input_file'] = args.input_file
        if args.mainline_repo:
            config['mainline_repo'] = args.mainline_repo
        if args.target_repo:
            config['target_repo'] = args.target_repo
        if args.output_file:
            config['output_file'] = args.output_file
        if args.output_format != 'json':  # Only override if explicitly set
            config['output_format'] = args.output_format
        if args.paths:
            config['paths'] = args.paths
        
        return config
    else:
        # Build config from command-line arguments
        if not args.mainline_repo:
            logger.error("--mainline-repo is required when not using --config")
            sys.exit(1)
        if not args.target_repo:
            logger.error("--target-repo is required when not using --config")
            sys.exit(1)
        
        config = {
            'input_file': args.input_file,
            'mainline_repo': args.mainline_repo,
            'target_repo': args.target_repo,
            'output_file': args.output_file,
            'output_format': args.output_format,
            'paths': args.paths if args.paths else DEFAULT_COMMIT_PATHS,
        }
        
        return config


def main():
    args = parse_args()
    
    # Set log level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(args)
    
    # Pass values from config
    commits = process_commits(
        config.get('input_file'),
        config['mainline_repo'],
        config['target_repo'],
        paths=config.get('paths', DEFAULT_COMMIT_PATHS)
    )

    # Create out directory if it doesn't exist
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')
    os.makedirs(out_dir, exist_ok=True)

    # Parse repo specs to get paths and refs
    ref_repo_path, ref_repo_ref = parse_repo_spec(config['mainline_repo'])
    target_repo_path, target_repo_ref = parse_repo_spec(config['target_repo'])

    # Get repo names and current branches
    ref_repo = GitRepo(ref_repo_path, ref=ref_repo_ref)
    target_repo = GitRepo(target_repo_path, ref=target_repo_ref)

    ref_name = get_repo_name(ref_repo_path)
    target_name = get_repo_name(target_repo_path)
    ref_branch = ref_repo_ref if ref_repo_ref else ref_repo.get_current_branch()
    target_branch = target_repo_ref if target_repo_ref else target_repo.get_current_branch()

    logger.info(f"Reference repository: {ref_name} (branch: {ref_branch})")
    logger.info(f"Target repository: {target_name} (branch: {target_branch})")

    # Prepare data for output
    output_data = []
    for c in commits:
        output_data.append({
            'release': c.release,
            'commit': c.hash,
            'patch_name': c.title,
            'priority': c.importance,
            'comments': c.comments,
            'found': 'yes' if (c.found_in_target or c.found_by_title) else 'no',
            'target_commit': c.matching_target_hash if (c.found_in_target or c.found_by_title) else '',
            'date': c.date.isoformat() if c.date else ''
        })

    # Output results
    output_file = config.get('output_file')
    output_format = config.get('output_format', 'json')
    
    if output_file:
        # Write to file
        if output_format == 'json':
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
        else:  # csv
            df = pd.DataFrame(output_data)
            df.to_csv(output_file, index=False)
        logger.info(f"Results written to: {output_file}")
    else:
        # Write to stdout
        if output_format == 'json':
            print(json.dumps(output_data, indent=2))
        else:  # csv
            df = pd.DataFrame(output_data)
            print(df.to_csv(index=False))


if __name__ == "__main__":
    main()
