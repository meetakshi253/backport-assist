#!/usr/bin/env python3

import os
import sys
import json
import re
import argparse
import logging
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import pandas as pd

from common import DEFAULT_COMMIT_PATHS, parse_repo_spec, GitRepo, setup_logging

# Configure logging
logger = setup_logging(__name__)

NOFILTER = False

@dataclass
class Commit:
    hash: str
    author_name: str
    author_email: str
    subject: str
    body: str
    date: datetime
    release: str = None

    @property
    def message(self) -> str:
        return f"{self.subject}\n\n{self.body}"


def get_cifs_commits(repo: GitRepo, start_ref: str, end_ref: str = "HEAD") -> List[Commit]:
    """Get all commits between start_ref and end_ref in the tracked paths

    The range is exclusive of start_ref and inclusive of end_ref
    in the paths of interest.
    For example, with start=v6.14 and end=v6.15, this will return
    all commits that went into 6.15 (everything after 6.14 tag up
    to and including 6.15 tag)."""
    # Use repo.ref if specified, otherwise use end_ref
    actual_end_ref = repo.ref if repo.ref else end_ref
    logger.info(f"Getting commits from {start_ref} to {actual_end_ref}...")
    logger.debug(f"Tracking paths: {repo.paths}")
    format_str = "%H%x00%an%x00%ae%x00%at%x00%s%x00%b%x1e"
    commits = []
    paths = repo.paths.copy()
    paths.append("Makefile")  # Also add Makefile to track version bumps
    logger.debug(f"Paths to scan: {paths}")
    
    # Run git log once with all paths
    log_data = repo.run_git([
        "log",
        f"{start_ref}..{actual_end_ref}",
        "--format=" + format_str,
        "--reverse",
        "--no-merges",
        "--"
    ] + paths)

    logger.debug(f"Raw log data length: {len(log_data.split('\x1e'))}")

    # Cache the current release tag to avoid repeated git calls
    current_release = None
    
    for entry in log_data.split("\x1e"):
        if not entry.strip():
            continue
        parts = entry.split("\x00")
        if len(parts) >= 6:
            commit_hash = parts[0].strip()
            commit_subject = parts[4].strip()

            # Skip Makefile version bump commits
            if re.match(r'Linux \d+\.\d+(\.\d+)?$', commit_subject):
                logger.debug(f"Skipping Makefile version bump commit: {commit_hash}: {commit_subject}")
                current_release = None  # Reset cached release
                continue

            # Check if we need to update the cached release
            if current_release is None:
                # First commit - get the release tag
                current_release = repo.get_release_tag(commit_hash)
            
            commits.append(Commit(
                hash=commit_hash,
                author_name=parts[1].strip(),
                author_email=parts[2].strip(),
                date=datetime.fromtimestamp(int(parts[3])),
                subject=parts[4].strip(),
                body=parts[5],
                release=current_release
            ))
    return commits


class CommitScanner:
    def __init__(self, config: Dict):
        self.config = config

        # Get optional ref from config
        repo_ref = config.get('mainline_repo_ref')
        
        # Get paths from config or use defaults
        paths = config.get('paths', DEFAULT_COMMIT_PATHS)
        
        self.repo = GitRepo(
            self.config['mainline_repo'],
            self.config.get('default_branch', 'master'),
            ref=repo_ref,
            paths=paths
        )
        self.important_emails = set(self.config['emails'])
        self.keywords = [k.lower() for k in self.config['keywords']]

    def is_cifs_commit(self, commit: Commit) -> bool:
        """Check if commit is related to CIFS subsystem."""
        message = commit.message.lower()
        return any(x in message for x in ['cifs:', 'smb3:', 'smb2:', "smb:", "smb/client"])

    def is_marked_for_stable(self, commit: Commit) -> bool:
        """Check if commit is marked for stable."""
        return ("stable@vger.kernel.org" in commit.body)

    def commits_to_df(self, commits: List[Commit], reasons: List[str] | None) -> pd.DataFrame:
        """Convert list of commits to a pandas DataFrame."""
        df = pd.DataFrame(columns=[
            'release', 'commit', 'patch_name', 'author_name', 'author_email', 'date', 'body', 'reasons'
        ])

        if reasons is None:
            reasons = [[] for _ in commits]

        for c, r in zip(commits, reasons):
            new_row = [{
                'release': c.release if c.release else "",
                'commit': c.hash,
                'patch_name': c.subject,
                'author_name': c.author_name,
                'author_email': c.author_email,
                'date': c.date,
                'body': c.body,
                'reasons': r,
                'priority': "",
                'comments': ""
            }]
            df = df._append(new_row, ignore_index=True)
        return df

    def is_important_first_pass(self, commit: Commit) -> tuple[bool, List[str]]:
        """First pass filter for important commits.
        Returns (is_important, reasons) tuple where reasons is a list of
        all reasons why this commit is considered important."""
        message = commit.message.lower()
        reasons = []

        # Check author
        if commit.author_email in self.important_emails:
            reasons.append(f"IMP AUTHOR: {commit.author_name}")

        # Check for stable tag
        if self.is_marked_for_stable(commit):
            reasons.append("CC STABLE")

        # Check keywords
        for keyword in self.keywords:
            if keyword in message:
                reasons.append(f"KEYWORD: {keyword}")

        return bool(reasons), reasons

    def get_fixes_hash(self, commit: Commit) -> Set[str]:
        """Extract commit hashes from Fixes: tags."""
        fixes = set()
        for line in commit.message.split('\n'):
            # Match both full and partial hashes in Fixes: tags
            match = re.search(r'Fixes:\s+([0-9a-f]{7,40})(?:\s|$|\()', line)
            if match:
                fix_hash = match.group(1)
                # Store both the exact hash and its prefix for matching
                fixes.add(fix_hash)
                if len(fix_hash) > 12:
                    fixes.add(fix_hash[:12])
        return fixes

    def scan_commits(self) -> List[Dict]:
        # Get commit range (start version is exclusive, end version is inclusive)
        start_version = self.config['start']  # commits after this version
        # commits up to and including this version
        end_version = self.config.get('end', 'HEAD')

        logger.info(f"Scanning commits after {start_version} (not inclusive) to {end_version} (inclusive)...")

        start_commit = self.repo.find_version_commit(start_version)
        if not start_commit:
            logger.error(f"Could not find start version: {start_version}")
            sys.exit(1)

        if end_version != "HEAD":
            end_commit = self.repo.find_version_commit(end_version)
            if not end_commit:
                logger.error(f"Could not find end version: {end_version}")
                sys.exit(1)
        else:
            end_commit = "HEAD"

        # Get all commits in range
        cifs_commits = get_cifs_commits(self.repo, start_commit, end_commit)
        logger.info(f"Found {len(cifs_commits)} total cifs-relevant commits")

        if NOFILTER:
            logger.info("NOFILTER is set - returning all CIFS commits as important")
            return self.commits_to_df(cifs_commits, None)

        # First pass - direct importance
        important_commits = []
        important_hashes = set()
        stable_commits = []

        for commit in cifs_commits:
            is_important, reasons = self.is_important_first_pass(commit)
            if is_important:
                important_commits.append((commit, reasons))
                important_hashes.add(commit.hash.strip())
                # Print extra info for commits that are both by important authors and marked for stable
                if "IMP AUTHOR" in reasons and "CC STABLE" in reasons:
                    logger.debug(f"Found commit marked for stable by important author:")
                    logger.debug(f"  Hash: {commit.hash}")
                    logger.debug(f"  Author: {commit.author_name} <{commit.author_email}>")
                    logger.debug(f"  Subject: {commit.subject}")
                    logger.debug(f"  Reasons: {', '.join(reasons)}")

        logger.info(f"First pass: found {len(important_commits)} important commits")

        # Second pass - fixes
        initial_count = len(important_commits)
        for commit in cifs_commits:
            if commit in important_commits:
                continue

            fixes = self.get_fixes_hash(commit)
            # Check if any of our important commits start with any of the fix hashes
            is_fix = False
            for imp_hash in important_hashes:
                if any(imp_hash.startswith(fix) or fix.startswith(imp_hash) for fix in fixes):
                    is_fix = True
                    break
            if is_fix:
                important_commits.append((commit, ["IMP FIXES"]))

        logger.info(f"Second pass: found {len(important_commits) - initial_count} additional fix commits")
        logger.info(f"Total important commits: {len(important_commits)}")

        # Print summary of stable commits
        if stable_commits:
            logger.info(f"Found {len(stable_commits)} commits marked for stable")

        # Create a dataframe-like output
        return self.commits_to_df([c[0] for c in important_commits], [c[1] for c in important_commits])


def parse_args():
    parser = argparse.ArgumentParser(
        description='Scan Linux kernel commits for important CIFS/SMB changes.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Usage Patterns:
  
  1. Using a configuration file:
     %(prog)s --config config.json
     %(prog)s --config config.json --no-filter
  
  2. Using command-line arguments (requires --start and --mainline-repo):
     %(prog)s --start 6.6 --mainline-repo /path/to/linux
     %(prog)s --start 6.6 --end 6.15 --mainline-repo /path/to/linux \\
              --output-file out/commits.json --output-format json
  
  3. Using specific git tag or commit in repository:
     %(prog)s --start 6.6 --mainline-repo /path/to/linux:v6.15
     %(prog)s --start 6.6 --mainline-repo /path/to/linux:abc123def
  
  4. With filtering options (when not using --config):
     %(prog)s --start 6.6 --mainline-repo /path/to/linux \\
              --emails user1@example.com user2@example.com \\
              --keywords CVE regression "memory leak" crash
  
  5. Track different subsystem paths:
     %(prog)s --start 6.6 --mainline-repo /path/to/linux \\
              --paths "fs/btrfs/" --emails user@example.com
     %(prog)s --start 6.6 --mainline-repo /path/to/linux \\
              --paths "net/core/" "drivers/net/" "include/net/"
  
  Note: When using command-line arguments without --emails or --keywords,
        filtering is automatically disabled (equivalent to --no-filter).

Examples:
  # Scan all CIFS commits between v6.6 and HEAD (no filtering, default JSON output)
  %(prog)s --start 6.6 --mainline-repo ~/linux
  
  # Scan with specific filters and CSV output
  %(prog)s --start 6.6 --mainline-repo ~/linux \\
           --emails maintainer@example.com \\
           --keywords CVE "use-after-free" regression \\
           --output-format csv
  
  # Use specific git tag or commit as endpoint
  %(prog)s --start 6.6 --mainline-repo ~/linux:v6.15
  %(prog)s --start 6.6 --mainline-repo ~/linux:abc123def456
  
  # Track different subsystem (e.g., btrfs filesystem)
  %(prog)s --start 6.6 --mainline-repo ~/linux --paths "fs/btrfs/"
  
  # Track multiple networking subsystems
  %(prog)s --start 6.6 --mainline-repo ~/linux \\
           --paths "net/core/" "drivers/net/ethernet/" --emails netdev@example.com
  
  # Use config file with explicit no-filter and output to JSON file
  %(prog)s --config config.json --no-filter --output-file out/commits.json
        ''')
    
    parser.add_argument('--config', type=str, metavar='FILE',
                        help='path to JSON configuration file (mutually exclusive with --start/--mainline-repo)')
    parser.add_argument('--no-filter', action='store_true',
                        help='disable filtering and return all CIFS commits')
    
    # Individual config options
    parser.add_argument('--start', type=str, metavar='VERSION',
                        help='start version (exclusive) - required if not using --config')
    parser.add_argument('--end', type=str, default='HEAD', metavar='VERSION',
                        help='end version (inclusive), defaults to HEAD')
    parser.add_argument('--mainline-repo', type=str, metavar='PATH',
                        help='path to mainline Linux kernel repository - required if not using --config. '
                             'Can specify PATH:TAG format where TAG is a git tag or commit hash to use instead of HEAD')
    parser.add_argument('--output-file', type=str, metavar='PATH',
                        help='output file path (prints to stdout if not specified)')
    parser.add_argument('--output-format', type=str, choices=['csv', 'json'], default='json', metavar='FORMAT',
                        help='output format: csv or json (default: json)')
    parser.add_argument('--default-branch', type=str, default='master', metavar='BRANCH',
                        help='default git branch (default: master)')
    parser.add_argument('--emails', nargs='+', type=str, metavar='EMAIL',
                        help='important author email addresses (space-separated)')
    parser.add_argument('--keywords', nargs='+', type=str, metavar='KEYWORD',
                        help='keywords to search for in commit messages (space-separated, use quotes for multi-word)')
    parser.add_argument('--paths', nargs='+', type=str, metavar='PATH',
                        help='paths to track in the repository (space-separated, e.g., "fs/cifs/" "fs/smb/client/"). '
                             'Defaults to CIFS/SMB paths if not specified')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='enable verbose debug logging')
    
    return parser.parse_args()


def load_config(args) -> tuple[Dict, bool]:
    """Load configuration from file or command-line arguments.
    Command-line arguments override config file values.
    
    Returns:
        tuple: (config dict, should_apply_nofilter bool)
    """
    should_apply_nofilter = False
    
    if args.config:
        # Load from config file
        with open(args.config) as f:
            config = json.load(f)
        
        # Override config file values with command-line arguments if provided
        if args.start:
            config['start'] = args.start
        if args.end != 'HEAD':  # Only override if explicitly set
            config['end'] = args.end
        if args.mainline_repo:
            repo_path, repo_ref = parse_repo_spec(args.mainline_repo)
            config['mainline_repo'] = repo_path
            config['mainline_repo_ref'] = repo_ref
        if args.output_file:
            config['output_file'] = args.output_file
        if args.default_branch != 'master':  # Only override if explicitly set
            config['default_branch'] = args.default_branch
        if args.emails:
            config['emails'] = args.emails
        if args.keywords:
            config['keywords'] = args.keywords
        if args.paths:
            config['paths'] = args.paths
        
        return config, should_apply_nofilter
    else:
        # Build config from command-line arguments
        if not args.start:
            logger.error("--start is required when not using --config")
            sys.exit(1)
        if not args.mainline_repo:
            logger.error("--mainline-repo is required when not using --config")
            sys.exit(1)
        
        # Parse mainline_repo to extract path and optional ref
        repo_path, repo_ref = parse_repo_spec(args.mainline_repo)
        
        config = {
            'start': args.start,
            'end': args.end,
            'mainline_repo': repo_path,
            'mainline_repo_ref': repo_ref,  # Store the ref separately
            'default_branch': args.default_branch,
            'emails': args.emails if args.emails else [],
            'keywords': args.keywords if args.keywords else [],
            'paths': args.paths if args.paths else DEFAULT_COMMIT_PATHS,
        }
        
        if args.output_file:
            config['output_file'] = args.output_file
        
        # If neither emails nor keywords are specified, implicitly enable no-filter
        if not args.emails and not args.keywords:
            should_apply_nofilter = True
        
        return config, should_apply_nofilter


def main():
    global NOFILTER
    
    args = parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration
    config, implicit_nofilter = load_config(args)
    
    # Set NOFILTER based on command-line flag or implicit detection
    if args.no_filter or implicit_nofilter:
        NOFILTER = True
        if implicit_nofilter:
            logger.info("No emails or keywords specified - running without filters")
    
    scanner = CommitScanner(config)
    important_commits = scanner.scan_commits()

    # Determine output format
    output_format = args.output_format
    
    # Sanitize data for CSV format by removing commas from fields
    if output_format == 'csv':
        # Replace commas with empty string in all string/object columns
        for col in important_commits.select_dtypes(include=['object']).columns:
            important_commits[col] = important_commits[col].apply(
                lambda x: str(x).replace(',', '') if pd.notna(x) else x
            )
    
    # Get output file from config or use stdout
    output_file = scanner.config.get('output_file')
    if output_file:
        output_file = os.path.abspath(output_file)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        if output_format == 'json':
            important_commits.to_json(output_file, orient='records', indent=2)
        else:  # csv
            important_commits.to_csv(output_file, index=True)
        
        logger.info(f"Results written to: {output_file}")
        logger.info(f"Important commits: {len(important_commits)}")
    else:
        # Output results to stdout if no file specified
        if output_format == 'json':
            print(important_commits.to_json(orient='records', indent=2))
        else:  # csv
            print(important_commits.to_csv(index=True))


if __name__ == "__main__":
    main()
