#!/usr/bin/env python3
"""Common utilities shared between commit_scanner.py and compare_trees.py"""

import os
import sys
import re
import subprocess
import logging
from typing import List, Tuple, Optional
from datetime import datetime

# Default paths for CIFS/SMB subsystem - can be overridden via config
DEFAULT_COMMIT_PATHS = [
    "fs/cifs/",
    "fs/smb/client/",
    "fs/netfs/"
]


def setup_logging(name: str = __name__):
    """Setup and return a logger with standard configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s',
        stream=sys.stderr
    )
    return logging.getLogger(name)


def parse_repo_spec(repo_spec: str) -> Tuple[str, str]:
    """Parse repository specification in PATH:TAG format.
    
    Args:
        repo_spec: Repository path, optionally followed by :TAG where TAG is a git tag or commit hash
        
    Returns:
        tuple: (repo_path, ref) where ref is None if not specified
    """
    if ':' in repo_spec:
        parts = repo_spec.split(':', 1)
        return parts[0], parts[1]
    return repo_spec, None


def get_repo_name(repo_path: str) -> str:
    """Extract repository name from path."""
    # Remove trailing slash if present
    repo_path = repo_path.rstrip('/')
    # Get the last component of the path
    return os.path.basename(repo_path)


class GitRepo:
    """Unified Git repository operations for both commit_scanner and compare_trees."""
    
    def __init__(self, repo_path: str, default_branch: str = None, ref: str = None, paths: List[str] = None):
        self.repo_path = repo_path
        self.default_branch = default_branch
        self.ref = ref  # Optional specific ref (tag or commit hash) to use
        self.paths = paths if paths else DEFAULT_COMMIT_PATHS
        if not os.path.exists(os.path.join(repo_path, ".git")):
            raise ValueError(f"Not a git repository: {repo_path}")
        
        # Get logger from the calling module
        self.logger = logging.getLogger(__name__)
        
        # Validate ref if specified
        if self.ref:
            try:
                subprocess.run(
                    ["git", "rev-parse", "--verify", self.ref],
                    cwd=self.repo_path,
                    check=True,
                    capture_output=True,
                    text=True
                )
            except subprocess.CalledProcessError:
                raise ValueError(f"Invalid git reference: {self.ref}")
        
        # Ensure clean state only if default_branch is set and no ref is specified
        if self.default_branch and not self.ref:
            self.ensure_clean_state()

    def ensure_clean_state(self):
        """Ensure the repo is in a clean state and on the default branch."""
        # Check if there are any uncommitted changes
        if self.run_git(["status", "--porcelain"]):
            raise ValueError(
                f"Repository has uncommitted changes: {self.repo_path}")

        # Checkout default branch if needed
        current_branch = self.run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        if current_branch != self.default_branch:
            self.run_git(["checkout", self.default_branch])

    def run_git(self, args: List[str]) -> str:
        """Execute a git command and return its output."""
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Git command failed: {' '.join(['git'] + args)}")
            self.logger.error(f"Error: {e.stderr}")
            sys.exit(1)

    def get_commit_date(self, commit_hash: str) -> datetime:
        """Get the commit date for a given hash."""
        try:
            timestamp = self.run_git(
                ["show", "-s", "--format=%at", commit_hash])
            return datetime.fromtimestamp(int(timestamp))
        except Exception as e:
            self.logger.warning(f"Could not get date for commit {commit_hash}: {e}")
            return None

    def check_commit_exists(self, commit_hash: str) -> bool:
        """Check if a commit exists in the repository."""
        try:
            # Use cat-file to verify it's a valid commit object
            self.run_git(["cat-file", "-e", f"{commit_hash}^{{commit}}"])
            # Get the full hash to ensure it's not ambiguous
            full_hash = self.run_git(
                ["rev-parse", "--verify", f"{commit_hash}^{{commit}}"])
            return bool(full_hash)
        except Exception:
            return False

    def get_current_branch(self) -> str:
        """Get the name of the current branch."""
        try:
            return self.run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        except Exception:
            return "unknown"

    def get_release_tag(self, commit_hash: str) -> Optional[str]:
        """Get the first release tag that contains this commit."""
        try:
            self.logger.debug(f"Getting release tag for commit {commit_hash}")
            result = self.run_git([
                "tag",
                "--sort=creatordate",
                "--contains", commit_hash
            ])
            if not result:
                return ""
            
            # Filter for version tags matching v[1-9]*\.[0-9]* (e.g., v6.12, v6.12.1)
            # Exclude rc, pre-release, or other suffixes
            pattern = re.compile(r'^v[1-9][0-9]*\.[0-9]+(\.[0-9]+)*$')
            for tag in result.split('\n'):
                tag = tag.strip()
                if tag and pattern.match(tag):
                    self.logger.debug(f"Got release tag for commit {commit_hash}: {tag}")
                    return tag
            return ""
        except Exception as e:
            self.logger.debug(f"Failed to get release tag for commit {commit_hash}: {e}")
            return ""

    def find_version_commit(self, version: str) -> Optional[str]:
        """Find commit hash for a kernel version, trying both tag and release message."""
        # Try as a tag first
        if version.startswith('v'):
            tag = version
        else:
            tag = f"v{version}"

        # First try exact tag match
        try:
            return self.run_git(["rev-parse", "--verify", tag])
        except Exception:
            # Try tag pattern match (for cases like v6.15 matching v6.15.0)
            try:
                tags = self.run_git(["tag", "-l", f"{tag}*"])
                if tags:
                    # Use the first matching tag (should be the base version)
                    return self.run_git(["rev-parse", "--verify", tags.split('\n')[0]])
            except Exception:
                pass

            # Try finding Linus' release commit
            try:
                # Look for exact "Linux x.y" commit by Linus
                commits = self.run_git([
                    "log", "-1",
                    "--format=%H",
                    "--author=Torvalds",
                    "--fixed-strings",  # Treat pattern as literal string
                    "--grep", f"Linux {version}",
                    "--grep-reflog", "Merge tag"  # Exclude merge tag messages
                    "--invert-grep"  # Exclude merge tag messages
                ])
                if commits:
                    # Verify it's an exact release message
                    commit_msg = self.run_git(
                        ["log", "-1", "--format=%s", commits.split('\n')[0]])
                    if commit_msg.strip() == f"Linux {version}":
                        self.logger.info(f"Found release commit for version {version}: {commits.split('\n')[0]}")
                        return commits.split('\n')[0]
                return None
            except Exception:
                return None

    def get_commits_since(self, date: datetime, branchname: str = None) -> List[Tuple[str, str]]:
        """Get all relevant commits since the given date, returns list of (hash, title) tuples."""
        format_str = "%H%x00%s"
        commits = []
        
        # Use self.ref if specified, otherwise use provided branchname
        ref_to_use = self.ref if self.ref else branchname
        
        self.logger.debug(f"Scanning paths: {self.paths}")
        
        # Run git log once with all paths
        log_data = self.run_git([
            "log",
            ref_to_use,
            f"--since={date.isoformat()}",
            "--format=" + format_str,
            "--no-merges",  # Exclude merge commits
            "--"
        ] + self.paths)
        
        for line in log_data.split('\n'):
            if not line.strip():
                continue
            commit_hash, title = line.split('\x00')
            commits.append((commit_hash, title))
        return commits
