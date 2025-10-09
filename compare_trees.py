#!/usr/bin/env python3

import os
import sys
import csv
import json
import re
import subprocess
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from datetime import datetime

# Configure the subsystems to track
TRACKED_SUBSYSTEMS = {
    'cifs',    # CIFS/SMB client
    'smb',     # SMB-related changes
    'netfs',   # Network filesystem framework
    'ksmbd',   # In-kernel SMB server
}


def is_relevant_commit(title: str) -> bool:
    """Check if a commit is relevant based on its title."""
    # Convert title to lowercase for case-insensitive matching
    title_lower = title.lower()

    # Check if the commit title starts with any of our tracked subsystems
    return any(
        title_lower.startswith(f"{subsys}:") or
        title_lower.startswith(f"[{subsys}]") or
        title_lower.startswith(f"fs/{subsys}:")
        for subsys in TRACKED_SUBSYSTEMS
    )


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


class GitRepo:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        if not os.path.exists(os.path.join(repo_path, ".git")):
            raise ValueError(f"Not a git repository: {repo_path}")

    def run_git(self, args: List[str]) -> str:
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
            print(
                f"Git command failed: {' '.join(['git'] + args)}", file=sys.stderr)
            print(f"Error: {e.stderr}", file=sys.stderr)
            sys.exit(1)

    def get_commit_date(self, commit_hash: str) -> datetime:
        """Get the commit date for a given hash."""
        try:
            timestamp = self.run_git(
                ["show", "-s", "--format=%at", commit_hash])
            return datetime.fromtimestamp(int(timestamp))
        except:
            print(
                f"Warning: Could not get date for commit {commit_hash}", file=sys.stderr)
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
        except:
            return False

    def get_current_branch(self) -> str:
        """Get the name of the current branch."""
        try:
            return self.run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        except:
            return "unknown"

    def get_commits_since(self, date: datetime) -> List[Tuple[str, str]]:
        """Get all relevant commits since the given date, returns list of (hash, title) tuples."""
        format_str = "%H%x00%s"
        log_data = self.run_git([
            "log",
            f"--since={date.isoformat()}",
            "--format=" + format_str,
            "--no-merges"  # Exclude merge commits
        ])

        commits = []
        for line in log_data.split('\n'):
            if not line.strip():
                continue
            commit_hash, title = line.split('\x00')
            # Only include commits that match our tracked subsystems
            if is_relevant_commit(title):
                commits.append((commit_hash, title))
        return commits


def title_similarity(title1: str, title2: str) -> float:
    """Compare two commit titles - exact match only."""
    # Simple exact match - kernel commit messages should be identical when backported
    return 1.0 if title1.strip() == title2.strip() else 0.0


def process_commits(csv_path: str, ref_repo_path: str, target_repo_path: str, similarity_threshold: float = 0.8) -> List[CommitInfo]:
    ref_repo = GitRepo(ref_repo_path)
    target_repo = GitRepo(target_repo_path)
    commits = []
    earliest_date = None

    def validate_commit_hash(hash_str: str) -> str:
        """Validate and normalize commit hash."""
        # Remove any whitespace
        hash_str = hash_str.strip()

        # Check if it's in scientific notation (e.g., 7.614E+11)
        try:
            if 'e' in hash_str.lower():
                return None
        except:
            return None

        # Basic validation: should be hexadecimal and at least 7 chars
        if not re.match(r'^[0-9a-f]{7,}$', hash_str, re.IGNORECASE):
            return None

        return hash_str

    # Read and validate commits from CSV
    print("Reading commits from CSV...", file=sys.stderr)
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            commit_hash = validate_commit_hash(row['commit'])
            if not commit_hash:
                print(
                    f"Warning: Skipping invalid commit hash: {row['commit']}", file=sys.stderr)
                continue

            commit = CommitInfo(
                hash=commit_hash,
                title=row['patch_name'].strip(),
                importance=row['priority'].strip(),
                release=row.get('release', '').strip(),
                comments=row.get('comments', '').strip()
            )

            # Get commit date from reference repo
            commit.date = ref_repo.get_commit_date(commit.hash)
            if commit.date:
                if earliest_date is None or commit.date < earliest_date:
                    earliest_date = commit.date

            commits.append(commit)

    if not earliest_date:
        print("Error: Could not determine earliest commit date", file=sys.stderr)
        sys.exit(1)

    print(
        f"\nEarliest commit date: {earliest_date.isoformat()}", file=sys.stderr)
    print(f"Total commits to check: {len(commits)}\n", file=sys.stderr)

    # First pass: Check for exact commit hashes in target
    print("First pass: Checking for exact commit hashes...", file=sys.stderr)
    for commit in commits:
        if target_repo.check_commit_exists(commit.hash):
            commit.found_in_target = True
            commit.matching_target_hash = commit.hash

    # Second pass: Look for similar commit titles in target tree
    print("\nSecond pass: Checking for similar commit titles...", file=sys.stderr)
    target_commits = target_repo.get_commits_since(earliest_date)
    print(f"Found {len(target_commits)} commits in target tree since {earliest_date.isoformat()}", file=sys.stderr)

    for commit in commits:
        if commit.found_in_target:
            continue

        for target_hash, target_title in target_commits:
            similarity = title_similarity(commit.title, target_title)
            if similarity >= similarity_threshold:
                commit.found_by_title = True
                commit.matching_target_hash = target_hash
                print(f"\nPotential title match found:", file=sys.stderr)
                print(
                    f"Reference: {commit.hash} - {commit.title}", file=sys.stderr)
                print(
                    f"Target   : {target_hash} - {target_title}", file=sys.stderr)
                print(f"Similarity: {similarity:.2f}", file=sys.stderr)
                break

    # Print summary
    found_exact = sum(1 for c in commits if c.found_in_target)
    found_title = sum(
        1 for c in commits if not c.found_in_target and c.found_by_title)
    not_found = sum(
        1 for c in commits if not c.found_in_target and not c.found_by_title)

    print("\nSummary:", file=sys.stderr)
    print(f"Commits found by hash: {found_exact}", file=sys.stderr)
    print(f"Additional commits found by title: {found_title}", file=sys.stderr)
    print(f"Commits not found: {not_found}", file=sys.stderr)

    return commits


def get_repo_name(repo_path: str) -> str:
    """Extract repository name from path."""
    # Remove trailing slash if present
    repo_path = repo_path.rstrip('/')
    # Get the last component of the path
    return os.path.basename(repo_path)


def main():
    if len(sys.argv) != 4:
        print(
            f"Usage: {sys.argv[0]} <commits.csv> <reference_repo_path> <target_repo_path>", file=sys.stderr)
        sys.exit(1)

    csv_path = sys.argv[1]
    ref_repo_path = sys.argv[2]
    target_repo_path = sys.argv[3]

    commits = process_commits(csv_path, ref_repo_path, target_repo_path)

    # Create out directory if it doesn't exist
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')
    os.makedirs(out_dir, exist_ok=True)

    # Get repo names and current branches
    ref_repo = GitRepo(ref_repo_path)
    target_repo = GitRepo(target_repo_path)

    ref_name = get_repo_name(ref_repo_path)
    target_name = get_repo_name(target_repo_path)
    ref_branch = ref_repo.get_current_branch()
    target_branch = target_repo.get_current_branch()

    print(
        f"\nReference repository: {ref_name} (branch: {ref_branch})", file=sys.stderr)
    print(
        f"Target repository: {target_name} (branch: {target_branch})", file=sys.stderr)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(
        out_dir, f'commits_{ref_name}-{ref_branch}_to_{target_name}-{target_branch}_{timestamp}.csv')

    # Output results as CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        # Write header
        writer.writerow([
            'release',
            'commit',
            'patch_name',
            'priority',
            'comments',
            'found',
            'target_commit',
            'date'
        ])
        for c in commits:
            writer.writerow([
                c.release,
                c.hash,
                c.title,
                c.importance,
                c.comments,
                'yes' if (c.found_in_target or c.found_by_title) else 'no',
                c.matching_target_hash if (
                    c.found_in_target or c.found_by_title) else '',
                c.date.isoformat() if c.date else ''
            ])

    print(f"\nResults written to: {output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
