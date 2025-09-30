#!/usr/bin/env python3

import os
import sys
import json
import re
import subprocess
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Commit:
    hash: str
    author_name: str
    author_email: str
    subject: str
    body: str
    date: datetime

    @property
    def message(self) -> str:
        return f"{self.subject}\n\n{self.body}"


class GitRepo:
    def __init__(self, repo_path: str, default_branch: str = "master"):
        self.repo_path = repo_path
        self.default_branch = default_branch
        if not os.path.exists(os.path.join(repo_path, ".git")):
            raise ValueError(f"Not a git repository: {repo_path}")
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
        except:
            # Try tag pattern match (for cases like v6.15 matching v6.15.0)
            try:
                tags = self.run_git(["tag", "-l", f"{tag}*"])
                if tags:
                    # Use the first matching tag (should be the base version)
                    return self.run_git(["rev-parse", "--verify", tags.split('\n')[0]])
            except:
                pass

            # Try finding Linus's release commit
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
                        return commits.split('\n')[0]
                return None
            except:
                return None

    def get_commits(self, start_ref: str, end_ref: str = "HEAD") -> List[Commit]:
        """Get all commits between start_ref and end_ref.

        The range is exclusive of start_ref and inclusive of end_ref.
        For example, with start=v6.14 and end=v6.15, this will return
        all commits that went into 6.15 (everything after 6.14 tag up
        to and including 6.15 tag)."""
        format_str = "%H%x00%an%x00%ae%x00%at%x00%s%x00%b%x1e"
        log_data = self.run_git([
            "log",
            f"{start_ref}..{end_ref}",
            "--format=" + format_str,
            "--reverse",
            "--no-merges"
        ])

        commits = []
        for entry in log_data.split("\x1e"):
            if not entry.strip():
                continue
            parts = entry.split("\x00")
            if len(parts) >= 6:
                commits.append(Commit(
                    hash=parts[0],
                    author_name=parts[1],
                    author_email=parts[2],
                    date=datetime.fromtimestamp(int(parts[3])),
                    subject=parts[4],
                    body=parts[5]
                ))
        return commits


class CommitScanner:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.config = json.load(f)

        self.repo = GitRepo(
            self.config['mainline_repo'],
            self.config.get('default_branch', 'master')
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

        print(
            f"\nScanning commits after {start_version} (not inclusive) to {end_version} (inclusive)...", file=sys.stderr)

        start_commit = self.repo.find_version_commit(start_version)
        if not start_commit:
            print(
                f"Could not find start version: {start_version}", file=sys.stderr)
            sys.exit(1)

        if end_version != "HEAD":
            end_commit = self.repo.find_version_commit(end_version)
            if not end_commit:
                print(
                    f"Could not find end version: {end_version}", file=sys.stderr)
                sys.exit(1)
        else:
            end_commit = "HEAD"

        # Get all commits in range
        all_commits = self.repo.get_commits(start_commit, end_commit)
        print(f"Found {len(all_commits)} total commits", file=sys.stderr)

        # Filter CIFS commits
        cifs_commits = [c for c in all_commits if self.is_cifs_commit(c)]
        print(f"Found {len(cifs_commits)} CIFS-related commits",
              file=sys.stderr)

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
                    print(
                        f"\nFound commit marked for stable by important author:", file=sys.stderr)
                    print(f"  Hash: {commit.hash}", file=sys.stderr)
                    print(
                        f"  Author: {commit.author_name} <{commit.author_email}>", file=sys.stderr)
                    print(f"  Subject: {commit.subject}", file=sys.stderr)
                    print(f"  Reasons: {', '.join(reasons)}", file=sys.stderr)

        print(
            f"First pass: found {len(important_commits)} important commits", file=sys.stderr)

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

        print(
            f"Second pass: found {len(important_commits) - initial_count} additional fix commits", file=sys.stderr)
        print(
            f"Total important commits: {len(important_commits)}", file=sys.stderr)

        # Print summary of stable commits
        if stable_commits:
            print(
                f"\nFound {len(stable_commits)} commits marked for stable", file=sys.stderr)

        # Convert to serializable format
        return [{
            'hash': c[0].hash.strip(),
            'author': c[0].author_name.strip(),
            'email': c[0].author_email.strip(),
            'date': c[0].date.isoformat(),
            'subject': c[0].subject.strip().replace('\n', ' '),
            'reasons': c[1],
            'marked_for_stable': self.is_marked_for_stable(c[0])
        } for c in important_commits]


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <config.json>", file=sys.stderr)
        sys.exit(1)

    scanner = CommitScanner(sys.argv[1])
    important_commits = scanner.scan_commits()

    # Get output file from config or use stdout
    output_file = scanner.config.get('output_file')
    if output_file:
        output_file = os.path.abspath(output_file)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(important_commits, f, indent=2)
        print(f"\nResults written to: {output_file}", file=sys.stderr)
    else:
        # Output results to stdout if no file specified
        json.dump(important_commits, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
