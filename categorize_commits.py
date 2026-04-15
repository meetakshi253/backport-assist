#!/usr/bin/env python3
"""
Categorize SMB client commits and store in SQLite database.

This script analyzes commit messages to categorize them as fixes vs features,
and further categorizes by issue type or feature area.

Also provides team contribution analysis by extracting author and trailer
information (Reviewed-by, Tested-by, Reported-by, Acked-by, Suggested-by).
"""

import sqlite3
import json
import re
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))
from common import GitRepo

# Database schema
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS commits (
    commit_hash TEXT PRIMARY KEY,
    patch_name TEXT NOT NULL,
    commit_date TEXT,
    release_version TEXT,
    in_stable BOOLEAN,
    likely_in_stable BOOLEAN,
    matching_stable_hash TEXT,
    
    -- Categorization
    category TEXT,  -- 'fix' or 'feature'
    issue_type TEXT,  -- For fixes: leak, corruption, crash, deadlock, etc.
    feature_area TEXT,  -- For features: area of functionality
    keywords TEXT,  -- JSON array of extracted keywords
    
    -- Full commit details
    commit_message TEXT,
    fixes_commit TEXT,  -- Hash of commit this fixes
    cc_stable BOOLEAN,  -- Whether marked for stable
    
    -- Metadata
    analyzed_at TEXT,
    analysis_version INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_category ON commits(category);
CREATE INDEX IF NOT EXISTS idx_issue_type ON commits(issue_type);
CREATE INDEX IF NOT EXISTS idx_feature_area ON commits(feature_area);
CREATE INDEX IF NOT EXISTS idx_in_stable ON commits(in_stable);
CREATE INDEX IF NOT EXISTS idx_release ON commits(release_version);
"""

# Issue type patterns for fixes
ISSUE_PATTERNS = {
    'memory_leak': r'\b(memory leak|memleak|kmemleak|leak|free.*memory)\b',
    'use_after_free': r'\b(use[- ]after[- ]free|UAF)\b',
    'null_pointer': r'\b(null pointer|nullptr|NULL deref|oops)\b',
    'buffer_overflow': r'\b(buffer overflow|overrun|out.of.bounds)\b',
    'data_corruption': r'\b(data corruption|corrupt|wrong data|incorrect data)\b',
    'deadlock': r'\b(deadlock|lock.*hang|hang.*lock)\b',
    'race_condition': r'\b(race condition|race|concurrent)\b',
    'refcount': r'\b(refcount|reference count|ref leak)\b',
    'resource_leak': r'\b(resource leak|fd leak|handle leak)\b',
    'crash': r'\b(crash|panic|BUG|kernel bug|oops|segfault)\b',
    'permission': r'\b(permission|access denied|EACCES|EPERM)\b',
    'performance': r'\b(slow|performance|latency|timeout|hang)\b',
    'regression': r'\b(regression|regress|revert|broke)\b',
    'security': r'\b(CVE|security|exploit|vulnerability)\b',
}

# Feature area patterns
FEATURE_PATTERNS = {
    'directory_lease': r'\b(directory.*leas|dir.*leas|lease.*director)\b',
    'file_lease': r'\b(file.*leas|oplocks?|leas)\b',
    'multichannel': r'\b(multichannel|multi.*channel|channel)\b',
    'authentication': r'\b(auth|kerberos|ntlm|spnego|ses.*setup)\b',
    'encryption': r'\b(encrypt|seal|sign|crypto|ccm|gcm)\b',
    'compression': r'\b(compress|decompress)\b',
    'caching': r'\b(cach|fscache|page.*cache)\b',
    'dfs': r'\b(dfs|referral)\b',
    'symlink': r'\b(symlink|reparse|wsl)\b',
    'mount': r'\b(mount|remount|umount)\b',
    'reconnect': r'\b(reconnect|resume|persistent.*handle)\b',
    'smb_direct': r'\b(rdma|smb.*direct)\b',
    'protocol': r'\b(smb3|smb2|dialect|negotiate)\b',
    'metadata': r'\b(getattr|setattr|chmod|chown|metadata|stat|inode)\b',
    'io_operations': r'\b(read|write|I/O|page.*fault|mmap)\b',
    'locking': r'\b(lock|unlock|flock|range.*lock)\b',
    'xattr': r'\b(xattr|extended.*attr|ea)\b',
}

def extract_fixes_hash(message: str) -> str:
    """Extract the commit hash from Fixes: tag."""
    match = re.search(r'Fixes:\s*([0-9a-f]{7,40})', message, re.IGNORECASE)
    return match.group(1) if match else None

def is_marked_stable(message: str) -> bool:
    """Check if commit is marked for stable."""
    return bool(re.search(r'cc:.*stable@', message, re.IGNORECASE))

def extract_trailers(message: str) -> dict:
    """Extract all commit trailers (Reviewed-by, Tested-by, etc.) from commit message.
    
    Returns a dictionary with trailer types as keys and lists of email addresses as values.
    """
    trailers = defaultdict(list)
    
    # Common trailer patterns
    trailer_patterns = [
        'Reviewed-by',
        'Tested-by',
        'Reported-by',
        'Acked-by',
        'Suggested-by',
        'Signed-off-by',
        'Co-developed-by',
        'Cc'
    ]
    
    for line in message.split('\n'):
        line = line.strip()
        for trailer_type in trailer_patterns:
            # Match pattern like "Reviewed-by: Name <email@domain.com>"
            pattern = rf'^{trailer_type}:\s*.*?<([^>]+)>|^{trailer_type}:\s*(\S+@\S+)'
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                email = match.group(1) or match.group(2)
                if email:
                    trailers[trailer_type.lower().replace('-', '_')].append(email.strip())
                break
    
    return dict(trailers)

def analyze_team_contributions(repo_path: str, team_emails: list, since_date: str = None, 
                               until_date: str = None, paths: list = None) -> dict:
    """Analyze contributions by team members.
    
    Args:
        repo_path: Path to git repository
        team_emails: List of email addresses to track
        since_date: Start date in 'YYYY-MM-DD' format (optional)
        until_date: End date in 'YYYY-MM-DD' format (optional)
        paths: List of paths to analyze (optional, defaults to SMB paths)
    
    Returns:
        Dictionary with contribution statistics by person and type
    """
    if paths is None:
        paths = ['fs/smb/client/', 'fs/cifs/', 'fs/netfs/']
    
    repo = GitRepo(repo_path, paths=paths)
    
    # Build git log command
    git_args = ['log', '--format=%H|%ae|%ad|%s%n%b', '--date=iso']
    
    if since_date:
        git_args.append(f'--since={since_date}')
    if until_date:
        git_args.append(f'--until={until_date}')
    
    # Add paths
    if paths:
        git_args.append('--')
        git_args.extend(paths)
    
    # Get commits
    output = repo.run_git(git_args)
    
    # Parse commits and track contributions
    contributions = defaultdict(lambda: defaultdict(set))
    
    current_commit = None
    current_body = []
    
    for line in output.split('\n'):
        if '|' in line and line.count('|') >= 3:
            # Process previous commit if exists
            if current_commit:
                process_team_commit(current_commit, current_body, team_emails, contributions)
            
            # Start new commit
            parts = line.split('|', 3)
            current_commit = {
                'hash': parts[0],
                'author_email': parts[1],
                'date': parts[2],
                'subject': parts[3] if len(parts) > 3 else ''
            }
            current_body = []
        else:
            # Add to current commit body
            current_body.append(line)
    
    # Process last commit
    if current_commit:
        process_team_commit(current_commit, current_body, team_emails, contributions)
    
    # Convert sets to counts and prepare summary
    summary = {}
    for email, contrib_types in contributions.items():
        summary[email] = {
            'authored': len(contrib_types['authored']),
            'reviewed_by': len(contrib_types['reviewed_by']),
            'tested_by': len(contrib_types['tested_by']),
            'reported_by': len(contrib_types['reported_by']),
            'acked_by': len(contrib_types['acked_by']),
            'suggested_by': len(contrib_types['suggested_by']),
            'signed_off_by': len(contrib_types['signed_off_by']),
            'total_unique_commits': len(
                contrib_types['authored'] | 
                contrib_types['reviewed_by'] | 
                contrib_types['tested_by'] |
                contrib_types['reported_by'] |
                contrib_types['acked_by'] |
                contrib_types['suggested_by']
            ),
            'commits': {
                'authored': sorted(contrib_types['authored']),
                'reviewed_by': sorted(contrib_types['reviewed_by']),
                'tested_by': sorted(contrib_types['tested_by']),
                'reported_by': sorted(contrib_types['reported_by']),
                'acked_by': sorted(contrib_types['acked_by']),
                'suggested_by': sorted(contrib_types['suggested_by'])
            }
        }
    
    return summary

def process_team_commit(commit: dict, body_lines: list, team_emails: list, contributions: dict):
    """Process a single commit and update contribution tracking."""
    commit_hash = commit['hash']
    author_email = commit['author_email'].strip()
    body = '\n'.join(body_lines)
    
    # Check if author is a team member
    if author_email in team_emails:
        contributions[author_email]['authored'].add(commit_hash)
    
    # Extract trailers
    trailers = extract_trailers(body)
    
    # Check each trailer type for team members
    for trailer_type, emails in trailers.items():
        for email in emails:
            if email in team_emails:
                contributions[email][trailer_type].add(commit_hash)

def get_team_contribution_details(repo_path: str, team_emails: list, since_date: str = None,
                                  until_date: str = None, paths: list = None) -> dict:
    """Get detailed commit information for team contributions.
    
    Returns commits grouped by contribution type with full commit messages.
    """
    if paths is None:
        paths = ['fs/smb/client/', 'fs/cifs/', 'fs/netfs/']
    
    repo = GitRepo(repo_path, paths=paths)
    
    # Build git log command with full details
    git_args = ['log', '--format=%H|%s|%ae|%ad%n%b', '--date=short']
    
    if since_date:
        git_args.append(f'--since={since_date}')
    if until_date:
        git_args.append(f'--until={until_date}')
    
    if paths:
        git_args.append('--')
        git_args.extend(paths)
    
    output = repo.run_git(git_args)
    
    # Track commits by type
    by_type = {
        'authored': {},
        'reviewed_by': {},
        'tested_by': {},
        'reported_by': {},
        'acked_by': {},
        'suggested_by': {}
    }
    
    current_commit = None
    current_body = []
    
    for line in output.split('\n'):
        if '|' in line and line.count('|') >= 3:
            # Process previous commit
            if current_commit:
                process_commit_details(current_commit, current_body, team_emails, by_type)
            
            # Start new commit
            parts = line.split('|', 3)
            current_commit = {
                'hash': parts[0],
                'subject': parts[1],
                'author': parts[2],
                'date': parts[3] if len(parts) > 3 else ''
            }
            current_body = []
        else:
            current_body.append(line)
    
    # Process last commit
    if current_commit:
        process_commit_details(current_commit, current_body, team_emails, by_type)
    
    return by_type

def process_commit_details(commit: dict, body_lines: list, team_emails: list, by_type: dict):
    """Process commit and categorize by contribution type."""
    commit_hash = commit['hash']
    subject = commit['subject']
    author = commit['author']
    body = '\n'.join(body_lines)
    
    # Check author
    if author in team_emails:
        by_type['authored'][commit_hash] = subject
    
    # Extract trailers
    trailers = extract_trailers(body)
    
    # Map trailer types to our categories
    trailer_map = {
        'reviewed_by': 'reviewed_by',
        'tested_by': 'tested_by',
        'reported_by': 'reported_by',
        'acked_by': 'acked_by',
        'suggested_by': 'suggested_by'
    }
    
    for trailer_type, category in trailer_map.items():
        if trailer_type in trailers:
            for email in trailers[trailer_type]:
                if email in team_emails:
                    by_type[category][commit_hash] = subject

def analyze_subsystem_contributions(
    repo_path: str,
    subsystem_paths: list,
    team_emails: list,
    since_date: str = None,
    until_date: str = None
) -> dict:
    """
    Analyze team contributions to a specific subsystem (e.g., fs/smb/client).
    
    Returns both team contributions and total contributions to calculate percentage.
    
    Args:
        repo_path: Path to git repository
        subsystem_paths: List of paths to analyze (e.g., ['fs/smb/client', 'fs/cifs'])
        team_emails: List of team member email addresses
        since_date: Start date for analysis (YYYY-MM-DD)
        until_date: End date for analysis (YYYY-MM-DD)
    
    Returns:
        dict with:
        - total_commits: Total commits to subsystem
        - team_commits: Commits with team involvement
        - team_percentage: Percentage of team involvement
        - breakdown: Detailed breakdown by contribution type
        - team_members: Individual contributions per team member
    """
    repo = GitRepo(repo_path)
    
    # Get total commits to subsystem
    total_git_args = ['log', '--format=%H|%s|%ae|%ad', '--date=short', '--no-merges']
    if since_date:
        total_git_args.append(f'--since={since_date}')
    if until_date:
        total_git_args.append(f'--until={until_date}')
    total_git_args.append('--')
    total_git_args.extend(subsystem_paths)
    
    total_output = repo.run_git(total_git_args)
    total_commits = set()
    for line in total_output.strip().split('\n'):
        if line and '|' in line:
            commit_hash = line.split('|', 1)[0]
            if commit_hash:
                total_commits.add(commit_hash)
    
    # Get team contributions to subsystem
    team_result = analyze_team_contributions(
        repo_path=repo_path,
        team_emails=team_emails,
        since_date=since_date,
        until_date=until_date,
        paths=subsystem_paths
    )
    
    # Calculate totals
    team_commit_set = set()
    for email, data in team_result.items():
        for commit_list in data['commits'].values():
            team_commit_set.update(commit_list)
    
    # Calculate by_type breakdown
    by_type = {
        'authored': 0,
        'reviewed_by': 0,
        'tested_by': 0,
        'reported_by': 0,
        'acked_by': 0,
        'suggested_by': 0
    }
    for email, data in team_result.items():
        for contrib_type in by_type.keys():
            by_type[contrib_type] += data.get(contrib_type, 0)
    
    team_count = len(team_commit_set)
    total_count = len(total_commits)
    percentage = (team_count / total_count * 100) if total_count > 0 else 0
    
    return {
        'subsystem_paths': subsystem_paths,
        'total_commits': total_count,
        'team_commits': team_count,
        'team_percentage': round(percentage, 2),
        'other_commits': total_count - team_count,
        'breakdown': by_type,
        'team_members': {
            email: {
                'total_commits': data['total_unique_commits'],
                'by_type': {
                    'authored': data['authored'],
                    'reviewed_by': data['reviewed_by'],
                    'tested_by': data['tested_by'],
                    'reported_by': data['reported_by'],
                    'acked_by': data['acked_by'],
                    'suggested_by': data['suggested_by']
                }
            }
            for email, data in team_result.items()
        }
    }

def get_commit_files(commit_hash: str, repo: GitRepo) -> set:
    """Get the set of files modified by a commit."""
    try:
        output = repo.run_git(['show', '--name-only', '--format=', commit_hash])
        files = set()
        for line in output.strip().split('\n'):
            line = line.strip()
            if line:
                files.add(line)
        return files
    except:
        return set()

def commit_touches_paths(files: set, paths: list) -> bool:
    """Check if commit modifies files under any of the provided paths."""
    if not paths:
        return True

    for file_path in files:
        for tracked_path in paths:
            if file_path.startswith(tracked_path):
                return True
    return False

def categorize_commit(commit_hash: str, message: str, repo: GitRepo, paths: list = None) -> dict:
    """Categorize a commit based on its message and files changed."""
    message_lower = message.lower()
    
    # Get files modified by this commit
    files_changed = get_commit_files(commit_hash, repo)
    in_tracked_paths = commit_touches_paths(files_changed, paths)
    
    # Determine if it's a fix or feature
    fixes_hash = extract_fixes_hash(message)
    cc_stable = is_marked_stable(message)
    
    # Check for explicit fix indicators
    is_fix = False
    if fixes_hash or cc_stable:
        is_fix = True
    elif re.search(r'\b(fix|fixes|fixed|fixing|repair|correct|resolve)\b', message_lower):
        is_fix = True
    
    category = 'fix' if is_fix else 'feature'
    
    # Categorize issue type for fixes
    issue_types = []
    if is_fix:
        for issue_type, pattern in ISSUE_PATTERNS.items():
            if re.search(pattern, message_lower):
                issue_types.append(issue_type)
    
    # Categorize feature areas only for commits in the tracked paths.
    # If no paths are provided, all commits are considered in scope.
    feature_areas = []
    if in_tracked_paths:
        for area, pattern in FEATURE_PATTERNS.items():
            if re.search(pattern, message_lower):
                feature_areas.append(area)
    
    # Extract keywords
    keywords = []
    # Common important keywords
    for keyword in ['CVE', 'regression', 'deadlock', 'crash', 'leak', 'corruption', 
                    'security', 'performance', 'multichannel', 'lease', 'encryption']:
        if re.search(rf'\b{keyword}\b', message, re.IGNORECASE):
            keywords.append(keyword.lower())
    
    return {
        'category': category,
        'issue_type': ','.join(issue_types) if issue_types else None,
        'feature_area': ','.join(feature_areas) if feature_areas and in_tracked_paths else None,
        'keywords': json.dumps(keywords),
        'fixes_commit': fixes_hash,
        'cc_stable': cc_stable,
        'in_tracked_paths': in_tracked_paths,
    }

def init_database(db_path: str):
    """Initialize the SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.executescript(DB_SCHEMA)
    conn.commit()
    return conn

def populate_database(db_path: str, analysis_file: str, mainline_repo_path: str, paths: list = None):
    """Populate database with categorized commits."""
    print(f"Initializing database: {db_path}")
    conn = init_database(db_path)
    
    print(f"Loading analysis results from: {analysis_file}")
    with open(analysis_file, 'r') as f:
        commits = json.load(f)
    
    print(f"Connecting to mainline repository: {mainline_repo_path}")
    repo = GitRepo(mainline_repo_path, paths=paths)
    
    print(f"\nAnalyzing and categorizing {len(commits)} commits...")
    print("-" * 80)
    
    analyzed_count = 0
    error_count = 0
    skipped_count = 0
    
    for i, commit_data in enumerate(commits, 1):
        commit_hash = commit_data['commit']
        
        if i % 100 == 0 or i == len(commits):
            percent = (i / len(commits)) * 100
            print(f"Progress: {i}/{len(commits)} commits ({percent:.1f}%) - "
                  f"Analyzed: {analyzed_count}, Skipped: {skipped_count}, Errors: {error_count}")
        
        try:
            # Get full commit message
            message = repo.run_git(['log', '-1', '--format=%B', commit_hash])
            
            # Categorize
            categorization = categorize_commit(commit_hash, message, repo, paths=paths)
            
            # Skip commits outside tracked paths only when paths are provided.
            if paths and not categorization['in_tracked_paths']:
                skipped_count += 1
                continue
            
            # Map the analysis data fields to database fields
            in_stable = commit_data.get('in_stable', 0)
            # Convert 'exists_in_target' field if present (from scan_and_compare output)
            if commit_data.get('exists_in_target') == 'yes':
                in_stable = 1
            elif commit_data.get('exists_in_target') == 'no':
                in_stable = 0
            
            likely_in_stable = commit_data.get('likely_in_stable', 0)
            matching_hash = commit_data.get('matching_target_hash', commit_data.get('matching_hash', ''))
            
            # Insert into database
            conn.execute("""
                INSERT OR REPLACE INTO commits (
                    commit_hash, patch_name, commit_date, release_version,
                    in_stable, likely_in_stable, matching_stable_hash,
                    category, issue_type, feature_area, keywords,
                    commit_message, fixes_commit, cc_stable,
                    analyzed_at, analysis_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                commit_hash,
                commit_data['patch_name'],
                commit_data['date'],
                commit_data['release'],
                in_stable,
                likely_in_stable,
                matching_hash,
                categorization['category'],
                categorization['issue_type'],
                categorization['feature_area'],
                categorization['keywords'],
                message,
                categorization['fixes_commit'],
                categorization['cc_stable'],
                datetime.now().isoformat(),
                1
            ))
            
            analyzed_count += 1
            
        except Exception as e:
            error_count += 1
            print(f"ERROR analyzing {commit_hash[:12]}: {e}")
            continue
    
    conn.commit()
    
    print("-" * 80)
    print(f"\n✓ Analysis complete!")
    print(f"  Successfully analyzed: {analyzed_count}")
    if paths:
        print(f"  Skipped (outside tracked paths): {skipped_count}")
    else:
        print(f"  Skipped: {skipped_count}")
    print(f"  Errors: {error_count}")
    
    # Print summary statistics
    print(f"\n" + "=" * 80)
    print("CATEGORIZATION SUMMARY")
    print("=" * 80)
    
    cursor = conn.cursor()
    
    # Category breakdown
    cursor.execute("SELECT category, COUNT(*) FROM commits GROUP BY category")
    print("\nBy Category:")
    for category, count in cursor.fetchall():
        print(f"  {category}: {count}")
    
    # Top issue types
    cursor.execute("""
        SELECT issue_type, COUNT(*) as cnt 
        FROM commits 
        WHERE category = 'fix' AND issue_type IS NOT NULL
        GROUP BY issue_type
        ORDER BY cnt DESC
        LIMIT 10
    """)
    print("\nTop Issue Types (for fixes):")
    for issue_type, count in cursor.fetchall():
        print(f"  {issue_type}: {count}")
    
    # Top feature areas
    cursor.execute("""
        SELECT feature_area, COUNT(*) as cnt 
        FROM commits 
        WHERE feature_area IS NOT NULL
        GROUP BY feature_area
        ORDER BY cnt DESC
        LIMIT 10
    """)
    print("\nTop Feature Areas:")
    for feature_area, count in cursor.fetchall():
        print(f"  {feature_area}: {count}")
    
    # Backport status
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN in_stable THEN 1 ELSE 0 END) as in_stable,
            SUM(CASE WHEN likely_in_stable AND NOT in_stable THEN 1 ELSE 0 END) as likely,
            SUM(CASE WHEN NOT in_stable AND NOT likely_in_stable THEN 1 ELSE 0 END) as missing
        FROM commits
    """)
    in_stable, likely, missing = cursor.fetchone()
    print(f"\nBackport Status:")
    print(f"  In stable-6.6: {in_stable}")
    print(f"  Likely in stable-6.6: {likely}")
    print(f"  Missing from stable-6.6: {missing}")
    
    # Critical fixes missing
    cursor.execute("""
        SELECT COUNT(*)
        FROM commits
        WHERE category = 'fix' 
        AND NOT in_stable 
        AND NOT likely_in_stable
        AND (cc_stable = 1 OR issue_type LIKE '%security%' OR issue_type LIKE '%crash%')
    """)
    critical_missing = cursor.fetchone()[0]
    print(f"\n⚠️  Critical fixes missing from stable-6.6: {critical_missing}")
    
    conn.close()
    print(f"\n✓ Database saved to: {db_path}")
    print("=" * 80)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Categorize SMB commits and store in SQLite')
    parser.add_argument('--analysis-file', required=True, help='JSON file with analysis results')
    parser.add_argument('--db-path', required=True, help='SQLite database path')
    parser.add_argument('--mainline-repo', required=True, help='Path to mainline kernel repo')
    parser.add_argument('--paths', nargs='+', default=None, help='Optional list of paths to restrict categorization')
    
    args = parser.parse_args()
    
    populate_database(args.db_path, args.analysis_file, args.mainline_repo, paths=args.paths)
