#!/usr/bin/env python3
"""
Categorize SMB client commits and store in SQLite database.

This script analyzes commit messages to categorize them as fixes vs features,
and further categorizes by issue type or feature area.
"""

import sqlite3
import json
import re
import sys
from pathlib import Path
from datetime import datetime

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

def categorize_commit(commit_hash: str, message: str, repo: GitRepo) -> dict:
    """Categorize a commit based on its message."""
    message_lower = message.lower()
    
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
    
    # Categorize feature areas
    feature_areas = []
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
        'feature_area': ','.join(feature_areas) if feature_areas else None,
        'keywords': json.dumps(keywords),
        'fixes_commit': fixes_hash,
        'cc_stable': cc_stable,
    }

def init_database(db_path: str):
    """Initialize the SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.executescript(DB_SCHEMA)
    conn.commit()
    return conn

def populate_database(db_path: str, analysis_file: str, mainline_repo_path: str):
    """Populate database with categorized commits."""
    print(f"Initializing database: {db_path}")
    conn = init_database(db_path)
    
    print(f"Loading analysis results from: {analysis_file}")
    with open(analysis_file, 'r') as f:
        commits = json.load(f)
    
    print(f"Connecting to mainline repository: {mainline_repo_path}")
    repo = GitRepo(mainline_repo_path, paths=['fs/smb/client/', 'fs/cifs/', 'fs/netfs/'])
    
    print(f"\nAnalyzing and categorizing {len(commits)} commits...")
    print("-" * 80)
    
    analyzed_count = 0
    error_count = 0
    
    for i, commit_data in enumerate(commits, 1):
        commit_hash = commit_data['commit']
        
        if i % 100 == 0 or i == len(commits):
            percent = (i / len(commits)) * 100
            print(f"Progress: {i}/{len(commits)} commits ({percent:.1f}%) - "
                  f"Analyzed: {analyzed_count}, Errors: {error_count}")
        
        try:
            # Get full commit message
            message = repo.run_git(['log', '-1', '--format=%B', commit_hash])
            
            # Categorize
            categorization = categorize_commit(commit_hash, message, repo)
            
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
                commit_data['in_stable'],
                commit_data['likely_in_stable'],
                commit_data['matching_hash'],
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
    
    args = parser.parse_args()
    
    populate_database(args.db_path, args.analysis_file, args.mainline_repo)
