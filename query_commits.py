#!/usr/bin/env python3
"""
Query interface for SMB commits database.

Provides easy access to categorized commit information with natural language queries.
"""

import sqlite3
import json
import sys
from pathlib import Path

class CommitDatabase:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # Return rows as dicts
    
    def query_by_feature_area(self, area: str, missing_only: bool = False):
        """Get all commits for a specific feature area."""
        query = """
            SELECT * FROM commits
            WHERE feature_area LIKE ?
        """
        if missing_only:
            query += " AND NOT in_stable AND NOT likely_in_stable"
        query += " ORDER BY commit_date DESC"
        
        cursor = self.conn.cursor()
        cursor.execute(query, (f'%{area}%',))
        return cursor.fetchall()
    
    def query_by_issue_type(self, issue_type: str, missing_only: bool = False):
        """Get all fixes for a specific issue type."""
        query = """
            SELECT * FROM commits
            WHERE category = 'fix' AND issue_type LIKE ?
        """
        if missing_only:
            query += " AND NOT in_stable AND NOT likely_in_stable"
        query += " ORDER BY commit_date DESC"
        
        cursor = self.conn.cursor()
        cursor.execute(query, (f'%{issue_type}%',))
        return cursor.fetchall()
    
    def query_by_keyword(self, keyword: str, missing_only: bool = False):
        """Search by keyword in commit message."""
        query = """
            SELECT * FROM commits
            WHERE (
                commit_message LIKE ? OR 
                patch_name LIKE ? OR
                keywords LIKE ?
            )
        """
        if missing_only:
            query += " AND NOT in_stable AND NOT likely_in_stable"
        query += " ORDER BY commit_date DESC"
        
        pattern = f'%{keyword}%'
        cursor = self.conn.cursor()
        cursor.execute(query, (pattern, pattern, pattern))
        return cursor.fetchall()
    
    def get_critical_missing(self):
        """Get critical fixes missing from stable."""
        query = """
            SELECT * FROM commits
            WHERE category = 'fix'
            AND NOT in_stable
            AND NOT likely_in_stable
            AND (
                cc_stable = 1 OR
                issue_type LIKE '%security%' OR
                issue_type LIKE '%crash%' OR
                issue_type LIKE '%corruption%' OR
                issue_type LIKE '%use_after_free%'
            )
            ORDER BY commit_date DESC
        """
        cursor = self.conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    
    def get_stats(self):
        """Get overall statistics."""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total counts
        cursor.execute("SELECT COUNT(*) FROM commits")
        stats['total_commits'] = cursor.fetchone()[0]
        
        # By category
        cursor.execute("SELECT category, COUNT(*) FROM commits GROUP BY category")
        stats['by_category'] = dict(cursor.fetchall())
        
        # Backport status
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN in_stable THEN 1 ELSE 0 END) as in_stable,
                SUM(CASE WHEN likely_in_stable AND NOT in_stable THEN 1 ELSE 0 END) as likely,
                SUM(CASE WHEN NOT in_stable AND NOT likely_in_stable THEN 1 ELSE 0 END) as missing
            FROM commits
        """)
        row = cursor.fetchone()
        stats['backport_status'] = {
            'in_stable': row[0],
            'likely_in_stable': row[1],
            'missing': row[2]
        }
        
        # Top issue types
        cursor.execute("""
            SELECT issue_type, COUNT(*) as cnt
            FROM commits
            WHERE category = 'fix' AND issue_type IS NOT NULL
            GROUP BY issue_type
            ORDER BY cnt DESC
            LIMIT 10
        """)
        stats['top_issue_types'] = [(row[0], row[1]) for row in cursor.fetchall()]
        
        # Top feature areas
        cursor.execute("""
            SELECT feature_area, COUNT(*) as cnt
            FROM commits
            WHERE feature_area IS NOT NULL
            GROUP BY feature_area
            ORDER BY cnt DESC
            LIMIT 10
        """)
        stats['top_feature_areas'] = [(row[0], row[1]) for row in cursor.fetchall()]
        
        return stats
    
    def format_commit(self, row, show_message: bool = False):
        """Format a commit row for display."""
        lines = []
        lines.append(f"Commit: {row['commit_hash'][:12]}")
        lines.append(f"Title:  {row['patch_name']}")
        lines.append(f"Date:   {row['commit_date'][:10] if row['commit_date'] else 'N/A'}")
        lines.append(f"Release: {row['release_version'] or 'N/A'}")
        lines.append(f"Category: {row['category']}")
        
        if row['issue_type']:
            lines.append(f"Issue Type: {row['issue_type']}")
        if row['feature_area']:
            lines.append(f"Feature Area: {row['feature_area']}")
        if row['fixes_commit']:
            lines.append(f"Fixes: {row['fixes_commit'][:12]}")
        if row['cc_stable']:
            lines.append("⚠️  Marked for stable")
        
        status = []
        if row['in_stable']:
            status.append("In stable-6.6")
        elif row['likely_in_stable']:
            status.append("Likely in stable-6.6")
        else:
            status.append("MISSING from stable-6.6")
        lines.append(f"Status: {', '.join(status)}")
        
        if show_message and row['commit_message']:
            lines.append("\nCommit Message:")
            lines.append("-" * 60)
            lines.append(row['commit_message'])
        
        return '\n'.join(lines)
    
    def close(self):
        self.conn.close()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Query SMB commits database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Get all changes relevant to directory leases
  %(prog)s smb_commits.db --feature-area "directory_lease"
  
  # Get missing changes for multichannel
  %(prog)s smb_commits.db --feature-area "multichannel" --missing-only
  
  # Get all memory leak fixes
  %(prog)s smb_commits.db --issue-type "memory_leak"
  
  # Search for specific keyword
  %(prog)s smb_commits.db --keyword "close_shroot"
  
  # Get critical missing fixes
  %(prog)s smb_commits.db --critical-missing
  
  # Get overall statistics
  %(prog)s smb_commits.db --stats
        '''
    )
    
    parser.add_argument('db_path', help='Path to SQLite database')
    parser.add_argument('--feature-area', help='Filter by feature area')
    parser.add_argument('--issue-type', help='Filter by issue type')
    parser.add_argument('--keyword', help='Search by keyword')
    parser.add_argument('--critical-missing', action='store_true', 
                       help='Show critical fixes missing from stable')
    parser.add_argument('--missing-only', action='store_true',
                       help='Show only commits missing from stable-6.6')
    parser.add_argument('--show-message', action='store_true',
                       help='Show full commit message')
    parser.add_argument('--stats', action='store_true',
                       help='Show statistics')
    parser.add_argument('--limit', type=int, default=50,
                       help='Maximum number of results to show (default: 50)')
    
    args = parser.parse_args()
    
    db = CommitDatabase(args.db_path)
    
    try:
        if args.stats:
            stats = db.get_stats()
            print("=" * 80)
            print("DATABASE STATISTICS")
            print("=" * 80)
            print(f"\nTotal commits: {stats['total_commits']}")
            print(f"\nBy category:")
            for cat, count in stats['by_category'].items():
                print(f"  {cat}: {count}")
            print(f"\nBackport status:")
            print(f"  In stable-6.6: {stats['backport_status']['in_stable']}")
            print(f"  Likely in stable-6.6: {stats['backport_status']['likely_in_stable']}")
            print(f"  Missing from stable-6.6: {stats['backport_status']['missing']}")
            print(f"\nTop issue types:")
            for issue_type, count in stats['top_issue_types']:
                print(f"  {issue_type}: {count}")
            print(f"\nTop feature areas:")
            for area, count in stats['top_feature_areas']:
                print(f"  {area}: {count}")
            return
        
        results = []
        
        if args.critical_missing:
            results = db.get_critical_missing()
        elif args.feature_area:
            results = db.query_by_feature_area(args.feature_area, args.missing_only)
        elif args.issue_type:
            results = db.query_by_issue_type(args.issue_type, args.missing_only)
        elif args.keyword:
            results = db.query_by_keyword(args.keyword, args.missing_only)
        else:
            print("Please specify --feature-area, --issue-type, --keyword, --critical-missing, or --stats")
            return
        
        print(f"\nFound {len(results)} matching commits")
        if len(results) > args.limit:
            print(f"Showing first {args.limit} results (use --limit to change)")
            results = results[:args.limit]
        
        print("=" * 80)
        
        for i, row in enumerate(results, 1):
            print(f"\n[{i}] " + db.format_commit(row, args.show_message))
            print("-" * 80)
    
    finally:
        db.close()


if __name__ == '__main__':
    main()
