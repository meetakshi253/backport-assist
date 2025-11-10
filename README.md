# Backport Assist

A tool to help identify backport status using commit scanning and tree comparison.

## Components

### `commit_scanner.py`
Reads the config.json to get the start and end commits, then scans the commit history of the default branch to:
- Get all cifs commits
- Classify commits as important or not based the provided filters
- With the "--no-filter" option, gives a list of all commits between the `start` and `end`.
- Writes the output to `output_file` path given in config.json

```bash
python commit_scanner.py
```
or

```bash
python commit_scanner.py --no-filter
```

### `compare_trees.py`
Takes a csv file of commits (output from `commit_scanner.py`), the source and target repos and:
- Compares the file trees between two current branches to determine if the changes from the commits are present in the target branch.
- Outputs a csv file composed of the reference repo + source repo + timestamp with the backport status of each commit as "yes/no".

## Using Git Worktrees

Git worktrees are particularly useful for this workflow, as they allow you to maintain multiple branches in separate directories without needing to clone the repository multiple times.

Example usage:

```bash
git clone <stable-repo-url>
git worktree add ../linux-6.12-stable linux-6.12.y
git worktree add ../linux-6.6-stable linux-6.6.y
git worktree add ../linux-mainline mainline # can use Linus' repo
python3 commit_scanner.py --no-filter # edit the config.json to point to the mainline worktree
python3 compare_trees.py ../out/mainline.csv /mnt/mainline /mnt/linux-6.6-stable
```
