#!/bin/bash
# git_push.sh — safely commit and push CyberSentinel AI to GitHub.
# Usage:  bash git_push.sh "your commit message"
#         (if you omit the message, a sensible default is used)
set -uo pipefail
cd "$(dirname "$0")"

MSG="${1:-Update World Model pipeline: benchmark + lead-time, generalization test, real-packet capture, refreshed README/COMMANDS}"

echo "==> Repo: $(pwd)"
if [ ! -d .git ]; then
  echo "[!] This folder is not a git repo. Initialise first:"
  echo "    git init && git branch -M main"
  echo "    git remote add origin https://github.com/YOUR_USERNAME/cybersentinel-ai.git"
  exit 1
fi

echo ""
echo "==> Current remote:"
git remote -v || true
echo ""

# Stage everything the .gitignore allows (big data files are excluded there).
git add -A

echo "==> Files staged for this commit:"
git status --short
echo ""

# Safety net: refuse to commit anything larger than 90 MB (GitHub hard limit 100 MB).
BIG=$(git diff --cached --name-only | while read -r f; do
        [ -f "$f" ] && sz=$(stat -c%s "$f" 2>/dev/null || echo 0) && [ "$sz" -gt 94371840 ] && echo "$f ($((sz/1048576)) MB)"
      done)
if [ -n "$BIG" ]; then
  echo "[!] REFUSING TO COMMIT — these staged files exceed 90 MB (GitHub will reject them):"
  echo "$BIG"
  echo "    Add them to .gitignore, then run:  git reset  and re-run this script."
  exit 1
fi

echo "==> Committing..."
git commit -m "$MSG" || { echo "[i] Nothing to commit (working tree clean)."; }

# Determine current branch (main or master).
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)
echo ""
echo "==> Pushing branch '$BRANCH'..."
if git remote | grep -q origin; then
  git push -u origin "$BRANCH"
else
  echo "[!] No 'origin' remote set. Add it, then push:"
  echo "    git remote add origin https://github.com/YOUR_USERNAME/cybersentinel-ai.git"
  echo "    git push -u origin $BRANCH"
  exit 1
fi

echo ""
echo "==> Done. Verify on GitHub that NO .csv / features_all.json / *.pt / *.pcap were pushed."
