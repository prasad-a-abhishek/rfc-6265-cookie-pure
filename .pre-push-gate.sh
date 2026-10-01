#!/bin/bash
# Pre-push gate for rfc-6265-cookie-pure
# Runs smoke tests and verifications before allowing a push.

set -e

echo "=== Pre-push gate: rfc-6265-cookie-pure ==="

cd /root/projects/rfc-6265-cookie-pure

# 1. Verify pytest passes (non-zero exit on failure)
echo "[1/3] Running pytest..."
pytest tests/ -q --tb=short
echo "pytest exit: $?"

# 2. Verify import works
echo "[2/3] Verifying import..."
python3 -c "import rfc6265_cookie_pure; print('import OK')"

# 3. Verify git status is clean for tracked files only
echo "[3/3] Checking git status..."
if [ -d .git ]; then
    # Only fail on modified/staged tracked files — untracked files are OK
    if [ -n "$(git status --porcelain | grep -v "^??")" ]; then
        echo "ERROR: uncommitted changes to tracked files:"
        git status --porcelain | grep -v "^??"
        exit 1
    fi
    echo "git status: clean (no uncommitted changes to tracked files)"
else
    echo "No .git directory found — skipping git check"
fi

echo "=== gate passed ==="
