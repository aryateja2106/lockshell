#!/usr/bin/env bash
# verify.sh: every check that must pass before a push. On success it records
# the verified commit in .git/verify-pass (agent push gates require it).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$HOME/.cargo/bin:$PATH"
step() { printf '\n== %s\n' "$1"; }

step "build (release)";       cargo build --release --locked 2>&1 | tail -1
step "lint (clippy, deny warnings)"; cargo clippy --all-targets --locked -- -D warnings 2>&1 | tail -1
step "tests";                 cargo test --locked 2>&1 | grep -E 'test result|FAILED|panicked'
step "secret scan (gitleaks)"
if command -v gitleaks >/dev/null; then gitleaks git . --redact --no-banner 2>&1 | tail -1
else echo "gitleaks not installed" >&2; exit 1; fi
step "working tree clean"
if [ -n "$(git status --porcelain)" ]; then
  echo "uncommitted changes: commit first, then re-run verify" >&2; exit 1
fi
git rev-parse HEAD > .git/verify-pass
echo; echo "✓ verified $(git rev-parse --short HEAD); push allowed after human confirmation"
