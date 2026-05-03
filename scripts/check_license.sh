#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verify every Rust source file in the workspace begins with the
# SPDX Apache-2.0 header. Run as a CI gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEADER='// SPDX-License-Identifier: Apache-2.0'
missing=0

while IFS= read -r -d '' f; do
  if ! head -n 5 "$f" | grep -qF "$HEADER"; then
    printf 'missing SPDX header: %s\n' "$f" >&2
    missing=$((missing + 1))
  fi
done < <(find "$ROOT/crates" -type f -name '*.rs' -not -path '*/target/*' -print0 2>/dev/null)

if [[ $missing -gt 0 ]]; then
  printf '\n%d file(s) missing the Apache-2.0 SPDX header.\n' "$missing" >&2
  printf 'Add this as the first line of each file:\n  %s\n' "$HEADER" >&2
  exit 1
fi

count=$(find "$ROOT/crates" -type f -name '*.rs' -not -path '*/target/*' 2>/dev/null | wc -l | tr -d ' ')
printf 'OK: %s files carry the Apache-2.0 SPDX header.\n' "$count"
