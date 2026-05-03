#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bring up the 5-container lockshell test rig, register host aliases,
# print the demo command. Tear down with: docker compose down

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$ROOT/docker"
CA_DIR="$DOCKER_DIR/ca"
CA_PUB="$CA_DIR/lockshell_ca.pub"

cd "$DOCKER_DIR"

mkdir -p "$CA_DIR"

# Step 1: extract the CA public key.
if [[ ! -s "$CA_PUB" ]]; then
  echo "→ extracting CA public key from lockshell"
  if ! command -v lockshell >/dev/null 2>&1; then
    echo "lockshell is not on PATH. Build it with: cargo build --release -p lockshell"
    exit 1
  fi
  # `lockshell ca print` outputs a `cert-authority` line; sshd's
  # TrustedUserCAKeys file wants just the bare public key portion.
  lockshell ca print 2>/dev/null \
    | sed -n 's/^cert-authority //p' \
    > "$CA_PUB"
  if [[ ! -s "$CA_PUB" ]]; then
    echo "lockshell ca print produced no output. Run 'lockshell ssh init' first."
    exit 1
  fi
fi
echo "✓ CA pubkey at $CA_PUB"

# Step 2: bring up the rig.
echo "→ docker compose up"
docker compose up -d --build

# Step 3: wait for healthchecks.
for i in 1 2 3 4 5; do
  for _ in $(seq 1 30); do
    if docker inspect --format '{{.State.Health.Status}}' "docker-target-${i}-1" 2>/dev/null | grep -q healthy; then
      break
    fi
    sleep 1
  done
done
echo "✓ all targets healthy"

# Step 4: register aliases (idempotent).
if command -v lockshell >/dev/null 2>&1; then
  for i in 1 2 3 4 5; do
    lockshell ssh add-host "self-${i}" "lockshell@127.0.0.1:220${i}" 2>/dev/null || true
  done
  echo "✓ host aliases registered: self-1 .. self-5"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────
  Lockshell SSH test rig is up.

  Try:
    lockshell ssh self-1            # Touch ID prompt -> shell in container 1
    lockshell ssh self-3            # Container 3
    lockshell audit -n 5            # See the SSH audit rows

  Tear down:
    (cd docker && docker compose down -v)
────────────────────────────────────────────────────────────────────
EOF
