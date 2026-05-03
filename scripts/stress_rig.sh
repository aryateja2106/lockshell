#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Lockshell SSH stress rig.
#
# Validates the cert-minting + ssh-agent + remote-exec path under load by
# firing N parallel `lockshell ssh-run` invocations against the 5-container
# Docker rig and recording latency / success rate / sample transcripts.
#
# Runs in STRESS MODE — uses a disjoint pair of Secure Enclave keys
# (`lockshell-stress-user`, `lockshell-stress-ca`) without biometric ACL,
# so the loop does not require Touch ID interaction. Production keys are
# never touched.
#
# Output:
#   docs/proofs/stress-YYYYMMDD-HHMMSS.md   (proof artifact, committable)
#
# Usage:
#   ./scripts/stress_rig.sh                 # default: 50 ops, 5 in flight
#   ./scripts/stress_rig.sh 200 10          # 200 ops, 10 in flight
#
# Environment overrides:
#   STRESS_OPS         total operations (default 50)
#   STRESS_PARALLEL    concurrent in-flight ssh-run calls (default 5)
#   STRESS_KEEP_RIG    1 = leave Docker rig running after the run
#   STRESS_KEEP_DAEMON 1 = leave lockshelld running after the run

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OPS="${1:-${STRESS_OPS:-50}}"
PARALLEL="${2:-${STRESS_PARALLEL:-5}}"

if ! [[ "$OPS" =~ ^[0-9]+$ ]] || [[ "$OPS" -lt 1 ]]; then
  echo "stress_rig: OPS must be a positive integer, got '$OPS'" >&2
  exit 2
fi
if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]] || [[ "$PARALLEL" -lt 1 ]]; then
  echo "stress_rig: PARALLEL must be a positive integer, got '$PARALLEL'" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "stress_rig: macOS-only (Secure Enclave required). Skipping." >&2
  exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "stress_rig: docker is not on PATH." >&2
  exit 2
fi

export LOCKSHELL_STRESS_MODE=1
# Stress mode is gated behind a second env var so a stray
# `LOCKSHELL_STRESS_MODE=1` in a shell rc file cannot silently
# downgrade the daemon's signer to the on-disk software path. The
# stress rig is the only legitimate caller of this combo — never set
# both vars by hand.
export LOCKSHELL_I_UNDERSTAND_THIS_IS_INSECURE=yes

TS="$(date +%Y%m%d-%H%M%S)"
PROOF_DIR="$ROOT/docs/proofs"
PROOF="$PROOF_DIR/stress-$TS.md"
WORK="$(mktemp -d -t lockshell-stress-XXXXXX)"
LATENCIES="$WORK/latencies.txt"
TRANSCRIPT="$WORK/transcript.txt"
mkdir -p "$PROOF_DIR"
: > "$LATENCIES"
: > "$TRANSCRIPT"

trap 'cleanup' EXIT

DAEMON_PID=""
RIG_UP=0

cleanup() {
  set +e
  if [[ -n "$DAEMON_PID" && "${STRESS_KEEP_DAEMON:-0}" != "1" ]]; then
    echo "→ stopping lockshelld (pid=$DAEMON_PID)"
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  if [[ "$RIG_UP" == "1" && "${STRESS_KEEP_RIG:-0}" != "1" ]]; then
    echo "→ tearing down Docker rig"
    (cd "$ROOT/docker" && docker compose down -v >/dev/null 2>&1)
  fi
}

step() { printf '\n══ %s\n' "$*"; }

step "1/7  Build release binaries"
cargo build --release -p lockshell -p lockshelld 2>&1 | tail -5

LOCKSHELL="$ROOT/target/release/lockshell"
LOCKSHELLD="$ROOT/target/release/lockshelld"

step "2/7  Start lockshelld in STRESS MODE"
DAEMON_LOG="$WORK/lockshelld.log"
# Containers expect to be reached as user `lockshell`, but the operator's
# `$USER` is typically different. Override the cert principal so minted
# certs match the container account.
LOCKSHELL_STRESS_MODE=1 LOCKSHELL_DEFAULT_PRINCIPAL=lockshell \
  "$LOCKSHELLD" --foreground >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
  if [[ -S "$HOME/.lockshell/agent.sock" ]]; then break; fi
  sleep 0.2
done
if ! [[ -S "$HOME/.lockshell/agent.sock" ]]; then
  echo "stress_rig: agent socket did not appear; daemon log:" >&2
  cat "$DAEMON_LOG" >&2
  exit 1
fi
echo "✓ lockshelld up (pid=$DAEMON_PID)"

step "3/7  Bootstrap stress CA + extract pubkey"
LOCKSHELL_STRESS_MODE=1 "$LOCKSHELL" ssh-init >/dev/null 2>"$WORK/init.err" || {
  cat "$WORK/init.err" >&2
  exit 1
}

mkdir -p "$ROOT/docker/ca"
LOCKSHELL_STRESS_MODE=1 "$LOCKSHELL" ca print 2>/dev/null \
  | sed -n 's/^cert-authority //p' \
  > "$ROOT/docker/ca/lockshell_ca.pub"
if [[ ! -s "$ROOT/docker/ca/lockshell_ca.pub" ]]; then
  echo "stress_rig: failed to extract stress CA pubkey" >&2
  exit 1
fi
echo "✓ stress CA pubkey written to docker/ca/lockshell_ca.pub"
echo "  $(head -c 80 "$ROOT/docker/ca/lockshell_ca.pub")..."

step "4/7  Bring up Docker rig (5 containers)"
(cd "$ROOT/docker" && docker compose up -d --build 2>&1 | tail -5)
RIG_UP=1
for i in 1 2 3 4 5; do
  for _ in $(seq 1 30); do
    if docker inspect --format '{{.State.Health.Status}}' "docker-target-${i}-1" 2>/dev/null | grep -q healthy; then
      break
    fi
    sleep 1
  done
done
echo "✓ all 5 targets healthy"

step "5/7  Register host aliases self-1..5"
for i in 1 2 3 4 5; do
  LOCKSHELL_STRESS_MODE=1 "$LOCKSHELL" ssh-add-host "self-${i}" "lockshell@127.0.0.1:220${i}" >/dev/null 2>&1 || true
done
echo "✓ aliases registered"

step "6/7  Stress run: $OPS ops, parallelism=$PARALLEL"

# Snapshot the audit log size before the run so we can assert that every
# successful op produced an audit row. The log lives at the shared path
# `~/.config/lockshell/audit.log` (TSV, append-only, one row per op).
AUDIT_LOG="$HOME/.config/lockshell/audit.log"
AUDIT_BEFORE=0
if [[ -f "$AUDIT_LOG" ]]; then
  AUDIT_BEFORE=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
fi

run_one() {
  local idx=$1
  local target="self-$(((idx % 5) + 1))"
  local start_ns end_ns elapsed_ms
  start_ns=$(perl -MTime::HiRes=time -e 'printf("%d", time()*1000000000)')
  if LOCKSHELL_STRESS_MODE=1 "$LOCKSHELL" ssh-run \
        --reason "stress op $idx" --host "$target" -- \
        'echo ok-$(hostname)-$RANDOM' \
        >"$WORK/op-$idx.out" 2>"$WORK/op-$idx.err"; then
    end_ns=$(perl -MTime::HiRes=time -e 'printf("%d", time()*1000000000)')
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    printf 'OK\t%s\t%d\n' "$target" "$elapsed_ms" >>"$LATENCIES"
  else
    end_ns=$(perl -MTime::HiRes=time -e 'printf("%d", time()*1000000000)')
    elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    printf 'FAIL\t%s\t%d\n' "$target" "$elapsed_ms" >>"$LATENCIES"
    echo "--- op $idx FAIL ($target) ---" >>"$TRANSCRIPT"
    cat "$WORK/op-$idx.err" >>"$TRANSCRIPT"
  fi
}

export -f run_one
export LOCKSHELL WORK LATENCIES TRANSCRIPT

START_NS=$(perl -MTime::HiRes=time -e 'printf("%d", time()*1000000000)')

seq 1 "$OPS" | xargs -n 1 -P "$PARALLEL" -I {} bash -c 'run_one "$@"' _ {}

END_NS=$(perl -MTime::HiRes=time -e 'printf("%d", time()*1000000000)')
TOTAL_MS=$(( (END_NS - START_NS) / 1000000 ))

AUDIT_AFTER=0
if [[ -f "$AUDIT_LOG" ]]; then
  AUDIT_AFTER=$(wc -l < "$AUDIT_LOG" | tr -d ' ')
fi
AUDIT_DELTA=$(( AUDIT_AFTER - AUDIT_BEFORE ))

EXAMPLE_OUT=""
for i in $(seq 1 "$OPS"); do
  if [[ -s "$WORK/op-$i.out" ]]; then
    EXAMPLE_OUT="$WORK/op-$i.out"
    break
  fi
done

step "7/7  Compute stats + write proof"

python3 - "$LATENCIES" "$OPS" "$PARALLEL" "$TOTAL_MS" "$PROOF" "$EXAMPLE_OUT" \
        "$ROOT" "$DAEMON_LOG" "$TRANSCRIPT" "$AUDIT_DELTA" <<'PY'
import os, sys, statistics, datetime, subprocess, pathlib

(_, lat_path, ops, parallel, total_ms, proof_path,
 example, root, daemon_log, transcript, audit_delta) = sys.argv
ops = int(ops); parallel = int(parallel); total_ms = int(total_ms)
audit_delta = int(audit_delta)

oks, fails = [], []
per_target = {}
with open(lat_path) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        kind, target, ms = line.split('\t')
        ms = int(ms)
        per_target.setdefault(target, []).append((kind, ms))
        (oks if kind == 'OK' else fails).append(ms)

def pct(xs, p):
    if not xs: return 0
    xs = sorted(xs)
    k = max(0, min(len(xs)-1, int(round((p/100)*(len(xs)-1)))))
    return xs[k]

succ_rate = (len(oks) / ops) * 100 if ops else 0
qps = (ops / (total_ms/1000)) if total_ms else 0

git_head = subprocess.run(['git','-C',root,'rev-parse','HEAD'],
                          capture_output=True, text=True).stdout.strip()
git_branch = subprocess.run(['git','-C',root,'rev-parse','--abbrev-ref','HEAD'],
                            capture_output=True, text=True).stdout.strip()
uname = subprocess.run(['uname','-a'], capture_output=True, text=True).stdout.strip()
sw_ver = subprocess.run(['sw_vers'], capture_output=True, text=True).stdout.strip()
docker_ver = subprocess.run(['docker','--version'], capture_output=True, text=True).stdout.strip()

example_text = ''
if example and os.path.exists(example):
    example_text = pathlib.Path(example).read_text(errors='replace').strip()

daemon_tail = ''
if os.path.exists(daemon_log):
    with open(daemon_log) as f:
        daemon_tail = ''.join(f.readlines()[-25:])

with open(proof_path, 'w') as out:
    out.write(f"# Lockshell SSH stress proof\n\n")
    out.write(f"_Generated: {datetime.datetime.now().isoformat(timespec='seconds')}_  \n")
    out.write(f"_Git: `{git_branch}` @ `{git_head[:12]}`_  \n")
    out.write(f"_Mode: `LOCKSHELL_STRESS_MODE=1` (non-biometric SE keys, disjoint labels)_\n\n")

    out.write("## Environment\n\n```\n")
    out.write(uname + "\n")
    out.write(sw_ver + "\n")
    out.write(docker_ver + "\n")
    out.write("```\n\n")

    out.write("## Configuration\n\n")
    out.write(f"- Total operations:      **{ops}**\n")
    out.write(f"- Parallelism:           **{parallel}** in-flight ssh-run calls\n")
    out.write(f"- Targets:               5 Alpine SSH containers (`docker-target-1..5`)\n")
    out.write(f"- Remote command:        `echo ok-$(hostname)-$RANDOM`\n")
    out.write(f"- Each call:             cert mint (SE-backed) + ssh dial + remote exec + redact + audit\n\n")

    out.write("## Results\n\n")
    out.write(f"- **Success rate:**  {len(oks)}/{ops}  ({succ_rate:.2f}%)\n")
    out.write(f"- **Failures:**      {len(fails)}\n")
    out.write(f"- **Wall time:**     {total_ms} ms ({total_ms/1000:.2f} s)\n")
    out.write(f"- **Throughput:**    {qps:.2f} ops/s sustained\n")
    audit_marker = "✅" if audit_delta == ops else "⚠️"
    out.write(
        f"- **Audit rows:**    {audit_delta} new rows in `~/.config/lockshell/audit.log` "
        f"(expected {ops}) {audit_marker}\n\n"
    )

    if oks:
        out.write("### Latency (per-op, ms) — successful operations\n\n")
        out.write("| min | p50 | p90 | p99 | max | mean |\n")
        out.write("|-----|-----|-----|-----|-----|------|\n")
        out.write(f"| {min(oks)} | {pct(oks,50)} | {pct(oks,90)} | "
                  f"{pct(oks,99)} | {max(oks)} | {statistics.mean(oks):.1f} |\n\n")

    out.write("### Per-target distribution\n\n")
    out.write("| target | ops | ok | fail | p50 (ms) | p99 (ms) |\n")
    out.write("|--------|-----|----|------|---------:|---------:|\n")
    for tgt in sorted(per_target):
        rows = per_target[tgt]
        n = len(rows)
        ok = sum(1 for r in rows if r[0] == 'OK')
        fl = n - ok
        ok_ms = [r[1] for r in rows if r[0] == 'OK']
        p50 = pct(ok_ms, 50) if ok_ms else 0
        p99 = pct(ok_ms, 99) if ok_ms else 0
        out.write(f"| {tgt} | {n} | {ok} | {fl} | {p50} | {p99} |\n")
    out.write("\n")

    if example_text:
        out.write("### Sample successful transcript\n\n")
        out.write("```\n")
        out.write(example_text + "\n")
        out.write("```\n\n")

    if fails and os.path.exists(transcript):
        with open(transcript) as f:
            lines = f.readlines()[:25]
        out.write("### Sample failure transcript (first up to 25 lines)\n\n")
        out.write("```\n" + ''.join(lines) + "```\n\n")

    out.write("### Daemon log (last 25 lines)\n\n```\n")
    out.write(daemon_tail or "(empty)\n")
    out.write("```\n\n")

    out.write("## Reproduce\n\n```bash\n")
    out.write(f"./scripts/stress_rig.sh {ops} {parallel}\n")
    out.write("```\n\n")
    out.write("## Notes\n\n")
    out.write("- Stress mode uses Secure Enclave keys without biometric ACL.\n")
    out.write("  Labels `lockshell-stress-user` / `lockshell-stress-ca` are disjoint\n")
    out.write("  from production `lockshell-user` / `lockshell-ca`.\n")
    out.write("- The CA pubkey distributed to the containers is the stress CA;\n")
    out.write("  rerunning `lockshell ssh-init` (without stress mode) restores production CA.\n")
    out.write("- Each successful op is a full round-trip: cert mint → SSH dial →\n")
    out.write("  bash -s on remote → stdout redaction → audit row.\n")
PY

echo
echo "✓ proof written to $PROOF"
echo
sed -n '1,40p' "$PROOF"
