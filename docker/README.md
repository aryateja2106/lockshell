# Lockshell SSH test rig

Five-container test fixture proving the cert-based flow end-to-end.

## What's here

| File | Purpose |
|------|---------|
| `Dockerfile.target` | alpine + openssh-server image used by all five targets |
| `sshd_config.docker` | hardened sshd config with `AllowUsers lockshell`; mirrors `crates/lockshell-ssh/templates/sshd_config.lockshell` |
| `docker-compose.yml` | five `target-1..5` services, ports 2201..2205, bind-mount sshd config + CA pubkey |
| `run.sh` | one-shot: extract CA pubkey, `docker compose up`, register host aliases, print demo command |
| `ca/.gitignore` | local CA pubkey (one per dev machine, don't track) |

## Why bind mounts

Both the hardened `sshd_config` and the CA public key are bind-mounted at run
time. Result: rotating the CA (`lockshell ca rotate`) or tweaking the sshd
config never forces a rebuild. The container image itself stays cache-warm.

## Quick start (after `lockshell ssh init`)

```bash
# from repo root
bash docker/run.sh

# Try it
lockshell ssh self-1
lockshell ssh self-3
lockshell audit -n 5

# Tear down
(cd docker && docker compose down -v)
```

## Manual cert smoke (without lockshell client)

If you want to verify the cert path bypassing the lockshell daemon:

```bash
# 1. Generate a temporary local CA + user key with ssh-keygen
ssh-keygen -t ecdsa -b 256 -f /tmp/lockshell-ca -N ""
ssh-keygen -t ecdsa -b 256 -f /tmp/lockshell-user -N ""

# 2. Sign a 5-minute user cert
ssh-keygen -s /tmp/lockshell-ca -I "manual-test" -n lockshell -V +5m \
  -O extension:permit-pty=true \
  /tmp/lockshell-user.pub

# 3. Drop the CA pubkey into docker/ca/
cp /tmp/lockshell-ca.pub docker/ca/lockshell_ca.pub

# 4. docker compose up
(cd docker && docker compose up -d --build)

# 5. Connect with the cert
ssh -i /tmp/lockshell-user -p 2201 lockshell@127.0.0.1
```

The 5-minute cert window means an expired session prompt verifies the
`valid_before` clamp is honored by sshd.

## CI

Linux CI runs `bash docker/run.sh` followed by automated probes that connect
to all five containers; macOS CI skips this rig because Docker on macos-14
runners is slow and the SE-backed signer can't be exercised in headless CI
anyway. The actual cert-format and CA logic are tested at the unit/property
level inside `crates/lockshell-ssh/src/ca.rs` (47-test suite).
