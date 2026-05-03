# Spec: Lockshell SSH — biometric, keyless SSH for humans and agents

**Status:** DRAFT (spec phase, not approved)
**Author:** Arya Teja Rudraraju
**Created:** 2026-05-02
**Target version:** lockshell v0.6 (pulled forward from roadmap)
**Replaces:** ROADMAP.md "v0.6 SSH agent bridge" (passphrase-only) — this is a strict superset

---

## 1. Objective

Make SSH usable for humans and AI agents without passwords, without long-lived `~/.ssh/id_*` private keys on disk, and without per-host key sprawl. Replace those with:

- A Secure-Enclave-backed signing key on macOS (Touch ID per signature) acting as a stock SSH agent.
- An optional in-browser WebAuthn / passkey gate for cross-device approval (inspired by meow-ssh's contribution, reimplemented from public crates — see License & Provenance, §10).
- A small SSH certificate authority so ephemeral targets (Docker containers, throwaway VMs) trust the lockshell user without per-host key distribution.
- A multi-session TUI that hosts up to five interactive SSH sessions in a single split-pane window.

### Users and stories

- **AT, the human owner.** Wants to `lockshell ssh staging-mac` from a fresh laptop, see a Touch ID prompt once, and land in the shell. No `ssh-keygen`, no `ssh-copy-id`, no `~/.ssh/config` editing.
- **Agent (Claude/Codex/Cursor).** Wants `lockshell ssh-run --reason "tail nginx logs" -- ssh prod-1 'tail -n 100 /var/log/nginx/error.log'`. Sees redacted output. Cannot exfiltrate the signing key.
- **Docker dev rig.** Five containers come up, lockshell signs five user certs valid for 5 minutes each, all five containers trust the lockshell user CA, agent connects to all five from the TUI without ever generating per-container keys.
- **Linux user (no Touch ID).** Same UX, but the gate is a vault-stored passphrase prompt (released through the existing `agent-password` flow) **OR** a QR code that completes the WebAuthn ceremony on the user's iPhone via FIDO2 hybrid transport (caBLE).

### Success looks like

| # | Condition | How we check |
|---|-----------|--------------|
| S1 | `lockshell ssh <alias>` connects to a registered host using only Touch ID, no on-disk private key | Run on a clean Mac after `lockshell ssh init`; verify `~/.ssh/` contains no new private key file; verify Touch ID prompt fired exactly once per session start |
| S2 | The SE key is non-extractable | `security-framework` `SecKeyCopyExternalRepresentation` returns `errSecAuthFailed` on the lockshell key; documented in test |
| S3 | Five concurrent sessions render in a single TUI split-pane window | Open TUI, attach to 5 dockerized hosts, run `top` in each, observe live updates without artifacts |
| S4 | A Docker container with only `TrustedUserCAKeys` configured accepts a 5-minute lockshell cert and rejects an expired one | Integration test in `tests/docker/` |
| S5 | Agent flow: `lockshell ssh-run --reason "X" -- <cmd>` produces redacted stdout/stderr, exits with subprocess code, leaves an audit entry tying SSH usage to the reason | Integration test asserting all four properties |
| S6 | Cold-start latency | First `lockshell ssh` on a session: < 1.5s wall clock excluding Touch ID prompt time. Subsequent: < 300ms |
| S7 | Build is green on `cargo clippy --all-targets -- -D warnings` and `cargo test` | CI gate |
| S8 | macOS binary is signed + notarized; SE ACL is honored | Manual verification on signed build |
| S9 | Threat model document amended; new failure modes enumerated | Review of `docs/THREAT_MODEL.md` |
| S10 | License header on every new file is Apache-2.0; no code lifted from BSL-licensed `meow-ssh` | License audit pass; provenance log in §10 |

### Anti-scope (we are NOT building these now)

- A bastion / jump host product (Teleport / Cloudflare Access territory).
- Cloud-hosted CA. The CA is local; private key is in Secure Enclave.
- Browser tab terminal. The TUI is the terminal.
- Windows support. macOS first; Linux as fallback target. Windows is not in scope until v1.0+.
- Server-side modifications to OpenSSH. We integrate via stock `sshd_config` with `TrustedUserCAKeys` and `authorized_keys`.
- Replacing `~/.ssh/config` semantics. We read it, we don't rewrite it.

---

## 2. Tech stack

### Language and toolchain

- Rust 1.74+ (matches current `Cargo.toml` `rust-version`).
- `cargo` workspace (this is a structural change — see §3).
- Edition 2021.
- License: Apache-2.0 across all new crates (matches existing).

### Crates (proposed; subject to review)

| Concern | Crate | Why |
|---|---|---|
| SSH client/protocol | `russh = "0.57"` | Same crate meow-ssh uses, post-quantum KEX, async, pure Rust, Apache-2.0 |
| SSH agent server | `russh-agent` or hand-rolled over `russh-keys` | Need to expose a Unix socket speaking the OpenSSH agent protocol |
| Apple Secure Enclave | `security-framework = "2"` + `core-foundation` | `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`; `SecKeyCreateSignature` |
| Apple biometric prompt | `objc2` + `LocalAuthentication` bindings (small wrapper) | `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`; per-signature gate |
| WebAuthn server (approval gate) | `webauthn-rs = "0.5"` with `danger-allow-state-serialisation` | Apache-2.0; full FIDO2 server-side |
| HTTP server (approval page) | `axum = "0.8"` + `tower-http` | Same as meow-ssh; bind 127.0.0.1 only |
| Embed approval HTML | `rust-embed` | Single-binary distribution |
| TUI | `ratatui = "0.29"` + `crossterm` | De-facto Rust TUI stack |
| PTY for in-TUI sessions | `portable-pty` | Cross-platform PTY allocation |
| QR code (Linux fallback / hybrid passkey) | `qrcode = "0.14"` | ASCII + image output |
| Daemon RPC | `tokio` + `serde_json` line-delimited JSON-RPC over Unix socket | Matches existing v0.2 plan |
| Existing crates we keep | `clap`, `serde`, `regex`, `anyhow`, `thiserror`, `chrono`, `which`, `nu-ansi-term`, `zeroize` | Already in `Cargo.toml` |

### Commands (new)

```
# Build
cargo build --release --workspace

# Lint (zero warnings required)
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check

# Tests
cargo test --workspace

# Integration tests (Docker rig)
./tests/docker/run.sh

# Local dev
cargo run -p lockshell -- ssh-debug <host>
cargo run -p lockshelld -- --foreground

# CI gate (single command)
./scripts/ci.sh
```

### Existing commands kept unchanged

```
lockshell run --reason "..." -- '...'
lockshell list / register / unregister / status / doctor / audit
```

---

## 3. Project structure

### Current (v0.1.4)

```
src/
  main.rs              clap dispatch
  cli.rs               arg structs
  vault.rs             AgentPassword adapter
  registry.rs          TSV mapping
  audit_log.rs         TSV append-only
  redact.rs            output filter
  ui.rs                colored output
  commands/            run, list, register, audit, doctor, status, setup, help_me, dashboard
docs/                  ARCHITECTURE, THREAT_MODEL, ROADMAP, PROVIDERS, SECURITY_AUDIT
skills/lockshell/      agent skill definition
examples/              one Linear example
```

### Target (after this spec lands)

Convert to a workspace. Move existing single-crate code into `crates/lockshell` (the CLI). Add four new crates.

```
Cargo.toml                  workspace root, no [package]
crates/
  lockshell/                CLI (existing code, rehomed)
    src/...                 unchanged module layout
    Cargo.toml
  lockshelld/               daemon (new in v0.2; SSH agent lives here too)
    src/
      main.rs
      rpc.rs                JSON-RPC server over Unix socket
      ssh_agent.rs          OpenSSH agent protocol on a separate Unix socket
      vault_adapter.rs      same Vault trait as docs/ARCHITECTURE.md
      sessions.rs           in-memory session table
    Cargo.toml
  lockshell-ssh/            pure SSH logic (client, CA, signing)
    src/
      lib.rs
      signer/
        mod.rs              `trait Signer`
        secure_enclave.rs   macOS impl
        passphrase.rs       Linux fallback (vault-stored key + passphrase)
      client.rs             russh wrapper
      ca.rs                 short-lived user-cert minting
      hosts.rs              host alias registry, parses ~/.ssh/config
    Cargo.toml
  lockshell-tui/            ratatui app
    src/
      main.rs               binary `lockshell-tui` or subcommand `lockshell tui`
      app.rs                state machine
      panes.rs              5-pane split layout
      pty_session.rs        per-pane PTY <-> ratatui buffer
      events.rs             input dispatch
    Cargo.toml
  lockshell-proto/          shared RPC types between CLI / daemon / TUI
    src/lib.rs
    Cargo.toml
  lockshell-webauthn/       optional approval gate (axum + webauthn-rs)
    src/lib.rs              `start_approval_server()` returns approval future
    static/                 embedded HTML/JS (rust-embed)
    Cargo.toml
docs/
  specs/
    lockshell-ssh.md        this file
    lockshell-tui.md        (follow-up; out of scope for this spec)
  ARCHITECTURE.md           amended with §SSH and §TUI sections
  THREAT_MODEL.md           amended with new boundaries
  ROADMAP.md                v0.6 entry expanded
tests/
  unit/                     in-crate `#[cfg(test)]`
  integration/              cross-crate, in `crates/*/tests/`
  docker/
    docker-compose.yml      five sshd containers
    Dockerfile.target
    run.sh                  bring up, run scenarios, tear down
    scenarios/
      cert_accept.rs
      cert_expired.rs
      five_session_tui.rs   spawns the TUI under expect-style harness
scripts/
  ci.sh                     fmt + clippy + test + docker
```

### Why workspace

- Lets the SSH module be reused by the daemon, the CLI, and the TUI without circular dependencies.
- Lets `lockshell-webauthn` stay optional — Linux build can omit it; macOS keeps it as a feature flag.
- Lets `cargo test -p lockshell-ssh` run in seconds without rebuilding the world.
- Matches existing v0.2 plan in ARCHITECTURE.md, which already implies `lockshelld` as a separate binary.

---

## 4. Code style

Match existing repo style. One illustrative snippet of how a new module should read:

```rust
// crates/lockshell-ssh/src/signer/secure_enclave.rs

use anyhow::{Context, Result};
use security_framework::key::SecKey;
use zeroize::Zeroizing;

use crate::signer::{Signature, Signer};

/// Lockshell's signing key, resident in the macOS Secure Enclave.
///
/// The private key material is non-extractable. Every call to [`sign`] triggers
/// `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`, which
/// presents a Touch ID prompt with `reason` shown to the user.
pub struct SecureEnclaveSigner {
    key: SecKey,
    label: String,
}

impl SecureEnclaveSigner {
    pub fn load_or_create(label: &str) -> Result<Self> {
        let key = match find_existing(label)? {
            Some(k) => k,
            None => create_resident(label).context("creating SE key")?,
        };
        Ok(Self {
            key,
            label: label.to_string(),
        })
    }
}

impl Signer for SecureEnclaveSigner {
    fn algorithm(&self) -> &'static str {
        "ecdsa-sha2-nistp256"
    }

    fn public_key_blob(&self) -> Result<Vec<u8>> {
        // SSH wire format for ecdsa-sha2-nistp256.
        crate::wire::encode_ecdsa_p256_public(&self.key)
    }

    fn sign(&self, data: &[u8], reason: &str) -> Result<Signature> {
        let digest = Zeroizing::new(sha256(data));
        // SecKeyCreateSignature internally invokes LAContext when the key
        // ACL has `kSecAccessControlBiometryCurrentSet` set.
        let sig_bytes = sign_with_la_reason(&self.key, &digest, reason)
            .context("Touch ID signature")?;
        Ok(Signature::from_der(sig_bytes))
    }
}
```

### Style rules

- `anyhow::Result` for application code; `thiserror`-derived enums for library errors that callers match on (matches existing `vault.rs`).
- `zeroize::Zeroizing` for any in-memory secret value (already a dep).
- Comments only for the **why**: invariants, security claims, surprising platform behavior. Not for what the code does.
- `tracing` once introduced (the daemon will need it). Until then keep using `eprintln!` consistent with current code.
- Avoid `unsafe` outside a single audited module per platform crate (Apple FFI). Wrap and isolate.
- No `unwrap()` / `expect()` outside tests and `main.rs` early init. Existing repo follows this; preserve it.
- Module privacy: prefer `pub(crate)` over `pub` unless deliberately exporting from the workspace.
- No file longer than ~400 lines. If a module gets larger, split it.

---

## 5. Testing strategy

### Test levels

| Level | Where | What it covers | Framework |
|---|---|---|---|
| Unit | `#[cfg(test)] mod tests` in each crate | Pure functions: SSH wire encoding, cert TTL math, registry parsing, redactor regex | stock `cargo test` |
| Property | `crates/lockshell-ssh/tests/property_*.rs` | Cert encode/decode roundtrip, signer/verifier symmetry | `proptest` |
| Crate-integration | `crates/<x>/tests/` | TUI state machine driven by scripted events; daemon RPC over an in-process socket | `tokio::test` |
| End-to-end | `tests/docker/` | Real `sshd` in Docker, real cert signing, real connection | shell + `assert_cmd` from existing dev-deps |
| Manual smoke | docs in `docs/MANUAL_QA.md` | Touch ID prompts, signed-binary biometric ACL, notarization | runbook |

### Coverage expectations

- Library crates (`lockshell-ssh`, `lockshell-proto`, `lockshell-webauthn`): ≥80% line coverage measured by `cargo llvm-cov`.
- Binary crates: smoke-test happy paths and one error path per subcommand. No coverage target.
- New crates land with tests in the same PR. No "tests later" allowed.

### Critical scenarios that must have tests before merge

1. **SE signer roundtrip on macOS CI** — generate ephemeral key, sign, verify with stock OpenSSL, delete key. (Skipped on Linux CI with `#[cfg(target_os = "macos")]`.)
2. **Cert validity window** — issued cert valid `now+5m`, expired cert refused. Use a fake clock.
3. **Five concurrent PTY sessions** — TUI under a `headless_chrome`-style harness or `expectrl`. Boot 5 mock servers, type into pane 3, assert pane 3 received it and 1/2/4/5 did not.
4. **Docker rig** — 5-container `docker-compose up`, all five SSH connections succeed using a single freshly minted CA.
5. **Failure modes** — Touch ID denied, daemon down, vault locked, expired cert, unreachable host. Each surfaces a specific human-readable error and an actionable next step (matches existing `doctor` aesthetic).
6. **WebAuthn approval timeout** — token expires after 120s of no browser activity; SSH attempt aborts cleanly.
7. **Audit log invariants** — for every `lockshell ssh*` invocation, exactly one audit row is appended; row contains reason and host alias, never any private key material.
8. **License header check** — `scripts/check_license.sh` greps every new `.rs` file for the SPDX header; CI fails otherwise.

### CI

- GitHub Actions matrix: `macos-14` and `ubuntu-22.04`.
- Jobs: `fmt` → `clippy` → `test` → `docker` (Linux only). All zero-warning.
- Notarization runs only on tagged releases via signed-runner workflow (out of scope for first PR; tracked separately).

---

## 6. Boundaries

### Always do

- Use `{{PLACEHOLDER}}` for any secret reaching `lockshell ssh-run` (existing rule, extended).
- Run `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` before any commit.
- Append exactly one audit row per SSH invocation.
- Bind every HTTP listener to `127.0.0.1` only. Never `0.0.0.0`. Never a public interface.
- Bind every Unix socket under a 0700 directory the user owns.
- Use `peercred` / `getpeereid` to verify the connecting UID matches the daemon's UID.
- Treat the SE key as a bearer credential: never log its handle, never write its serialized form anywhere.
- License-stamp every new file with `// SPDX-License-Identifier: Apache-2.0`.
- Cite the public crate (`webauthn-rs`, `russh`, etc.) when reimplementing a meow-ssh idea.

### Ask first

- Adding any new dependency not listed in §2.
- Changing the on-disk layout of `~/.config/lockshell/`.
- Introducing a network listener on anything other than `127.0.0.1`.
- Modifying the existing `lockshell run` pipeline (current tests must keep passing).
- Touching `docs/THREAT_MODEL.md` (security claims need explicit approval).
- Deleting or rewriting any code under `src/` during the workspace migration. Migration must preserve git blame: prefer `git mv`.
- Pulling in a GPL or BSL crate (we won't ship one).

### Never do

- Copy code from `meow-ssh` (BSL 1.1) into this repo. Reading their public source is fine; reimplementation in our own words from public crate APIs is the rule. Provenance log (§10) must list every meow-ssh-influenced module with a one-line "we read X, we wrote Y from public crate Z" entry.
- Write a private key to disk in any form, including PEM, OpenSSH, JSON, or Base64.
- Accept a WebAuthn assertion against a non-`localhost` rpID without explicit user opt-in (future feature, not this spec).
- Forward an SSH agent request the user did not approve. No transitive trust.
- Run `--no-redact` by default. Keep redaction on for SSH paths too.
- Use `unwrap()` in any code path reachable from a user command.
- Skip notarization on a release build that ships SE-backed signing. Without notarization the biometric ACL silently degrades (this is the v0.1 lesson).
- Add telemetry, crash reporting, or any outbound network call. Lockshell is single-machine, period.

---

## 7. Assumptions I'm making

I will proceed with these unless you correct me:

1. **macOS first, Linux second, Windows never (this spec).** The first PR ships macOS-only `SecureEnclaveSigner`; Linux ships `PassphraseSigner` (vault-released ed25519 with passphrase + zeroize) and stub `SecureEnclaveSigner` that errors with a clear message.
2. **The Touch ID gate is per-signature, not per-session.** Every SSH publickey auth signature triggers Touch ID. We can add a "trust this session for N minutes" UX toggle later, but the safe default is per-signature.
3. **No on-disk private keys at all.** Even the Linux passphrase fallback stores the key blob inside `agent-password` (encrypted at rest), not in `~/.ssh/`. The vault is the source of truth.
4. **The SSH CA is local-only.** Lockshell is the CA. `~/.lockshell/ca/ca.pub` ships in `authorized_keys` / `TrustedUserCAKeys` on targets you control. We do **not** become a multi-tenant CA.
5. **Cert TTL = 5 minutes default, max 1 hour.** Short enough to be safe, long enough that a 5-pane TUI session doesn't re-prompt during normal work.
6. **WebAuthn is opt-in, not the default path on macOS.** Touch ID via SE-agent is the macOS default. WebAuthn / browser approval is for cross-device approve-from-iPhone via FIDO2 hybrid (caBLE) or for headless Linux machines.
7. **The TUI is a separate binary `lockshell-tui` shipped in the same release.** We will probably also expose `lockshell tui` as a thin re-exec wrapper, but the binary lives in its own crate.
8. **Daemon = `lockshelld` from existing v0.2 plan.** SSH module hosts inside the daemon process. Single daemon, multiple sockets: one for control RPC, one for the SSH agent protocol.
9. **Existing v0.1 code paths stay compatible.** `lockshell run` keeps working unchanged. New SSH commands are additive.
10. **Existing `agent-password` integration stays.** The Linux passphrase fallback releases the SSH key passphrase via the existing `agent-password` flow; no parallel vault.
11. **License stays Apache-2.0.** No BSL contamination. Provenance log enforces this.
12. **CMUX browser is OK for our manual WebAuthn smoke tests** during development, but CI and shipped tests do **not** depend on a browser; they exercise WebAuthn at the protocol level using `webauthn-rs` test fixtures.

---

## 8. Open questions

These need your call before we leave the spec phase:

- **Q1.** Linux fallback default: vault-released ed25519 + passphrase, **or** QR-to-iPhone hybrid passkey, **or** both with a `--linux-auth=` flag? Both is more code, fewer surprises.
- **Q2.** Should `lockshell ssh init` create the user CA automatically and print the `cert-authority` line for `authorized_keys`, or require an explicit `lockshell ca init` step?
- **Q3.** TUI: tmux-style key bindings (`Ctrl-b` prefix), VS Code-style (`Cmd-1..5`), or configurable from the start?
- **Q4.** Per-signature Touch ID for `git push` over SSH will prompt many times during a busy push. Acceptable for v1 of this spec, or do we need a "5-minute grace" mode behind a flag?
- **Q5.** Do we ship the TUI in this same PR train, or split it into `docs/specs/lockshell-tui.md` after the SSH module merges? My preference: split. SSH module first; TUI is a thicker ratatui project that benefits from a stable agent protocol underneath it.
- **Q6.** Workspace migration: do it as a dedicated cleanup PR before any SSH code lands, or fold into the first SSH PR? My preference: dedicated cleanup PR first, easier review, preserves git history.
- **Q7.** Threat model boundary for the SSH agent socket: do we permit non-lockshell tools (`ssh`, `git`) to use it via `SSH_AUTH_SOCK`, or do we require all SSH go through `lockshell ssh`? Permitting `SSH_AUTH_SOCK` is more useful, slightly larger attack surface (any tool the user runs can ask for a signature; user sees Touch ID for each, so trust is intact, but UX could be confusing).
- **Q8.** Metrics on Touch ID prompts: do we surface "Touch ID prompted N times today" in `lockshell status` for visibility? Cheap to add, helps users notice anomalies.

---

## 9. Plan after this spec is approved

This spec ends here. The next document is `docs/plans/lockshell-ssh-plan.md` produced from the `/agent-skills:plan` workflow, which decomposes into ordered tasks with file ownership boundaries (so we can dispatch parallel implementer agents safely).

Sketch — DO NOT START until both spec and plan are approved:

1. Workspace migration PR (no behavior change).
2. `lockshell-proto` crate with empty types.
3. `lockshell-ssh` crate scaffolding + `Signer` trait + macOS SE impl + unit tests.
4. `lockshelld` crate scaffolding + RPC + SSH agent socket; CLI `lockshell ssh` proxies to daemon.
5. CA module + `lockshell ssh init`.
6. Docker rig in `tests/docker/`.
7. `lockshell-webauthn` opt-in module.
8. `lockshell-ssh-run` for agent flow.
9. Linux passphrase fallback.
10. TUI follow-up spec + implementation.

Each step lands as its own PR with green CI before the next starts.

---

## 10. License & provenance

Lockshell remains Apache-2.0. No code is copied or translated from `meow-ssh` (BSL 1.1, "Competing Service" use grant). When a meow-ssh idea is the cleanest available reference, the implementation is **rewritten from public crate documentation**, and a one-line entry is added to `docs/PROVENANCE.md`:

```
# docs/PROVENANCE.md (new)
| Module | Idea source (read, not copied) | Implemented from |
|---|---|---|
| lockshell-webauthn::approval_token | meow-ssh src/db.rs single-use token UPDATE pattern | webauthn-rs 0.5 docs |
| lockshell-webauthn::static/auth.html | meow-ssh src/public/auth.html (UX flow only) | navigator.credentials.get MDN docs, hand-written |
```

Reviewers should reject any PR that does not include a provenance entry for a meow-ssh-influenced module.

---

## 11. Definition of done for this spec phase

- [ ] You read this file.
- [ ] Open questions in §8 have answers (yours).
- [ ] Assumptions in §7 are accepted or corrected.
- [ ] Boundaries in §6 are agreed.
- [ ] You say "spec approved" or equivalent.

Until then, no code lands.
