# Todo: Lockshell SSH

**Status:** DRAFT (plan phase, not approved)
**Companion to:** `docs/specs/lockshell-ssh.md`, `tasks/plan.md`
**Conventions:**
- Tasks are vertical slices: each one delivers something runnable.
- Each task lists **Acceptance** (what is true when done), **Verify** (how we confirm), **Files** (what gets touched).
- A phase is done only when every task in it is checked AND a code review has been signed off.

Legend: `[ ]` not started · `[~]` in progress · `[x]` complete · `[!]` blocked

---

## Phase 0 — Workspace migration

Behavior-neutral refactor. Land before any SSH work.

- [ ] **0.1** Create `Cargo.toml` workspace root, move existing crate to `crates/lockshell/`
  - Acceptance: `cargo build` builds at workspace root; binary still at `target/debug/lockshell`.
  - Verify: `cargo run -- --version` prints same version.
  - Files: `Cargo.toml` (root, new), `crates/lockshell/Cargo.toml` (moved), all of `src/` → `crates/lockshell/src/`.

- [ ] **0.2** Update `[package]` of `crates/lockshell/Cargo.toml`, bump to `0.2.0-alpha.1`
  - Acceptance: `cargo metadata` shows the new path; `cargo publish --dry-run` succeeds for the CLI crate.
  - Files: `crates/lockshell/Cargo.toml`.

- [ ] **0.3** Update CI / scripts that reference `src/` to use `crates/lockshell/src/`
  - Acceptance: All scripts under `scripts/` and any GH Actions workflow paths are correct.
  - Files: `scripts/*`, `.github/workflows/*.yml` if any.

- [ ] **0.4** Update `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `docs/ARCHITECTURE.md` to reference workspace layout
  - Acceptance: No stale `src/` references except as historical notes.
  - Files: as listed.

- [ ] **0.5** Add `scripts/smoke_v01.sh` that exercises every existing subcommand against `LOCKSHELL_CONFIG_DIR=$(mktemp -d)`
  - Acceptance: Script passes locally and in CI; covers `register`, `list`, `unregister`, `audit`, `doctor`, `status`.
  - Verify: CI green.
  - Files: `scripts/smoke_v01.sh`.

- [ ] **0.6** Open PR `feat/workspace-migration` → `main`. Tag for review.
  - Acceptance: Reviewer (`code-reviewer` agent + AT) signs off; CI green; merged.
  - Verify: branch deleted, main builds.

**Phase 0 done when:** all checked AND `lockshell --version` works AND existing functionality untouched.

---

## Phase 1 — Foundation crates

API surface only. No real SSH yet.

- [ ] **1.1** Create `crates/lockshell-proto/` with shared RPC types
  - Acceptance: `Request`, `Response`, `Error`, `SessionStatus` defined; `serde::{Serialize,Deserialize}` derived; zero deps beyond `serde`.
  - Verify: `cargo build -p lockshell-proto`.
  - Files: `crates/lockshell-proto/Cargo.toml`, `crates/lockshell-proto/src/lib.rs`.

- [ ] **1.2** Create `crates/lockshell-ssh/` scaffolding
  - Acceptance: Crate compiles; exposes `pub trait Signer` with `algorithm()`, `public_key_blob()`, `sign(data, reason)`; `pub mod wire` with SSH wire-format helpers (length-prefixed strings, mpints).
  - Verify: `cargo test -p lockshell-ssh` (wire format unit tests pass).
  - Files: `crates/lockshell-ssh/Cargo.toml`, `crates/lockshell-ssh/src/lib.rs`, `crates/lockshell-ssh/src/signer/mod.rs`, `crates/lockshell-ssh/src/wire.rs`.

- [ ] **1.3** Create `crates/lockshelld/` scaffolding
  - Acceptance: Binary `lockshelld` boots, listens on `~/.lockshell/control.sock`, answers `vault.status` with a stub.
  - Verify: `cargo run -p lockshelld -- --foreground &` then `nc -U ~/.lockshell/control.sock` and send `{"jsonrpc":"2.0","id":1,"method":"vault.status"}` returns valid JSON.
  - Files: `crates/lockshelld/Cargo.toml`, `crates/lockshelld/src/main.rs`, `crates/lockshelld/src/rpc.rs`.

- [ ] **1.4** Add license header check to CI
  - Acceptance: `scripts/check_license.sh` greps every `.rs` for `// SPDX-License-Identifier: Apache-2.0` and exits non-zero on miss.
  - Verify: Intentionally remove a header, CI fails. Restore, CI passes.
  - Files: `scripts/check_license.sh`, `.github/workflows/ci.yml`.

- [ ] **1.5** Add `cargo deny` config
  - Acceptance: `cargo deny check` rejects BSL, GPL-3 (without classpath exception), AGPL.
  - Verify: Add a fake BSL dep, CI fails. Remove, CI passes.
  - Files: `deny.toml`, `.github/workflows/ci.yml`.

- [ ] **1.6** Open PR `feat/ssh-foundation`. Reviewers: `code-reviewer`, `security-auditor`.

**Phase 1 done when:** workspace has 4 crates (`lockshell`, `lockshelld`, `lockshell-ssh`, `lockshell-proto`); license check + cargo deny gates active.

---

## Phase 2 — macOS happy path

The first user-visible SSH demo.

- [ ] **2.1** Implement `SecureEnclaveSigner` in `crates/lockshell-ssh/src/signer/secure_enclave.rs`
  - Acceptance: `load_or_create("lockshell-user")` either finds the existing SE key or creates one with `kSecAttrTokenIDSecureEnclave` + `kSecAttrAccessControl(kSecAccessControlBiometryCurrentSet)`. Signs SHA-256 of `data`. Public key extractable, private key not.
  - Verify: `cargo test -p lockshell-ssh --target macos -- secure_enclave::tests::roundtrip` — generates ephemeral key, signs, verifies via `ring`, deletes.
  - Files: `crates/lockshell-ssh/src/signer/secure_enclave.rs`, `crates/lockshell-ssh/src/signer/secure_enclave/la.rs` (LAContext FFI).

- [ ] **2.2** Implement OpenSSH agent protocol server in `crates/lockshelld/src/ssh_agent.rs`
  - Acceptance: Listens on `~/.lockshell/agent.sock`. Handles `SSH_AGENTC_REQUEST_IDENTITIES` and `SSH_AGENTC_SIGN_REQUEST`. Identities = the SE signer's public key. Sign requests dispatch to the signer.
  - Verify: `ssh-add -l -a ~/.lockshell/agent.sock` lists the key. `ssh -i /dev/null -o IdentityAgent=~/.lockshell/agent.sock <host>` triggers a signature.
  - Files: `crates/lockshelld/src/ssh_agent.rs`.

- [ ] **2.3** Implement `lockshell ssh <alias>` in `crates/lockshell/src/commands/ssh.rs`
  - Acceptance: Looks up alias from `~/.config/lockshell/hosts.tsv`. Spawns `ssh` with `IdentityAgent=~/.lockshell/agent.sock` and the registered user/host. Inherits TTY.
  - Verify: Manual smoke against `localhost`.
  - Files: `crates/lockshell/src/commands/ssh.rs`, `crates/lockshell/src/cli.rs`, `crates/lockshell/src/commands/mod.rs`.

- [ ] **2.4** Implement `lockshell ssh init --self`
  - Acceptance: Creates SE key if missing, prints `authorized_keys` line, offers clipboard copy.
  - Verify: Run on a clean Mac, line is valid (paste into `~/.ssh/authorized_keys`, then `lockshell ssh self` connects).
  - Files: `crates/lockshell/src/commands/ssh_init.rs`.

- [ ] **2.5** Implement `lockshell ssh add-host <alias> <user>@<hostname>:<port>`
  - Acceptance: Appends to `~/.config/lockshell/hosts.tsv`, validates duplicates, supports unregister.
  - Files: `crates/lockshell-ssh/src/hosts.rs`, `crates/lockshell/src/commands/ssh_host.rs`.

- [ ] **2.6** Wire `lockshelld` autostart on macOS via `launchctl bootstrap` (manual step in this phase; full LaunchAgent plist in Phase 9)
  - Acceptance: `lockshell doctor` detects daemon-down and prints the bootstrap command.
  - Files: `crates/lockshell/src/commands/doctor.rs`, `docs/MANUAL_QA.md`.

- [ ] **2.7** Audit log row for every SSH session start
  - Acceptance: Row format: `timestamp \t reason \t op=ssh \t alias \t host \t principal \t cert_ttl_or_NA`.
  - Files: `crates/lockshell/src/audit_log.rs`.

- [ ] **2.8** Manual smoke: AT runs `lockshell ssh self` on his Mac, sees Touch ID, lands in shell.

- [ ] **2.9** Open PR `feat/ssh-macos-happy-path`. Reviewers: `code-reviewer`, `security-auditor`.

**Phase 2 done when:** AT has demoed it live. The first time we feel like the project shipped something.

---

## Phase 3 — CA + `lockshell ssh init` + hardened sshd

- [ ] **3.1** Implement `Ca` type in `crates/lockshell-ssh/src/ca.rs`
  - Acceptance: Generates ed25519 CA keypair (CA can use ed25519 even though user signer is ECDSA-P256), signs SSH user certificates per draft-miller-ssh-cert.
  - Verify: Property test: encode → decode → verify, with random principals and TTLs.
  - Files: `crates/lockshell-ssh/src/ca.rs`.

- [ ] **3.2** Store CA private key in SE (separate label `lockshell-ca`)
  - Acceptance: Same hardware-backed protection as the user signer.
  - Files: `crates/lockshell-ssh/src/signer/secure_enclave.rs` (extend with named-key support).

- [ ] **3.3** Implement `lockshell ssh init` (no `--self`) — CA bootstrap
  - Acceptance: Creates user CA if missing, prints `cert-authority` line, prints hardened `sshd_config` excerpt, offers to copy CA pubkey to clipboard.
  - Files: `crates/lockshell/src/commands/ssh_init.rs`, `crates/lockshell-ssh/templates/sshd_config.lockshell`.

- [ ] **3.4** `lockshell ca print` and `lockshell ca rotate`
  - Acceptance: `print` outputs the CA pubkey; `rotate` generates new CA, archives old (with timestamp suffix), prints migration note.
  - Files: `crates/lockshell/src/commands/ca.rs`.

- [ ] **3.5** Cert minting in the agent socket
  - Acceptance: When `ssh` requests a signature, the agent now presents a fresh cert (TTL 5m, principal `$USER`) signed by the CA, not the raw key.
  - Verify: Local target with only `TrustedUserCAKeys` set accepts the connection.
  - Files: `crates/lockshelld/src/ssh_agent.rs`, `crates/lockshell-ssh/src/ca.rs`.

- [ ] **3.6** `--cert-ttl=Nm` flag, capped at 60m
  - Acceptance: Out-of-range values rejected with helpful error.
  - Files: `crates/lockshell/src/cli.rs`, `crates/lockshell/src/commands/ssh.rs`.

- [ ] **3.7** Cert TTL test with fake clock
  - Acceptance: `cargo test -p lockshell-ssh ca::tests::expired_cert_rejected` passes.
  - Files: `crates/lockshell-ssh/src/ca.rs` (under `#[cfg(test)]`).

- [ ] **3.8** Open PR `feat/ssh-ca-init`. Reviewers: `code-reviewer`, `security-auditor`.

**Phase 3 done when:** `~/.ssh/authorized_keys` is no longer needed for managed targets.

---

## Phase 4 — Docker test rig (parallel to Phase 3)

- [ ] **4.1** `tests/docker/Dockerfile.target`
  - Acceptance: Alpine + openssh-server + the lockshell hardened sshd_config + a `TrustedUserCAKeys` baked at build time.
  - Files: `tests/docker/Dockerfile.target`.

- [ ] **4.2** `tests/docker/docker-compose.yml`
  - Acceptance: Five services `target-1` through `target-5`, mapped to host ports 2201..2205, all share the same CA pubkey.
  - Files: `tests/docker/docker-compose.yml`.

- [ ] **4.3** `tests/docker/run.sh`
  - Acceptance: `compose up -d`, runs scenarios, `compose down`. Exits 0 on success.
  - Files: `tests/docker/run.sh`.

- [ ] **4.4** Scenario: `cert_accept`
  - Acceptance: Connect to all five sequentially, exit 0.
  - Files: `tests/docker/scenarios/cert_accept.rs`.

- [ ] **4.5** Scenario: `cert_concurrent`
  - Acceptance: Connect to all five concurrently, all exit 0 within 10s.
  - Files: `tests/docker/scenarios/cert_concurrent.rs`.

- [ ] **4.6** Scenario: `cert_expired`
  - Acceptance: A cert with `valid_before = now - 1m` is rejected; exit code matches sshd's.
  - Files: `tests/docker/scenarios/cert_expired.rs`.

- [ ] **4.7** Scenario: `ca_rotated`
  - Acceptance: Rotate CA, old certs no longer accepted; new cert accepted after re-distribution.
  - Files: `tests/docker/scenarios/ca_rotated.rs`.

- [ ] **4.8** GH Actions job `docker-rig`
  - Acceptance: Linux CI runs `./tests/docker/run.sh`. Cached Docker layers between runs.
  - Files: `.github/workflows/ci.yml`.

- [ ] **4.9** Open PR `feat/ssh-docker-rig`. Reviewers: `code-reviewer`.

**Phase 4 done when:** five-container demo runs locally and on CI.

---

## Phase 5 — Agent flow (`lockshell ssh-run`)

- [ ] **5.1** `lockshell ssh-run` subcommand
  - Acceptance: Same shape as `lockshell run` but for SSH. `--reason` required. Resolves `{{PLACEHOLDER}}`. Mints cert. Spawns `ssh` non-interactively. Redacts output. Returns subprocess exit code.
  - Files: `crates/lockshell/src/commands/ssh_run.rs`, `crates/lockshell/src/cli.rs`.

- [ ] **5.2** Audit row format extended
  - Acceptance: SSH-run rows include `op=ssh-run`, `alias`, `cert_ttl`, `redacted_byte_count`.
  - Files: `crates/lockshell/src/audit_log.rs`.

- [ ] **5.3** AGENTS.md updated with SSH agent contract
  - Acceptance: Mirrors existing `lockshell run` pattern; explicit "never paste" rules; recipe for the Docker rig.
  - Files: `AGENTS.md`.

- [ ] **5.4** `skills/lockshell/SKILL.md` updated to surface `ssh` and `ssh-run` triggers
  - Files: `skills/lockshell/SKILL.md`.

- [ ] **5.5** Per-process rate-limit (default 60 signatures/minute, override via env)
  - Acceptance: Rate-limit tested via integration test that bursts 100 signatures and observes throttling.
  - Files: `crates/lockshelld/src/ssh_agent.rs`.

- [ ] **5.6** Open PR `feat/ssh-agent-flow`. Reviewers: `code-reviewer`, `security-auditor`.

**Phase 5 done when:** Claude/Codex can run a real `ssh-run` against the Docker rig and see redacted output.

---

## Phase 6 — Linux fallback (parallel to Phase 7)

- [ ] **6.1** `PassphraseSigner` in `crates/lockshell-ssh/src/signer/passphrase.rs`
  - Acceptance: Generates ed25519, encrypts via passphrase released by `agent-password`, persists ciphertext at `~/.config/lockshell/keys/<label>.enc`. Decrypts only at sign time. Zeroizes plaintext.
  - Verify: Property test (passphrase round-trip).
  - Files: `crates/lockshell-ssh/src/signer/passphrase.rs`.

- [ ] **6.2** `--linux-auth=passphrase` works end-to-end
  - Acceptance: Ubuntu CI: `lockshell ssh self` succeeds with `--linux-auth=passphrase`. One passphrase prompt, one connection.
  - Files: `crates/lockshell/src/commands/ssh.rs`.

- [ ] **6.3** `CableQrSigner` skeleton (defer real caBLE if libfido2-rs isn't ready)
  - Acceptance: Generates a session-bound QR encoding a caBLE handshake URL. Either drives a real `libfido2-rs` hybrid flow OR returns "caBLE not implemented; use --linux-auth=passphrase" with a clear message.
  - Files: `crates/lockshell-ssh/src/signer/cable_qr.rs`.

- [ ] **6.4** `lockshell ssh pair-phone`
  - Acceptance: Pairs an iPhone via QR; persists pairing in `~/.config/lockshell/pairings.tsv`.
  - Files: `crates/lockshell/src/commands/pair_phone.rs`.

- [ ] **6.5** `--linux-auth=auto` heuristic
  - Acceptance: Use cable if pairing exists AND `libfido2-rs` hybrid available; else passphrase.
  - Files: `crates/lockshell-ssh/src/signer/mod.rs`.

- [ ] **6.6** Open PR `feat/ssh-linux-fallback`. Reviewers: `code-reviewer`, `security-auditor`.

**Phase 6 done when:** at minimum the passphrase path works on Linux CI; caBLE can be a Phase-9 follow-up if blocked.

---

## Phase 7 — WebAuthn approval gate (parallel to Phase 6)

- [ ] **7.1** `crates/lockshell-webauthn/` crate
  - Acceptance: Compiles. Exposes `pub async fn run_approval(reason: &str, timeout: Duration) -> Result<Approval>`.
  - Files: `crates/lockshell-webauthn/Cargo.toml`, `crates/lockshell-webauthn/src/lib.rs`.

- [ ] **7.2** Embedded `static/auth.html` (hand-written)
  - Acceptance: `navigator.credentials.get()` round-trip. Looks like our brand, not meow-ssh's.
  - Files: `crates/lockshell-webauthn/static/auth.html`, `crates/lockshell-webauthn/static/auth.js`.

- [ ] **7.3** Single-use, TTL-bounded approval token
  - Acceptance: Atomic CAS in an in-memory store; token consumed on verify; expires after 120s.
  - Files: `crates/lockshell-webauthn/src/tokens.rs`.

- [ ] **7.4** `--approve-with=webauthn` flag on `lockshell ssh`
  - Acceptance: Opens default browser, blocks SSH until approved or timeout. Timeout aborts cleanly with message.
  - Files: `crates/lockshell/src/commands/ssh.rs`.

- [ ] **7.5** `docs/PROVENANCE.md`
  - Acceptance: One row per meow-ssh-influenced file with idea source and implementation source.
  - Files: `docs/PROVENANCE.md`.

- [ ] **7.6** Test using `webauthn-rs` test fixtures
  - Acceptance: Full register → authenticate ceremony exercised in CI without a real browser.
  - Files: `crates/lockshell-webauthn/tests/integration.rs`.

- [ ] **7.7** Open PR `feat/ssh-webauthn`. Reviewers: `code-reviewer`, `security-auditor`.

**Phase 7 done when:** `--approve-with=webauthn` works end-to-end and license audit is clean.

---

## Phase 8 — Basic TUI

- [ ] **8.1** `crates/lockshell-tui/` crate scaffolding (`ratatui` + `crossterm`)
  - Acceptance: Single empty pane renders with title bar.
  - Files: `crates/lockshell-tui/Cargo.toml`, `crates/lockshell-tui/src/main.rs`, `crates/lockshell-tui/src/app.rs`.

- [ ] **8.2** Five-pane split layout
  - Acceptance: Five empty panes render side-by-side or in a 2x3 grid (configurable).
  - Files: `crates/lockshell-tui/src/panes.rs`.

- [ ] **8.3** `portable-pty` PTY session per pane
  - Acceptance: Each pane can spawn a process, render its output, accept input.
  - Files: `crates/lockshell-tui/src/pty_session.rs`.

- [ ] **8.4** Connect a pane to a registered SSH host
  - Acceptance: Connection picker (`Cmd-T`) shows registered hosts; selecting connects the active pane.
  - Files: `crates/lockshell-tui/src/connect.rs`.

- [ ] **8.5** VS Code keybindings (`Cmd-1..5`, `Cmd-T`, `Cmd-W`, `Cmd-K`)
  - Acceptance: Keybindings work as documented; configurable via `~/.config/lockshell/tui-keys.toml`.
  - Files: `crates/lockshell-tui/src/keys.rs`, `crates/lockshell-tui/src/config.rs`.

- [ ] **8.6** Touch-friendly bottom bar
  - Acceptance: Tappable buttons mirror keybindings; sized for finger taps when run via mosh-on-iPad.
  - Files: `crates/lockshell-tui/src/statusbar.rs`.

- [ ] **8.7** Cert TTL countdown + Touch ID activity indicator
  - Acceptance: Top bar shows current cert TTL (mm:ss) and a transient Touch ID flash.
  - Files: `crates/lockshell-tui/src/topbar.rs`.

- [ ] **8.8** Headless test
  - Acceptance: `expectrl` test boots TUI against five mock servers, types into pane 3, asserts isolation.
  - Files: `crates/lockshell-tui/tests/headless.rs`.

- [ ] **8.9** Open PR `feat/ssh-tui`. Reviewers: `code-reviewer`.

**Phase 8 done when:** AT can do a real working session in the TUI.

---

## Phase 9 — Polish

- [ ] **9.1** `docs/THREAT_MODEL.md` updated
  - Acceptance: New rows for SE-key threat, CA-key threat, agent-socket threat, WebAuthn boundary, audit-log SSH invariants.
  - Files: `docs/THREAT_MODEL.md`.

- [ ] **9.2** `docs/ARCHITECTURE.md` updated with workspace + SSH diagrams
  - Files: `docs/ARCHITECTURE.md`.

- [ ] **9.3** `docs/ROADMAP.md` updated; v0.6 marked done
  - Files: `docs/ROADMAP.md`.

- [ ] **9.4** `docs/MANUAL_QA.md` checklist for every release
  - Files: `docs/MANUAL_QA.md`.

- [ ] **9.5** macOS Developer ID signing + notarization workflow
  - Acceptance: Tagged release produces a notarized binary; `spctl --assess` returns "accepted".
  - Files: `.github/workflows/release.yml`.

- [ ] **9.6** Latency tightened to S6 targets
  - Acceptance: `cargo bench -p lockshell-ssh` confirms cold < 1.5s, warm < 300ms on M-series Mac.
  - Files: `crates/lockshell-ssh/benches/ssh_session.rs`.

- [ ] **9.7** `lockshell status` shows metrics
  - Acceptance: Touch ID prompts today, signatures, hosts touched, cert issuances, last 5 audit rows.
  - Files: `crates/lockshell/src/commands/status.rs`.

- [ ] **9.8** Audit log rotation at 100MB
  - Files: `crates/lockshell/src/audit_log.rs`.

- [ ] **9.9** Homebrew tap update
  - Files: external repo (`aryateja2106/homebrew-tap`).

- [ ] **9.10** Final QA: clean Mac + clean Linux box + Docker rig pass
  - Files: `docs/MANUAL_QA.md` checklist.

- [ ] **9.11** Open PR `feat/ssh-polish`. Reviewers: `code-reviewer`, `security-auditor`.

**Phase 9 done when:** S1–S10 in the spec are all true on a fresh machine.

---

## Cross-cutting standing rules (apply to every PR)

- [ ] Every new file has `// SPDX-License-Identifier: Apache-2.0`.
- [ ] No code from `meow-ssh` (BSL) copied; provenance row added if idea-influenced.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace` green.
- [ ] `cargo deny check` clean.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] Every new public API has a doc comment.
- [ ] Every new error path is reachable from a test (or has a comment justifying why not).
- [ ] No `unwrap()` outside tests / `main.rs` early init.
- [ ] No `0.0.0.0` listeners. No outbound network calls.

---

## Estimate roll-up

| Phase | Estimate |
|-------|----------|
| 0 — Workspace migration | 0.5 day |
| 1 — Foundation crates | 1 day |
| 2 — macOS happy path | 4 days |
| 3 — CA + ssh init | 3 days |
| 4 — Docker rig | 3 days (parallel to 3) |
| 5 — Agent flow | 2 days |
| 6 — Linux fallback | 5 days (parallel to 7) |
| 7 — WebAuthn gate | 4 days |
| 8 — Basic TUI | 5 days |
| 9 — Polish | 3 days |
| **Total elapsed (with parallelism)** | **~22 working days** |
| **Total person-days** | **~30** |

Multiply by 2 per ROADMAP.md tradition: **~6–8 calendar weeks** to ship v0.6 with everything in this plan.

---

## Definition of done for this plan phase

- [ ] You read `tasks/plan.md` and `tasks/todo.md`.
- [ ] You agree with the phase order.
- [ ] You agree with the cuts (zero-trust port management deferred; mosaic TUI deferred).
- [ ] You say "plan approved" or "rewrite phase X".

When you approve, we commit `docs/specs/lockshell-ssh.md` + `tasks/plan.md` + `tasks/todo.md` to `spec/lockshell-ssh`, open a PR for review, and after that PR merges, Phase 0 begins on `feat/workspace-migration`.
