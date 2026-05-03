# Plan: Lockshell SSH

**Status:** DRAFT (plan phase, not approved)
**Companion to:** `docs/specs/lockshell-ssh.md`
**Created:** 2026-05-02
**Branch:** `spec/lockshell-ssh` (planning); each phase will get its own branch

---

## 0. Decisions locked from spec review

- **Q1.** Linux fallback: BOTH `passphrase` (vault-stored ed25519) AND `cable-qr` (caBLE QR to iPhone passkey). Selected via `--linux-auth=passphrase|cable|auto`. Default `auto` = QR if camera-equipped phone is paired, else passphrase.
- **Q2.** `lockshell ssh init` auto-creates the user CA, prints the `cert-authority` line, and offers to copy it to clipboard. Explicit `lockshell ca *` subcommand exists but is not required for first-time use.
- **Q3.** TUI keybindings: VS Code style by default (`Cmd/Ctrl-1..5` to switch panes, `Cmd/Ctrl-T` new pane, `Cmd/Ctrl-W` close, `Cmd/Ctrl-K` palette). Fully overridable via `~/.config/lockshell/tui-keys.toml`. Touch-friendly: every action exposes a single-key shortcut for on-screen-keyboard use.
- **Q4.** Per-signature Touch ID by default. `--grace=Nm` flag enables an N-minute approval grace window per process (capped at 60m, written into the audit log). Off by default.
- **Q5.** Basic TUI ships in this release (Phase 8). "Basic" = the 5-pane connect/disconnect happy path + status bar + key palette. Polish, sessions persistence, and mosaic layouts are a follow-up spec.
- **Q6.** Workspace migration ships as a dedicated cleanup PR (Phase 0). Behavior-neutral, easier to review, preserves git blame.
- **Q7.** SSH agent socket honors `SSH_AUTH_SOCK` for any local tool (`ssh`, `git`, `rsync`). Each signature still triggers a fresh Touch ID prompt unless the grace flag is enabled. The audit log records the requesting `pid + comm + euid` for every signature.
- **Q8.** Metrics surfaced in `lockshell status`: Touch ID prompts today / week, signatures issued, approvals granted, hosts touched, certs minted. Implementation: count rows in audit log; no separate counter.
- **NEW.** Zero-trust SSH hardening: `lockshell ssh init` writes a hardened `sshd_config` template for managed targets (Docker, lab boxes). Port-knocking-style "open this port for the next N minutes, then close" lands in a **follow-up spec** (`lockshell-zerotrust.md`), not this train.

---

## 1. Approach

### Vertical slicing

Each phase delivers a **complete, demonstrable capability** end-to-end. We do not build a frontend on top of a missing backend, and we do not build a backend that has no caller. Every phase ends with: "you can run X and see Y."

### Branch strategy

- `spec/lockshell-ssh` — current. Holds the spec and this plan.
- `feat/workspace-migration` — Phase 0.
- `feat/ssh-foundation` — Phase 1.
- `feat/ssh-macos-happy-path` — Phase 2.
- `feat/ssh-ca-init` — Phase 3.
- `feat/ssh-docker-rig` — Phase 4.
- `feat/ssh-agent-flow` — Phase 5.
- `feat/ssh-linux-fallback` — Phase 6.
- `feat/ssh-webauthn` — Phase 7.
- `feat/ssh-tui` — Phase 8.
- `feat/ssh-polish` — Phase 9.

Each branch merges to `main` via PR with green CI before the next branch starts. **One open PR at a time** until Phase 5; after that, parallel agent work is possible because file ownership stabilizes.

### Reviewer cadence

- **You (AT)** review every PR — these are security-critical changes.
- **`code-reviewer` agent** runs on each PR and posts findings as comments before you read it.
- **`security-auditor` agent** runs on Phases 2, 3, 5, 7, 9 (anything touching the signer, the agent socket, the WebAuthn gate, or notarization).

---

## 2. Dependency graph

```
                        Phase 0
                  Workspace migration
                          │
                          ▼
                        Phase 1
                  Foundation crates
              (lockshell-proto, lockshell-ssh
               scaffolding, Signer trait)
                          │
                          ▼
                        Phase 2
              macOS happy path (SE signer +
              agent socket + russh + CLI)
                          │
                          ▼
              ┌───────────┴───────────┐
              ▼                       ▼
           Phase 3                 Phase 4
        CA + ssh init           Docker test rig
        + hardened sshd        (5-container e2e)
              │                       │
              └───────────┬───────────┘
                          ▼
                        Phase 5
              Agent flow (lockshell ssh-run
              + audit + redaction)
                          │
                ┌─────────┴─────────┐
                ▼                   ▼
             Phase 6             Phase 7
         Linux fallback       WebAuthn opt-in
       (passphrase + caBLE)    (cross-device)
                │                   │
                └─────────┬─────────┘
                          ▼
                        Phase 8
                       Basic TUI
                          │
                          ▼
                        Phase 9
              Polish (metrics, docs,
              threat model, notarization)
```

Phases 3 and 4 can run in parallel after Phase 2. Phases 6 and 7 can run in parallel after Phase 5. Everything else is strictly sequential.

---

## 3. Phase-by-phase

### Phase 0 — Workspace migration

**Goal:** Convert single-crate `lockshell` to a Cargo workspace. Zero behavior change. Pure structural refactor.

**Why first:** All later phases assume the workspace layout. Doing this as a standalone PR keeps the migration noise out of the SSH diffs and makes git blame survive.

**Acceptance:**

- `cargo build --workspace` succeeds.
- `cargo test --workspace` succeeds (all existing tests pass).
- `cargo clippy --workspace --all-targets -- -D warnings` succeeds.
- `lockshell --version` prints the same version as before.
- Every existing subcommand (`run`, `list`, `register`, `audit`, `doctor`, `status`, `setup`, `help_me`, `dashboard`) works identically. Manual smoke-tested.
- `git log --follow` on existing files traces back through the move (i.e. we used `git mv`, not delete-then-add).

**Verification:**

- CI green on macos-14 and ubuntu-22.04.
- `bash scripts/smoke_v01.sh` runs every existing subcommand against a temp config dir.

**Tasks:** see `tasks/todo.md` § Phase 0.

**Risk:** Path-aware tests, hard-coded `src/` references, the published `lockshell` package on crates.io. Mitigation: bump version to `0.2.0-alpha.1` and publish only the CLI crate, exactly as today.

**Estimate:** 0.5 day.

---

### Phase 1 — Foundation crates

**Goal:** Stand up `lockshell-proto`, `lockshell-ssh` (scaffolding only, no platform impl), and `lockshelld` (scaffolding only, returns "not implemented" for SSH calls). Define the `Signer` trait. Define the JSON-RPC types. No real SSH yet.

**Why:** Establishes the API surface. Lets later phases be parallelizable because crate boundaries are settled.

**Acceptance:**

- `cargo build -p lockshell-proto` succeeds with zero deps beyond `serde`.
- `cargo build -p lockshell-ssh` succeeds and exposes `trait Signer`.
- `cargo build -p lockshelld` succeeds and produces a binary that listens on a Unix socket and answers `vault.status` (no-op stub).
- `cargo test -p lockshell-ssh` runs property tests for SSH wire encoding (zero unsafe code yet).
- `cargo doc --workspace --no-deps` builds clean.

**Verification:**

- CI green.
- `cargo run -p lockshelld -- --foreground` starts and accepts a `vault.status` JSON-RPC call from a hand-written `nc` test.

**Risk:** Over-designing the Signer trait. Mitigation: only model `algorithm()`, `public_key_blob()`, `sign(data, reason)` for now. Extend in later phases.

**Estimate:** 1 day.

---

### Phase 2 — macOS happy path (the demo)

**Goal:** End-to-end "I can SSH into my own Mac with Touch ID, no on-disk private key." This is the **first phase that produces a demoable artifact**.

**Capabilities delivered:**

- `lockshell ssh init --self` — generates SE-resident keypair labeled `lockshell-user`, prints the public key as both an `authorized_keys` line and a `ssh-cert` line.
- `lockshell ssh add-host <alias> <user>@<hostname>:<port>` — register a host alias.
- `lockshell ssh <alias>` — interactive SSH session.
- `lockshelld` runs as a foreground process; it owns the SE key handle and listens on `~/.lockshell/agent.sock` speaking the OpenSSH agent protocol.
- Stock OpenSSH on the target sees an `ecdsa-sha2-nistp256` key and accepts it via `authorized_keys`.

**Acceptance:**

- Manual: I add my own laptop's `~/.ssh/authorized_keys` line, run `lockshell ssh self`, see Touch ID, land in shell. Works.
- `~/.ssh/` contains zero new files (no private key written).
- `security-framework` confirms the key has `kSecAttrTokenIDSecureEnclave` and `kSecAttrAccessControl` set with `kSecAccessControlBiometryCurrentSet`.
- Touch ID prompt fires for each `ssh-publickey` signature (per-signature default).
- Cold-start latency < 2.5s (relaxed from S6 because Phase 2 doesn't have caching yet; Phase 9 tightens this).

**Verification:**

- Smoke test on the author's Mac (test plan in `docs/MANUAL_QA.md`).
- Macos CI runs the SE roundtrip test (sign + verify + delete) using a per-job ephemeral label so the test machine doesn't accumulate keys.
- Linux CI is `#[cfg]`-skipped for SE tests; runs the rest.

**Risk:** `LAContext.evaluatePolicy` requires a UI. On a headless macos CI runner, the prompt cannot be answered. Mitigation: in tests, create the SE key with `kSecAccessControlPrivateKeyUsage` only (no biometric ACL) and document this is a test-only path in code comments. Real builds always set the biometric ACL.

**Risk:** Without notarization, the biometric ACL silently degrades — same lesson the v0.1 audit captured. Mitigation: Phase 2 ships behind a "developer build" disclaimer banner; Phase 9 adds notarization. We do not claim biometric-bound until Phase 9.

**Estimate:** 4 days.

---

### Phase 3 — CA + `lockshell ssh init` + hardened target

**Goal:** Replace per-host `authorized_keys` editing with a CA-signed cert flow. One-time CA bootstrap, short-lived user certs per session.

**Capabilities delivered:**

- `lockshell ssh init` (no `--self`) — generates user CA, stores the CA's signing key in the SE (separate from the user signer key), prints the `cert-authority` line and a hardened `sshd_config` excerpt.
- `lockshell ca print` — prints the CA public key.
- `lockshell ca rotate` — rotates the CA, invalidates outstanding certs.
- `lockshell ssh <alias>` now mints a 5-minute user cert at session start, presents the cert + signature instead of raw key.
- `--cert-ttl=Nm` flag, capped at 60m.
- Hardened `sshd_config` template: `PasswordAuthentication no`, `PubkeyAuthentication yes`, `TrustedUserCAKeys /etc/ssh/lockshell_ca.pub`, `AuthorizedKeysFile none`, `MaxAuthTries 3`, `LoginGraceTime 30`, `PermitRootLogin no`, `AllowUsers <flag>`, `UsePAM yes`. Lives in `crates/lockshell-ssh/templates/sshd_config.lockshell`.

**Acceptance:**

- A target configured with only `TrustedUserCAKeys` (no `authorized_keys`) accepts a fresh cert.
- Same target rejects an expired cert.
- Same target rejects a cert signed by a different CA.
- Cert principals match `--principal` flag (defaults to `$USER`).
- `lockshell ssh status` shows current cert TTL countdown.

**Verification:**

- Crate tests with a fake clock for TTL.
- Property test: cert encode/decode roundtrip.
- One Docker scenario (`tests/docker/scenarios/cert_accept.rs`) — minimal, paves the way for Phase 4's full rig.

**Risk:** CA key compromise = total compromise. Mitigation: CA key is in SE just like the user signer key; CA signing requires Touch ID; CA key never in memory beyond a single signature. Threat model document gets a new row.

**Estimate:** 3 days.

---

### Phase 4 — Docker test rig

**Goal:** Five-container `docker-compose` proving the system at scale. This is the user's stated acceptance demo.

**Capabilities delivered:**

- `tests/docker/docker-compose.yml` — five `sshd-target-{1..5}` containers based on `Dockerfile.target`.
- `Dockerfile.target` — bare alpine + openssh-server + the lockshell hardened `sshd_config` + a `TrustedUserCAKeys` baked at build.
- `tests/docker/run.sh` — brings up the compose, runs all scenarios, tears down.
- `tests/docker/scenarios/` — Rust integration tests that drive `lockshell` against the live containers.
- Scenarios cover: connect to one, connect to five sequentially, connect to five concurrently, connect with expired cert, connect with rotated CA after rotation.

**Acceptance:**

- `./tests/docker/run.sh` exits 0 on macos and ubuntu CI.
- All five concurrent connections complete within 10 seconds wall-clock.
- Each connection appears in the audit log with the host alias, container id, and TTL.

**Verification:**

- CI integration test job that spins up the rig and runs the scenarios.
- Manual: AT runs `./tests/docker/run.sh` locally and watches Touch ID prompts.

**Risk:** Docker on macOS uses HyperKit/Virtualization.framework, slow at boot. Mitigation: `docker-compose` warm-up step in the CI cache; reuse images between runs.

**Estimate:** 3 days.

---

### Phase 5 — Agent flow

**Goal:** AI agents can use lockshell SSH safely. `lockshell ssh-run` is to SSH what `lockshell run` is to API calls.

**Capabilities delivered:**

- `lockshell ssh-run --reason "<text>" -- <ssh command template>` — exec form. Resolves any `{{PLACEHOLDER}}` against the vault, mints a cert, runs the SSH command non-interactively, redacts output, returns subprocess exit code.
- `--host-alias` shorthand — agents pass an alias instead of full ssh args.
- Audit log entry includes: timestamp, reason, host alias, principal, cert TTL, exit code, redacted-byte count.
- Doctor checks for SSH readiness.
- AGENTS.md updated with the SSH agent contract (mirroring the existing run pattern).
- Skill updated.

**Acceptance:**

- Agents can run `lockshell ssh-run --reason "tail nginx" -- ssh prod-1 'tail -n 100 /var/log/nginx/error.log'` without ever seeing the SE key.
- `lockshell run` is unaffected; existing tests pass.
- Audit log contains exactly one row per `ssh-run` invocation.
- Redactor is applied to ssh-run output (regex from `redactors.txt`).

**Verification:**

- Integration test: drive `lockshell ssh-run` against a Docker target, assert audit row, exit code, redaction.
- Negative test: missing `--reason` → non-zero exit, helpful error.

**Risk:** Agents echoing the cert blob in stdout for debugging. Mitigation: cert is a public artifact (not the private key), so this is informational, not a vulnerability. Documented.

**Estimate:** 2 days.

---

### Phase 6 — Linux fallback

**Goal:** Lockshell SSH works on Linux without Touch ID. Both fallback paths shipped.

**Capabilities delivered:**

- `PassphraseSigner` — generates ed25519 in memory, encrypts with passphrase released by `agent-password`, persists the encrypted blob in `~/.config/lockshell/keys/<label>.enc`. Decrypted only at signature time, zeroized after.
- `CableQrSigner` — generates a session-bound QR code encoding a caBLE handshake, user scans with iPhone, iPhone performs WebAuthn ceremony, response signs the SSH challenge.
- `--linux-auth={passphrase|cable|auto}` flag, default `auto`.
- `auto` heuristic: if `lockshell ssh pair-phone` has been completed, use cable; else passphrase.
- `lockshell ssh pair-phone` — pairs a phone via QR.

**Acceptance:**

- On a clean Ubuntu machine: `lockshell ssh self` succeeds via passphrase fallback, prompting once for the passphrase.
- On an Ubuntu machine with paired iPhone: same command shows a QR, iPhone Face ID prompt completes, SSH connects.
- Both paths work end-to-end against the Docker rig.

**Verification:**

- Ubuntu CI runs the passphrase path (no UI).
- Manual: AT pairs iPhone, runs cable path on his Linux box.
- Property test: passphrase round-trip (encrypt with passphrase, decrypt with same passphrase, sign, verify).

**Risk:** caBLE / hybrid CTAP is a moving target — the spec evolves. Mitigation: pin to libfido2's hybrid implementation, vendor through a `caBLE` crate (write our own thin wrapper around `libfido2-rs` if needed). If `libfido2-rs` doesn't expose hybrid yet, ship passphrase-only on Linux for this phase and split caBLE into a follow-up phase.

**Estimate:** 5 days (3 if caBLE is deferred).

---

### Phase 7 — WebAuthn approval gate

**Goal:** Optional cross-device approval. The meow-ssh idea, reimplemented our way, behind an opt-in flag.

**Capabilities delivered:**

- `lockshell-webauthn` crate: `axum` server bound to `127.0.0.1:<random>`, embeds `static/auth.html`, exposes `/api/auth/options/:token` and `/api/auth/verify/:token`.
- `lockshell ssh --approve-with=webauthn <alias>` — flag that opens browser, waits up to 120s for approval before proceeding.
- One-time tokens, single-use, atomic UPDATE pattern (independently implemented from `webauthn-rs` examples; see `docs/PROVENANCE.md`).
- Local rpID = `localhost`. No public domain.

**Acceptance:**

- `--approve-with=webauthn` opens the default browser, prompts Touch ID/Face ID via the browser, completes SSH connection.
- Token expires after 120s.
- WebAuthn rpID rejected if not `localhost`.
- Integration test using `webauthn-rs` test fixtures (no real browser).

**Verification:**

- Crate test exercising the full register + authenticate flow with the test authenticator.
- Manual smoke on macos using Safari and Chrome.
- License audit: `cargo deny` confirms no BSL deps; `docs/PROVENANCE.md` updated.

**Risk:** Browser ceremony adds latency and complexity. Mitigation: opt-in only; default macOS path remains pure SE.

**Estimate:** 4 days.

---

### Phase 8 — Basic TUI

**Goal:** A 5-pane terminal UI you can use today and extend later.

**Capabilities delivered:**

- `lockshell tui` and `lockshell-tui` (re-exec wrapper) launch the TUI.
- Five-pane split layout. Each pane is a live SSH PTY session.
- VS Code-style keybindings: `Cmd/Ctrl-1..5` switch panes, `Cmd/Ctrl-T` open a connection picker, `Cmd/Ctrl-W` close pane, `Cmd/Ctrl-K` palette, `Cmd/Ctrl-Shift-P` settings.
- Configurable via `~/.config/lockshell/tui-keys.toml` from day one.
- Touch-friendly bottom bar with tappable buttons mirroring every keybinding (designed for mosh-on-iPad-style use).
- Status indicators: cert TTL countdown, Touch ID activity, daemon status.

**Acceptance:**

- Open TUI, attach to 5 dockerized hosts, run `top` in each, no rendering artifacts.
- Switch panes with `Cmd-3`, type, see input go only to pane 3.
- Edit `tui-keys.toml`, restart TUI, new bindings active.
- Cert TTL updates every second.

**Verification:**

- `expectrl`-style headless test that drives the TUI against five mock SSH servers.
- Manual: AT uses the TUI for a real working session.

**Risk:** Ratatui + portable-pty + russh is a non-trivial async stack. Mitigation: build incrementally — single pane first, then 2, then 5. Each step a separate commit.

**Estimate:** 5 days.

---

### Phase 9 — Polish, docs, threat model, notarization

**Goal:** Ship-ready release. Numbers tightened, docs honest, binary signed.

**Capabilities delivered:**

- `docs/THREAT_MODEL.md` updated: SSH boundaries, SE-key threat row, cert-CA threat row, WebAuthn boundary, audit-log invariants extended.
- `docs/ARCHITECTURE.md` updated: workspace diagram, ssh-agent socket layer, CA flow.
- `docs/ROADMAP.md` updated: v0.6 marked done, follow-up `lockshell-zerotrust.md` referenced.
- `docs/PROVENANCE.md` complete: every meow-ssh-influenced module has a row.
- `docs/MANUAL_QA.md` checklist for release.
- macOS Developer ID signing + notarization GitHub Actions workflow.
- Latency tightened to S6 targets in spec (<1.5s cold, <300ms warm).
- `lockshell status` now shows: Touch ID prompts today, cert issuances, hosts touched, last 5 audit rows.
- Homebrew tap (`aryateja2106/homebrew-tap`) ships the signed binary.

**Acceptance:**

- All S1–S10 in the spec are demonstrably true on a clean Mac and a clean Linux box.
- `cargo deny check` passes (no BSL/GPL deps).
- License header check passes (`scripts/check_license.sh`).
- Release artifact is signed + notarized; `spctl` returns "accepted".

**Verification:**

- Manual QA on a freshly booted Mac.
- Linux QA on a Ubuntu 22.04 cloud VM.
- One full Docker rig pass.

**Risk:** Notarization can be slow / flaky. Mitigation: Phase 9 ships behind a feature gate; if notarization stalls, release without it but mark biometric ACL "best effort" in the README.

**Estimate:** 3 days.

---

## 4. Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|-----------|--------|-----------|
| R1 | meow-ssh BSL contamination claim | Low | High | `docs/PROVENANCE.md` + per-PR review; `cargo deny` for license; we never read meow-ssh code while writing — only AFTER our own draft, as a check |
| R2 | Notarization failure → biometric ACL silently degrades | Medium | High | Phase 9 gates the "biometric-bound" claim on a notarized build; documented |
| R3 | caBLE crate maturity | High | Medium | Defer caBLE to Phase 6.5 if libfido2-rs hybrid support isn't ready |
| R4 | Per-signature Touch ID UX hostile for git push | High | Medium | `--grace=Nm` flag; documented; user toggles when needed |
| R5 | Workspace migration breaks crates.io publishing flow | Low | Medium | Bump to 0.2.0-alpha.1, only publish CLI crate, keep package name `lockshell` |
| R6 | Five concurrent PTYs in ratatui = perf cliff | Medium | Medium | Bench in Phase 8; if hot, reduce default to 4 panes |
| R7 | Docker rig flakiness on macOS CI | Medium | Low | Cache compose images; Linux CI is canonical for the rig |
| R8 | SE key migration when Mac is replaced | Medium | Medium | Document recovery: re-run `lockshell ssh init`, distribute new CA to targets; Phase 9 ships a "fingerprint changed" banner |
| R9 | Audit log grows unbounded | Low | Low | Phase 9 adds rotation at 100MB |
| R10 | Agent abuse: agent calls `ssh-run` aggressively | Medium | High | Per-process grace cap; rate limit in daemon (Phase 5); Touch ID is the brake |

---

## 5. Definition of done for this plan phase

- [ ] You read `tasks/plan.md` (this file).
- [ ] You read `tasks/todo.md`.
- [ ] You are OK with the phase order, the cuts (zero-trust deferred), and the estimates.
- [ ] You say "plan approved" or "rewrite Phase X".
- [ ] We commit the spec + plan + todo to `spec/lockshell-ssh` and open a PR for review before any code lands.

When you say go, Phase 0 begins on a fresh `feat/workspace-migration` branch.

---

## 6. Out-of-scope items captured for follow-up specs

The following are explicitly NOT in this plan, but were discussed during spec review and deserve their own specs after this train ships:

1. **`lockshell-zerotrust.md`** — port-knocking-style "open this port for N minutes, then close" flow for managed targets. Agent-friendly: any agent can request a port-open with a reason, user approves with Touch ID, lockshell pokes the firewall (iptables / pf) and schedules the close. **Why follow-up:** firewall integration is platform-specific and large; threat model needs its own pass.
2. **`lockshell-tui-mosaic.md`** — beyond 5-pane, dynamic mosaic, session save/restore, scrollback search, copy-mode. **Why follow-up:** scope creep on top of the basic TUI.
3. **`lockshell-mobile.md`** — companion iOS app for on-phone approvals (replaces caBLE QR with a push notification and a tap-to-approve UI). **Why follow-up:** requires a developer Apple ID for the iOS app, separate signing pipeline.
4. **`lockshell-team.md`** — multi-user CA, signed cert handoff between teammates. **Why follow-up:** explicitly out of scope per existing `docs/ARCHITECTURE.md` "Where this is NOT going" section.
