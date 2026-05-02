# Roadmap

Phased plan from v0.1 (today) to v1.0. Honest timeboxes; multiply by 2 when in doubt.

## v0.1 — alpha foundation (DONE)

**Shipped:** 2026-05-02

- [x] Single Rust binary (`lockshell`)
- [x] Registry (TSV) at `~/.config/lockshell/registry.tsv`
- [x] Audit log (TSV) at `~/.config/lockshell/audit.log`
- [x] Default redactor patterns (Linear, Anthropic, GitHub, Slack, Google, JWT, AWS)
- [x] Subprocess execution with env-injected secrets, redacted output
- [x] Subcommands: `setup`, `register`, `unregister`, `list`, `run`, `request`, `audit`, `status`, `doctor`, `version`
- [x] Adapter to `agent-password` as v0.1 vault backend
- [x] Apache-2.0 license
- [x] README, CONTRIBUTING, ARCHITECTURE, THREAT_MODEL, this ROADMAP

## v0.2 — daemon + protocol (target: 1-2 weeks)

- [ ] `lockshelld` long-running daemon
- [ ] LaunchAgent plist for autostart at login
- [ ] Unix domain socket at `~/.lockshell/sock`
- [ ] JSON-RPC protocol spec (`lockshell-proto`)
- [ ] Peer-credential verification (only same-UID processes can talk to the daemon)
- [ ] CLI client switches from direct subprocess calls to RPC over socket
- [ ] MCP server (stdio + HTTP variants) so Cursor / Claude Code / Codex can call lockshell directly
- [ ] In-daemon request queue with TTL
- [ ] Smoke tests covering daemon happy path

## v0.3 — native Apple Keychain (target: 1 week after v0.2)

Apple Developer ID + notarization:

- [ ] Developer ID certificate provisioning
- [ ] Bundle id `dev.aryateja.lockshell` registered
- [ ] Codesign + notarize CI workflow

Native Keychain backend:

- [ ] `AppleKeychainVault` impl using `Security.framework`
- [ ] `kSecAttrAccessControl` with `kSecAccessControlBiometryCurrentSet` for hardware-backed biometric gating
- [ ] `LAContext.evaluatePolicy` for prompt UX
- [ ] Migration tool: `lockshell migrate-from-agent-password`
- [ ] Updated threat model + blog post on the integrity upgrade

## v0.4 — macOS menu bar app (target: 2-3 weeks)

SwiftUI menubar:

- [ ] Pending requests badge
- [ ] Approve / deny per-secret with reason visible
- [ ] Active grants list (vault id, requesting process, time remaining)
- [ ] Recent activity / audit
- [ ] Secure input modal for adding new secrets (no clipboard, paste-from-keychain only)
- [ ] Connect via the v0.2 daemon socket

## v0.5 — schema + varlock (target: 1 week after v0.4)

Varlock integration:

- [ ] Read `.env.schema` files for placeholder discovery
- [ ] Validate placeholders are registered before `lockshell run`
- [ ] `@varlock/lockshell-plugin` published to npm
- [ ] Joint blog with dmno-dev

Schema-driven UX:

- [ ] `lockshell run` with auto-detected placeholders from `.env.schema`
- [ ] Project-scoped registries (per-repo `.lockshell/registry.tsv`)

## v0.6 — SSH agent bridge (target: 1 week)

- [ ] Load passphrase-protected private keys via lockshell into ssh-agent on demand
- [ ] `lockshell ssh-key add ~/.ssh/id_ed25519 --label github` (passphrase from vault)
- [ ] Auto-revoke after configurable TTL
- [ ] Integration with the existing agent-password "login add" stdin pattern

## v0.7 — small-LM NL frontend (target: 2 weeks, depends on NL2Shell maturity)

- [ ] Optional `lockshell ask "<natural language>"` subcommand
- [ ] Local model (NL2Shell or FunctionGemma) translates intent → command template
- [ ] Falls back to "no model available" with the manual flow if model not installed
- [ ] Never sends NL prompts or generated commands to a cloud LLM
- [ ] Only suggests; never auto-executes

## v0.8 — crypto wallet signer bridge (target: 1-2 weeks)

- [ ] Forward signing requests to Ledger / hardware wallets (no private key extraction)
- [ ] Ethereum + Solana initial coverage
- [ ] Approval flow shows the transaction in human-readable form before signing

## v0.9 — passkey / WebAuthn handler (target: 1 week)

- [ ] WebAuthn assertion via macOS native APIs
- [ ] Lockshell as a passkey provider for agents that want one
- [ ] Pairs with v0.4 menu bar app for biometric prompts

## v1.0 — Linux port + stability (target: open-ended)

- [ ] Linux port using libsecret / GNOME Keyring / KDE Wallet as the vault backend
- [ ] Stable JSON-RPC protocol (versioned)
- [ ] Stable plugin API
- [ ] Documented migration paths between vault backends
- [ ] Public binaries on GitHub Releases
- [ ] Homebrew formula

## Beyond v1.0 (no commitments)

- Browser extension (Chrome / Firefox) for web flows
- Mobile companion (Approve from iPhone via push)
- Team sync via end-to-end encrypted backend (only if anyone asks for it)
- Plugin marketplace
- Audit log shippable to InnerWarden for cross-host correlation

## What we will not build

- A general password manager UI
- A cloud sync product
- A SaaS pricing tier
- Anything that requires a server we operate
