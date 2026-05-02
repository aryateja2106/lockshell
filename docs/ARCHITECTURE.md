# Architecture

This is the design doc for what Lockshell is and how the pieces fit together. The README is the elevator pitch; this is the schematic.

## v0.1 (today)

```
┌────────────────────────────────────────────────────┐
│ user terminal                                      │
│   $ lockshell run --reason "..." -- <cmd template> │
└──────┬─────────────────────────────────────────────┘
       │ in-process
       ▼
┌────────────────────────────────────────────────────┐
│ lockshell binary (Rust)                            │
│  cli.rs           clap dispatch                    │
│  registry.rs      ~/.config/lockshell/registry.tsv │
│  audit_log.rs     ~/.config/lockshell/audit.log    │
│  redact.rs        ~/.config/lockshell/redactors.txt│
│  vault.rs         shells out to agent-password     │
└──────┬─────────────────────────────────────────────┘
       │ subprocess
       ▼
┌────────────────────────────────────────────────────┐
│ agent-password binary                              │
│  ~/.agent-password/vault.db (SQLite, encrypted)    │
│  vault key in macOS login keychain                 │
└────────────────────────────────────────────────────┘
```

Single binary. Each invocation calls out to `agent-password` for a vault read, runs the user's command in a `bash -c` subprocess with secrets injected via env, and pipes the result through the redactor.

This is intentionally simple. It proves the broker pattern with off-the-shelf parts. v0.2 introduces a long-running daemon to enable session-aware UX, MCP integration, and the menu bar app.

## v0.2 (target)

```
┌─────────────────────────────────────────────────────────────────┐
│ macOS LaunchAgent                                               │
│   ~/Library/LaunchAgents/dev.aryateja.lockshelld.plist          │
└──────┬──────────────────────────────────────────────────────────┘
       │ spawns
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ lockshelld (long-running daemon)                                │
│  - Unix domain socket: ~/.lockshell/sock                        │
│  - JSON-RPC protocol (lockshell-proto)                          │
│  - holds session state, request queue, recent grants            │
└──┬──────────────┬─────────────────┬─────────────────────────────┘
   │              │                 │
   ▼              ▼                 ▼
┌────────┐  ┌──────────┐     ┌──────────────┐
│ CLI    │  │ MCP      │     │ Menu bar app │
│        │  │ server   │     │ (SwiftUI)    │
│        │  │ (stdio)  │     │              │
└────────┘  └──────────┘     └──────────────┘
   │              │                 │
   └──────────────┴─────────────────┘
                  │
                  ▼
              ┌──────────────────────┐
              │ Vault adapter trait  │
              │  - AgentPassword     │  v0.1 backend
              │  - AppleKeychain     │  v0.3 backend
              │  - VarlockBacked     │  v0.5 backend
              └──────────────────────┘
```

The daemon owns all vault reads. Clients (CLI, MCP, menu bar app) speak JSON-RPC over the local socket. Authentication between client and daemon uses peer-credential checks (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` / `getpeereid` on macOS) to verify the connecting process is the same UID as the daemon.

## v0.3 (target): Native Apple Keychain

Replace the `agent-password` adapter with native Security.framework calls:

```
SecKeychain APIs
  - SecAddSharedWebCredential / SecItemAdd for storage
  - kSecAttrAccessControl with kSecAccessControlBiometryCurrentSet
    forces a real biometric prompt per access
  - kSecAttrAccessGroup scoped to the signed lockshell bundle id
LocalAuthentication framework
  - LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)
    for the prompt itself
```

Requirements:

- Apple Developer ID signing certificate
- Notarized binary
- Bundle id e.g. `dev.aryateja.lockshell`

Without signing, the biometric ACL is ignored on unsigned binaries (this is the agent-password limitation we hit in v0.1). Signing is non-optional for v0.3 to deliver on the security claim.

## v0.5 (target): Varlock integration

Two integration points:

1. **Schema reading.** Lockshell parses `.env.schema` files (varlock-compatible) and uses them to discover the placeholder set for a project. Helps `lockshell run` validate that all required placeholders are registered before invoking.

2. **Plugin direction.** Publish `@varlock/lockshell-plugin` so any varlock-managed schema can resolve from a Lockshell vault via `lockshell()` resolver, parallel to varlock's existing `op()` (1Password) resolver.

```
.env.schema
  # @plugin(@varlock/lockshell-plugin)
  # @sensitive @type=string(startsWith=lin_api_)
  LINEAR_API_KEY=lockshell(linear-api.password)
```

`varlock load` then reaches into the lockshell daemon for resolution, with the broker's full request/approve/audit flow.

## Component contracts

### Registry (TSV)

`~/.config/lockshell/registry.tsv`

```
ENV_NAME<TAB>vault-id<TAB>field
```

One mapping per line. Comments start with `#`. The format is intentionally trivial so users can grep, sort, and edit it by hand.

### Audit log (TSV)

`~/.config/lockshell/audit.log`

```
ISO-8601-UTC<TAB>reason<TAB>command-template<TAB>comma-separated-secret-names
```

Append-only. Human-readable. The log captures **templates and reasons, never values**. If your template hard-codes a secret literal, that literal appears in the log; that is a misuse.

### Vault adapter trait (v0.2+)

```rust
pub trait Vault {
    fn session_status(&self) -> Result<SessionStatus>;
    fn request(&self, vault_id: &str, requester: &str, reason: &str) -> Result<u32>;
    fn approve(&self, request_id: u32) -> Result<()>;
    fn get_field(&self, vault_id: &str, field: &str) -> Result<String>;
    fn list(&self) -> Result<Vec<SecretMetadata>>;
}
```

Backend implementations:

- `AgentPasswordVault` (v0.1, current): subprocess to `agent-password`
- `AppleKeychainVault` (v0.3): direct Security.framework calls
- `VarlockVault` (v0.5): defers to the varlock daemon

### Daemon protocol (v0.2)

JSON-RPC 2.0 over Unix socket.

Methods:

- `vault.status` → SessionStatus
- `vault.request(id, requester, reason)` → request_id
- `vault.approve(request_id)` → bool
- `vault.list()` → [SecretMetadata]
- `broker.run(template, reason)` → { stdout, stderr, exit_code }

All values stay daemon-side. The CLI receives only redacted output.

## Why this layout

- **Single binary in v0.1** so users can `cargo install` and try it. No daemon to install. No launchd plist to debug.
- **Daemon in v0.2** because session UX (one Touch ID approving N reads) needs a process that lives longer than a single command. Also needed for MCP and the menu bar app.
- **Native Keychain in v0.3** because the v0.1 biometric gate degrades silently when the upstream binary is unsigned. We can either fix it upstream in agent-password or do it ourselves; doing it ourselves is faster.
- **Schema integration in v0.5** because varlock is the right schema layer and we should not duplicate it.

## Where this is NOT going

- Cloud sync. Lockshell is single-machine.
- Team sharing. Use varlock plugins or 1Password for that.
- Generic password manager. Use 1Password / Bitwarden / pass for that.
- Browser autofill. Out of scope.
- Cross-platform v1. macOS first; Linux when v0.3 stabilizes.
