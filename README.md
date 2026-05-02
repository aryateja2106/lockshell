# lockshell

**AI-safe secret broker.** Cloud LLMs decide what to run. Lockshell resolves secrets locally and executes commands without exposing values to the cloud LLM, the chat log, the process argv list, or any tracked file.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.74+-orange.svg)](https://www.rust-lang.org)
[![status: alpha](https://img.shields.io/badge/status-alpha-yellow.svg)](#stability)

```
┌──────────────────────────────────────────────────────────────────┐
│ CLOUD LLM   intent + reasoning, no secrets                       │
└────────────────────────┬─────────────────────────────────────────┘
                         │ command template with placeholders
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│ LOCKSHELL    resolves secrets, executes, redacts output          │
└──────┬─────────────────────────────────────────────┬─────────────┘
       ▼                                             ▼
┌────────────────┐                          ┌──────────────────┐
│ LOCAL VAULT    │                          │  TOOL SUBPROCESS │
│ Touch ID gate  │                          │  any CLI you run │
└────────────────┘                          └──────────────────┘
```

## Why

If you have ever told an AI coding agent "deploy this", "run this migration", or "list my issues", you have probably also given it your API key. Pasted in chat, copied to env, captured in a debug log, or held server-side by a tool layer you do not control.

Lockshell flips that. The cloud LLM produces a command **template** with named placeholders (`{{LINEAR_API_KEY}}`). You run the template through `lockshell`. The broker resolves placeholders against a local vault (Touch ID gated), runs the command in a subprocess with the secret in env (never argv), pipes output through a redaction filter, and returns only the cleaned output.

The cloud LLM never sees the value. The chat log never contains the value. Your shell history never contains the value. The audit log records the *template* and a *reason*, not values.

## Status: alpha

This is the v0.1 baseline. The CLI works end to end against the [`agent-password`](https://github.com/tartavull/agent-password) vault. The roadmap below lays out where this goes:

- v0.2: Long-running daemon, Unix-socket protocol, MCP server.
- v0.3: Native Apple Keychain backend with biometric ACL on a signed binary.
- v0.4: macOS menu bar app (SwiftUI).
- v0.5: SSH agent bridge, varlock plugin, schema-aware (`.env.schema`) integration.
- v1.0: Crypto wallet signer bridge, passkey handler, Linux port.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full plan.

## Install

### Prerequisites

- Rust 1.74+
- macOS (Linux support coming in v1.0)
- [`agent-password`](https://github.com/tartavull/agent-password) installed and on `PATH`

### Build from source

```bash
git clone https://github.com/aryateja2106/lockshell ~/Projects/lockshell
cd ~/Projects/lockshell
cargo install --path .
```

That puts `lockshell` in `~/.cargo/bin/`. Make sure that's on `PATH`.

### One-time setup

```bash
lockshell setup     # walks you through vault init + first secret
```

## Quickstart

Three commands and a real API call:

```bash
# 1) Add a secret to the vault. Pipe via stdin so the value never appears
#    on argv or in shell history.
printf '%s' 'lin_api_YOURKEYHERE' | agent-password login add linear-api \
  --username arya --url https://linear.app \
  --password-stdin --tag agent

# 2) Register a placeholder name mapping.
lockshell register LINEAR_API_KEY linear-api password

# 3) Approve for this session (Touch ID may prompt).
agent-password secrets request linear-api --requester arya --reason "linear cli"
agent-password requests approve <id> all

# 4) Run a real command. The cloud LLM that wrote this command never sees the key.
lockshell run --reason "list my issues" -- \
  'curl -s -X POST -H "Authorization: {{LINEAR_API_KEY}}" \
    -H "Content-Type: application/json" \
    --data "{\"query\":\"{ viewer { id name email } }\"}" \
    https://api.linear.app/graphql'
```

## Commands

| Command | Description |
|---|---|
| `lockshell setup` | Interactive first-time setup wizard |
| `lockshell register <ENV> <vault-id> <field>` | Map a placeholder to a vault entry |
| `lockshell unregister <ENV>` | Remove a mapping |
| `lockshell list [--json]` | Show registered mappings |
| `lockshell run --reason "..." -- <cmd>` | Run a command with placeholders resolved |
| `lockshell request <vault-id> [--wait]` | Issue a vault request, optionally wait for approval |
| `lockshell audit [-n N] [--json]` | Show audit log entries (templates and reasons, never values) |
| `lockshell status [--json]` | Show daemon, vault, and session state |
| `lockshell doctor [--fix]` | Diagnose setup issues |
| `lockshell version` | Print version |

Each command supports `--help` with examples.

## Threat model

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full version. The short version:

**What lockshell protects against:**
- Secret values reaching cloud LLM context windows or chat logs.
- Secret values appearing in `ps`-visible argv lists.
- Secret values in shell history (when the broker is used correctly).
- Accidentally leaked tokens in tool stdout/stderr (regex-based redaction).

**What lockshell does NOT protect against:**
- Full local compromise (any process running as you can ask the vault directly).
- You typing the secret into chat anyway. Habit beats tooling. Use `--password-stdin`.
- Bad scope at the source. A read-only token is safer than a perfectly brokered full-access one.
- Cloud LLMs exfiltrating the *content* the tool returns. Redaction filters tokens, not arbitrary data.
- Today's biometric gate is best-effort. The unsigned `cargo install` binary path in upstream `agent-password` silently degrades to login-keychain access. v0.3 fixes this with a properly signed Keychain integration.

## Comparison

| Tool | Audience | Encrypted at rest | Per-call biometric | AI-aware request flow | Schema layer | Cross-platform |
|---|---|---|---|---|---|---|
| `lockshell` (this) | Agents + you | Yes (via vault) | Yes (signed v0.3) | Yes | Yes (varlock-compatible v0.5) | macOS first |
| [`agent-password`](https://github.com/tartavull/agent-password) | Agents + you | Yes | Best-effort | Yes | No | macOS only |
| [`varlock`](https://github.com/dmno-dev/varlock) | Apps + you | via plugins | n/a | n/a | Yes (the standard) | Cross-platform |
| 1Password CLI | Humans (mostly) | Yes (cloud) | Yes | Limited | No | Cross-platform |
| `pass` | Humans | Yes (GPG) | n/a | No | No | Cross-platform |
| `direnv` + `.env` | Devs | No (plain) | No | No | No | Cross-platform |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The TL;DR: run `cargo test`, follow the existing module patterns, file an issue before a large change.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Related

- [`agent-password`](https://github.com/tartavull/agent-password): the local vault we currently use as a backend.
- [`varlock`](https://github.com/dmno-dev/varlock): AI-safe `.env` schemas and runtime protection. We plan a `@varlock/lockshell-plugin`.
- [`InnerWarden`](https://github.com/InnerWarden/innerwarden): autonomous host security agent for Linux. Same audience.

## Author

[Arya Teja Rudraraju](https://www.aryateja.com), San Francisco. Building [LeSearch AI](https://lesearch.ai), [CloudAGI](https://github.com/aryateja2106/cloudagi), [LeCoder MConnect](https://github.com/aryateja2106), [NL2Shell](https://nl2shell.com).
