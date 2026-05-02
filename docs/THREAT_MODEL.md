# Threat Model

Honest description of what Lockshell defends against, what it does not, and where the seams are.

## Adversaries we care about

1. **Cloud LLM provider.** Anthropic, OpenAI, Google. They run the models and log conversations. Most of the time this is fine. But "the chat is stored locally" is not the full picture: it is *also* on their servers. Lockshell's first job is to keep secret values out of conversations entirely.

2. **A compromised cloud LLM session.** Prompt injection, malicious tool output, jailbreak. If the cloud LLM is hijacked, the worst it can do via lockshell is request a secret. Approval is yours.

3. **Casual local snooping.** Someone with brief access to your terminal or your shell history. `ps`-visible argv. `.bash_history` / `.zsh_history`.

4. **Process-table snooping.** A different process on the same machine running `ps -ef` and reading your command lines.

5. **Tool-side leaks.** A CLI you invoke that helpfully echoes your auth header in `-v` output, a stack trace, or a debug log.

## Adversaries we explicitly do NOT defend against in v0.1

1. **Full local compromise.** If an attacker has shell as your user, they can run `agent-password secrets get` themselves. The vault is encrypted at rest, not at runtime against your own UID.

2. **Hardware compromise.** Cold-boot attack, kernel rootkit, evil-maid, malicious USB peripheral. Out of scope. If your laptop is compromised at this level, you have bigger problems than a Linear API key.

3. **You typing the secret value into chat.** Habits beat tooling. Lockshell exists to make the right path the easy path; it does not enforce the right path.

4. **Bad token scope at the source.** A read-only Linear token is safer than a full-access one regardless of brokering. Always scope at the API provider first.

5. **Cloud LLM exfiltrating tool *output*.** If your tool returns customer emails and the cloud LLM gets them, that is a separate leak. Lockshell redacts known token formats, not arbitrary sensitive content. For workflows that touch sensitive data, prefer a local model.

## Properties Lockshell provides (v0.1)

| Property | Mechanism |
|---|---|
| Secret never in cloud LLM context | Cloud LLM only sees command templates with `{{NAME}}` and redacted output |
| Secret never on argv | Resolved values are injected via env, command refers to them by name |
| Secret never in shell history | `lockshell run` is the only thing in your history |
| Secret never in tracked files | Vault is in `~/.agent-password/`, registry has names not values, audit log has templates not values |
| Audit trail | Append-only TSV log of templates + reasons + secret names |
| Output redaction safety net | Regex against known token formats applied to stdout/stderr before printing |

## Properties Lockshell does NOT provide (v0.1)

| Missing property | Why |
|---|---|
| Live biometric per access | Upstream `agent-password` is unsigned, biometric ACL silently degrades. Fixed in v0.3 with native Keychain + Developer ID signing. |
| Per-bundle-id granular grants | Daemon model needed (v0.2). Today any process running as you can talk to the vault. |
| Tamper-evident audit log | Audit log is plain TSV. v0.2 daemon will sign entries with Ed25519. |
| Network egress detection | Out of scope. Pair with InnerWarden or similar host-side EDR. |
| Hardware-bound secrets (Secure Enclave) | v0.3, requires Developer ID signing. |
| Outbound DNS leak detection | Out of scope. |

## Trust boundaries (v0.1)

```
Trust boundary 1: cloud LLM ↔ your machine
  what crosses: command templates (in), redacted output (out)
  what does NOT cross: secret values, vault contents, raw stderr

Trust boundary 2: lockshell binary ↔ agent-password vault
  what crosses: vault id + field name (request), value (response)
  same UID, same machine, same login session

Trust boundary 3: lockshell subprocess ↔ tool subprocess
  what crosses: env vars (in), stdout/stderr (out)
  argv does NOT carry secrets
```

## Failure modes and mitigations

| Failure | Mitigation |
|---|---|
| You paste a secret into chat | Read this doc, use `lockshell run`. There's no software cure for habit. |
| Tool prints secret in stdout | Redactor catches known token formats. Add patterns to `~/.config/lockshell/redactors.txt` for new formats. |
| Tool prints secret in stderr | Same redactor applies to stderr. |
| Tool stores secret in its own config file | Out of scope for the broker. Audit your tools. |
| Vault file lost or corrupted | Vault is on disk only; no cloud sync in v0.1. Back up `~/.agent-password/` if you care. |
| Audit log tampered with | v0.1 limitation. v0.2 daemon will sign. |
| Cloud LLM asks for a secret it should not have | Approval is yours. Read the request reason before approving. v0.2 menu bar app shows this prominently. |

## Comparison

Threats other tools claim to handle:

| Threat | 1Password | varlock | agent-password | lockshell v0.1 | lockshell v0.3 |
|---|---|---|---|---|---|
| Cloud LLM context leak | partial | yes (schema only) | partial | yes | yes |
| Argv leak | yes | yes (via load) | yes | yes | yes |
| Shell history leak | yes | yes | yes | yes | yes |
| Per-call biometric | yes (Touch ID) | n/a | best-effort | best-effort | yes |
| Per-app/process grants | partial | n/a | no | no | yes |
| Audit log signing | yes | no | no | no | yes |
| Schema validation | no | yes | no | no | yes (via varlock) |
| Hardware-bound (Secure Enclave) | yes | no | no | no | yes |

## Reporting vulnerabilities

Email the maintainer directly. See [`README.md`](../README.md) author block. Do not file a public GitHub issue.

## Glossary

- **Cloud LLM**: Claude, GPT, Gemini, etc. Models you talk to over the internet.
- **Local LLM**: A model running on your machine (e.g. NL2Shell, Gemma 270M, FunctionGemma).
- **Broker**: Lockshell. Resolves secrets and runs commands.
- **Vault**: Local encrypted store. Today: `agent-password`. v0.3: macOS Keychain.
- **Secret**: API key, OAuth token, SSH passphrase, etc.
- **Capability**: A scoped, time-bounded grant to use a secret. Today equivalent to "approved within session"; v0.2+ can be tighter.
- **Redactor**: Output filter that masks known sensitive token formats.
