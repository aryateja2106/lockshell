---
name: lockshell
description: Use lockshell when you need to authenticate against any API, CLI tool, or service that requires a secret (API key, token, password, SSH passphrase). Lockshell brokers the secret locally so you never see the value, the user never has to paste it in chat, and the secret never enters argv, shell history, or the cloud LLM context. Triggers on any task involving authenticated API calls, CLI tools that read tokens from env, database connections, or anything where a secret would otherwise need to be exposed.
license: Apache-2.0
allowed-tools: bash
metadata:
  version: 0.1.2
  homepage: https://github.com/aryateja2106/lockshell
---

# lockshell

## Use this skill when

- You need to call an authenticated API on behalf of the user
- You need to run a CLI tool that wants `LINEAR_TOKEN`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `SUPABASE_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, `VERCEL_TOKEN`, etc.
- You need to access a database with a password
- The user mentioned they want secrets handled "via lockshell" or "without me typing the key again"

## The pattern (memorize this)

```bash
lockshell run --reason "<short, specific reason>" -- '<command with {{PLACEHOLDER_NAME}}>'
```

You write `{{PLACEHOLDER_NAME}}`. Lockshell resolves it locally and runs the command. You see only the API response, redacted for known token formats.

## Step-by-step usage

### Step 1 — Verify lockshell is on PATH

```bash
which lockshell
```

If empty, the user must install lockshell first. See `https://github.com/aryateja2106/lockshell` for instructions. Stop here and tell the user.

### Step 2 — Run the doctor

```bash
lockshell doctor
```

Read the exit code:

- `exit 0` — you can proceed
- `exit 1` — there is a blocker. Read the output and run the printed fix commands literally.
- `exit 2` — non-blocking issue (e.g. audit log not writable in your sandbox). Proceed; lockshell will warn but the broker still works.

The most common `exit 1` blocker is "no active agent-password session". The user needs to run `agent-password session create` from their normal shell. You cannot do this for them in a sandboxed agent.

### Step 3 — Check the registry

```bash
lockshell list
```

This shows every placeholder that is mapped to a vault secret. Example output:

```
PLACEHOLDER                    VAULT_ID                       FIELD
----------------------------------------------------------------------------
LINEAR_API_KEY                 linear-api                     password
GITHUB_TOKEN                   github-pat                     password
```

If the placeholder you want is in the list, skip to Step 5.

### Step 4 — If the placeholder is missing

The user has not added this secret yet. Tell them, but **never ask them to paste the value in chat**. Print these instructions for them to run in their terminal:

```bash
# 1. Add the secret to the vault (value via stdin, never on argv).
#    Replace <VAULT_ID> with a short name like "github-pat" and pipe
#    the actual value from clipboard or paste:
printf '%s' 'PASTE_VALUE_HERE' | agent-password login add <VAULT_ID> \
  --username you --url https://example.com \
  --password-stdin --tag agent

# 2. Register the placeholder mapping:
lockshell register <PLACEHOLDER_NAME> <VAULT_ID> password
```

Wait for the user to confirm. Then re-run Step 3 to verify, and proceed.

### Step 5 — Check if the secret is approved for this session

```bash
lockshell status
```

Look at the `approved=[...]` field. If your `vault-id` (e.g. `linear-api`) is in the list, skip to Step 7.

### Step 6 — If the secret is not approved

Issue a request and ask the user to approve it:

```bash
agent-password secrets request <VAULT_ID> --requester $(whoami) --reason "<your reason>"
agent-password requests list
agent-password requests approve <ID> all
```

The third command needs the user (Touch ID may prompt; on unsigned cargo builds the prompt may silently no-op but the approval still goes through). The `<ID>` is shown by `requests list`.

### Step 7 — Run the actual command

```bash
lockshell run --reason "<short, specific reason>" -- '<your command>'
```

The command is a single string with `{{PLACEHOLDER_NAME}}` markers. Lockshell will:

1. Substitute each `{{NAME}}` with `"$NAME"` (a properly-quoted env var reference)
2. Inject each value as an env var on the subprocess (never on argv)
3. Run the command via `bash -c`
4. Pipe stdout and stderr through a redactor before printing
5. Append a record of the template + reason (never values) to the audit log

Example for Linear:

```bash
lockshell run --reason "fetch viewer info from linear" -- \
  'curl -s -X POST -H "Authorization: {{LINEAR_API_KEY}}" \
    -H "Content-Type: application/json" \
    --data "{\"query\":\"{ viewer { id name email } }\"}" \
    https://api.linear.app/graphql'
```

Example for GitHub:

```bash
lockshell run --reason "list my private repos" -- \
  'curl -s -H "Authorization: Bearer {{GITHUB_TOKEN}}" \
    https://api.github.com/user/repos?visibility=private'
```

Example for a CLI tool that reads from env:

```bash
lockshell run --reason "deploy preview to vercel" -- \
  'VERCEL_TOKEN={{VERCEL_TOKEN}} vercel deploy'
```

### Step 8 — Check the audit log (optional)

```bash
lockshell audit -n 5
```

Shows the most recent 5 invocations. Each entry has timestamp, reason, command template (with `{{PLACEHOLDER}}` markers), and the secret names that were used. Never values.

## Common failure modes and recovery

### `LINEAR_API_KEY is not registered`

You skipped Step 3. The placeholder you wrote is not in `lockshell list`. Either it has a different name (check the list output), or the user has not added the secret yet (Step 4).

### `LINEAR_API_KEY is in the vault but not approved for this session`

You skipped Step 5/6. The secret exists in the vault but the current `agent-password` session has not approved it. Run the request → list → approve flow.

### `agent-password daemon is not running and could not be started`

The user closed the session, or your sandbox blocks Unix socket creation under `~/.agent-password/`. Tell the user to run `agent-password session create` in their normal shell. You cannot do this for them.

### `audit log not writable`

Your sandbox cannot write to `~/.config/lockshell/audit.log`. Lockshell warns and continues. The broker still works. If you want a clean audit trail in your sandbox, set `LOCKSHELL_CONFIG_DIR=$TMPDIR/lockshell` and copy the existing registry over once.

### Output looks empty or the command exited non-zero

The subprocess failed. Look at stderr (lockshell pipes it through too, with redaction). Most often it's the API itself responding with an error: 401 (auth), 403 (scope), 429 (rate limit), 5xx (provider issue). The cloud-leak prevention is independent of the command's success.

## Hard rules

1. **NEVER** write the literal value of a secret into any command. Use `{{PLACEHOLDER}}`.
2. **NEVER** ask the user to paste a secret value in chat. Always pipe via stdin to `agent-password`.
3. **ALWAYS** use `{{PLACEHOLDER}}` syntax inside the command template.
4. **ALWAYS** pass `--reason` with a short, specific human-readable string.
5. **ALWAYS** check `lockshell list` before assuming a placeholder is registered.
6. **NEVER** use `--no-redact` unless the user explicitly asks for it AND has set `LOCKSHELL_ALLOW_NO_REDACT=1`. Even then, prefer not to.
7. **NEVER** suggest the user store a secret in `.env` or any tracked file. The vault is the only place.

## Self-check before you write a command

- [ ] Did I use `{{PLACEHOLDER}}` instead of a literal secret?
- [ ] Did I pass `--reason` with a specific, human-readable string?
- [ ] If the secret was just added, did I run the request → approve flow (Step 6)?
- [ ] Did I check `lockshell list` to confirm the placeholder is registered (Step 3)?
- [ ] If the placeholder is missing, did I tell the user how to add it without pasting the value in chat (Step 4)?

If all five are yes, you are using lockshell correctly.

## Discover more commands

```bash
lockshell --help              # all subcommands
lockshell run --help          # the most-used one
lockshell <any> --help        # any subcommand has detailed help
lockshell version
```

## What lockshell does NOT do

- It does not know how to call any specific API. Look up the API in the provider's docs (the right header format, query shape, etc.).
- It does not protect against you typing the secret value yourself. Use `{{PLACEHOLDER}}`.
- It does not protect against full local compromise (an attacker with shell as the user can talk to the vault directly).
- It does not enforce live biometric on every access in v0.1 (best-effort with `agent-password`'s unsigned binary; v0.3 fixes this with native Apple Keychain).
- It does not redact arbitrary sensitive content in tool output (e.g. customer emails). The redactor catches known token formats only.
