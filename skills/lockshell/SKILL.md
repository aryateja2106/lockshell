---
name: lockshell
description: Use lockshell when you need to authenticate against any API, CLI tool, or service that requires a secret (API key, token, password, SSH passphrase). Lockshell brokers the secret locally so you never see the value, the user never has to paste it in chat, and the secret never enters argv, shell history, or the cloud LLM context. Triggers on any task involving authenticated API calls, CLI tools that read tokens from env, database connections, or anything where a secret would otherwise need to be exposed.
license: Apache-2.0
allowed-tools: bash
metadata:
  version: 0.1.0
  homepage: https://github.com/aryateja2106/lockshell
---

# lockshell

## Use this skill when

- You need to call an authenticated API on behalf of the user
- You need to run a CLI tool that wants `LINEAR_TOKEN`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `SUPABASE_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, etc.
- You need to access a database with a password
- The user mentioned they want secrets handled "via lockshell" or "without me typing the key again"

## The pattern (memorize this)

```bash
lockshell run --reason "<short, specific reason>" -- '<command with {{PLACEHOLDER_NAME}}>'
```

Example:

```bash
lockshell run --reason "fetch viewer info from linear" -- \
  'curl -s -X POST -H "Authorization: {{LINEAR_API_KEY}}" \
    -H "Content-Type: application/json" \
    --data "{\"query\":\"{ viewer { id name email } }\"}" \
    https://api.linear.app/graphql'
```

You write `{{LINEAR_API_KEY}}`. Lockshell resolves it locally and runs the command. You see only the API response.

## First contact (every new session)

```bash
lockshell doctor    # diagnose state, prints fix commands for anything missing
lockshell status    # shows session unlock state + count of pending requests
lockshell list      # shows what placeholders are already mapped
```

If `doctor` shows missing pieces, run the commands it prints, in order.

## When you get "not approved"

```
✗ FOO_KEY is in the vault but not approved for this session.
  agent-password secrets request foo --requester arya --reason "..."
  agent-password requests list
  agent-password requests approve <id> all
```

Run those three lines exactly as printed. The third one needs the user (Touch ID may prompt). Then retry your original `lockshell run`.

## When the placeholder is not registered

The user needs to:
1. Add the secret to the vault (NEVER paste the value in chat — pipe via stdin):
   ```bash
   printf '%s' 'PASTE_HERE' | agent-password login add my-thing \
     --username you --url https://example.com --password-stdin --tag agent
   ```
2. Register the mapping:
   ```bash
   lockshell register MY_THING_KEY my-thing password
   ```

Then your `lockshell run` with `{{MY_THING_KEY}}` works.

## Hard rules

- NEVER write the literal value of a secret into any command
- NEVER ask the user to paste a secret value in chat
- ALWAYS use `{{PLACEHOLDER}}` syntax inside the command template
- ALWAYS pass `--reason` with a short, specific human-readable string
- ALWAYS check `lockshell list` before assuming a placeholder is registered

## Discover commands

```bash
lockshell --help              # all subcommands
lockshell run --help          # the most-used one
lockshell <any> --help        # any subcommand has detailed help
```

## What lockshell does not do

- It does not know how to call any specific API. Look up the API in the provider's docs.
- It does not protect against you typing the secret value yourself. Use `{{PLACEHOLDER}}`.
- It does not protect against full local compromise. Pair with host-side EDR.
