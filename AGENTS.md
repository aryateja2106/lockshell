# AGENTS.md — lockshell

If you are an AI coding agent (Claude Code, Codex, Cursor, pi, Copilot, etc.) and you found this file, read it once. It tells you everything you need to use lockshell correctly, in order.

## What lockshell is, in one paragraph

`lockshell` is a CLI on the user's machine that brokers secret values for you. You produce a command **template** with `{{PLACEHOLDER}}` names. You pass that template to `lockshell run`. Lockshell resolves placeholders against a local encrypted vault, runs the command in a subprocess with secrets in env (never argv), pipes output through a regex redactor, and returns the redacted result. **You never see the secret value.** The user never has to paste it in chat. This is the pattern.

## When to use lockshell

ALWAYS, when:

- You need to call any API that requires authentication (`Authorization` header, query param, `--token` flag)
- You need to run a CLI tool that reads a secret from env (`LINEAR_TOKEN`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `SUPABASE_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, etc.)
- You need to reach a database with a password
- You need to sign anything with a private key

NEVER:

- Ask the user to paste the value of a secret into chat
- Write a secret value into any file the agent can see
- Echo a secret to stdout deliberately (the redactor is a safety net, not the plan)

## The contract

You write:
```
'<some command> --token "{{LINEAR_API_KEY}}"'
```

You hand that string to:
```
lockshell run --reason "<short human-readable reason>" -- '<that command>'
```

You receive:
- stdout: the tool's output, with known token formats redacted
- stderr: same treatment
- exit code: the subprocess's exit code

You do NOT receive: the value of any `{{PLACEHOLDER}}`.

## First-time-on-this-machine flow (do once per session)

Run these checks, in order:

```bash
# 1. Is lockshell on PATH?
which lockshell

# 2. Is the vault and broker healthy?
lockshell doctor

# 3. What placeholders are already mapped?
lockshell list

# 4. What does the live session look like?
lockshell status
```

`doctor` exits non-zero on actionable problems. Read the output and run the printed commands.

Exit codes:
- 0 — ready to broker
- 1 — blocker present (`lockshell run` will fail). Fix before attempting.
- 2 — non-blocking issue (e.g. audit log not writable in your sandbox)

Most common gaps:

- `agent-password vault init` — brand-new install only. The user does this once with Touch ID. You cannot.
- `agent-password session create` — once per shell session, by the user from an unsandboxed shell. Sandboxed agents cannot bind the daemon socket and will see "internal daemon did not become ready".
- `agent-password secrets request <id> --requester <you> --reason "..."` then `agent-password requests approve <N> all` — once per session per secret.

## Sandboxed agents (Codex `workspace-write`, similar)

If your sandbox restricts writes to `~/.config/`, lockshell's audit log location may not be writable. Two options:

- **Set `LOCKSHELL_CONFIG_DIR`** to a directory you can write (e.g. `$TMPDIR/lockshell`). Copy the existing registry over once:

  ```bash
  export LOCKSHELL_CONFIG_DIR="${TMPDIR%/}/lockshell"
  mkdir -p "$LOCKSHELL_CONFIG_DIR"
  cp -n ~/.config/lockshell/registry.tsv "$LOCKSHELL_CONFIG_DIR/" 2>/dev/null || true
  cp -n ~/.config/lockshell/redactors.txt "$LOCKSHELL_CONFIG_DIR/" 2>/dev/null || true
  ```

- **Or accept best-effort auditing.** v0.1 lockshell warns when the audit log can't be written but still runs the command. The cloud-leak prevention does not depend on the audit log; it depends on env-only secret injection.

If your sandbox blocks Unix socket creation under `~/.agent-password/`, you cannot start the daemon. Ask the user to run `agent-password session create` in their normal shell. The daemon then becomes reachable to your sandbox via the existing socket file (read-only access is sufficient for most agent operations).

## When `lockshell run` fails with "not approved"

You will see something like:

```
✗ LINEAR_API_KEY is in the vault but not approved for this session.
  agent-password secrets request linear-api --requester arya --reason "list issues"
  agent-password requests list
  agent-password requests approve <id> all
```

Run those three commands, in that order, *as printed*. The third one fires Touch ID for the user. Then re-run your original `lockshell run` line.

## When the placeholder is not registered

```
✗ Error: LINEAR_API_KEY is not registered.
  Run: lockshell register LINEAR_API_KEY <vault-id> <field>
```

You need two things from the user:
- The **vault id** (a name like `linear-api`)
- The **field** within that vault entry (typically `password` for `login add` style entries, `token` for `secret put --type api_key`)

If neither exists, the user hasn't added the secret yet. Tell them to add it via `agent-password login add ... --password-stdin` (the value is piped in via stdin so it never appears on argv or in chat). Do NOT propose the user paste the value into the conversation.

## Persistence across sessions

The **registry** (`~/.config/lockshell/registry.tsv`) persists. Once a placeholder is registered, every future agent on this machine sees it via `lockshell list`. You do not re-register.

The **vault** persists. Once a secret is in the vault, it stays.

The **session unlock + per-secret approval** does NOT persist across `agent-password session close` or reboots. That is intentional — the user re-asserts presence by approving each session. If you (the agent) come into a fresh session and need a secret, follow the "When `lockshell run` fails with not approved" flow above.

## Discovering what API to call

`lockshell` does not know how to call APIs. That is your job. `lockshell` only handles the secret. For example:

- Linear GraphQL → `https://api.linear.app/graphql`, header `Authorization: <token>`
- GitHub REST → `https://api.github.com`, header `Authorization: Bearer <token>`
- Vercel → `https://api.vercel.com`, header `Authorization: Bearer <token>`
- Supabase → `https://api.supabase.com` for the platform CLI; project-specific for data
- OpenAI → `https://api.openai.com/v1`, header `Authorization: Bearer <token>`

Look up the actual API in the provider's docs, then write the curl/CLI invocation with `{{PLACEHOLDER}}` for the secret.

## Reasoning text in `--reason`

You will write the reason. Make it short and specific so the user, looking at the audit log next month, knows why a secret was used. Good reasons:

- `"fetch viewer info from linear"`
- `"deploy aryateja.com to vercel preview"`
- `"list open issues assigned to me"`

Bad reasons:

- `"do stuff"`
- `"as requested"`
- `"linear"` (too generic)

## What you should NEVER do

1. Write the literal value of a secret into a `lockshell run` command. Use `{{PLACEHOLDER}}`.
2. Ask the user to paste a secret value in chat.
3. Use `lockshell run --no-redact` unless explicitly debugging with the user's permission.
4. Call `agent-password secret put` with the value as a CLI arg. Always pipe via stdin.
5. Suggest the user add the secret to a `.env` file (use the vault).

## Self-check before you write a command

Ask yourself:

- [ ] Did I use `{{PLACEHOLDER}}` instead of a literal secret?
- [ ] Did I pass `--reason` with a specific, human-readable string?
- [ ] If the secret was just added, did I run the request → approve flow?
- [ ] Did I check `lockshell list` to confirm the placeholder is registered?
- [ ] If the placeholder is missing, did I tell the user how to add it without pasting the value in chat?

If all five are yes, you are using lockshell correctly.

## Where to read more

- `README.md` for the human pitch
- `docs/THREAT_MODEL.md` for what lockshell defends against
- `docs/ARCHITECTURE.md` for the v0.1 → v0.3 plan
- `examples/linear-graphql.md` for a worked example


<claude-mem-context>
# Memory Context

# [lockshell] recent context, 2026-05-02 2:02pm PDT

Legend: 🎯session 🔴bugfix 🟣feature 🔄refactor ✅change 🔵discovery ⚖️decision 🚨security_alert 🔐security_note
Format: ID TIME TYPE TITLE
Fetch details: get_observations([IDs]) | Search: mem-search skill

Stats: 2 obs (741t read) | 8,318t work | 91% savings

### May 2, 2026
3877 2:01p 🔵 Lockshell agent contract and workflow documented
3878 " 🔵 Lockshell skill defines agent trigger patterns and hard rules

Access 8k tokens of past work via get_observations([IDs]) or mem-search skill.
</claude-mem-context>