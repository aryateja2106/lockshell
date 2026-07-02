# AGENTS.md — lockshell

If AI coding agent (Claude Code, Codex, Cursor, pi, Copilot, etc.) found this file, read once. Tell everything need to use lockshell correctly, in order.

## What lockshell is, in one paragraph

`lockshell` = CLI on user machine that brokers secret values for you. You produce command **template** with `{{PLACEHOLDER}}` names. Pass template to `lockshell run`. Lockshell resolves placeholders against local encrypted vault, runs command in subprocess with secrets in env (never argv), pipes output through regex redactor, returns redacted result. **You never see secret value.** User never paste in chat. This pattern.

## When to use lockshell

ALWAYS, when:

- Need to call any API requiring authentication (`Authorization` header, query param, `--token` flag)
- Need to run CLI tool reading secret from env (`LINEAR_TOKEN`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `SUPABASE_ACCESS_TOKEN`, `CLOUDFLARE_API_TOKEN`, etc.)
- Need to reach database with password
- Need to sign anything with private key

NEVER:

- Ask user to paste secret value into chat
- Write secret value into any file agent can see
- Echo secret to stdout deliberately (redactor = safety net, not plan)

## The contract

You write:
```
'<some command> --token "{{LINEAR_API_KEY}}"'
```

Hand string to:
```
lockshell run --reason "<short human-readable reason>" -- '<that command>'
```

Receive:
- stdout: tool output, known token formats redacted
- stderr: same treatment
- exit code: subprocess exit code

Do NOT receive: value of any `{{PLACEHOLDER}}`.

## First-time-on-this-machine flow (do once per session)

Run checks, in order:

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

`doctor` exits non-zero on actionable problems. Read output, run printed commands.

Exit codes:
- 0 — ready to broker
- 1 — blocker present (`lockshell run` will fail). Fix before attempting.
- 2 — non-blocking issue (e.g. audit log not writable in your sandbox)

Most common gaps:

- `agent-password vault init` — brand-new install only. User does once with Touch ID. You cannot.
- `agent-password session create` — once per shell session, by user from unsandboxed shell. Sandboxed agents cannot bind daemon socket, will see "internal daemon did not become ready".
- `agent-password secrets request <id> --requester <you> --reason "..."` then `agent-password requests approve <N> all` — once per session per secret.

## Sandboxed agents (Codex `workspace-write`, similar)

If sandbox restricts writes to `~/.config/`, lockshell audit log location may not be writable. Two options:

- **Set `LOCKSHELL_CONFIG_DIR`** to directory you can write (e.g. `$TMPDIR/lockshell`). Copy existing registry over once:

  ```bash
  export LOCKSHELL_CONFIG_DIR="${TMPDIR%/}/lockshell"
  mkdir -p "$LOCKSHELL_CONFIG_DIR"
  cp -n ~/.config/lockshell/registry.tsv "$LOCKSHELL_CONFIG_DIR/" 2>/dev/null || true
  cp -n ~/.config/lockshell/redactors.txt "$LOCKSHELL_CONFIG_DIR/" 2>/dev/null || true
  ```

- **Or accept best-effort auditing.** v0.1 lockshell warns when audit log can't be written but still runs command. Cloud-leak prevention does not depend on audit log; depends on env-only secret injection.

If sandbox blocks Unix socket creation under `~/.agent-password/`, cannot start daemon. Ask user to run `agent-password session create` in normal shell. Daemon then reachable to sandbox via existing socket file (read-only access sufficient for most agent operations).

## When `lockshell run` fails with "not approved"

Will see something like:

```
✗ LINEAR_API_KEY is in the vault but not approved for this session.
  agent-password secrets request linear-api --requester arya --reason "list issues"
  agent-password requests list
  agent-password requests approve <id> all
```

Run those three commands, in that order, *as printed*. Third fires Touch ID for user. Then re-run original `lockshell run` line.

## When the placeholder is not registered

```
✗ Error: LINEAR_API_KEY is not registered.
  Run: lockshell register LINEAR_API_KEY <vault-id> <field>
```

Need two things from user:
- **vault id** (name like `linear-api`)
- **field** within vault entry (typically `password` for `login add` style entries, `token` for `secret put --type api_key`)

If neither exists, user hasn't added secret yet. Tell them to add via `agent-password login add ... --password-stdin` (value piped via stdin so never appears on argv or in chat). Do NOT propose user paste value into conversation.

## Persistence across sessions

**Registry** (`~/.config/lockshell/registry.tsv`) persists. Once placeholder registered, every future agent on machine sees via `lockshell list`. Do not re-register.

**Vault** persists. Once secret in vault, stays.

**Session unlock + per-secret approval** does NOT persist across `agent-password session close` or reboots. Intentional — user re-asserts presence by approving each session. If you (agent) come into fresh session and need secret, follow "When `lockshell run` fails with not approved" flow above.

## Discovering what API to call

`lockshell` does not know how to call APIs. Your job. `lockshell` only handles secret. Examples:

- Linear GraphQL → `https://api.linear.app/graphql`, header `Authorization: <token>`
- GitHub REST → `https://api.github.com`, header `Authorization: Bearer <token>`
- Vercel → `https://api.vercel.com`, header `Authorization: Bearer <token>`
- Supabase → `https://api.supabase.com` for platform CLI; project-specific for data
- OpenAI → `https://api.openai.com/v1`, header `Authorization: Bearer <token>`

Look up actual API in provider docs, then write curl/CLI invocation with `{{PLACEHOLDER}}` for secret.

## Reasoning text in `--reason`

You write reason. Short and specific so user, looking at audit log next month, knows why secret was used. Good reasons:

- `"fetch viewer info from linear"`
- `"deploy aryateja.com to vercel preview"`
- `"list open issues assigned to me"`

Bad reasons:

- `"do stuff"`
- `"as requested"`
- `"linear"` (too generic)

## What you should NEVER do

1. Write literal value of secret into `lockshell run` command. Use `{{PLACEHOLDER}}`.
2. Ask user to paste secret value in chat.
3. Use `lockshell run --no-redact` unless explicitly debugging with user permission.
4. Call `agent-password secret put` with value as CLI arg. Always pipe via stdin.
5. Suggest user add secret to `.env` file (use vault).

## Self-check before you write a command

Ask yourself:

- [ ] Did I use `{{PLACEHOLDER}}` instead of literal secret?
- [ ] Did I pass `--reason` with specific, human-readable string?
- [ ] If secret just added, did I run request → approve flow?
- [ ] Did I check `lockshell list` to confirm placeholder registered?
- [ ] If placeholder missing, did I tell user how to add without pasting value in chat?

If all five yes, using lockshell correctly.

## Where to read more

- `README.md` for human pitch
- `docs/THREAT_MODEL.md` for what lockshell defends against
- `docs/ARCHITECTURE.md` for v0.1 → v0.3 plan
- `examples/linear-graphql.md` for worked example


<claude-mem-context>
# Memory Context

# [lockshell] recent context, 2026-05-02 2:16pm PDT

Legend: 🎯session 🔴bugfix 🟣feature 🔄refactor ✅change 🔵discovery ⚖️decision 🚨security_alert 🔐security_note
Format: ID TIME TYPE TITLE
Fetch details: get_observations([IDs]) | Search: mem-search skill

Stats: 13 obs (5,062t read) | 142,837t work | 96% savings

### May 2, 2026
3877 2:01p 🔵 Lockshell agent contract and workflow documented
3878 " 🔵 Lockshell skill defines agent trigger patterns and hard rules
3879 2:02p 🔵 Lockshell doctor diagnosed system state and missing session
3880 " 🔵 Agent-password daemon fails to start with ready check timeout
3881 " 🔵 Lockshell run fails with audit log permission error
3883 " 🔵 lockshell agent-password session creation fails silently
3882 2:03p 🔵 Audit log implementation traced to config_dir plus audit.log
3884 " 🔵 lockshell run fails with permission error on audit.log despite correct Unix permissions
3885 2:04p 🔵 LOCKSHELL_CONFIG_DIR workaround bypasses audit.log permission issue but exposes agent-password daemon failure
3887 " 🔵 agent-password daemon startup timeout mechanism reveals 5-second connection window
3888 2:05p 🔵 agent-password daemon fails to bind Unix socket due to macOS Operation not permitted error
3890 2:06p 🔵 macOS blocks Unix socket bind operations across all directories for agent-password binary
3894 " ✅ lockshell agent-readiness audit report completed documenting macOS security failures

Access 143k tokens of past work via get_observations([IDs]) or mem-search skill.
</claude-mem-context>