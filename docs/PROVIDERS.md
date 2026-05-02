# Provider playbook

Tested setup recipes for the CLIs and APIs Arya uses daily, plus the multi-account convention.

Every recipe follows the same shape:

1. **Create the API key** at the provider's dashboard.
2. **Pipe it into the vault** without ever pasting into chat or argv.
3. **Register a placeholder** so agents can refer to it by name.
4. **Approve it** (one Touch ID) for this session.
5. **Use it** via `lockshell run`.

If you have multiple accounts (e.g. Supabase for three different projects), use a suffix convention. There is a section on that at the bottom.

---

## Linear

**Token type:** Personal API key (full account access). Create at: <https://linear.app/settings/api>.

```bash
# 1. Pipe the value in (paste-from-clipboard pattern)
pbpaste | agent-password login add linear-api \
  --username you --url https://linear.app \
  --password-stdin --tag agent

# 2. Register
lockshell register LINEAR_API_KEY linear-api password

# 3. Approve
agent-password secrets request linear-api --requester you --reason "linear access"
agent-password requests list   # note the id
agent-password requests approve <id> all   # Touch ID

# 4. Use
lockshell run --reason "fetch viewer info" -- \
  'curl -s -X POST -H "Authorization: {{LINEAR_API_KEY}}" \
    -H "Content-Type: application/json" \
    --data "{\"query\":\"{ viewer { name email } }\"}" \
    https://api.linear.app/graphql'
```

---

## Vercel

**Token type:** [Account-level token](https://vercel.com/account/tokens). You can scope it to a team or specific projects when creating it; lockshell does not affect scope, only how the token is brokered.

```bash
# 1. Pipe in
pbpaste | agent-password login add vercel \
  --username you --url https://vercel.com \
  --password-stdin --tag agent

# 2. Register
lockshell register VERCEL_TOKEN vercel password

# 3. Approve
agent-password secrets request vercel --requester you --reason "vercel deploy"
agent-password requests approve <id> all

# 4. Use the official Vercel CLI through the broker
lockshell run --reason "list my projects" -- \
  'VERCEL_TOKEN={{VERCEL_TOKEN}} vercel project ls'

lockshell run --reason "deploy preview from current dir" -- \
  'VERCEL_TOKEN={{VERCEL_TOKEN}} vercel deploy --yes'
```

The pattern for any CLI that reads an env var is identical: prefix the command with `<ENV_VAR_NAME>={{PLACEHOLDER}}`. The CLI sees a normal env var; lockshell ensures the value is set only in the subprocess.

---

## Supabase (single project)

**Token type:** [Personal access token](https://supabase.com/dashboard/account/tokens). Has wide access; consider per-project tokens if available.

```bash
# 1. Pipe in
pbpaste | agent-password login add supabase \
  --username you --url https://supabase.com \
  --password-stdin --tag agent

# 2. Register
lockshell register SUPABASE_ACCESS_TOKEN supabase password

# 3. Approve
agent-password secrets request supabase --requester you --reason "supabase cli"
agent-password requests approve <id> all

# 4. Use
lockshell run --reason "list my supabase projects" -- \
  'SUPABASE_ACCESS_TOKEN={{SUPABASE_ACCESS_TOKEN}} supabase projects list'

lockshell run --reason "push migrations to staging" -- \
  'SUPABASE_ACCESS_TOKEN={{SUPABASE_ACCESS_TOKEN}} supabase db push --linked'
```

---

## Supabase (multiple projects) — multi-account pattern

This is the canonical multi-account workflow. Suppose you have three Supabase projects: a personal one, one for CloudAGI, and one for aryateja.com.

**Vault step:** add each token under a distinct vault id.

```bash
pbpaste | agent-password login add supabase-personal --username you \
  --url https://supabase.com --password-stdin --tag agent

pbpaste | agent-password login add supabase-cloudagi --username you \
  --url https://supabase.com --password-stdin --tag agent

pbpaste | agent-password login add supabase-aryateja --username you \
  --url https://supabase.com --password-stdin --tag agent
```

**Register step:** map each to a distinctly-named placeholder. The convention is `<PROVIDER>_TOKEN_<CONTEXT>`.

```bash
lockshell register SUPABASE_TOKEN_PERSONAL supabase-personal password
lockshell register SUPABASE_TOKEN_CLOUDAGI supabase-cloudagi password
lockshell register SUPABASE_TOKEN_ARYATEJA supabase-aryateja password
```

**Discoverability:**

```bash
lockshell list --grep supabase
# PLACEHOLDER                    VAULT_ID                       FIELD
# ----------------------------------------------------------------------------
# SUPABASE_TOKEN_PERSONAL        supabase-personal              password
# SUPABASE_TOKEN_CLOUDAGI        supabase-cloudagi              password
# SUPABASE_TOKEN_ARYATEJA        supabase-aryateja              password
```

**Use:** the placeholder you write in the command picks the project. There is no global "active project" state; the explicit name in each command is the source of truth, which is exactly what you want when an agent is making the choice.

```bash
# Personal project
lockshell run --reason "list personal projects" -- \
  'SUPABASE_ACCESS_TOKEN={{SUPABASE_TOKEN_PERSONAL}} supabase projects list'

# CloudAGI project
lockshell run --reason "push CloudAGI migrations" -- \
  'SUPABASE_ACCESS_TOKEN={{SUPABASE_TOKEN_CLOUDAGI}} supabase db push --linked'
```

When an agent says "I want to call Supabase", it should ask which context, not assume. `lockshell list --grep supabase` is the discoverability tool.

> **v0.2 plans:** `lockshell context set cloudagi` will set an active context, and `{{SUPABASE_TOKEN}}` (no suffix) will resolve to the active context's mapping. Until then, suffixes are explicit and safer for agents to reason about.

---

## GitHub

**Token type:** [Fine-grained personal access token](https://github.com/settings/personal-access-tokens). Always prefer fine-grained over classic; scope to specific repositories.

```bash
pbpaste | agent-password login add github-pat --username you \
  --url https://github.com --password-stdin --tag agent
lockshell register GITHUB_TOKEN github-pat password
agent-password secrets request github-pat --requester you --reason "github access"
agent-password requests approve <id> all

lockshell run --reason "list my private repos" -- \
  'curl -s -H "Authorization: Bearer {{GITHUB_TOKEN}}" \
    "https://api.github.com/user/repos?visibility=private&per_page=5"'
```

**Multi-account:** if you have separate work and personal GitHub accounts, suffix it: `GITHUB_TOKEN_WORK`, `GITHUB_TOKEN_PERSONAL`.

---

## OpenAI

**Token type:** [API key](https://platform.openai.com/api-keys). Create a project-scoped key, not the legacy account key.

```bash
pbpaste | agent-password login add openai --username you \
  --url https://platform.openai.com --password-stdin --tag agent
lockshell register OPENAI_API_KEY openai password
agent-password secrets request openai --requester you --reason "openai access"
agent-password requests approve <id> all

lockshell run --reason "list available models" -- \
  'curl -s https://api.openai.com/v1/models \
    -H "Authorization: Bearer {{OPENAI_API_KEY}}"'
```

---

## Anthropic

**Token type:** [API key](https://console.anthropic.com/settings/keys).

```bash
pbpaste | agent-password login add anthropic --username you \
  --url https://console.anthropic.com --password-stdin --tag agent
lockshell register ANTHROPIC_API_KEY anthropic password
agent-password secrets request anthropic --requester you --reason "anthropic access"
agent-password requests approve <id> all

lockshell run --reason "anthropic ping" -- \
  'curl -s https://api.anthropic.com/v1/messages \
    -H "x-api-key: {{ANTHROPIC_API_KEY}}" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d "{\"model\":\"claude-3-haiku-20240307\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"'
```

---

## OpenRouter

```bash
pbpaste | agent-password login add openrouter --username you \
  --url https://openrouter.ai --password-stdin --tag agent
lockshell register OPENROUTER_API_KEY openrouter password
agent-password secrets request openrouter --requester you --reason "openrouter access"
agent-password requests approve <id> all
```

---

## Cloudflare (handle with care)

**Cloudflare tokens are powerful.** A token with "Edit zone DNS" can redirect your domain to anywhere. Treat them as production-blast-radius secrets.

**Recommended scope:** create a token at <https://dash.cloudflare.com/profile/api-tokens> with the **minimum** zone:permission set you need. For DNS-only changes, use "Zone DNS Edit" scoped to specific zones.

```bash
pbpaste | agent-password login add cloudflare --username you \
  --url https://dash.cloudflare.com --password-stdin --tag agent
lockshell register CLOUDFLARE_API_TOKEN cloudflare password
agent-password secrets request cloudflare --requester you --reason "cloudflare zone read"
agent-password requests approve <id> all
```

**Recommendation for agents using Cloudflare**: write only `--reason` strings that include the zone or operation. Lockshell's audit log makes it easy to spot a `cloudflare` invocation that does not match what you expected.

```bash
# Read-only zone list — safe pattern
lockshell run --reason "list zones I own" -- \
  'curl -s -H "Authorization: Bearer {{CLOUDFLARE_API_TOKEN}}" \
    https://api.cloudflare.com/client/v4/zones'
```

**For wrangler**: until v0.2, the safest pattern is to broker `wrangler` commands explicitly through lockshell:

```bash
lockshell run --reason "wrangler whoami sanity check" -- \
  'CLOUDFLARE_API_TOKEN={{CLOUDFLARE_API_TOKEN}} wrangler whoami'
```

Avoid running `wrangler` against production zones inside an unsupervised agent loop until you have explicit reason-string discipline and a habit of reviewing the audit log.

---

## Multi-account convention summary

The naming convention to use across all providers when you have multiple accounts:

| Pattern | Example |
|---|---|
| Single account | `SUPABASE_ACCESS_TOKEN`, `LINEAR_API_KEY`, `VERCEL_TOKEN` |
| Multi-account | `SUPABASE_TOKEN_<CONTEXT>`, `LINEAR_API_KEY_<CONTEXT>`, `VERCEL_TOKEN_<CONTEXT>` |

Where `<CONTEXT>` is a short uppercase token: `PERSONAL`, `WORK`, `CLOUDAGI`, `ARYATEJA`, `LESEARCH`, etc.

The vault id should match the same naming so they are easy to grep:

| Vault id | Placeholder |
|---|---|
| `supabase-cloudagi` | `SUPABASE_TOKEN_CLOUDAGI` |
| `linear-api-personal` | `LINEAR_API_KEY_PERSONAL` |
| `vercel-aryateja-com` | `VERCEL_TOKEN_ARYATEJA_COM` |

To see all of them at once:

```bash
lockshell list --grep <provider>
```

To see only placeholder names (for piping into a fzf-style picker):

```bash
lockshell list --grep <provider> --names-only
```

---

## Cleaning up

Removing a registered placeholder (does not delete the vault entry):

```bash
lockshell unregister LINEAR_API_KEY
```

Removing the secret from the vault entirely:

```bash
agent-password secrets delete linear-api
```

Closing the session (drops all approvals):

```bash
agent-password session close
```

---

## Getting the dashboard view

Once you have several placeholders set up, render the local HTML dashboard:

```bash
lockshell dashboard
```

This opens a self-contained HTML page in your default browser showing your registry, recent audit entries, and session state. No values are shown — by design.
