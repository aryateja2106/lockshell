# Example: Linear GraphQL via lockshell

End-to-end example using a real Linear API key via lockshell. The actual key value never enters chat, never appears on argv, never enters shell history, and never reaches the cloud LLM that wrote the command.

## Prerequisites

```bash
which agent-password           # must be on PATH
agent-password vault init      # one-time
agent-password session create  # per session
```

## Add the secret without ever typing it in chat

Browser: `linear.app/<workspace>/settings/account/security` → New API key. Copy the value (`lin_api_...`).

Terminal: pipe the value via stdin so it never appears on argv.

```bash
printf '%s' 'PASTE_HERE_AND_HIT_ENTER' | agent-password login add linear-api \
  --username arya \
  --url https://linear.app \
  --password-stdin \
  --tag agent
```

## Register the placeholder mapping

```bash
lockshell register LINEAR_API_KEY linear-api password
lockshell list
```

## Approve for this session

Touch ID may prompt. On the unsigned cargo-installed `agent-password` build, the prompt may silently no-op (see THREAT_MODEL.md).

```bash
agent-password secrets request linear-api --requester $USER --reason "linear graphql"
agent-password requests list
agent-password requests approve <id> all
```

## Run a real GraphQL query through the broker

```bash
lockshell run --reason "fetch viewer info" -- \
  'curl -s -X POST -H "Authorization: {{LINEAR_API_KEY}}" -H "Content-Type: application/json" --data "{\"query\":\"{ viewer { id name email } }\"}" https://api.linear.app/graphql'
```

Expected output (real data, no key value visible):

```
{"data":{"viewer":{"id":"...","name":"Your Name","email":"you@example.com"}}}
```

## Inspect the audit log

```bash
lockshell audit -n 5
```

Each entry shows timestamp, reason, command template (with `{{LINEAR_API_KEY}}` placeholder), and the secret names used. Never values.
