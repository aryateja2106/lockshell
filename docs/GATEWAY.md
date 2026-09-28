# Model gateway (`lockshell gateway`)

`lockshell run` protects secrets used in **commands**. `lockshell gateway` protects
secrets used for **model calls**: any agent harness that speaks the OpenAI Chat
Completions API (Claude Code tools, Hermes, pi, Codex-style agents, scripts, `fm`)
points at a local endpoint instead of the provider, and never holds a provider key.

```
agent / harness ──(local client token)──► lockshell gateway ──(provider key)──► provider
                                            │  allowlist · mask · budget · audit
                                            └─ key read once from the Keychain, held in zeroized memory
```

## Setup

```bash
lockshell key add fireworks          # paste at a hidden prompt; prints a fingerprint only
lockshell gateway                    # first run writes ~/.config/lockshell/gateway.json
```

On start, macOS asks once per provider key whether lockshell may read it. Click **Allow**
(not *Always Allow*, unless you have decided the lockshell binary may read it silently).

Clients:

| Setting | Value |
|---|---|
| base URL | `http://127.0.0.1:8787/v1` |
| API key | contents of `~/.config/lockshell/gateway-token` (local-only, revocable: delete the file and restart) |
| model | `<provider>/<model>`, e.g. `fireworks/accounts/fireworks/models/deepseek-v4p1-flash`; `GET /v1/models` lists them |

## `gateway.json`

```json
{
  "host": "127.0.0.1", "port": 8787,
  "max_tokens_cap": 8192, "daily_token_budget": 2000000, "max_body_bytes": 8388608,
  "terms_file": null, "allowlist_file": null,
  "providers": {
    "fireworks": { "base_url": "https://api.fireworks.ai/inference/v1", "key": "fireworks",
                   "mask": true, "models": ["accounts/fireworks/models/deepseek-v4p1-flash"] },
    "apple":     { "base_url": "http://127.0.0.1:1976/v1", "key": null,
                   "mask": false, "models": ["system"] }
  }
}
```

- `host` must be a loopback address. The gateway refuses to start otherwise.
- `key` is a `lockshell key` name; `null` for local providers (no key, e.g. `fm serve`, llama.cpp, LM Studio).
- `mask: true` for anything that leaves the machine.
- `terms_file` / `allowlist_file` point the masker at your own lists (defaults:
  `~/.config/lockshell/sensitive-terms.txt`, `mask-allowlist.txt`).

## What happens to each request

1. Local client token checked (constant-time). Other macOS users on the machine can't use the gateway.
2. `provider/model` must be on the allowlist.
3. Daily token budget checked; `max_tokens` / `max_completion_tokens` capped.
4. If `mask: true`: every message `content` **and every earlier `tool_calls[].function.arguments`**
   is masked (`[EMAIL_1]`, `[PERSON_2]`, …). Multi-part (image) content is refused.
5. Upstream is called non-streaming, so the whole reply can be unmasked locally
   (`content`, `reasoning_content`, tool-call arguments). Clients that asked for
   `stream: true` get the finished reply replayed as SSE.
6. One audit line in `gateway-audit.jsonl`: provider, model, status, a hash of what was sent,
   masked-item counts per category, and token counts. Never text.

## Masking

`lockshell mask check|apply|restore` uses the same engine. Built-in patterns: API keys
(`fw_`, `sk-`, `ghp_`, …), email, Indian phone numbers, Aadhaar, PAN, IPv4. Add your own
names, clients, products and sites to the terms file (`CATEGORY: term`, any script).

Masking is deterministic and only as good as its lists. It will not catch a name that
isn't in the terms file or a sensitive fact phrased in plain words. Decide per document
whether it may go to a cloud model at all.

## Limits (v0.1.x)

- Chat Completions only (no embeddings, Responses API, images).
- Streaming is replayed, not incremental.
- No per-client tokens yet: one local token for all clients.
