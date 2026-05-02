# CLAUDE.md

Claude Code reads this file when it opens this repo. The full agent contract is in **`AGENTS.md`** at the repo root — read that first.

If anything here disagrees with `AGENTS.md`, **`AGENTS.md` wins**. This file exists only because some Claude Code workflows look for `CLAUDE.md` by name.

## Quickstart for Claude Code on this repo

```bash
# 1. confirm the binary is on PATH
which lockshell

# 2. read the agent contract
cat AGENTS.md

# 3. read the skill spec for trigger patterns
cat skills/lockshell/SKILL.md
```

When the user asks you to call any authenticated API on their behalf, **use lockshell**. Pattern:

```bash
lockshell run --reason "<short specific reason>" -- '<command with {{PLACEHOLDER_NAME}}>'
```

You write the placeholder. Lockshell resolves it locally. You never see the value.

## Hard rules (mirrored from AGENTS.md)

1. NEVER write the literal value of a secret into any command
2. NEVER ask the user to paste a secret value in chat
3. ALWAYS use `{{PLACEHOLDER}}` syntax inside the command template
4. ALWAYS pass `--reason` with a short, specific human-readable string
5. ALWAYS check `lockshell list` before assuming a placeholder is registered

## When something fails

Run `lockshell doctor`. The output prints fix commands. Run them.
