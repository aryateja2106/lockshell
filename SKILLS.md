# SKILLS.md

Index of agent skills shipped with this repo. Each skill follows the [Agent Skills spec](https://github.com/anthropics/claude-code/tree/main/agent-skills) (frontmatter + body, discoverable by `npx skills`, `claude skills`, `gemini skills`, etc.).

## Available skills

| Skill | Path | Purpose |
|---|---|---|
| **lockshell** | `skills/lockshell/SKILL.md` | Use lockshell to broker any secret an agent needs. Triggers on authenticated API calls, CLI tools that read tokens from env, database connections, anything where a secret would otherwise need to be exposed. |

## Installing

If your agent supports the agent-skills spec:

```bash
# Anthropic Claude (when running with skills support)
claude skills add /path/to/lockshell/skills/lockshell

# Gemini CLI
gemini skills add /path/to/lockshell/skills/lockshell

# OpenClaw / nanobot (community skill registries)
openclaw skills install lockshell
```

If your agent does NOT support the spec, point it at `skills/lockshell/SKILL.md` and `AGENTS.md` directly. Both are plain markdown.

## Authoring more skills

If you want to ship a follow-on skill (e.g. a `lockshell-ssh` for SSH key handling once v0.6 lands), add a new directory under `skills/<skill-name>/` with a `SKILL.md` inside.

## Skill format reference

```markdown
---
name: skill-name
description: |
  Description used by agents to decide if this skill applies. Be specific
  about trigger conditions. Bad: "helps with auth". Good: "use when you
  need to call any API requiring an Authorization header".
license: Apache-2.0
allowed-tools: bash
metadata:
  version: 0.1.0
---

# skill-name

## Use this skill when
(bulleted, specific)

## The pattern (memorize this)
(one canonical example)

## First contact (every new session)
(idempotent setup checks)

## Common failure modes and recovery
(error message → exact remediation)

## Hard rules
(do / never)
```

Each skill should be concise enough that an agent reads it once at session start and remembers the pattern.

## Validating new skills

Before committing a new skill, run:

```bash
~/.config/scripts/skill-eval.sh ./skills/<new-skill-name>
```

This runs the skill through Skill-Lab (quality 0-100) and the Cisco AI Defense skill-scanner (severity-tagged threat findings). Skills must pass with no HIGH/CRITICAL findings before being merged.
