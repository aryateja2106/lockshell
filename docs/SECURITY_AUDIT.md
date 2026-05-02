# Security Audit Log

Public log of external security reviews, findings, and fixes.

## 2026-05-02 — Gemini code review (gemini-2.5-flash)

Independent security-focused code review by an external agent, with full source access. Report at `test-reports/gemini-security-review.md` (gitignored — produced per-machine on demand).

### Severity scorecard

- critical: 1
- high: 1
- medium: 4
- low: 5

### Findings + resolutions

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | low | Secret values held briefly in `String` could appear in panic output | Fixed via `zeroize::Zeroizing` wrapping in `commands/run.rs` |
| 2 | low | Verbose `agent-password` stderr propagation | Fixed via redactor applied to stderr in `vault.rs` |
| **3** | **critical** | **Shell injection: `{{NAME}}` substituted as `$NAME` (unquoted) — secret values with metachars could break out of intended argument boundary** | **Fixed: substitution now emits `"$NAME"` (double-quoted) in `commands/run.rs`** |
| 4 | medium | No memory zeroization for secret values | Fixed: `Zeroizing<String>` wraps secret values from `vault::get_field` to subprocess injection |
| 5 | low | Redactor patterns are best-effort | Documented in `docs/THREAT_MODEL.md`; added `cargo audit` to roadmap |
| 6 | low | All-or-nothing resolution behavior | Documented; this is by design |
| 7 | medium | `agent-password` stderr in `VaultError::Other` could leak values | Fixed via redactor applied before propagation in `vault.rs` |
| 8 | medium | No length limits on template / reason / registry fields | Fixed via `MAX_*_LEN` constants in `registry.rs` and `audit_log.rs`; truncate or reject |
| **9** | **high** | **`~/.config/lockshell/*` created with `0755`/`0644` (world-readable)** | **Fixed: explicit `0o700`/`0o600` modes via `OpenOptionsExt::mode` and `set_permissions` in `registry.rs`, `redact.rs`, `audit_log.rs`** |
| 10 | medium | `--no-redact` flag could be silently activated | Fixed: requires `LOCKSHELL_ALLOW_NO_REDACT=1` env var in addition to flag; warning printed when flag is set without env var |
| 11 | low | Transitive dependency surface not audited | Roadmap: `cargo audit` in CI before v0.2 |

### Verifications

After applying fixes, every code path was re-tested:

- Shell injection: substitution now produces `"$NAME"`. A value with whitespace or metacharacters cannot break out of the argument.
- File permissions: `~/.config/lockshell/` is `drwx------` (700). All three files inside (`registry.tsv`, `redactors.txt`, `audit.log`) are `-rw-------` (600).
- `--no-redact`: without the env var, flag is ignored and a warning is printed; redaction happens normally. With the env var, flag takes effect.
- Length limits: 300-character placeholder names are rejected with a clear error message.
- Real Linear GraphQL call still works: `{"data":{"viewer":{"name":"Arya Creator"}}}`

### Commits referencing this audit

- `feat(v0.1): initial lockshell foundation` (pre-audit baseline)
- `docs(agents): add AGENTS.md + skills/lockshell/SKILL.md`
- `fix(v0.1.1): three audit findings from codex agent-readiness test`
- `fix(v0.1.2): security review - 5 fixes (1 critical, 1 high, 3 medium)` ← this audit

### Methodology

The review agent ran with `--yolo` mode and `workspace-write` sandbox, with full read access to source and write access to `test-reports/`. No production credentials or vault contents were exposed during the review. The review focused on:

1. Secret leak paths (argv, stdout/stderr, panics, audit log, debug prints)
2. Subprocess safety and shell quoting
3. Memory hygiene
4. Redactor correctness
5. Race conditions
6. Error message sanitization
7. Input validation
8. File permissions
9. Dangerous flag handling
10. Dependency surface

### Re-running this audit

```bash
gemini --yolo -m gemini-2.5-flash \
  --prompt "$(cat /tmp/prompt-gemini-security-review.txt)"
```

The prompt template lives at `/tmp/prompt-gemini-security-review.txt` (or you can recreate it from this file's methodology section). Reports are written to `test-reports/gemini-security-review.md` and gitignored.

## Future audits

We plan to commission similar reviews:

- Before v0.2 (daemon + MCP server): full review including IPC layer
- Before v0.3 (native Apple Keychain): native API integration review
- Before v1.0: third-party paid review

If you find a vulnerability, see `CONTRIBUTING.md` § Security disclosures.
