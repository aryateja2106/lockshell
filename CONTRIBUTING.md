# Contributing to Lockshell

Thanks for considering a contribution. This is alpha software with a small surface area, and we want to keep it focused.

## Before you write code

File an issue first if your change is anything beyond:

- A bug fix obvious from the symptom
- A docs typo or clarification
- A test for an existing path that is currently untested
- A new redactor pattern with evidence the format is real

For everything else, open an issue with the proposed design. We'd rather agree on direction than rework a PR.

## Setup

```bash
git clone https://github.com/aryateja2106/lockshell
cd lockshell
cargo build
cargo test
```

Required tools:

- Rust 1.74 or newer
- `agent-password` on `PATH` (for integration tests; install from https://github.com/tartavull/agent-password)
- A local vault you don't mind testing against (run `lockshell setup` once)

## Project layout

```
lockshell/
├── Cargo.toml           # workspace root (members = ["crates/*"])
├── crates/
│   └── lockshell/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs          # entry point, dispatches to commands
│           ├── cli.rs           # clap definitions for every subcommand
│           ├── commands/        # one module per subcommand
│           ├── registry.rs      # placeholder→vault mappings
│           ├── audit_log.rs     # append-only audit
│           ├── redact.rs        # regex-based output redaction
│           ├── vault.rs         # adapter to agent-password (replaced in v0.3)
│           └── ui.rs            # terminal output helpers
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   └── ROADMAP.md
└── tests/
    └── smoke.rs         # integration tests that hit the binary
```

## Code style

- `cargo fmt` before every commit. CI will fail without it.
- `cargo clippy --all-targets -- -D warnings`. No exceptions.
- Public functions get rustdoc comments. Private functions get them when behavior is non-obvious.
- Errors return `anyhow::Result` for top-level commands and `thiserror::Error` enums for library code.
- No `unwrap()` outside tests. Use `?` or `expect("a sentence describing why this is unreachable")`.

## Commit style

Conventional Commits:

```
feat(cli): add `lockshell unregister` command
fix(redact): correctly handle multi-line tool output
docs(threat-model): clarify per-bundle-id grants
chore(deps): bump clap to 4.5.4
```

One change per commit when reasonable.

## Tests

- Unit tests live next to the code (`#[cfg(test)] mod tests`).
- Integration tests live in `tests/`.
- Tests that hit a real `agent-password` vault must be feature-gated and skipped in CI by default.

Run everything:

```bash
cargo test --all-features
```

## Docs

If you change behavior, update:

- `README.md` for user-visible changes
- `docs/THREAT_MODEL.md` for security-property changes
- `docs/ROADMAP.md` if you complete or reshape a planned phase
- `--help` text in `crates/lockshell/src/cli.rs` for command flags

## Security disclosures

Find a vulnerability? Do not file a public issue. Email the maintainer directly (see README author block). PGP key TBA.

## License

By submitting a contribution you agree it is licensed under Apache-2.0, the project's license.

## Code of conduct

Be precise, be honest, do not waste each other's time. We are mostly individuals shipping personal software in the open. Disagreement is fine; condescension is not.
