// SPDX-License-Identifier: Apache-2.0

use crate::audit_log;
use crate::cli::DoctorArgs;
use crate::redact;
use crate::registry;
use crate::ui;
use anyhow::Result;
use std::process::Command;

pub fn run(_args: DoctorArgs) -> Result<()> {
    let mut issues = 0;
    let mut blockers = 0; // anything that prevents `lockshell run` from succeeding

    println!("running doctor checks…");
    println!();

    // 1. agent-password binary
    match which::which("agent-password") {
        Ok(p) => ui::ok(&format!("agent-password installed at {}", p.display())),
        Err(_) => {
            ui::err("agent-password binary not in PATH");
            ui::hint("cargo install --path ~/Projects/agent-password");
            issues += 1;
        }
    }

    // 2. vault initialised
    let vault_dir = std::env::var("HOME").map(|h| std::path::PathBuf::from(h).join(".agent-password"))
        .unwrap_or_default();
    if vault_dir.join("vault.db").exists() {
        ui::ok(&format!("vault file exists at {}", vault_dir.join("vault.db").display()));
    } else {
        ui::err("vault not initialised");
        ui::hint("agent-password vault init");
        issues += 1;
    }

    // 3. session
    if let Ok(out) = Command::new("agent-password").args(["session", "status"]).output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let combined = format!("{}\n{}", stdout, stderr);
        if combined.contains("internal daemon did not become ready")
            || combined.contains("failed to bind")
        {
            ui::err("agent-password daemon is not running (cannot bind socket).");
            ui::hint("Ask the user to run, in their normal shell: agent-password session create");
            ui::hint("Sandboxed agents cannot start the daemon themselves.");
            blockers += 1;
            issues += 1;
        } else if stdout.contains("exists: true") {
            ui::ok("agent-password session exists");
        } else {
            ui::warn("no active agent-password session");
            ui::hint("agent-password session create");
            blockers += 1;
            issues += 1;
        }
    }

    // 4. config dir + audit log writability (critical for `lockshell run`)
    let cfg = registry::config_dir();
    if cfg.exists() {
        ui::ok(&format!("config dir at {}", cfg.display()));
    } else {
        ui::warn(&format!("config dir does not exist (will be created on first use): {}", cfg.display()));
    }

    // Probe audit log writability by attempting a no-op append.
    match audit_log::append("doctor:writability-probe", "echo ok", &[]) {
        Ok(true) => ui::ok(&format!("audit log writable at {}", audit_log::audit_path().display())),
        Ok(false) | Err(_) => {
            ui::warn(&format!(
                "audit log not writable at {}",
                audit_log::audit_path().display()
            ));
            ui::hint("For sandboxed agents, export LOCKSHELL_CONFIG_DIR to a writable directory.");
            ui::hint("e.g. LOCKSHELL_CONFIG_DIR=$TMPDIR/lockshell mkdir -p $LOCKSHELL_CONFIG_DIR && cp ~/.config/lockshell/* $LOCKSHELL_CONFIG_DIR/ || true");
            issues += 1;
        }
    }

    // 5. redactor file
    redact::ensure_default()?;
    let count = redact::load_patterns()?.len();
    ui::ok(&format!("redactor patterns loaded: {} active", count));

    // 6. registry sanity
    match registry::load() {
        Ok(entries) => ui::ok(&format!("registry loaded: {} mapping(s)", entries.len())),
        Err(e) => {
            ui::err(&format!("registry corrupt or unreadable: {}", e));
            issues += 1;
        }
    }

    println!();
    if blockers > 0 {
        ui::err(&format!(
            "action required: {} blocker(s), {} issue(s). `lockshell run` will fail until resolved.",
            blockers, issues
        ));
        std::process::exit(1);
    } else if issues > 0 {
        ui::warn(&format!("{} non-blocking issue(s) found", issues));
        std::process::exit(2);
    } else {
        ui::ok("all checks passed");
    }
    Ok(())
}
