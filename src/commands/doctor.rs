// SPDX-License-Identifier: Apache-2.0

use crate::cli::DoctorArgs;
use crate::redact;
use crate::registry;
use crate::ui;
use anyhow::Result;
use std::process::Command;

pub fn run(_args: DoctorArgs) -> Result<()> {
    let mut issues = 0;

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
        let s = String::from_utf8_lossy(&out.stdout);
        if s.contains("exists: true") {
            ui::ok("agent-password session exists");
        } else {
            ui::warn("no active agent-password session");
            ui::hint("agent-password session create");
        }
    }

    // 4. config dir
    let cfg = registry::config_dir();
    if cfg.exists() {
        ui::ok(&format!("config dir at {}", cfg.display()));
    } else {
        ui::warn(&format!("config dir does not exist (will be created on first use): {}", cfg.display()));
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
    if issues == 0 {
        ui::ok("all checks passed");
    } else {
        ui::err(&format!("{} issue(s) found", issues));
        std::process::exit(1);
    }
    Ok(())
}
