// SPDX-License-Identifier: Apache-2.0

use crate::cli::SetupArgs;
use crate::ui;
use anyhow::Result;
use std::process::Command;

pub fn run(args: SetupArgs) -> Result<()> {
    println!("lockshell setup");
    println!("─────────────────────────────────────────────────────────────");
    println!();

    // Step 1: agent-password installed?
    if which::which("agent-password").is_err() {
        ui::err("agent-password is not installed.");
        ui::info("Install it (clones, builds, copies binary into ~/.cargo/bin):");
        ui::hint("git clone https://github.com/tartavull/agent-password ~/Projects/agent-password");
        ui::hint("cd ~/Projects/agent-password && cargo install --path .");
        return Ok(());
    }
    ui::ok("agent-password is installed");

    // Step 2: vault init?
    let home = std::env::var("HOME").unwrap_or_default();
    let vault_db = std::path::Path::new(&home).join(".agent-password").join("vault.db");
    if !vault_db.exists() {
        ui::warn("vault not initialised yet");
        ui::info("Run this in your terminal (interactive, may prompt for keychain):");
        ui::hint("agent-password vault init");
        if !args.non_interactive {
            print!("Run it now? [y/N] ");
            use std::io::Write;
            std::io::stdout().flush().ok();
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            if buf.trim().eq_ignore_ascii_case("y") {
                let s = Command::new("agent-password").args(["vault", "init"]).status()?;
                if !s.success() {
                    ui::err("vault init failed; check the error above");
                    return Ok(());
                }
            } else {
                ui::info("Skipping vault init. Re-run `lockshell setup` after running it manually.");
                return Ok(());
            }
        }
    } else {
        ui::ok("vault initialised");
    }

    // Step 3: session
    let session_out = Command::new("agent-password").args(["session", "status"]).output()?;
    let session_text = String::from_utf8_lossy(&session_out.stdout);
    if !session_text.contains("exists: true") {
        ui::warn("no active session");
        ui::hint("agent-password session create");
        if !args.non_interactive {
            print!("Create one now? [y/N] ");
            use std::io::Write;
            std::io::stdout().flush().ok();
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            if buf.trim().eq_ignore_ascii_case("y") {
                Command::new("agent-password").args(["session", "create"]).status()?;
            }
        }
    } else {
        ui::ok("session active");
    }

    println!();
    ui::ok("setup looks good");
    println!();
    println!("Next steps:");
    println!("  1. Add a secret to the vault (NEVER paste the value into chat):");
    println!("     printf %s 'YOUR_KEY' | agent-password login add my-api \\");
    println!("       --username you --url https://example.com --password-stdin --tag agent");
    println!();
    println!("  2. Register the placeholder mapping:");
    println!("     lockshell register MY_API_KEY my-api password");
    println!();
    println!("  3. Run a command using the placeholder:");
    println!("     lockshell run --reason \"first call\" -- \\");
    println!("       'curl -s -H \"Authorization: {{{{MY_API_KEY}}}}\" https://api.example.com'");

    Ok(())
}
