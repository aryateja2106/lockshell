// SPDX-License-Identifier: Apache-2.0

use crate::cli::RequestArgs;
use crate::ui;
use crate::vault::AgentPasswordVault;
use anyhow::Result;
use std::thread;
use std::time::{Duration, Instant};

pub fn run(args: RequestArgs) -> Result<()> {
    let user = std::env::var("USER").unwrap_or_else(|_| "lockshell".into());
    let id = AgentPasswordVault::request(&args.vault_id, &user, &args.reason)?;
    ui::ok(&format!("created request {} for '{}'", id, args.vault_id));
    println!();
    ui::info("To approve (Touch ID may prompt; on unsigned cargo builds it may silently no-op):");
    ui::hint(&format!("agent-password requests show {}", id));
    ui::hint(&format!("agent-password requests approve {} all", id));

    if args.wait {
        println!();
        ui::info("Waiting for approval (max 5 min, polling every 2s)...");
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(300) {
                ui::err("timeout: 5 minutes elapsed without approval");
                std::process::exit(4);
            }
            let status = AgentPasswordVault::session_status()?;
            if status.approved.iter().any(|s| s == &args.vault_id) {
                ui::ok(&format!("'{}' approved.", args.vault_id));
                return Ok(());
            }
            thread::sleep(Duration::from_secs(2));
        }
    }

    Ok(())
}
