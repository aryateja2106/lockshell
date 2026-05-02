// SPDX-License-Identifier: Apache-2.0

use crate::cli::StatusArgs;
use crate::registry;
use crate::ui;
use crate::vault::AgentPasswordVault;
use anyhow::Result;
use serde_json::json;

pub fn run(args: StatusArgs) -> Result<()> {
    let mappings = registry::load().unwrap_or_default();
    let session_result = AgentPasswordVault::session_status();
    let session = session_result.as_ref().ok().cloned();

    if args.json {
        let s = json!({
            "registry": {
                "path": registry::registry_path(),
                "count": mappings.len(),
            },
            "session": match &session {
                Some(s) => json!({
                    "exists": s.exists,
                    "unlocked": s.unlocked,
                    "approved": s.approved,
                    "pending_requests": s.pending_requests,
                }),
                None => json!(null),
            }
        });
        println!("{}", serde_json::to_string_pretty(&s)?);
        return Ok(());
    }

    ui::info(&format!("registry: {} ({} mapping{})",
        registry::registry_path().display(),
        mappings.len(),
        if mappings.len() == 1 { "" } else { "s" }
    ));

    match session {
        Some(s) if s.exists => {
            ui::ok(&format!("session: exists={}, unlocked={}, approved=[{}], pending={}",
                s.exists, s.unlocked,
                s.approved.join(","),
                s.pending_requests));
        }
        Some(_) => {
            ui::warn("session: not active. Run: agent-password session create");
        }
        None => {
            // Surface the actual error rather than a generic message.
            let err = session_result.err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".into());
            ui::err(&format!("session: {}", err));
        }
    }
    Ok(())
}
