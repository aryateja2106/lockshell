// SPDX-License-Identifier: Apache-2.0

use crate::cli::ListArgs;
use crate::registry;
use anyhow::Result;

pub fn run(args: ListArgs) -> Result<()> {
    let mut entries = registry::load()?;

    // Apply --grep filter if provided. Case-insensitive substring match against
    // either placeholder or vault id. This is the main multi-account UX:
    // `lockshell list --grep supabase` finds every supabase-* placeholder
    // regardless of whether you used _PROD/_DEV suffixes or per-project ids.
    if let Some(pattern) = &args.grep {
        let p = pattern.to_lowercase();
        entries.retain(|m| {
            m.env_name.to_lowercase().contains(&p) || m.vault_id.to_lowercase().contains(&p)
        });
    }

    if args.json {
        let json = serde_json::to_string_pretty(&entries)?;
        println!("{}", json);
        return Ok(());
    }

    if args.names_only {
        for m in entries {
            println!("{}", m.env_name);
        }
        return Ok(());
    }

    if entries.is_empty() {
        if args.grep.is_some() {
            println!("(no placeholders match filter)");
        } else {
            println!("(no placeholder mappings registered)");
            println!();
            println!("  Register one with:");
            println!("    lockshell register LINEAR_API_KEY linear-api password");
        }
        return Ok(());
    }
    println!("{:<30} {:<30} FIELD", "PLACEHOLDER", "VAULT_ID");
    println!("{}", "-".repeat(76));
    for m in entries {
        println!("{:<30} {:<30} {}", m.env_name, m.vault_id, m.field);
    }
    Ok(())
}
