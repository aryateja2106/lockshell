// SPDX-License-Identifier: Apache-2.0

use crate::cli::ListArgs;
use crate::registry;
use anyhow::Result;

pub fn run(args: ListArgs) -> Result<()> {
    let entries = registry::load()?;
    if args.json {
        let json = serde_json::to_string_pretty(&entries)?;
        println!("{}", json);
        return Ok(());
    }
    if entries.is_empty() {
        println!("(no placeholder mappings registered)");
        println!();
        println!("  Register one with:");
        println!("    lockshell register LINEAR_API_KEY linear-api password");
        return Ok(());
    }
    println!("{:<30} {:<30} FIELD", "PLACEHOLDER", "VAULT_ID");
    println!("{}", "-".repeat(76));
    for m in entries {
        println!("{:<30} {:<30} {}", m.env_name, m.vault_id, m.field);
    }
    Ok(())
}
