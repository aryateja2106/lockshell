// SPDX-License-Identifier: Apache-2.0

use crate::audit_log;
use crate::cli::AuditArgs;
use anyhow::Result;

pub fn run(args: AuditArgs) -> Result<()> {
    let entries = audit_log::tail(args.lines)?;
    if entries.is_empty() {
        println!("(no audit entries yet — run something with `lockshell run`)");
        return Ok(());
    }
    if args.json {
        for e in &entries {
            println!("{}", serde_json::to_string(e)?);
        }
        return Ok(());
    }
    for e in &entries {
        println!("{}", e.timestamp);
        println!("  reason:    {}", e.reason);
        println!("  template:  {}", e.template);
        if e.secrets.is_empty() {
            println!("  secrets:   (none)");
        } else {
            println!("  secrets:   {}", e.secrets.join(", "));
        }
        println!();
    }
    Ok(())
}
