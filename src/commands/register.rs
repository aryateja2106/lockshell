// SPDX-License-Identifier: Apache-2.0

use crate::cli::{RegisterArgs, UnregisterArgs};
use crate::registry;
use crate::ui;
use anyhow::Result;

pub fn run(args: RegisterArgs) -> Result<()> {
    if !is_valid_env_name(&args.env_name) {
        ui::err(&format!("invalid env name '{}'. Must match [A-Z_][A-Z0-9_]*", args.env_name));
        std::process::exit(2);
    }
    if registry::is_forbidden_env_name(&args.env_name) {
        ui::err(&format!(
            "'{}' controls how programs run (shell/loader/runtime variable); pick another name, e.g. MY_{}",
            args.env_name, args.env_name
        ));
        std::process::exit(2);
    }
    if let Some(name) = args.vault_id.strip_prefix(crate::keychain::PREFIX) {
        if !crate::keychain::exists(name) {
            ui::warn(&format!("no Keychain item '{name}' yet; add it with: lockshell key add {name}"));
        }
    }
    registry::upsert(&args.env_name, &args.vault_id, &args.field)?;
    ui::ok(&format!(
        "registered: {} → {}.{}",
        args.env_name, args.vault_id, args.field
    ));
    Ok(())
}

pub fn unregister(args: UnregisterArgs) -> Result<()> {
    let removed = registry::remove(&args.env_name)?;
    if removed {
        ui::ok(&format!("unregistered: {}", args.env_name));
    } else {
        ui::warn(&format!("no mapping for {}", args.env_name));
    }
    Ok(())
}

fn is_valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}
