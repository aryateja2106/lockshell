// SPDX-License-Identifier: Apache-2.0

//! `lockshell ssh add-host <alias> <user>@<host>:<port>` — register a host alias.
//!
//! Persists to `~/.config/lockshell/hosts.tsv` via `lockshell_ssh::hosts::add`.
//! The alias is later used by `lockshell ssh <alias>` for connection.

use crate::cli::SshAddHostArgs;
use anyhow::{Context, Result};
use lockshell_ssh::hosts;

pub fn add(args: SshAddHostArgs) -> Result<()> {
    let path = hosts::default_path().context("locating hosts.tsv")?;
    hosts::add(&path, &args.alias, &args.target)
        .with_context(|| format!("registering alias '{}' -> '{}'", args.alias, args.target))?;
    println!("added alias {} -> {}", args.alias, args.target);
    Ok(())
}
