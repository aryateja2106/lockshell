// SPDX-License-Identifier: Apache-2.0
//
// `lockshell key add|list|rm`: manage secrets in the native macOS Keychain.
// Metadata (name, fingerprint, date) lives in keys.tsv; values live only in the Keychain.

use crate::cli::{KeyArgs, KeyCommand};
use crate::{keychain, registry, ui};
use anyhow::{bail, Result};
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use zeroize::Zeroizing;

fn meta_path() -> std::path::PathBuf {
    registry::config_dir().join("keys.tsv")
}

fn load_meta() -> Vec<(String, String, String)> {
    fs::read_to_string(meta_path())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split('\t').collect();
            (p.len() == 3).then(|| (p[0].into(), p[1].into(), p[2].into()))
        })
        .collect()
}

fn save_meta(rows: &[(String, String, String)]) -> Result<()> {
    let dir = registry::config_dir();
    fs::create_dir_all(&dir)?;
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(meta_path())?;
    for (n, fp, d) in rows {
        writeln!(f, "{n}\t{fp}\t{d}")?;
    }
    Ok(())
}

pub fn run(args: KeyArgs) -> Result<()> {
    match args.command {
        KeyCommand::Add { name, stdin } => add(&name, stdin),
        KeyCommand::List => list(),
        KeyCommand::Rm { name } => rm(&name),
    }
}

fn add(name: &str, from_stdin: bool) -> Result<()> {
    if !keychain::valid_name(name) {
        bail!("invalid name '{}': use lowercase letters, digits, '-' or '_' (e.g. fireworks)", name);
    }
    let value = Zeroizing::new(if from_stdin || !std::io::stdin().is_terminal() {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s.trim().to_string()
    } else {
        rpassword::prompt_password(format!("Paste the '{name}' key (hidden), then press Enter: "))?
            .trim()
            .to_string()
    });
    keychain::store(name, &value)?;
    let fp = keychain::fingerprint(&value);
    let mut rows = load_meta();
    rows.retain(|r| r.0 != name);
    rows.push((name.into(), fp.clone(), chrono::Local::now().format("%Y-%m-%d").to_string()));
    save_meta(&rows)?;
    ui::ok(&format!("stored '{name}' in the Keychain. Fingerprint {fp} (safe to share)"));
    ui::hint(&format!("use in commands:  lockshell register SOME_NAME keychain:{name} value"));
    ui::hint("use for model calls: restart `lockshell gateway`");
    Ok(())
}

fn list() -> Result<()> {
    let rows = load_meta();
    if rows.is_empty() {
        ui::info("no keys yet. Add one with: lockshell key add <name>");
    }
    for (n, fp, d) in rows {
        let state = if keychain::exists(&n) { "ok" } else { "MISSING from Keychain" };
        println!("{:<16} {}  added {}  [{}]", n, fp, d, state);
    }
    Ok(())
}

fn rm(name: &str) -> Result<()> {
    let removed = keychain::delete(name)?;
    let mut rows = load_meta();
    rows.retain(|r| r.0 != name);
    save_meta(&rows)?;
    if removed {
        ui::ok(&format!("removed '{name}' from the Keychain"));
    } else {
        ui::warn(&format!("'{name}' was not in the Keychain"));
    }
    ui::hint("if it may have leaked, also revoke it on the provider's website");
    Ok(())
}
