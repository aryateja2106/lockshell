// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub env_name: String,
    pub vault_id: String,
    pub field: String,
}

pub fn config_dir() -> PathBuf {
    if let Ok(p) = std::env::var("LOCKSHELL_CONFIG_DIR") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".config/lockshell")
}

pub fn registry_path() -> PathBuf {
    config_dir().join("registry.tsv")
}

fn ensure_dir() -> Result<()> {
    let dir = config_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    Ok(())
}

pub fn load() -> Result<Vec<Mapping>> {
    ensure_dir()?;
    let path = registry_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in raw.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 3 {
            anyhow::bail!("registry line {} malformed (expected 3 tab-separated fields)", n + 1);
        }
        out.push(Mapping {
            env_name: parts[0].into(),
            vault_id: parts[1].into(),
            field: parts[2].into(),
        });
    }
    Ok(out)
}

pub fn save(entries: &[Mapping]) -> Result<()> {
    ensure_dir()?;
    let path = registry_path();
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    for m in entries {
        writeln!(f, "{}\t{}\t{}", m.env_name, m.vault_id, m.field)?;
    }
    Ok(())
}

pub fn upsert(env_name: &str, vault_id: &str, field: &str) -> Result<()> {
    let mut entries = load()?;
    entries.retain(|m| m.env_name != env_name);
    entries.push(Mapping {
        env_name: env_name.into(),
        vault_id: vault_id.into(),
        field: field.into(),
    });
    save(&entries)
}

pub fn remove(env_name: &str) -> Result<bool> {
    let mut entries = load()?;
    let before = entries.len();
    entries.retain(|m| m.env_name != env_name);
    let removed = entries.len() < before;
    save(&entries)?;
    Ok(removed)
}

pub fn lookup(env_name: &str) -> Result<Option<Mapping>> {
    Ok(load()?.into_iter().find(|m| m.env_name == env_name))
}
