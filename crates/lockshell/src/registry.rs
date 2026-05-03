// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

// Sensible upper bounds for registry input fields, to prevent a malicious
// LLM or template from filling the registry with multi-megabyte garbage.
pub const MAX_ENV_NAME_LEN: usize = 256;
pub const MAX_VAULT_ID_LEN: usize = 256;
pub const MAX_FIELD_LEN: usize = 64;

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
    // Owner-only access; we explicitly set this even if the dir already
    // existed with looser permissions from an earlier version.
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
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
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    for m in entries {
        writeln!(f, "{}\t{}\t{}", m.env_name, m.vault_id, m.field)?;
    }
    // Re-assert permissions in case the file already existed with looser modes.
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn upsert(env_name: &str, vault_id: &str, field: &str) -> Result<()> {
    if env_name.len() > MAX_ENV_NAME_LEN {
        anyhow::bail!("env_name too long ({} chars; max {})", env_name.len(), MAX_ENV_NAME_LEN);
    }
    if vault_id.len() > MAX_VAULT_ID_LEN {
        anyhow::bail!("vault_id too long ({} chars; max {})", vault_id.len(), MAX_VAULT_ID_LEN);
    }
    if field.len() > MAX_FIELD_LEN {
        anyhow::bail!("field too long ({} chars; max {})", field.len(), MAX_FIELD_LEN);
    }
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
