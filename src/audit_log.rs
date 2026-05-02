// SPDX-License-Identifier: Apache-2.0

use crate::registry;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub fn audit_path() -> PathBuf {
    registry::config_dir().join("audit.log")
}

#[derive(Serialize, Clone, Debug)]
pub struct Entry {
    pub timestamp: String,
    pub reason: String,
    pub template: String,
    pub secrets: Vec<String>,
}

pub fn append(reason: &str, template: &str, secrets: &[String]) -> Result<()> {
    let path = audit_path();
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let entry = Entry {
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        reason: reason.into(),
        template: template.into(),
        secrets: secrets.to_vec(),
    };
    writeln!(
        f,
        "{}\t{}\t{}\t{}",
        entry.timestamp,
        entry.reason,
        entry.template,
        entry.secrets.join(",")
    )?;
    Ok(())
}

pub fn tail(n: usize) -> Result<Vec<Entry>> {
    let path = audit_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = std::fs::read_to_string(&path)?;
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(n);
    let mut out = Vec::new();
    for line in &lines[start..] {
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() < 4 {
            continue;
        }
        out.push(Entry {
            timestamp: parts[0].into(),
            reason: parts[1].into(),
            template: parts[2].into(),
            secrets: if parts[3].is_empty() {
                vec![]
            } else {
                parts[3].split(',').map(String::from).collect()
            },
        });
    }
    Ok(out)
}
