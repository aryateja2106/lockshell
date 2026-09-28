// SPDX-License-Identifier: Apache-2.0

use crate::registry;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

// Cap the audit log entry sizes to prevent a malicious template/reason
// from ballooning the log to megabytes. Long values are truncated.
const MAX_TEMPLATE_LEN: usize = 8192;
const MAX_REASON_LEN: usize = 512;

/// Make a value safe for one TSV field: no tabs/newlines (which would let a
/// template or reason forge extra columns or whole fake entries), and truncate
/// on a char boundary (byte slicing panics on multi-byte text such as Telugu).
fn clean_field(s: &str, max: usize) -> String {
    let flat: String = s
        .chars()
        .map(|c| if matches!(c, '\t' | '\n' | '\r') || c.is_control() { ' ' } else { c })
        .collect();
    if flat.len() <= max {
        return flat;
    }
    let mut end = max;
    while !flat.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &flat[..end])
}

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

/// Append an audit entry. Returns `Ok(true)` on success, `Ok(false)` if the audit
/// path could not be written (e.g. sandboxed agent without write access). The caller
/// should print a warning on `Ok(false)` but MUST NOT fail the broker call —
/// auditing is best-effort, not a security gate.
pub fn append(reason: &str, template: &str, secrets: &[String]) -> Result<bool> {
    let path = audit_path();
    if let Some(parent) = path.parent() {
        if !parent.exists() && std::fs::create_dir_all(parent).is_err() {
            return Ok(false);
        }
    }
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path);
    let mut f = match f {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    // Re-assert permissions in case the file already existed with looser modes.
    let _ = fs::set_permissions(&path, Permissions::from_mode(0o600));
    // Truncate over-long inputs rather than rejecting; a partial audit
    // entry is better than no audit entry.
    let entry = Entry {
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        reason: clean_field(reason, MAX_REASON_LEN),
        template: clean_field(template, MAX_TEMPLATE_LEN),
        secrets: secrets.to_vec(),
    };
    if writeln!(
        f,
        "{}\t{}\t{}\t{}",
        entry.timestamp,
        entry.reason,
        entry.template,
        entry.secrets.join(",")
    )
    .is_err()
    {
        return Ok(false);
    }
    Ok(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_truncation_does_not_panic() {
        let telugu = "రియాక్టర్ ".repeat(100);
        let out = clean_field(&telugu, MAX_REASON_LEN);
        assert!(out.ends_with("...[truncated]"));
    }

    #[test]
    fn tabs_and_newlines_cannot_forge_entries() {
        let evil = "ok\t2026-01-01T00:00:00Z\tfake\tFAKE\nsecond line";
        let out = clean_field(evil, MAX_TEMPLATE_LEN);
        assert!(!out.contains('\t') && !out.contains('\n'));
    }
}
