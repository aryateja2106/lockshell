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
    let reason_trunc = if reason.len() > MAX_REASON_LEN {
        format!("{}...[truncated]", &reason[..MAX_REASON_LEN])
    } else {
        reason.into()
    };
    let template_trunc = if template.len() > MAX_TEMPLATE_LEN {
        format!("{}...[truncated]", &template[..MAX_TEMPLATE_LEN])
    } else {
        template.into()
    };
    let entry = Entry {
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        reason: reason_trunc,
        template: template_trunc,
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

/// Append an SSH-related audit entry. Same best-effort semantics as
/// [`append`] (returns `Ok(false)` if the audit path can't be written).
///
/// Row format (tab-separated):
///   timestamp \t reason \t op=ssh \t alias \t host \t principal \t cert_ttl
///
/// `cert_ttl` is `"NA"` in Phase 2 (raw key auth, no cert) and a duration
/// string like `"5m"` from Phase 3 onward. Never contains private key material.
pub fn append_ssh(
    reason: &str,
    alias: &str,
    host: &str,
    principal: &str,
    cert_ttl: &str,
) -> Result<bool> {
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
    let _ = fs::set_permissions(&path, Permissions::from_mode(0o600));

    fn truncate(s: &str, max: usize) -> String {
        if s.len() > max {
            format!("{}...[truncated]", &s[..max])
        } else {
            s.to_string()
        }
    }

    const MAX_FIELD: usize = 256;
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    if writeln!(
        f,
        "{}\t{}\top=ssh\t{}\t{}\t{}\t{}",
        timestamp,
        truncate(reason, MAX_REASON_LEN),
        truncate(alias, MAX_FIELD),
        truncate(host, MAX_FIELD),
        truncate(principal, MAX_FIELD),
        truncate(cert_ttl, 32),
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
