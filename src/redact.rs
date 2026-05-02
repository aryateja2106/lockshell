// SPDX-License-Identifier: Apache-2.0

use crate::registry;
use anyhow::Result;
use regex::Regex;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub fn redactor_path() -> PathBuf {
    registry::config_dir().join("redactors.txt")
}

const DEFAULT_PATTERNS: &str = r#"# lockshell default redaction patterns
# One regex per line. Lines starting with # are ignored.
# These are post-hoc safety nets; the primary defense is env-only secret injection.
lin_api_[A-Za-z0-9]+
sk-[A-Za-z0-9_-]{20,}
sk-ant-[A-Za-z0-9_-]+
ghp_[A-Za-z0-9]{20,}
gho_[A-Za-z0-9]{20,}
github_pat_[A-Za-z0-9_]+
xoxb-[A-Za-z0-9-]+
xoxp-[A-Za-z0-9-]+
AIza[A-Za-z0-9_-]{35}
eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+
AKIA[0-9A-Z]{16}
"#;

pub fn ensure_default() -> Result<()> {
    let path = redactor_path();
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        fs::write(&path, DEFAULT_PATTERNS)?;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_patterns() -> Result<Vec<Regex>> {
    ensure_default()?;
    let raw = fs::read_to_string(redactor_path())?;
    let mut patterns = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match Regex::new(trimmed) {
            Ok(r) => patterns.push(r),
            Err(e) => eprintln!("lockshell: skipping invalid redactor pattern '{}': {}", trimmed, e),
        }
    }
    Ok(patterns)
}

pub fn redact(input: &str, patterns: &[Regex]) -> String {
    let mut out = input.to_string();
    for r in patterns {
        out = r.replace_all(&out, "[REDACTED]").to_string();
    }
    out
}
