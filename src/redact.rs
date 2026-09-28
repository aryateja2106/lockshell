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
fw_[A-Za-z0-9]{16,}
"#;

/// Exact-match patterns for the secret values resolved for this run. This
/// catches any format, including ones no regex above knows about. Values
/// shorter than 6 chars are skipped to avoid redacting common words.
pub fn exact_value_patterns<'a>(values: impl Iterator<Item = &'a str>) -> Vec<Regex> {
    let mut vals: Vec<&str> = values.filter(|v| v.len() >= 6).collect();
    vals.sort_by_key(|v| std::cmp::Reverse(v.len())); // longest first
    vals.iter().filter_map(|v| Regex::new(&regex::escape(v)).ok()).collect()
}

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
    // Built-ins are always active, even if redactors.txt was written by an older
    // version (it is only created when missing, so it would never gain new ones).
    let raw = format!("{}\n{}", DEFAULT_PATTERNS, fs::read_to_string(redactor_path())?);
    let mut patterns = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in raw.lines() {
        if !seen.insert(line.trim().to_string()) {
            continue;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_values_are_redacted_whatever_their_format() {
        let p = exact_value_patterns(["weird.format+Secret$(1)"].into_iter());
        assert_eq!(redact("token=weird.format+Secret$(1) ok", &p), "token=[REDACTED] ok");
    }

    #[test]
    fn short_values_are_not_turned_into_patterns() {
        assert!(exact_value_patterns(["abc"].into_iter()).is_empty());
    }

    #[test]
    fn builtin_patterns_include_fireworks() {
        let p: Vec<Regex> = DEFAULT_PATTERNS
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| Regex::new(l).unwrap())
            .collect();
        assert_eq!(redact("key fw_AbCdEf1234567890XYZ", &p), "key [REDACTED]");
    }
}
