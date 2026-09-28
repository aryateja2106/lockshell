// SPDX-License-Identifier: Apache-2.0
//
// Deterministic masking of sensitive text before it leaves the machine.
//
//   "Call Ravi at +91 98480 22338"  ->  "Call [PERSON_1] at [PHONE_1]"
//
// Sources of "sensitive":
//   * built-in patterns (API keys, email, Indian phone, Aadhaar, PAN, IPv4)
//   * a terms file: one term per line, optional "CATEGORY: term" (any script)
//   * an allowlist file: exact values that are never masked
// The same value always maps to the same placeholder within one Masker run, so
// a model can still reason about "[PERSON_1] asked [PERSON_2]".

use anyhow::Result;
use regex::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// (category, regex, digit-boundary check needed)
/// Rust's regex has no look-around, so number patterns get an explicit check
/// that the match isn't glued to neighbouring digits.
const PATTERNS: &[(&str, &str, bool)] = &[
    ("APIKEY", r"\b(?:fw|sk|sk-ant|ghp|gho|github_pat|lin_api|xox[baprs])[-_][A-Za-z0-9_-]{16,}", false),
    ("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", false),
    ("AADHAAR", r"[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}", true),
    ("PHONE", r"(?:\+?91[ -]?)?[6-9][0-9]{4}[ -]?[0-9]{5}", true),
    ("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", false),
    ("IP", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", false),
];

pub struct Masker {
    rules: Vec<(String, Regex, bool)>,
    allow: Vec<String>,
}

#[derive(Default, Debug, Clone)]
pub struct Mapping {
    /// placeholder -> original
    pub forward: BTreeMap<String, String>,
    reverse: BTreeMap<String, String>,
    counters: BTreeMap<String, usize>,
}

impl Mapping {
    pub fn counts(&self) -> BTreeMap<String, usize> {
        self.counters.clone()
    }
}

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

pub fn default_terms_path() -> PathBuf {
    std::env::var("LOCKSHELL_TERMS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::registry::config_dir().join("sensitive-terms.txt"))
}

pub fn default_allowlist_path() -> PathBuf {
    std::env::var("LOCKSHELL_ALLOWLIST_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate::registry::config_dir().join("mask-allowlist.txt"))
}

fn glued_to_digit(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    matches!(before, Some(c) if c.is_ascii_digit() || c == '.') || matches!(after, Some(c) if c.is_ascii_digit())
}

fn is_placeholder(s: &str) -> bool {
    s.starts_with('[') && s.ends_with(']')
}

impl Masker {
    pub fn load(terms: &Path, allowlist: &Path) -> Result<Self> {
        Self::from_lists(lines(terms), lines(allowlist))
    }

    pub fn from_lists(term_lines: Vec<String>, allow: Vec<String>) -> Result<Self> {
        let cat_rx = Regex::new(r"^([A-Z_]+):\s*(.+)$")?;
        let mut terms: Vec<(String, String)> = term_lines
            .into_iter()
            .map(|l| match cat_rx.captures(&l) {
                Some(c) => (c[1].to_string(), c[2].trim().to_string()),
                None => ("TERM".to_string(), l),
            })
            .collect();
        terms.sort_by_key(|t| std::cmp::Reverse(t.1.chars().count())); // longest first
        let mut rules = Vec::new();
        for (cat, term) in terms {
            rules.push((cat, Regex::new(&format!("(?i){}", regex::escape(&term)))?, false));
        }
        for (cat, p, boundary) in PATTERNS {
            rules.push((cat.to_string(), Regex::new(p)?, *boundary));
        }
        Ok(Masker { rules, allow })
    }

    pub fn mask(&self, text: &str, map: &mut Mapping) -> String {
        let ph_rx = Regex::new(r"\[[A-Z_]+_[0-9]+\]").expect("static regex");
        let mut out = text.to_string();
        for (cat, rx, boundary) in &self.rules {
            // Never rewrite inside a placeholder an earlier rule already inserted.
            let taken: Vec<(usize, usize)> = ph_rx.find_iter(&out).map(|p| (p.start(), p.end())).collect();
            let mut result = String::with_capacity(out.len());
            let mut last = 0;
            for m in rx.find_iter(&out) {
                let value = m.as_str();
                if taken.iter().any(|&(s, e)| m.start() < e && s < m.end())
                    || (*boundary && glued_to_digit(&out, m.start(), m.end()))
                    || is_placeholder(value)
                    || self.allow.iter().any(|a| a == value)
                {
                    continue;
                }
                let ph = match map.reverse.get(value) {
                    Some(ph) => ph.clone(),
                    None => {
                        let n = map.counters.entry(cat.clone()).or_insert(0);
                        *n += 1;
                        let ph = format!("[{}_{}]", cat, n);
                        map.reverse.insert(value.to_string(), ph.clone());
                        map.forward.insert(ph.clone(), value.to_string());
                        ph
                    }
                };
                result.push_str(&out[last..m.start()]);
                result.push_str(&ph);
                last = m.end();
            }
            result.push_str(&out[last..]);
            out = result;
        }
        out
    }

    pub fn unmask(text: &str, map: &Mapping) -> String {
        let mut keys: Vec<&String> = map.forward.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len())); // [PHONE_12] before [PHONE_1]
        let mut out = text.to_string();
        for k in keys {
            out = out.replace(k.as_str(), &map.forward[k]);
        }
        out
    }

    /// Category -> count. Never returns the values.
    pub fn findings(&self, text: &str) -> BTreeMap<String, usize> {
        let mut map = Mapping::default();
        self.mask(text, &mut map);
        map.counts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> Masker {
        Masker::from_lists(
            vec!["PERSON: Ravi Kumar".into(), "PERSON: రవి".into(), "CLIENT: Acme Pharma".into()],
            vec!["public@example.org".into()],
        )
        .unwrap()
    }

    #[test]
    fn masks_and_roundtrips() {
        let text = "Ravi Kumar (ravi@acme.com, +91 98480 22338) from acme pharma. Aadhaar 2345 6789 0123, PAN ABCDE1234F, key fw_AbCdEf1234567890XYZ.";
        let mut map = Mapping::default();
        let masked = m().mask(text, &mut map);
        for leak in ["Ravi", "ravi@acme.com", "98480", "2345 6789", "ABCDE1234F", "fw_AbCd", "acme pharma"] {
            assert!(!masked.contains(leak), "leaked {leak}: {masked}");
        }
        assert_eq!(Masker::unmask(&masked, &map), text);
    }

    #[test]
    fn same_value_same_placeholder() {
        let mut map = Mapping::default();
        let a = m().mask("Ravi Kumar said hi", &mut map);
        let b = m().mask("then Ravi Kumar left", &mut map);
        assert!(a.contains("[PERSON_1]") && b.contains("[PERSON_1]"));
        assert_eq!(map.counts()["PERSON"], 1);
    }

    #[test]
    fn telugu_terms_and_allowlist() {
        let mut map = Mapping::default();
        let out = m().mask("రవి గారు mail public@example.org", &mut map);
        assert!(out.starts_with("[PERSON_1]"));
        assert!(out.contains("public@example.org"));
    }

    #[test]
    fn numbers_inside_longer_numbers_are_left_alone() {
        let f = m().findings("batch 1234567890123456 and version 1.9848022338");
        assert!(!f.contains_key("PHONE") && !f.contains_key("AADHAAR"), "{f:?}");
        assert!(m().findings("no pii here, ANFD drying 14h").is_empty());
    }

    #[test]
    fn many_placeholders_unmask_correctly() {
        let mut map = Mapping::default();
        let text: String = (0..12).map(|i| format!("u{i}@x.com ")).collect();
        let masked = m().mask(&text, &mut map);
        assert!(masked.contains("[EMAIL_12]"));
        assert_eq!(Masker::unmask(&masked, &map), text);
    }
}
