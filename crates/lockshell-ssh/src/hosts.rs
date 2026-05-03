// SPDX-License-Identifier: Apache-2.0

//! Host alias registry persisted as TSV at `$HOME/.config/lockshell/hosts.tsv`.
//!
//! Format (one record per line):
//! ```text
//! alias\tuser@hostname[:port]
//! ```
//! Lines beginning with `#` and blank lines are ignored. Files are stored mode
//! `0600` with parent directory mode `0700`.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// A single SSH host alias entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAlias {
    pub alias: String,
    pub user: String,
    pub hostname: String,
    pub port: u16,
}

impl HostAlias {
    fn target(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.user, self.hostname)
        } else {
            format!("{}@{}:{}", self.user, self.hostname, self.port)
        }
    }
}

/// Returns the default registry path: `$HOME/.config/lockshell/hosts.tsv`.
pub fn default_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("lockshell")
        .join("hosts.tsv"))
}

/// Load all host aliases from `path`. Returns an empty Vec if the file does
/// not exist.
pub fn load(path: &Path) -> Result<Vec<HostAlias>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body = fs::read_to_string(path)
        .with_context(|| format!("read hosts registry {}", path.display()))?;
    let mut out = Vec::new();
    for (lineno, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, '\t');
        let alias = parts
            .next()
            .ok_or_else(|| anyhow!("hosts: line {}: missing alias", lineno + 1))?
            .trim();
        let target = parts
            .next()
            .ok_or_else(|| anyhow!("hosts: line {}: missing target", lineno + 1))?
            .trim();
        if alias.is_empty() {
            bail!("hosts: line {}: empty alias", lineno + 1);
        }
        let parsed = parse_target(target)
            .with_context(|| format!("hosts: line {}: target {target:?}", lineno + 1))?;
        out.push(HostAlias {
            alias: alias.to_string(),
            user: parsed.0,
            hostname: parsed.1,
            port: parsed.2,
        });
    }
    Ok(out)
}

/// Atomically rewrite `path` with `hosts`. Ensures parent dir is `0700` and
/// file is `0600`.
pub fn save(path: &Path, hosts: &[HostAlias]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create hosts parent {}", parent.display()))?;
        #[cfg(unix)]
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", parent.display()))?;
    }
    let tmp = path.with_extension("tsv.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("open tmp {}", tmp.display()))?;
        #[cfg(unix)]
        f.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", tmp.display()))?;
        for h in hosts {
            writeln!(f, "{}\t{}", h.alias, h.target())
                .with_context(|| format!("write hosts {}", tmp.display()))?;
        }
        f.flush()
            .with_context(|| format!("flush hosts {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Append `alias -> target` to the registry. Errors if `alias` already exists.
pub fn add(path: &Path, alias: &str, target: &str) -> Result<()> {
    if alias.is_empty() {
        bail!("alias must be non-empty");
    }
    if alias.contains('\t') || alias.contains(char::is_whitespace) {
        bail!("alias must not contain whitespace or tabs");
    }
    let (user, hostname, port) = parse_target(target)?;
    let mut hosts = load(path)?;
    if hosts.iter().any(|h| h.alias == alias) {
        bail!("alias {alias:?} already exists");
    }
    hosts.push(HostAlias {
        alias: alias.to_string(),
        user,
        hostname,
        port,
    });
    save(path, &hosts)?;
    Ok(())
}

/// Remove `alias` from the registry. No-op if absent (returns Ok).
pub fn remove(path: &Path, alias: &str) -> Result<()> {
    let mut hosts = load(path)?;
    let before = hosts.len();
    hosts.retain(|h| h.alias != alias);
    if hosts.len() == before {
        return Ok(());
    }
    save(path, &hosts)?;
    Ok(())
}

/// Look up `alias` in the registry.
pub fn lookup(path: &Path, alias: &str) -> Result<Option<HostAlias>> {
    let hosts = load(path)?;
    Ok(hosts.into_iter().find(|h| h.alias == alias))
}

fn parse_target(target: &str) -> Result<(String, String, u16)> {
    let (user, rest) = target
        .split_once('@')
        .ok_or_else(|| anyhow!("target must be user@host or user@host:port"))?;
    if user.is_empty() {
        bail!("target user is empty");
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => {
            let parsed: u16 = p.parse().map_err(|e| anyhow!("invalid port {p:?}: {e}"))?;
            (h, parsed)
        }
        None => (rest, 22u16),
    };
    if host.is_empty() {
        bail!("target hostname is empty");
    }
    Ok((user.to_string(), host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn td() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("hosts.tsv");
        (dir, path)
    }

    #[test]
    fn parse_default_port() {
        let (u, h, p) = parse_target("alice@example.com").unwrap();
        assert_eq!(u, "alice");
        assert_eq!(h, "example.com");
        assert_eq!(p, 22);
    }

    #[test]
    fn parse_explicit_port() {
        let (u, h, p) = parse_target("bob@10.0.0.5:2222").unwrap();
        assert_eq!(u, "bob");
        assert_eq!(h, "10.0.0.5");
        assert_eq!(p, 2222);
    }

    #[test]
    fn parse_missing_user_fails() {
        assert!(parse_target("@host").is_err());
        assert!(parse_target("nohost").is_err());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let (_d, p) = td();
        let entries = vec![
            HostAlias {
                alias: "prod".into(),
                user: "deploy".into(),
                hostname: "web1.example.com".into(),
                port: 22,
            },
            HostAlias {
                alias: "stage".into(),
                user: "deploy".into(),
                hostname: "stage.example.com".into(),
                port: 2222,
            },
        ];
        save(&p, &entries).unwrap();
        let loaded = load(&p).unwrap();
        assert_eq!(loaded, entries);
    }

    #[test]
    fn add_dedup_rejects_duplicate() {
        let (_d, p) = td();
        add(&p, "prod", "deploy@web1").unwrap();
        let err = add(&p, "prod", "deploy@web2").unwrap_err();
        assert!(format!("{err}").contains("already exists"));
    }

    #[test]
    fn remove_alias() {
        let (_d, p) = td();
        add(&p, "a", "u@h1").unwrap();
        add(&p, "b", "u@h2").unwrap();
        remove(&p, "a").unwrap();
        let loaded = load(&p).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].alias, "b");
    }

    #[test]
    fn remove_missing_is_noop() {
        let (_d, p) = td();
        add(&p, "a", "u@h").unwrap();
        remove(&p, "nope").unwrap();
        assert_eq!(load(&p).unwrap().len(), 1);
    }

    #[test]
    fn lookup_hit_and_miss() {
        let (_d, p) = td();
        add(&p, "a", "user@host:2200").unwrap();
        let hit = lookup(&p, "a").unwrap().unwrap();
        assert_eq!(hit.user, "user");
        assert_eq!(hit.hostname, "host");
        assert_eq!(hit.port, 2200);
        assert!(lookup(&p, "missing").unwrap().is_none());
    }

    #[test]
    fn load_skips_comments_and_blanks() {
        let (_d, p) = td();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            "# comment\n\nalias1\tuser@host\n  \n# trailing\nalias2\tu@h:99\n",
        )
        .unwrap();
        let loaded = load(&p).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].port, 99);
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_unix_perms() {
        let (_d, p) = td();
        add(&p, "x", "u@h").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let pmode = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(pmode, 0o700);
    }

    #[test]
    fn add_rejects_whitespace_alias() {
        let (_d, p) = td();
        assert!(add(&p, "with space", "u@h").is_err());
        assert!(add(&p, "", "u@h").is_err());
    }
}
