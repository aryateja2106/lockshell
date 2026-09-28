// SPDX-License-Identifier: Apache-2.0
//
// Native macOS Keychain backend (no agent-password dependency).
//
// Storage model:
//   service = "lockshell:<name>", account = $USER, label = "lockshell <name>"
//   The item is created with an EMPTY trusted-application list (`-T ""`), so every
//   read of the value raises a macOS password/Touch ID dialog attributed to the
//   reading binary. Clicking "Always Allow" would add that binary to the ACL:
//   don't, unless you have decided lockshell should read silently.
//
// Writing goes through `/usr/bin/security -i` with the command on STDIN, so the
// value never appears in argv (process list), shell history, or any file.
// Reading uses Security.framework directly, so the dialog names lockshell.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub const PREFIX: &str = "keychain:";

pub fn service(name: &str) -> String {
    format!("lockshell:{}", name)
}

fn account() -> String {
    std::env::var("USER").unwrap_or_else(|_| "lockshell".into())
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// API keys / tokens only: printable, no quotes, no whitespace. Keeps the
/// `security -i` command line unambiguous (no escaping games).
pub fn valid_secret(value: &str) -> bool {
    (8..=4096).contains(&value.len())
        && value.chars().all(|c| c.is_ascii_alphanumeric() || "._~+/=-:@".contains(c))
}

/// Short, one-way, safe-to-print identifier for a secret.
pub fn fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let hex: String = digest.iter().take(6).map(|b| format!("{:02x}", b)).collect();
    format!("sha256:{}", hex)
}

pub fn store(name: &str, value: &str) -> Result<()> {
    if !valid_name(name) {
        bail!("invalid key name '{}': use lowercase letters, digits, '-' or '_'", name);
    }
    if !valid_secret(value) {
        bail!("value rejected: expected an API key/token (8-4096 chars, no spaces or quotes)");
    }
    let cmd = Zeroizing::new(format!(
        "add-generic-password -U -s \"{}\" -a \"{}\" -l \"lockshell {}\" -T \"\" -w \"{}\"\n",
        service(name),
        account(),
        name,
        value
    ));
    let mut child = Command::new("/usr/bin/security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting /usr/bin/security")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("no stdin for security"))?
        .write_all(cmd.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() || !exists(name) {
        bail!("Keychain refused to store the item: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Attribute-only lookup: never reads the value, never prompts.
pub fn exists(name: &str) -> bool {
    Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", &service(name), "-a", &account()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read the value. Triggers the macOS access dialog (by design).
#[cfg(target_os = "macos")]
pub fn get(name: &str) -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(
        security_framework::passwords::get_generic_password(&service(name), &account())
            .map_err(|e| anyhow!("Keychain read of '{}' failed or was denied: {}", name, e))?,
    );
    let s = std::str::from_utf8(&bytes).context("Keychain value is not UTF-8")?;
    Ok(Zeroizing::new(s.to_string()))
}

#[cfg(not(target_os = "macos"))]
pub fn get(_name: &str) -> Result<Zeroizing<String>> {
    bail!("the keychain backend is macOS-only")
}

pub fn delete(name: &str) -> Result<bool> {
    let st = Command::new("/usr/bin/security")
        .args(["delete-generic-password", "-s", &service(name), "-a", &account()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(st.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("fireworks"));
        assert!(valid_name("openrouter-work_2"));
        assert!(!valid_name("Fireworks"));
        assert!(!valid_name("-x"));
        assert!(!valid_name("a b"));
        assert!(!valid_name("a\"b"));
    }

    #[test]
    fn secrets_cannot_break_out_of_quotes() {
        assert!(valid_secret("fw_AbCdEf1234567890"));
        assert!(!valid_secret("abc\" -T /bin/sh \"xyz"));
        assert!(!valid_secret("has space 12345"));
        assert!(!valid_secret("line\nbreak12345"));
        assert!(!valid_secret("short"));
    }

    #[test]
    fn fingerprint_is_stable_and_short() {
        assert_eq!(fingerprint("abc"), "sha256:ba7816bf8f01");
    }
}
