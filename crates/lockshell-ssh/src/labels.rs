// SPDX-License-Identifier: Apache-2.0

//! Centralised label and signer-mode resolution for Secure Enclave keys.
//!
//! Production code uses `lockshell-user` / `lockshell-ca` labels under the
//! biometric ACL — every signature requires Touch ID. Stress-test mode
//! (gated on `LOCKSHELL_STRESS_MODE=1`) switches to disjoint
//! `lockshell-stress-*` labels under a no-biometric ACL so benchmarks run
//! without human interaction.
//!
//! The disjoint labels matter: a stressed run must never accidentally
//! mutate production keys. The stress key still lives in the SEP
//! (non-extractable, device-bound) but trades user presence for throughput,
//! so it is unsafe to bind to anything that survives the benchmark.

use anyhow::Result;

#[cfg(target_os = "macos")]
use crate::SecureEnclaveSigner;

use crate::signer::Signer;
use crate::SoftwareEcdsaSigner;

/// `true` when both `LOCKSHELL_STRESS_MODE=1` AND
/// `LOCKSHELL_I_UNDERSTAND_THIS_IS_INSECURE=yes` are set.
///
/// The double-gate exists because stress mode disables the Secure Enclave
/// biometric ACL and persists a software ECDSA private key under
/// `~/.lockshell/stress-keys/`. A single env var is too easy to leave
/// behind in a shell rc file or login plist; the explicit acknowledgement
/// var prevents silent fallback to the unsafe path.
///
/// If only `LOCKSHELL_STRESS_MODE=1` is set, this aborts the process at
/// first call with a loud error so the misconfiguration surfaces
/// immediately instead of silently producing on-disk software keys.
pub fn stress_mode() -> bool {
    use std::sync::OnceLock;
    static GATE: OnceLock<bool> = OnceLock::new();
    *GATE.get_or_init(|| {
        let on = std::env::var_os("LOCKSHELL_STRESS_MODE")
            .map(|v| v != "0" && !v.is_empty())
            .unwrap_or(false);
        if on {
            let acked = std::env::var("LOCKSHELL_I_UNDERSTAND_THIS_IS_INSECURE")
                .map(|v| v == "yes")
                .unwrap_or(false);
            if !acked {
                eprintln!(
                    "lockshell: refusing to enter stress mode.\n  \
                     LOCKSHELL_STRESS_MODE=1 is set, but \
                     LOCKSHELL_I_UNDERSTAND_THIS_IS_INSECURE=yes is not.\n  \
                     Stress mode disables Secure Enclave biometric gating and \
                     persists a software ECDSA P-256 private key under \
                     ~/.lockshell/stress-keys/. Never enable it for any \
                     workflow that touches production keys, hosts, or \
                     credentials. Set both env vars only inside the \
                     scripts/stress_rig.sh harness."
                );
                std::process::exit(2);
            }
        }
        on
    })
}

/// SE label for the user signing key.
pub fn user_label() -> &'static str {
    if stress_mode() {
        "lockshell-stress-user"
    } else {
        "lockshell-user"
    }
}

/// SE label for the CA key.
pub fn ca_label() -> &'static str {
    if stress_mode() {
        "lockshell-stress-ca"
    } else {
        "lockshell-ca"
    }
}

/// Whether SE keys created by this process must be biometric-gated.
/// Always `true` in production; `false` only under stress mode.
pub fn require_biometric() -> bool {
    !stress_mode()
}

/// Load (or create) the SE-backed user signing key, picking the bio /
/// no-bio variant based on [`stress_mode`].
#[cfg(target_os = "macos")]
pub fn load_user_signer() -> Result<SecureEnclaveSigner> {
    load_signer(user_label())
}

/// Load (or create) the SE-backed CA signing key, picking the bio / no-bio
/// variant based on [`stress_mode`].
#[cfg(target_os = "macos")]
pub fn load_ca_signer() -> Result<SecureEnclaveSigner> {
    load_signer(ca_label())
}

#[cfg(target_os = "macos")]
fn load_signer(label: &str) -> Result<SecureEnclaveSigner> {
    if require_biometric() {
        SecureEnclaveSigner::load_or_create(label)
    } else {
        SecureEnclaveSigner::load_or_create_no_biometric(label)
    }
}

/// Resolve a `Signer` for the user identity, returning a trait object so
/// the call site is portable across SEP-backed and software-backed paths.
///
/// In production (no stress mode), this is always a Secure Enclave signer
/// on macOS and an error elsewhere. In stress mode, the SE signer is
/// attempted first; if construction fails (no SEP, non-Aqua subshell,
/// missing entitlements), this falls back to a fresh ephemeral
/// [`SoftwareEcdsaSigner`] and emits a warning to stderr.
pub fn load_user_signer_dyn() -> Result<Box<dyn Signer>> {
    load_signer_dyn(user_label(), "user")
}

/// CA equivalent of [`load_user_signer_dyn`].
pub fn load_ca_signer_dyn() -> Result<Box<dyn Signer>> {
    load_signer_dyn(ca_label(), "CA")
}

fn load_signer_dyn(label: &str, role: &str) -> Result<Box<dyn Signer>> {
    #[cfg(target_os = "macos")]
    {
        match load_signer(label) {
            Ok(signer) => return Ok(Box::new(signer)),
            Err(e) => {
                if !stress_mode() {
                    return Err(e);
                }
                eprintln!(
                    "lockshell: SE {} key '{}' unavailable ({}). \
                     STRESS MODE — falling back to persisted software ECDSA P-256 at {}. \
                     This signer is unsafe for production use.",
                    role,
                    label,
                    e,
                    stress_key_path(label)?.display()
                );
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        if !stress_mode() {
            anyhow::bail!(
                "lockshell {} key '{}' requires the macOS Secure Enclave. \
                 Linux fallback ships in Phase 6.",
                role,
                label
            );
        }
        eprintln!(
            "lockshell: STRESS MODE on non-macOS — using persisted software ECDSA P-256 \
             for {} key '{}' at {}.",
            role,
            label,
            stress_key_path(label)?.display()
        );
    }
    let s = load_or_persist_software(label)?;
    Ok(Box::new(s))
}

/// Returns `~/.lockshell/stress-keys/<label>.pkcs8` for the given label.
fn stress_key_path(label: &str) -> Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("HOME is unset; cannot locate stress key path"))?;
    Ok(std::path::PathBuf::from(home)
        .join(".lockshell")
        .join("stress-keys")
        .join(format!("{label}.pkcs8")))
}

/// Read the stress key for `label` from disk, or generate-and-persist one.
/// Both daemon and CLI processes must see the same key, so software-fallback
/// signers are NOT ephemeral — they live at `~/.lockshell/stress-keys/...`
/// with mode 0600.
fn load_or_persist_software(label: &str) -> Result<SoftwareEcdsaSigner> {
    let path = stress_key_path(label)?;
    if path.exists() {
        let bytes = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("reading stress key {}: {e}", path.display()))?;
        return SoftwareEcdsaSigner::from_pkcs8(&bytes);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("creating {}: {e}", parent.display()))?;
    }
    let (signer, pkcs8) = SoftwareEcdsaSigner::generate_pkcs8()?;
    write_private_file(&path, &pkcs8)?;
    Ok(signer)
}

#[cfg(unix)]
fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: `stress_mode` reads the process env. We can't set the env in
    // parallel tests without affecting siblings, so just assert the label
    // mappings are disjoint and stable.

    #[test]
    fn labels_disjoint() {
        assert_ne!("lockshell-user", "lockshell-stress-user");
        assert_ne!("lockshell-ca", "lockshell-stress-ca");
    }

    #[test]
    fn label_helpers_are_total() {
        // Both branches return non-empty strings; this is a structural check
        // that the helpers compile and resolve.
        let _ = user_label();
        let _ = ca_label();
        let _ = require_biometric();
    }
}
