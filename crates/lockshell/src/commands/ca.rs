// SPDX-License-Identifier: Apache-2.0

//! `lockshell ca print | rotate` — manage the local user CA.
//!
//! The CA is a separate Secure Enclave-resident ECDSA P-256 key, distinct
//! from the user signing key. Targets you control trust this CA via
//! `TrustedUserCAKeys`; lockshell mints short-lived user certificates that
//! authenticate against it.
//!
//! macOS-only in v0.6 (SE required). Linux fallback ships in Phase 6.

use crate::cli::CaArgs;
use crate::cli::CaCommand;
use anyhow::Result;

pub fn run(args: CaArgs) -> Result<()> {
    match args.cmd {
        CaCommand::Print => print_ca(),
        CaCommand::Rotate => rotate_ca(),
    }
}

#[cfg(target_os = "macos")]
fn print_ca() -> Result<()> {
    use anyhow::Context;
    use base64::Engine;
    use lockshell_ssh::{SecureEnclaveSigner, Signer};

    let signer = SecureEnclaveSigner::load_or_create("lockshell-ca")
        .context("loading or creating the lockshell CA in the Secure Enclave")?;
    let blob = signer.public_key_blob()?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let label = format!("lockshell-ca@{}", host_label());

    // The `cert-authority` prefix tells `sshd` (when used in authorized_keys)
    // or `ssh-keygen -L` that this is a CA, not a regular host key.
    println!("cert-authority {} {} {}", signer.algorithm(), b64, label);
    eprintln!();
    eprintln!("To use on a managed target:");
    eprintln!("  1. Save the line above (without 'cert-authority') to /etc/ssh/lockshell_ca.pub");
    eprintln!("  2. Set in /etc/ssh/sshd_config:  TrustedUserCAKeys /etc/ssh/lockshell_ca.pub");
    eprintln!(
        "  3. See crates/lockshell-ssh/templates/sshd_config.lockshell for a hardened template."
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn print_ca() -> Result<()> {
    anyhow::bail!("lockshell ca is macOS-only in v0.6 (Secure Enclave required for the CA key).")
}

#[cfg(target_os = "macos")]
fn rotate_ca() -> Result<()> {
    use anyhow::Context;
    use lockshell_ssh::{SecureEnclaveSigner, Signer};

    eprintln!("WARNING: rotating the CA invalidates every outstanding lockshell-issued cert.");
    eprintln!("Targets that trust the old CA will reject your sessions until they receive the new pubkey.");
    eprintln!();

    // Best-effort delete of the old CA key. Errors are warned but not fatal —
    // the user may have nuked it manually already.
    if let Err(e) = SecureEnclaveSigner::delete("lockshell-ca") {
        eprintln!("warning: could not delete old CA key: {}", e);
    }

    let signer = SecureEnclaveSigner::load_or_create("lockshell-ca")
        .context("creating new lockshell CA after rotation")?;
    let _ = signer.public_key_blob()?;
    eprintln!("rotated. Run `lockshell ca print` to see the new public key.");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn rotate_ca() -> Result<()> {
    anyhow::bail!(
        "lockshell ca rotate is macOS-only in v0.6 (Secure Enclave required for the CA key)."
    )
}

#[cfg(target_os = "macos")]
fn host_label() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}
