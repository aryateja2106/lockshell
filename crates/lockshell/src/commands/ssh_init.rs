// SPDX-License-Identifier: Apache-2.0

//! `lockshell ssh init` — bootstrap the SSH module.
//!
//! Default mode (no flag): creates both the user signing key and the user CA
//! key in the Secure Enclave, prints the CA's `cert-authority` line for
//! distribution to managed targets, and points at the hardened
//! `sshd_config.lockshell` template. This is the recommended path for any
//! target you control (Docker container, lab box, your own Mac).
//!
//! `--self`: shortcut for the same-Mac case. Creates only the user signing
//! key, prints the `authorized_keys` line, copies it to the clipboard via
//! `pbcopy`, and skips the CA. Use when you just want to SSH into your own
//! laptop and don't need cert-based auth.
//!
//! macOS-only in v0.6. The Linux fallback path lands in Phase 6.

use crate::cli::SshInitArgs;
use anyhow::Result;

#[cfg(target_os = "macos")]
pub fn run(args: SshInitArgs) -> Result<()> {
    use anyhow::Context;
    use base64::Engine;
    use lockshell_ssh::labels;

    if args.self_only {
        // Same-Mac shortcut: just the user key + authorized_keys line.
        let signer = labels::load_user_signer_dyn()
            .context("failed to load or create the user signing key")?;
        let blob = signer.public_key_blob()?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let host = host_label();
        let line = format!(
            "{} {} {}@{}",
            signer.algorithm(),
            b64,
            labels::user_label(),
            host
        );
        println!("{}", line);
        eprintln!();
        eprintln!(
            "Add the line above to ~/.ssh/authorized_keys on the machine you want to SSH INTO."
        );
        eprintln!("Then run:  lockshell ssh add-host self <user>@localhost:22");
        eprintln!("And then:  lockshell ssh self");
        let _ = copy_to_clipboard(&line);
        return Ok(());
    }

    // Default mode: bootstrap CA + user key. Print the CA cert-authority line
    // for distribution to managed targets.
    let user =
        labels::load_user_signer_dyn().context("failed to load or create the user signing key")?;
    let _ = user.public_key_blob()?; // touch it so the SE entry materialises

    let ca = labels::load_ca_signer_dyn().context("failed to load or create the CA signing key")?;
    let ca_blob = ca.public_key_blob()?;
    let ca_b64 = base64::engine::general_purpose::STANDARD.encode(&ca_blob);
    let host = host_label();

    eprintln!("✓ user signing key ready (label: {})", labels::user_label());
    eprintln!("✓ CA key ready          (label: {})", labels::ca_label());
    if labels::stress_mode() {
        eprintln!("⚠ STRESS MODE — keys are non-biometric. Do not use in production.");
    }
    eprintln!();
    eprintln!("CA public key — distribute to managed targets:");
    eprintln!();
    println!(
        "{} {} {}@{}",
        ca.algorithm(),
        ca_b64,
        labels::ca_label(),
        host
    );
    eprintln!();
    eprintln!("Per-target setup:");
    eprintln!(
        "  1. Save the line above to /etc/ssh/lockshell_ca.pub (without 'cert-authority' prefix)"
    );
    eprintln!("  2. Add to /etc/ssh/sshd_config:  TrustedUserCAKeys /etc/ssh/lockshell_ca.pub");
    eprintln!(
        "  3. Hardened reference template:  crates/lockshell-ssh/templates/sshd_config.lockshell"
    );
    eprintln!("  4. systemctl reload sshd  (or `launchctl kickstart -k system/com.openssh.sshd` on macOS)");
    eprintln!();
    eprintln!("Once the CA is trusted, every `lockshell ssh <alias>` mints a fresh 5-minute cert.");
    eprintln!(
        "Use `lockshell ssh init --self` instead if you only want same-Mac SSH without the CA."
    );
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn run(_args: SshInitArgs) -> Result<()> {
    anyhow::bail!(
        "lockshell ssh init is macOS-only in v0.6 (Secure Enclave required). \
         Linux fallback (passphrase / caBLE QR) ships in Phase 6."
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

#[cfg(target_os = "macos")]
fn copy_to_clipboard(s: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("pbcopy").stdin(Stdio::piped()).spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(s.as_bytes())?;
    }
    child.wait()?;
    Ok(())
}
