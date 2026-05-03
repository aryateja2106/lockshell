// SPDX-License-Identifier: Apache-2.0

//! `lockshell ssh init [--self]` — bootstrap the user's Secure Enclave key.
//!
//! Creates the SE-resident `lockshell-user` key if absent and prints an
//! `authorized_keys` line for the public component. With `--self`, also
//! prints follow-up instructions and best-effort copies the line to the
//! macOS clipboard via `pbcopy`.
//!
//! macOS-only in v0.6. The Linux fallback path lands in Phase 6.

use crate::cli::SshInitArgs;
use anyhow::Result;

#[cfg(target_os = "macos")]
pub fn run(args: SshInitArgs) -> Result<()> {
    use anyhow::Context;
    use base64::Engine;
    use lockshell_ssh::{SecureEnclaveSigner, Signer};

    let signer = SecureEnclaveSigner::load_or_create("lockshell-user")
        .context("failed to load or create the Secure Enclave key")?;

    // The signer's public_key_blob is the full SSH wire-format payload:
    //   string("ecdsa-sha2-nistp256") || string("nistp256") || string(0x04 || X || Y)
    // For an authorized_keys line we want the same blob, base64-encoded as a
    // single field, prefixed by the algorithm name.
    let blob = signer.public_key_blob()?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let host = host_label();
    let line = format!("{} {} lockshell-user@{}", signer.algorithm(), b64, host);

    println!("{}", line);

    if args.self_only {
        eprintln!();
        eprintln!(
            "Add the line above to ~/.ssh/authorized_keys on the machine you want to SSH INTO."
        );
        eprintln!("Then run:  lockshell ssh add-host self <user>@localhost:22");
        eprintln!("And then:  lockshell ssh self");
        // Best-effort clipboard copy. Failures are silent — the printed line is the
        // source of truth.
        let _ = copy_to_clipboard(&line);
    }
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
