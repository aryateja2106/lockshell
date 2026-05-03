// SPDX-License-Identifier: Apache-2.0

//! `lockshell ssh-run --reason ... --host <alias> -- <remote cmd>` —
//! agent-friendly remote command execution.
//!
//! Mirrors `lockshell run` but the resolved command runs on a remote host
//! reached via the lockshell SSH agent socket. Like `run`, secrets never
//! appear on argv: the remote command (with placeholders substituted) is
//! piped into `bash -s` over the SSH session's stdin.
//!
//! Audit row: `op=ssh-run`, host alias, principal, redacted-byte count.
//! Output: stdout + stderr piped through the redactor, returned to caller.

use crate::audit_log;
use crate::cli::SshRunArgs;
use crate::redact;
use crate::registry;
use crate::ui;
use crate::vault::{AgentPasswordVault, VaultError};
use anyhow::{anyhow, Context, Result};
use lockshell_ssh::hosts;
use regex::Regex;
use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub fn run(args: SshRunArgs) -> Result<()> {
    let template = args.command.join(" ");

    // Find {{NAME}} placeholders in the remote command template.
    let re = Regex::new(r"\{\{([A-Z_][A-Z0-9_]*)\}\}")?;
    let placeholders: BTreeSet<String> = re
        .captures_iter(&template)
        .map(|c| c[1].to_string())
        .collect();

    let host_path = hosts::default_path().context("locating hosts.tsv")?;
    let host = hosts::lookup(&host_path, &args.host)?
        .ok_or_else(|| anyhow!("host alias '{}' is not registered", args.host))?;

    // Audit BEFORE resolution. Log the template, never values. The placeholder
    // names appear in the row so an auditor knows which secrets the command
    // referenced. Best-effort: warn but don't abort.
    let audit_ok = audit_log::append_ssh_run(
        &args.reason,
        &host.alias,
        &host.hostname,
        &host.user,
        &template,
        &placeholders.iter().cloned().collect::<Vec<_>>(),
    )
    .unwrap_or(false);
    if !audit_ok {
        ui::warn(&format!(
            "audit log not writable at {} — continuing",
            audit_log::audit_path().display()
        ));
    }

    // Resolve each placeholder against the vault. Same error handling as
    // `lockshell run` so agents see consistent UX.
    let mut resolved: Vec<(String, Zeroizing<String>)> = Vec::new();
    for ph in &placeholders {
        let mapping = registry::lookup(ph)?.ok_or_else(|| {
            anyhow!(
                "{} is not registered. Run: lockshell register {} <vault-id> <field>",
                ph,
                ph
            )
        })?;
        match AgentPasswordVault::get_field(&mapping.vault_id, &mapping.field) {
            Ok(val) => resolved.push((ph.clone(), Zeroizing::new(val))),
            Err(e) => {
                if let Some(VaultError::NotApproved(_)) = e.downcast_ref::<VaultError>() {
                    ui::err(&format!(
                        "{} is in the vault but not approved for this session.",
                        ph
                    ));
                    ui::hint(&format!(
                        "agent-password secrets request {} --requester {} --reason {:?}",
                        mapping.vault_id, args.host, args.reason
                    ));
                    return Err(e);
                }
                return Err(e);
            }
        }
    }

    // Substitute placeholders into the remote command. The substituted
    // command never touches argv — it is piped via the ssh session's stdin
    // into `bash -s` on the remote host.
    let mut remote_cmd = Zeroizing::new(template.clone());
    for (name, value) in &resolved {
        let needle = format!("{{{{{}}}}}", name);
        *remote_cmd = remote_cmd.replace(&needle, value);
    }

    // Build the local ssh invocation. Secrets do NOT appear on argv —
    // the remote command body is fed via stdin.
    let agent_sock = agent_socket_path()?;
    let user_pub = user_pubkey_path()?;
    let user_cert = user_cert_path()?;

    // Trigger a REQUEST_IDENTITIES round-trip with the daemon so it mints a
    // fresh cert and persists it at `~/.lockshell/user-cert.pub`. Spawning
    // `ssh` immediately afterwards picks up the file via `CertificateFile`.
    // OpenSSH 10.x will not offer agent-only certs during the attempt list,
    // so the disk-cached cert is required for cert-based auth.
    refresh_user_cert(&agent_sock);

    let mut ssh = Command::new("ssh");
    ssh.arg("-o")
        .arg(format!("IdentityAgent={}", agent_sock.display()));
    if user_pub.exists() {
        ssh.arg("-o")
            .arg(format!("IdentityFile={}", user_pub.display()));
    }
    if user_cert.exists() {
        ssh.arg("-o")
            .arg(format!("CertificateFile={}", user_cert.display()));
    }
    ssh.arg("-o").arg("IdentitiesOnly=yes");
    ssh.arg("-o")
        .arg("PubkeyAcceptedAlgorithms=+ecdsa-sha2-nistp256-cert-v01@openssh.com");
    ssh.arg("-o").arg("BatchMode=yes");
    ssh.arg("-o").arg("StrictHostKeyChecking=accept-new");
    ssh.arg("-p").arg(host.port.to_string());
    ssh.arg(format!("{}@{}", host.user, host.hostname));
    ssh.arg("bash").arg("-s");
    ssh.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = ssh.spawn().context("failed to spawn ssh")?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(remote_cmd.as_bytes())
            .context("piping remote command to ssh stdin")?;
    }
    drop(child.stdin.take()); // close stdin so remote bash exits

    let output = child.wait_with_output().context("waiting for ssh")?;

    // Redact output before returning to the agent. Same regex set as
    // `lockshell run` (Linear / GitHub / OpenAI / AWS / etc.).
    let patterns = redact::load_patterns().unwrap_or_default();
    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let stderr_raw = String::from_utf8_lossy(&output.stderr);
    let stdout = if args.no_redact {
        stdout_raw.to_string()
    } else {
        redact::redact(&stdout_raw, &patterns)
    };
    let stderr = if args.no_redact {
        stderr_raw.to_string()
    } else {
        redact::redact(&stderr_raw, &patterns)
    };

    print!("{}", stdout);
    eprint!("{}", stderr);

    let exit_code = output.status.code().unwrap_or(1);
    std::process::exit(exit_code);
}

fn agent_socket_path() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("HOME not set; cannot locate ~/.lockshell/agent.sock")?;
    Ok(home.join(".lockshell").join("agent.sock"))
}

fn user_pubkey_path() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("HOME not set; cannot locate ~/.lockshell/user.pub")?;
    Ok(home.join(".lockshell").join("user.pub"))
}

fn user_cert_path() -> Result<std::path::PathBuf> {
    let home =
        dirs::home_dir().context("HOME not set; cannot locate ~/.lockshell/user-cert.pub")?;
    Ok(home.join(".lockshell").join("user-cert.pub"))
}

/// Force a REQUEST_IDENTITIES round-trip with the agent so the daemon mints
/// a fresh cert and persists it on disk for `CertificateFile=` to pick up.
/// Best-effort — if `ssh-add` is missing or the agent socket is dead the
/// caller still proceeds (a stale or absent cert just yields a clean
/// publickey-denied error from sshd, identical to the no-cert case).
fn refresh_user_cert(agent_sock: &std::path::Path) {
    let _ = Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", agent_sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
