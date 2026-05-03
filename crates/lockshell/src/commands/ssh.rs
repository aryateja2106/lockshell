// SPDX-License-Identifier: Apache-2.0

//! `lockshell ssh <alias>` — interactive SSH session.
//!
//! Looks up the host alias in `~/.config/lockshell/hosts.tsv`, audits the
//! attempt, then execs OpenSSH with `IdentityAgent` pointed at the lockshell
//! daemon's agent socket. The daemon performs the signature in the Secure
//! Enclave, gated by Touch ID. The signing key never leaves the SE.

use crate::audit_log;
use crate::cli::SshArgs;
use anyhow::{anyhow, Context, Result};
use lockshell_ssh::hosts;
use std::process::Command;

pub fn run(args: SshArgs) -> Result<()> {
    let path = hosts::default_path().context("locating hosts.tsv")?;
    let host = hosts::lookup(&path, &args.alias)?
        .ok_or_else(|| {
            anyhow!(
                "host alias '{}' is not registered.\n  hint: lockshell ssh add-host {} <user>@<host>:<port>",
                args.alias,
                args.alias
            )
        })?;

    let reason = args
        .reason
        .clone()
        .unwrap_or_else(|| "interactive ssh".to_string());
    let _ = audit_log::append_ssh(
        &reason,
        &host.alias,
        &host.hostname,
        &host.user,
        args.cert_ttl.as_deref().unwrap_or("NA"),
    );

    let agent_sock = agent_socket_path()?;
    let mut cmd = Command::new("ssh");
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", agent_sock.display()));
    cmd.arg("-o").arg("IdentitiesOnly=yes");
    cmd.arg("-p").arg(host.port.to_string());
    cmd.arg(format!("{}@{}", host.user, host.hostname));

    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn ssh for alias {}", args.alias))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn agent_socket_path() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("HOME not set; cannot locate ~/.lockshell/agent.sock")?;
    Ok(home.join(".lockshell").join("agent.sock"))
}
