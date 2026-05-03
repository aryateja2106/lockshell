// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use lockshell_ssh::Signer;
use lockshelld::{rpc, ssh_agent};

#[derive(Debug, Parser)]
#[command(name = "lockshelld", version, about = "Lockshell daemon")]
struct Cli {
    /// Run in the foreground. Phase 1 only supports foreground mode; without
    /// this flag the binary exits immediately (daemonization is Phase 9+).
    #[arg(long)]
    foreground: bool,

    /// Override the control socket path. Defaults to `$HOME/.lockshell/control.sock`.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Override the ssh-agent socket path. Defaults to `$HOME/.lockshell/agent.sock`.
    #[arg(long, value_name = "PATH")]
    agent_socket: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.foreground {
        eprintln!("lockshelld: --foreground is required in Phase 1");
        std::process::exit(0);
    }

    let lockshell_dir = lockshell_dir()?;
    let control_path = match cli.socket {
        Some(p) => p,
        None => lockshell_dir.join("control.sock"),
    };
    let agent_path = match cli.agent_socket {
        Some(p) => p,
        None => lockshell_dir.join("agent.sock"),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(async move {
        let signer = build_default_signer()?;

        let rpc_task = tokio::spawn(async move { rpc::serve(&control_path).await });
        let agent_task = match signer {
            Some(signer) => Some(tokio::spawn(ssh_agent::serve(agent_path, signer))),
            None => {
                eprintln!(
                    "lockshelld: ssh-agent disabled (no Secure Enclave signer on this platform)"
                );
                None
            }
        };

        let rpc_result = match agent_task {
            Some(agent_task) => tokio::select! {
                rpc = rpc_task => rpc,
                agent = agent_task => agent,
            },
            None => rpc_task.await,
        };

        rpc_result.map_err(anyhow::Error::from).and_then(|r| r)
    })
}

fn lockshell_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME env var is unset")?;
    Ok(PathBuf::from(home).join(".lockshell"))
}

#[cfg(target_os = "macos")]
fn build_default_signer() -> Result<Option<Arc<dyn Signer>>> {
    // Tests / CI / headless runners can disable the SE-backed signer entirely.
    // The control RPC keeps running; ssh-agent is simply absent.
    if std::env::var_os("LOCKSHELL_DISABLE_SSH_AGENT").is_some() {
        eprintln!("lockshelld: ssh-agent disabled by LOCKSHELL_DISABLE_SSH_AGENT");
        return Ok(None);
    }
    // SE access can fail at startup for benign reasons: unsigned binary, no
    // SEP available (Intel Mac, virtualization), missing entitlements, no UI
    // to consent to a biometric ACL. Don't crash the daemon — log and skip
    // the ssh-agent task so the rest of the daemon still runs.
    match lockshell_ssh::SecureEnclaveSigner::load_or_create("lockshell-user") {
        Ok(signer) => Ok(Some(Arc::new(signer) as Arc<dyn Signer>)),
        Err(e) => {
            eprintln!(
                "lockshelld: ssh-agent disabled (Secure Enclave unavailable: {}). \
                 lockshell ssh will not work until this is resolved.",
                e
            );
            Ok(None)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn build_default_signer() -> Result<Option<Arc<dyn Signer>>> {
    Ok(None)
}
