// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use lockshell_ssh::Signer;
use lockshelld::ssh_agent::{AgentBackend, CertMinter};
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
        let backend = build_agent_backend();
        let user_pub_path = lockshell_dir.join("user.pub");

        let rpc_task = tokio::spawn(async move { rpc::serve(&control_path).await });
        let agent_task = match backend {
            Some(backend) => {
                if let Err(e) = write_user_pubkey(&user_pub_path, &*backend.user_signer) {
                    eprintln!(
                        "lockshelld: warning — could not write user.pub at {}: {}",
                        user_pub_path.display(),
                        e
                    );
                } else {
                    eprintln!(
                        "lockshelld: published user pubkey at {}",
                        user_pub_path.display()
                    );
                }
                Some(tokio::spawn(ssh_agent::serve_with_backend(
                    agent_path, backend,
                )))
            }
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

/// Persist the daemon's current user pubkey to disk in `authorized_keys`
/// format so the lockshell CLI can pass it to OpenSSH via `IdentityFile`.
///
/// Without this file the OpenSSH client refuses to offer the agent's
/// certificate identity (cert keys in the agent only get tried when the
/// underlying user pubkey is also configured as an `IdentityFile`).
///
/// Best-effort: failure is logged but does not abort the daemon, since
/// the agent socket itself remains functional for callers that pass an
/// `IdentityFile` explicitly.
fn write_user_pubkey(path: &Path, signer: &dyn Signer) -> Result<()> {
    use base64::Engine;
    use std::io::Write;

    let blob = signer.public_key_blob().context("rendering user pubkey")?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let line = format!("{} {} lockshell-user@daemon\n", signer.algorithm(), b64);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("pub.tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Default principal for minted user certs.
///
/// Resolution order:
/// 1. `LOCKSHELL_DEFAULT_PRINCIPAL` env var (explicit override).
/// 2. `$USER` (the most common identity match for managed targets where
///    accounts mirror the operator's Mac account).
/// 3. Hardcoded `lockshell-user` (Launch agent / system contexts).
///
/// The principal is recorded inside every cert the daemon mints. The
/// remote sshd compares it to the connecting username, so this needs to
/// match the account name on the target. Stress rigs and containers
/// where the remote user differs from `$USER` should set the env var.
fn default_principal() -> String {
    if let Ok(p) = std::env::var("LOCKSHELL_DEFAULT_PRINCIPAL") {
        if !p.is_empty() {
            return p;
        }
    }
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "lockshell-user".to_string())
}

#[cfg(target_os = "macos")]
fn build_agent_backend() -> Option<Arc<AgentBackend>> {
    // Tests / CI / headless runners can disable the SE-backed signer entirely.
    // The control RPC keeps running; ssh-agent is simply absent.
    if std::env::var_os("LOCKSHELL_DISABLE_SSH_AGENT").is_some() {
        eprintln!("lockshelld: ssh-agent disabled by LOCKSHELL_DISABLE_SSH_AGENT");
        return None;
    }

    let user_signer = build_user_signer()?;

    // CA signer is best-effort: if SE init for the CA key fails, we still
    // serve the agent with the raw user key so the operator can debug. The
    // real failure mode (no SE at all) is handled by the user-signer branch.
    let cert_minter = build_cert_minter();

    let backend = match cert_minter {
        Some(minter) => AgentBackend::with_cert_minter(user_signer, minter),
        None => AgentBackend::raw_only(user_signer),
    };
    Some(Arc::new(backend))
}

#[cfg(not(target_os = "macos"))]
fn build_agent_backend() -> Option<Arc<AgentBackend>> {
    None
}

#[cfg(target_os = "macos")]
fn build_user_signer() -> Option<Arc<dyn Signer>> {
    if lockshell_ssh::labels::stress_mode() {
        eprintln!(
            "lockshelld: STRESS MODE ACTIVE — user key label '{}' (non-biometric, \
             SE preferred, software fallback if SEP unreachable). \
             DO NOT use this mode for real workflows.",
            lockshell_ssh::labels::user_label()
        );
    }
    match lockshell_ssh::labels::load_user_signer_dyn() {
        Ok(boxed) => Some(Arc::from(boxed)),
        Err(e) => {
            eprintln!(
                "lockshelld: ssh-agent disabled (signer unavailable: {}). \
                 lockshell ssh will not work until this is resolved.",
                e
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn build_cert_minter() -> Option<Arc<dyn CertMinter>> {
    match lockshell_ssh::labels::load_ca_signer_dyn() {
        Ok(ca_signer) => match ca_minter::CaCertMinter::new(ca_signer, default_principal()) {
            Ok(minter) => Some(Arc::new(minter) as Arc<dyn CertMinter>),
            Err(e) => {
                eprintln!(
                    "lockshelld: cert minting disabled (CA init failed: {}). Agent \
                     will advertise the raw user key as a fallback.",
                    e
                );
                None
            }
        },
        Err(e) => {
            eprintln!(
                "lockshelld: cert minting disabled (CA signer unavailable: {}). \
                 Agent will advertise the raw user key as a fallback.",
                e
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
mod ca_minter {
    //! Bridge between `lockshell_ssh::ca::Ca` and the `CertMinter` trait the
    //! agent expects. Owns the CA signer for the daemon's lifetime so the
    //! `Ca<'static>` borrow is well-defined.

    use anyhow::Result;
    use lockshell_ssh::ca::{Ca, CertOptions, Clock, SystemClock, DEFAULT_TTL_SECS};
    use lockshell_ssh::Signer;

    use super::CertMinter;

    pub struct CaCertMinter {
        // `ca_signer` lives forever — leaked into a `&'static` so the inner
        // `Ca<'static>` reference is sound. The daemon process owns the box
        // until shutdown, at which point the kernel reclaims it. There is
        // exactly one `CaCertMinter` per process so the leak is bounded.
        ca: Ca<'static>,
        clock: SystemClock,
        principal: String,
        ttl_secs: u64,
    }

    impl CaCertMinter {
        pub fn new(ca_signer: Box<dyn Signer>, principal: String) -> Result<Self> {
            let leaked: &'static dyn Signer = Box::leak(ca_signer);
            let ca = Ca::new(leaked)?;
            Ok(Self {
                ca,
                clock: SystemClock,
                principal,
                ttl_secs: DEFAULT_TTL_SECS,
            })
        }
    }

    impl CertMinter for CaCertMinter {
        fn mint_user_cert(&self, user_pubkey_blob: &[u8]) -> Result<Vec<u8>> {
            let serial = self.clock.now_unix_secs();
            let key_id = format!("lockshell-{}-{}", self.principal, serial);
            let opts = CertOptions {
                principal: &self.principal,
                ttl_secs: self.ttl_secs,
                key_id: &key_id,
            };
            self.ca.mint_user_cert(user_pubkey_blob, opts, &self.clock)
        }
    }
}
