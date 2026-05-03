// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Parser;

mod rpc;

#[derive(Debug, Parser)]
#[command(name = "lockshelld", version, about = "Lockshell daemon")]
struct Cli {
    /// Run in the foreground. Phase 1 only supports foreground mode; without
    /// this flag the binary exits immediately (daemonization is Phase 2+).
    #[arg(long)]
    foreground: bool,

    /// Override the control socket path. Defaults to $HOME/.lockshell/control.sock.
    #[arg(long, value_name = "PATH")]
    socket: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.foreground {
        eprintln!("lockshelld: --foreground is required in Phase 1");
        std::process::exit(0);
    }

    let socket_path = match cli.socket {
        Some(p) => p,
        None => default_socket_path()?,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(rpc::serve(&socket_path))
}

fn default_socket_path() -> Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME").context("HOME env var is unset")?;
    Ok(std::path::PathBuf::from(home)
        .join(".lockshell")
        .join("control.sock"))
}
