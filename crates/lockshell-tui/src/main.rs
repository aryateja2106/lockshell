// SPDX-License-Identifier: Apache-2.0

//! Lockshell TUI binary.
//!
//! Thin entry point — argument parsing only. All UI logic lives in the
//! library crate so the rendering and event loop can be unit-tested
//! against ratatui's `TestBackend`.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "lockshell-tui",
    version,
    about = "Lockshell terminal UI — multi-pane SSH session manager (Phase 8 scaffold)."
)]
struct Cli {
    /// Reserved for future use: which `lockshell ssh-add-host` aliases
    /// should auto-attach to panes 1..5 on launch.
    #[arg(long, value_name = "ALIAS", num_args = 0..=5)]
    host: Vec<String>,
}

fn main() -> Result<()> {
    let _cli = Cli::parse();
    lockshell_tui::run()
}
