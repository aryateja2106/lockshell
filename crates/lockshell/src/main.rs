// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Arya Teja Rudraraju
//
// lockshell — AI-safe secret broker.

mod audit_log;
mod cli;
mod commands;
mod redact;
mod registry;
mod ui;
mod vault;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let args = cli::Args::parse();

    match args.command {
        cli::Command::Register(c) => commands::register::run(c),
        cli::Command::Unregister(c) => commands::register::unregister(c),
        cli::Command::List(c) => commands::list::run(c),
        cli::Command::Run(c) => commands::run::run(c),
        cli::Command::Request(c) => commands::request::run(c),
        cli::Command::Audit(c) => commands::audit::run(c),
        cli::Command::Status(c) => commands::status::run(c),
        cli::Command::Doctor(c) => commands::doctor::run(c),
        cli::Command::Setup(c) => commands::setup::run(c),
        cli::Command::HelpMe => commands::help_me::run(),
        cli::Command::Dashboard(c) => commands::dashboard::run(c),
        cli::Command::Ssh(c) => commands::ssh::run(c),
        cli::Command::SshInit(c) => commands::ssh_init::run(c),
        cli::Command::SshAddHost(c) => commands::ssh_host::add(c),
        cli::Command::Ca(c) => commands::ca::run(c),
        cli::Command::SshRun(c) => commands::ssh_run::run(c),
        cli::Command::Version => {
            println!(
                "lockshell {} ({})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_DESCRIPTION")
            );
            Ok(())
        }
    }
}
