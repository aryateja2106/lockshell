// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};

/// Lockshell — AI-safe secret broker.
///
/// Cloud LLMs decide what to run. Lockshell resolves secrets locally and
/// executes commands without exposing values to the cloud LLM, the chat
/// log, the process argv list, or any tracked file.
///
/// Quick start:
///
///     lockshell setup                      # one-time interactive setup
///     lockshell register LINEAR_API_KEY linear-api password
///     lockshell run --reason "list issues" -- linear list --token '{{LINEAR_API_KEY}}'
///
/// Full docs: https://github.com/aryateja2106/lockshell
#[derive(Parser, Debug)]
#[command(
    name = "lockshell",
    version,
    about,
    long_about = None,
    propagate_version = true,
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Interactive first-time setup (vault init, session, first secret)
    Setup(SetupArgs),

    /// Map a placeholder name to a vault secret (env-name → vault-id.field)
    #[command(after_help = "EXAMPLE:\n    lockshell register LINEAR_API_KEY linear-api password")]
    Register(RegisterArgs),

    /// Remove a registered placeholder mapping
    Unregister(UnregisterArgs),

    /// List registered placeholder mappings (does not show secret values)
    List(ListArgs),

    /// Run a command, resolving {{PLACEHOLDER}} secrets from the vault
    #[command(after_help = "EXAMPLES:\n  \
        lockshell run --reason \"list linear issues\" -- linear list --token '{{LINEAR_API_KEY}}'\n  \
        lockshell run --reason \"deploy preview\" -- vercel deploy --token '{{VERCEL_TOKEN}}'")]
    Run(RunArgs),

    /// Issue a vault request and (optionally) wait for approval
    Request(RequestArgs),

    /// Show the audit log (templates and reasons; never values)
    Audit(AuditArgs),

    /// Show daemon, vault, and session status
    Status(StatusArgs),

    /// Diagnose setup issues with helpful fix suggestions
    Doctor(DoctorArgs),

    /// Print version
    Version,
}

#[derive(Parser, Debug)]
pub struct SetupArgs {
    /// Skip interactive prompts (useful for CI or scripted setup)
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Parser, Debug)]
pub struct RegisterArgs {
    /// Placeholder name as it appears in command templates (e.g. LINEAR_API_KEY)
    pub env_name: String,

    /// Vault secret id (e.g. "linear-api")
    pub vault_id: String,

    /// Field within the secret (e.g. "password" for login-style secrets, "token" for api_key)
    pub field: String,
}

#[derive(Parser, Debug)]
pub struct UnregisterArgs {
    /// Placeholder name to remove
    pub env_name: String,
}

#[derive(Parser, Debug)]
pub struct ListArgs {
    /// JSON output
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// Brief human-readable reason for this invocation (recorded in audit log)
    #[arg(long)]
    pub reason: String,

    /// Suppress redaction (for debugging — use sparingly, never with real keys)
    #[arg(long, hide = true)]
    pub no_redact: bool,

    /// The command and arguments to execute. Anything after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct RequestArgs {
    /// Vault secret id to request
    pub vault_id: String,

    /// Reason for the request (recorded with the request)
    #[arg(long, default_value = "lockshell access")]
    pub reason: String,

    /// Wait for approval and poll until granted (max 5 minutes)
    #[arg(long)]
    pub wait: bool,
}

#[derive(Parser, Debug)]
pub struct AuditArgs {
    /// Number of entries to show (most recent first)
    #[arg(short = 'n', long, default_value = "20")]
    pub lines: usize,

    /// JSON output (one object per line)
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct StatusArgs {
    /// JSON output
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct DoctorArgs {
    /// Attempt to fix issues automatically where safe
    #[arg(long)]
    pub fix: bool,
}
