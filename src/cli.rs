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

    /// Print a friendly step-by-step guide for first-time users
    HelpMe,

    /// Render a local HTML dashboard of registry, session, and audit log
    Dashboard(DashboardArgs),

    /// Store, list, or remove secrets in the native macOS Keychain
    #[command(after_help = "EXAMPLES:\n  \
        lockshell key add fireworks        # paste at a hidden prompt\n  \
        lockshell key list                 # names + fingerprints, never values\n  \
        lockshell register FIREWORKS_API_KEY keychain:fireworks value")]
    Key(KeyArgs),

    /// Mask sensitive text (emails, phones, IDs, API keys, your own terms) locally
    #[command(after_help = "EXAMPLES:\n  \
        lockshell mask check notes.md\n  \
        lockshell mask apply notes.md --map notes.map.json > notes.masked.md\n  \
        lockshell mask restore reply.md --map notes.map.json")]
    Mask(MaskArgs),

    /// Run the local OpenAI-compatible model gateway (keys stay in this process)
    #[command(after_help = "Config: ~/.config/lockshell/gateway.json   Client token: ~/.config/lockshell/gateway-token\n\
        Clients: base_url http://127.0.0.1:8787/v1, api_key = contents of the token file,\n\
        model = \"<provider>/<model>\" (GET /v1/models lists them).")]
    Gateway,

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

    /// Filter mappings by case-insensitive substring match against placeholder OR vault id.
    /// Useful for multi-account workflows: `lockshell list --grep supabase` shows
    /// every Supabase-related placeholder regardless of suffix convention.
    #[arg(long, value_name = "PATTERN")]
    pub grep: Option<String>,

    /// Print placeholder names only, one per line. Pipes cleanly into other tools.
    #[arg(long)]
    pub names_only: bool,
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

#[derive(Parser, Debug)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommand,
}

#[derive(Subcommand, Debug)]
pub enum KeyCommand {
    /// Add or replace a key. Prompts with hidden input (or reads stdin with --stdin)
    Add {
        /// Key name, e.g. fireworks
        name: String,
        /// Read the value from stdin (e.g. piped from a password manager)
        #[arg(long)]
        stdin: bool,
    },
    /// List stored keys: names, fingerprints, dates. Never values
    List,
    /// Remove a key from the Keychain
    Rm { name: String },
}

#[derive(Parser, Debug)]
pub struct MaskArgs {
    #[command(subcommand)]
    pub command: MaskCommand,
}

#[derive(Subcommand, Debug)]
pub enum MaskCommand {
    /// Count sensitive items by category (exit 1 if any). Never prints values
    Check { file: Option<String> },
    /// Print masked text; write the placeholder map (mode 600) to --map
    Apply {
        file: Option<String>,
        #[arg(long)]
        map: String,
    },
    /// Put original values back using a map from `apply`
    Restore {
        file: Option<String>,
        #[arg(long)]
        map: String,
    },
}

#[derive(Parser, Debug)]
pub struct DashboardArgs {
    /// Path to write the dashboard HTML. Defaults to a tempfile that auto-opens in your browser.
    #[arg(long, value_name = "PATH")]
    pub out: Option<String>,

    /// Do not auto-open the file in your browser.
    #[arg(long)]
    pub no_open: bool,

    /// Number of recent audit entries to render. Default 20.
    #[arg(short = 'n', long, default_value = "20")]
    pub lines: usize,
}
