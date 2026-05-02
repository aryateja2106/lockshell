// SPDX-License-Identifier: Apache-2.0

use crate::audit_log;
use crate::cli::RunArgs;
use crate::redact;
use crate::registry;
use crate::ui;
use crate::vault::{AgentPasswordVault, VaultError};
use anyhow::Result;
use regex::Regex;
use std::collections::BTreeSet;
use std::process::{Command, Stdio};

pub fn run(args: RunArgs) -> Result<()> {
    let template = args.command.join(" ");

    // Find {{NAME}} placeholders.
    let re = Regex::new(r"\{\{([A-Z_][A-Z0-9_]*)\}\}")?;
    let placeholders: BTreeSet<String> = re
        .captures_iter(&template)
        .map(|c| c[1].to_string())
        .collect();

    // Audit BEFORE we do anything. Log the template + reason, never values.
    // Audit is best-effort — sandboxed agents may not have write access to
    // ~/.config/lockshell/audit.log. We warn and continue rather than blocking.
    let audit_ok = audit_log::append(
        &args.reason,
        &template,
        &placeholders.iter().cloned().collect::<Vec<_>>(),
    )
    .unwrap_or(false);
    if !audit_ok {
        ui::warn(&format!(
            "audit log not writable at {} — continuing (broker call still works)",
            audit_log::audit_path().display()
        ));
        ui::hint("For sandboxed agents, set LOCKSHELL_CONFIG_DIR to a writable directory.");
    }

    // Resolve each placeholder.
    let mut resolved: Vec<(String, String)> = Vec::new();
    for ph in &placeholders {
        let mapping = registry::lookup(ph)?
            .ok_or_else(|| anyhow::anyhow!(
                "{} is not registered. Run: lockshell register {} <vault-id> <field>",
                ph, ph
            ))?;
        match AgentPasswordVault::get_field(&mapping.vault_id, &mapping.field) {
            Ok(val) => resolved.push((ph.clone(), val)),
            Err(e) => {
                if let Some(VaultError::NotApproved(_)) = e.downcast_ref::<VaultError>() {
                    ui::err(&format!(
                        "{} is in the vault but not approved for this session.",
                        ph
                    ));
                    ui::hint(&format!("agent-password secrets request {} --requester $(whoami) --reason {:?}",
                        mapping.vault_id, args.reason));
                    ui::hint("agent-password requests list");
                    ui::hint("agent-password requests approve <id> all");
                    std::process::exit(3);
                }
                if let Some(VaultError::NoSession) = e.downcast_ref::<VaultError>() {
                    ui::err("no active vault session.");
                    ui::hint("agent-password session create");
                    std::process::exit(3);
                }
                if let Some(VaultError::Other(msg)) = e.downcast_ref::<VaultError>() {
                    if msg.contains("internal daemon did not become ready") {
                        ui::err("agent-password daemon is not running and could not be started.");
                        ui::hint("This usually means: (a) you closed the session and the user must run");
                        ui::hint("   `agent-password session create` from their unsandboxed shell, OR");
                        ui::hint("(b) the sandbox blocks Unix socket creation at ~/.agent-password/daemon.sock.");
                        ui::hint("Sandboxed agents cannot start the daemon themselves; ask the user.");
                        std::process::exit(4);
                    }
                }
                return Err(e);
            }
        }
    }

    // Substitute {{NAME}} → $NAME and inject values via env.
    let mut resolved_cmd = template.clone();
    for (name, _) in &resolved {
        let placeholder = format!("{{{{{}}}}}", name);
        let replacement = format!("${}", name);
        resolved_cmd = resolved_cmd.replace(&placeholder, &replacement);
    }

    let mut cmd = Command::new("/bin/bash");
    cmd.arg("-c").arg(&resolved_cmd);
    for (name, value) in &resolved {
        cmd.env(name, value);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let patterns = if args.no_redact {
        vec![]
    } else {
        redact::load_patterns()?
    };

    let stdout_clean = if args.no_redact { stdout } else { redact::redact(&stdout, &patterns) };
    let stderr_clean = if args.no_redact { stderr } else { redact::redact(&stderr, &patterns) };

    print!("{}", stdout_clean);
    if !stderr_clean.is_empty() {
        eprint!("{}", stderr_clean);
    }
    std::process::exit(output.status.code().unwrap_or(1));
}
