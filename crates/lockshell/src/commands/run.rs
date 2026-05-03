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
use zeroize::Zeroizing;

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

    // Resolve each placeholder. Wrap the value in `Zeroizing` so the
    // string buffer is overwritten with zeros when it goes out of scope.
    // This is best-effort: `Command::env` clones the bytes internally and
    // we cannot zero those, but we can at least clean up our own copies.
    let mut resolved: Vec<(String, Zeroizing<String>)> = Vec::new();
    for ph in &placeholders {
        let mapping = registry::lookup(ph)?
            .ok_or_else(|| anyhow::anyhow!(
                "{} is not registered. Run: lockshell register {} <vault-id> <field>",
                ph, ph
            ))?;
        match AgentPasswordVault::get_field(&mapping.vault_id, &mapping.field) {
            Ok(val) => resolved.push((ph.clone(), Zeroizing::new(val))),
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

    // Substitute {{NAME}} → "$NAME" and inject values via env.
    //
    // CRITICAL: we always emit DOUBLE-QUOTED env references. Without the
    // quotes, if a template like `tool --arg {{KEY}}` is paired with a
    // secret value that contains whitespace or shell metacharacters,
    // bash will word-split or expand the value at runtime, breaking out
    // of the intended argument boundary. Double quotes guarantee the
    // value is treated as exactly one argument.
    let mut resolved_cmd = template.clone();
    for (name, _) in &resolved {
        let placeholder = format!("{{{{{}}}}}", name);
        let replacement = format!("\"${}\"", name);
        resolved_cmd = resolved_cmd.replace(&placeholder, &replacement);
    }

    let mut cmd = Command::new("/bin/bash");
    cmd.arg("-c").arg(&resolved_cmd);
    for (name, value) in &resolved {
        // Pass via env so the secret never appears on argv.
        cmd.env(name, value.as_str());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // --no-redact requires an explicit env var to actually take effect.
    // The flag alone is not enough; agents that defaulted to passing
    // --no-redact would otherwise be one config bug away from leaking
    // values. Both must be present to disable redaction.
    let no_redact_allowed =
        args.no_redact && std::env::var("LOCKSHELL_ALLOW_NO_REDACT").as_deref() == Ok("1");
    if args.no_redact && !no_redact_allowed {
        ui::warn("--no-redact requires LOCKSHELL_ALLOW_NO_REDACT=1; ignoring flag and redacting normally.");
    }
    let patterns = if no_redact_allowed {
        vec![]
    } else {
        redact::load_patterns()?
    };

    let stdout_clean = if no_redact_allowed { stdout } else { redact::redact(&stdout, &patterns) };
    let stderr_clean = if no_redact_allowed { stderr } else { redact::redact(&stderr, &patterns) };

    print!("{}", stdout_clean);
    if !stderr_clean.is_empty() {
        eprint!("{}", stderr_clean);
    }
    std::process::exit(output.status.code().unwrap_or(1));
}
