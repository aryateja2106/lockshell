// SPDX-License-Identifier: Apache-2.0
//
// Vault adapter. v0.1.x calls out to the `agent-password` binary.
// In v0.3 we'll replace this with native Apple Keychain via Security.framework.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::process::Command;

pub struct AgentPasswordVault;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // NotInitialized is reserved for v0.2 native-Keychain backend
pub enum VaultError {
    #[error("agent-password binary not found in PATH. Install: cargo install --path ~/Projects/agent-password")]
    BinaryMissing,

    #[error("vault not initialized. Run: agent-password vault init")]
    NotInitialized,

    #[error("no active session. Run: agent-password session create")]
    NoSession,

    #[error("secret '{0}' is not approved for the current session")]
    NotApproved(String),

    #[error("agent-password error: {0}")]
    Other(String),
}

impl AgentPasswordVault {
    pub fn check_installed() -> Result<()> {
        which::which("agent-password")
            .map(|_| ())
            .map_err(|_| VaultError::BinaryMissing.into())
    }

    pub fn session_status() -> Result<SessionStatus> {
        Self::check_installed()?;
        let out = Command::new("agent-password")
            .args(["session", "status"])
            .output()
            .context("running agent-password session status")?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr);
        let combined = format!("{}\n{}", text, stderr);

        // Detect daemon-unavailable failures distinctly from "no session".
        if combined.contains("internal daemon did not become ready")
            || combined.contains("failed to bind")
        {
            return Err(VaultError::Other(
                "agent-password daemon is not running and could not be started \
                 (likely sandbox restriction or session was closed). Run \
                 `agent-password session create` from an unsandboxed shell."
                    .into(),
            )
            .into());
        }

        if combined.contains("no shared session") {
            return Ok(SessionStatus {
                exists: false,
                unlocked: false,
                approved: vec![],
                pending_requests: 0,
            });
        }

        // Parse the human-readable output. Default to exists=false; only flip to true
        // when we see explicit `exists: true` output.
        let mut status = SessionStatus {
            exists: false,
            unlocked: false,
            approved: vec![],
            pending_requests: 0,
        };
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("exists:") {
                status.exists = rest.trim() == "true";
            } else if let Some(rest) = line.strip_prefix("unlocked:") {
                status.unlocked = rest.trim() == "true";
            } else if let Some(rest) = line.strip_prefix("approved:") {
                let r = rest.trim();
                if r != "<none>" && !r.is_empty() {
                    status.approved = r.split(',').map(|s| s.trim().to_string()).collect();
                }
            } else if let Some(rest) = line.strip_prefix("pending requests:") {
                let r = rest.trim();
                status.pending_requests = if r == "<none>" {
                    0
                } else {
                    r.parse().unwrap_or(0)
                };
            }
        }
        Ok(status)
    }

    /// Get a field from a vault secret. Requires the secret to be approved in the current session.
    pub fn get_field(vault_id: &str, field: &str) -> Result<String> {
        Self::check_installed()?;
        let out = Command::new("agent-password")
            .args(["secrets", "get", vault_id, "--field", field, "--json"])
            .output()
            .context("running agent-password secrets get")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("not approved") {
                return Err(VaultError::NotApproved(vault_id.into()).into());
            }
            if stderr.contains("no shared session") {
                return Err(VaultError::NoSession.into());
            }
            // Defense-in-depth: redact the upstream stderr before surfacing.
            // If agent-password ever leaks a value to its stderr, we don't
            // want to propagate it through our error chain.
            let patterns = crate::redact::load_patterns().unwrap_or_default();
            let redacted = crate::redact::redact(stderr.trim(), &patterns);
            return Err(VaultError::Other(redacted).into());
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v: Value = serde_json::from_str(&stdout)
            .with_context(|| format!("parsing agent-password JSON: {}", stdout))?;
        let val = v
            .get(field)
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("field '{}' missing from vault response", field))?;
        Ok(val.to_string())
    }

    /// Issue a request for a secret. Returns the request id.
    pub fn request(vault_id: &str, requester: &str, reason: &str) -> Result<u32> {
        Self::check_installed()?;
        let out = Command::new("agent-password")
            .args([
                "secrets",
                "request",
                vault_id,
                "--requester",
                requester,
                "--reason",
                reason,
            ])
            .output()
            .context("running agent-password secrets request")?;
        if !out.status.success() {
            let patterns = crate::redact::load_patterns().unwrap_or_default();
            let redacted =
                crate::redact::redact(String::from_utf8_lossy(&out.stderr).trim(), &patterns);
            return Err(VaultError::Other(redacted).into());
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if let Some(num) = line.strip_prefix("created request ") {
                return num
                    .trim()
                    .parse::<u32>()
                    .with_context(|| format!("parsing request id from '{}'", line));
            }
        }
        Err(anyhow!(
            "could not parse request id from agent-password output: {}",
            stdout
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SessionStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub approved: Vec<String>,
    pub pending_requests: u32,
}
