// SPDX-License-Identifier: Apache-2.0

//! Shared RPC types between the lockshell CLI, daemon, and TUI.
//!
//! Wire format is JSON-RPC 2.0 line-delimited over a Unix socket. Concrete
//! method-specific payloads are supplied by callers via the type parameters
//! on [`VaultRequest`] / [`VaultResponse`]; this crate has no dependency on
//! `serde_json` so it stays cheap to depend on.

use serde::{Deserialize, Serialize};

/// Status of the local secret vault as reported by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SessionStatus {
    Locked,
    Unlocked,
    NoSession,
}

/// JSON-RPC request body. `P` is the method-specific params type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRequest<P = ()> {
    pub method: String,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    pub params: Option<P>,
}

/// JSON-RPC response body. `R` is the method-specific result type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultResponse<R = ()> {
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    pub result: Option<R>,
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    pub error: Option<VaultError>,
}

/// Structured error returned by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultError {
    pub code: i32,
    pub message: String,
}
