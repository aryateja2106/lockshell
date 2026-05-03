// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC 2.0 error codes used by the daemon.
mod error_code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    #[allow(dead_code)]
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

/// Bind the control socket and accept connections forever.
pub async fn serve(socket_path: &Path) -> Result<()> {
    prepare_socket(socket_path)?;

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding control socket at {}", socket_path.display()))?;
    set_socket_perms(socket_path)?;

    eprintln!("lockshelld: listening on {}", socket_path.display());

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                eprintln!("lockshelld: accept failed: {err}");
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream).await {
                eprintln!("lockshelld: connection error: {err}");
            }
        });
    }
}

fn prepare_socket(socket_path: &Path) -> Result<()> {
    let parent: PathBuf = socket_path
        .parent()
        .map(Path::to_path_buf)
        .context("control socket path has no parent directory")?;
    std::fs::create_dir_all(&parent)
        .with_context(|| format!("creating control socket dir at {}", parent.display()))?;
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting 0700 on {}", parent.display()))?;
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("removing stale socket at {}", socket_path.display()))?;
    }
    Ok(())
}

fn set_socket_perms(socket_path: &Path) -> Result<()> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting 0600 on {}", socket_path.display()))
}

async fn handle_connection(stream: UnixStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = process_line(&line);
        let mut payload = serde_json::to_vec(&response)?;
        payload.push(b'\n');
        write_half.write_all(&payload).await?;
        write_half.flush().await?;
    }
    Ok(())
}

fn process_line(line: &str) -> RpcResponse {
    let req: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(err) => {
            return RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: Value::Null,
                result: None,
                error: Some(RpcError {
                    code: error_code::PARSE_ERROR,
                    message: format!("parse error: {err}"),
                }),
            };
        }
    };

    let id = req.id.clone().unwrap_or(Value::Null);

    if req.jsonrpc != JSONRPC_VERSION {
        return RpcResponse {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: None,
            error: Some(RpcError {
                code: error_code::INVALID_REQUEST,
                message: format!("unsupported jsonrpc version: {}", req.jsonrpc),
            }),
        };
    }

    match req.method.as_str() {
        "vault.status" => RpcResponse {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: Some(json!({
                "status": status_label(lockshell_proto::SessionStatus::NoSession),
            })),
            error: None,
        },
        other => RpcResponse {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: None,
            error: Some(RpcError {
                code: error_code::METHOD_NOT_FOUND,
                message: format!("method not found: {other}"),
            }),
        },
    }
}

fn status_label(s: lockshell_proto::SessionStatus) -> &'static str {
    match s {
        lockshell_proto::SessionStatus::Locked => "Locked",
        lockshell_proto::SessionStatus::Unlocked => "Unlocked",
        lockshell_proto::SessionStatus::NoSession => "NoSession",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_returns_null_id() {
        let resp = process_line("not json");
        assert_eq!(resp.id, Value::Null);
        let err = resp.error.expect("error expected");
        assert_eq!(err.code, error_code::PARSE_ERROR);
    }

    #[test]
    fn unknown_method_yields_method_not_found() {
        let resp = process_line(r#"{"jsonrpc":"2.0","id":7,"method":"vault.bogus"}"#);
        assert_eq!(resp.id, Value::from(7));
        let err = resp.error.expect("error expected");
        assert_eq!(err.code, error_code::METHOD_NOT_FOUND);
    }

    #[test]
    fn vault_status_returns_no_session() {
        let resp = process_line(r#"{"jsonrpc":"2.0","id":1,"method":"vault.status"}"#);
        assert!(resp.error.is_none());
        let result = resp.result.expect("result expected");
        assert_eq!(result["status"], "NoSession");
    }

    #[test]
    fn rejects_wrong_jsonrpc_version() {
        let resp = process_line(r#"{"jsonrpc":"1.0","id":1,"method":"vault.status"}"#);
        let err = resp.error.expect("error expected");
        assert_eq!(err.code, error_code::INVALID_REQUEST);
    }
}
