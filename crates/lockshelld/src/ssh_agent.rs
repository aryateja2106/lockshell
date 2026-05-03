// SPDX-License-Identifier: Apache-2.0

//! OpenSSH agent protocol server (`draft-miller-ssh-agent-04`).
//!
//! Listens on a Unix-domain socket, accepts connections from the OpenSSH
//! client (`ssh -o IdentityAgent=...`), and brokers signature requests through
//! a [`lockshell_ssh::Signer`] implementation. The signer is responsible for
//! gating each signature behind the user-visible consent prompt (Touch ID).
//!
//! Only the minimum set of message types needed for `IdentityAgent`-style
//! pubkey auth is implemented; everything else returns `SSH_AGENT_FAILURE`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use lockshell_ssh::Signer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const SSH_AGENT_FAILURE: u8 = 5;
#[allow(dead_code)]
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Hard cap on agent message size. The spec allows up to 256 KiB; we are
/// stricter to bound memory per connection.
const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Bind `socket_path`, set tight permissions, and serve agent connections
/// forever. Each connection gets its own task; the signer is shared via `Arc`.
pub async fn serve(socket_path: PathBuf, signer: Arc<dyn Signer>) -> Result<()> {
    prepare_socket(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding ssh-agent socket at {}", socket_path.display()))?;
    set_socket_perms(&socket_path)?;

    eprintln!(
        "lockshelld: ssh-agent listening on {}",
        socket_path.display()
    );

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                eprintln!("lockshelld: ssh-agent accept failed: {err}");
                continue;
            }
        };
        let signer = signer.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, signer).await {
                eprintln!("lockshelld: ssh-agent connection error: {err}");
            }
        });
    }
}

fn prepare_socket(socket_path: &Path) -> Result<()> {
    let parent: PathBuf = socket_path
        .parent()
        .map(Path::to_path_buf)
        .context("ssh-agent socket path has no parent directory")?;
    std::fs::create_dir_all(&parent)
        .with_context(|| format!("creating ssh-agent socket dir at {}", parent.display()))?;
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

async fn handle_connection(mut stream: UnixStream, signer: Arc<dyn Signer>) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        if let Err(err) = stream.read_exact(&mut len_buf).await {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(err.into());
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_MESSAGE_LEN {
            write_failure(&mut stream).await?;
            return Ok(());
        }

        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;

        let response = handle_message(&msg, signer.as_ref()).unwrap_or_else(|err| {
            eprintln!("lockshelld: ssh-agent message error: {err}");
            vec![SSH_AGENT_FAILURE]
        });

        write_message(&mut stream, &response).await?;
    }
}

async fn write_failure(stream: &mut UnixStream) -> Result<()> {
    write_message(stream, &[SSH_AGENT_FAILURE]).await
}

async fn write_message(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).context("response too large for u32 length prefix")?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

fn handle_message(msg: &[u8], signer: &dyn Signer) -> Result<Vec<u8>> {
    let (&kind, rest) = msg
        .split_first()
        .context("ssh-agent message has no type byte")?;

    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => Ok(build_identities_answer(signer)?),
        SSH_AGENTC_SIGN_REQUEST => build_sign_response(rest, signer),
        _ => Ok(vec![SSH_AGENT_FAILURE]),
    }
}

fn build_identities_answer(signer: &dyn Signer) -> Result<Vec<u8>> {
    let blob = signer.public_key_blob()?;
    let comment = format!("lockshell-user@{}", hostname());

    let mut out = Vec::with_capacity(1 + 4 + 4 + blob.len() + 4 + comment.len());
    out.push(SSH_AGENT_IDENTITIES_ANSWER);
    lockshell_ssh::wire::encode_uint32(&mut out, 1);
    lockshell_ssh::wire::encode_string(&mut out, &blob);
    lockshell_ssh::wire::encode_string(&mut out, comment.as_bytes());
    Ok(out)
}

fn build_sign_response(body: &[u8], signer: &dyn Signer) -> Result<Vec<u8>> {
    let (key_blob, rest) = lockshell_ssh::wire::decode_string(body)?;
    let (data, rest) = lockshell_ssh::wire::decode_string(rest)?;
    if rest.len() < 4 {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    // u32 flags trail; we accept and ignore (Phase 2 supports default ECDSA).

    let our_blob = signer.public_key_blob()?;
    if key_blob != our_blob.as_slice() {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }

    let signature = signer.sign(data, "ssh signature")?;

    let mut out = Vec::with_capacity(1 + 4 + signature.len());
    out.push(SSH_AGENT_SIGN_RESPONSE);
    lockshell_ssh::wire::encode_string(&mut out, &signature);
    Ok(out)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| {
            // `hostname(1)` is universally available on macOS/Linux. Fall back
            // to "localhost" if the call fails for any reason.
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| {
                    if o.status.success() {
                        Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                    } else {
                        None
                    }
                })
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "localhost".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubSigner {
        blob: Vec<u8>,
    }

    impl Signer for StubSigner {
        fn algorithm(&self) -> &'static str {
            "ecdsa-sha2-nistp256"
        }
        fn public_key_blob(&self) -> Result<Vec<u8>> {
            Ok(self.blob.clone())
        }
        fn sign(&self, data: &[u8], _reason: &str) -> Result<Vec<u8>> {
            // Echo input as "signature" for parser-only tests.
            Ok(data.to_vec())
        }
    }

    #[test]
    fn unknown_message_returns_failure() {
        let signer = StubSigner {
            blob: vec![1, 2, 3],
        };
        let resp = handle_message(&[99], &signer).unwrap();
        assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn identities_answer_carries_one_key() {
        let signer = StubSigner {
            blob: b"FAKE-BLOB".to_vec(),
        };
        let resp = build_identities_answer(&signer).unwrap();
        assert_eq!(resp[0], SSH_AGENT_IDENTITIES_ANSWER);
        // count = 1 in the next 4 bytes
        assert_eq!(&resp[1..5], &[0, 0, 0, 1]);
        // string(blob): length prefix == blob.len()
        assert_eq!(&resp[5..9], &(b"FAKE-BLOB".len() as u32).to_be_bytes());
        assert_eq!(&resp[9..9 + b"FAKE-BLOB".len()], b"FAKE-BLOB");
    }

    #[test]
    fn sign_request_with_matching_blob_returns_signature() {
        let signer = StubSigner {
            blob: b"PUBKEY".to_vec(),
        };
        // body = string(key_blob) || string(data) || u32(flags)
        let mut body = Vec::new();
        lockshell_ssh::wire::encode_string(&mut body, b"PUBKEY");
        lockshell_ssh::wire::encode_string(&mut body, b"payload");
        lockshell_ssh::wire::encode_uint32(&mut body, 0);

        let resp = build_sign_response(&body, &signer).unwrap();
        assert_eq!(resp[0], SSH_AGENT_SIGN_RESPONSE);
        let (sig, _) = lockshell_ssh::wire::decode_string(&resp[1..]).unwrap();
        assert_eq!(sig, b"payload");
    }

    #[test]
    fn sign_request_with_mismatched_blob_returns_failure() {
        let signer = StubSigner {
            blob: b"PUBKEY".to_vec(),
        };
        let mut body = Vec::new();
        lockshell_ssh::wire::encode_string(&mut body, b"OTHERKEY");
        lockshell_ssh::wire::encode_string(&mut body, b"payload");
        lockshell_ssh::wire::encode_uint32(&mut body, 0);

        let resp = build_sign_response(&body, &signer).unwrap();
        assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn sign_request_truncated_flags_returns_failure() {
        let signer = StubSigner {
            blob: b"PUBKEY".to_vec(),
        };
        let mut body = Vec::new();
        lockshell_ssh::wire::encode_string(&mut body, b"PUBKEY");
        lockshell_ssh::wire::encode_string(&mut body, b"payload");
        // omit flags

        let resp = build_sign_response(&body, &signer).unwrap();
        assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
    }
}
