// SPDX-License-Identifier: Apache-2.0

//! OpenSSH agent protocol server (`draft-miller-ssh-agent-04`).
//!
//! Listens on a Unix-domain socket, accepts connections from the OpenSSH
//! client (`ssh -o IdentityAgent=...`), and brokers signature requests through
//! a [`lockshell_ssh::Signer`] implementation. The signer is responsible for
//! gating each signature behind the user-visible consent prompt (Touch ID).
//!
//! From Phase 3 onward the agent advertises a freshly minted OpenSSH user
//! certificate (algorithm `ecdsa-sha2-nistp256-cert-v01@openssh.com`) instead
//! of a raw public key. The client then signs with the user key whose private
//! material lives in the Secure Enclave, and presents the cert to `sshd`,
//! which validates it via `TrustedUserCAKeys`. Per-host key distribution is
//! eliminated.
//!
//! Only the minimum set of message types needed for `IdentityAgent`-style
//! pubkey/cert auth is implemented; everything else returns
//! `SSH_AGENT_FAILURE`.

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

/// OpenSSH cert algorithm used by the lockshell user CA.
pub const CERT_ALG_ECDSA_P256: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// Hard cap on agent message size. The spec allows up to 256 KiB; we are
/// stricter to bound memory per connection.
const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Mints a fresh OpenSSH user certificate over `user_pubkey_blob`.
///
/// Implementations wrap a CA signer; each call produces a fresh cert and
/// therefore triggers a Touch ID prompt for the CA key. Lockshell amortises
/// that cost by minting one cert per `REQUEST_IDENTITIES` call (the SSH
/// client typically only does this once per session).
pub trait CertMinter: Send + Sync {
    /// Sign and encode a user certificate. The returned blob is the SSH wire
    /// format certificate body (the value that goes in the agent identity
    /// answer's "key blob" field for a cert algorithm).
    fn mint_user_cert(&self, user_pubkey_blob: &[u8]) -> Result<Vec<u8>>;
}

/// Wiring for the agent: a user signer (private material in SE) and an
/// optional cert minter. When the minter is absent the agent falls back to
/// advertising the raw user public key — useful in tests and for the
/// pre-Phase-3 happy path.
pub struct AgentBackend {
    pub user_signer: Arc<dyn Signer>,
    pub cert_minter: Option<Arc<dyn CertMinter>>,
}

impl AgentBackend {
    pub fn raw_only(user_signer: Arc<dyn Signer>) -> Self {
        Self {
            user_signer,
            cert_minter: None,
        }
    }

    pub fn with_cert_minter(
        user_signer: Arc<dyn Signer>,
        cert_minter: Arc<dyn CertMinter>,
    ) -> Self {
        Self {
            user_signer,
            cert_minter: Some(cert_minter),
        }
    }
}

/// Bind `socket_path`, set tight permissions, and serve agent connections
/// forever. Wraps `signer` in a [`AgentBackend::raw_only`] backend so the
/// agent advertises only the raw public key. Use [`serve_with_backend`] when
/// a CA cert minter should also be wired in.
pub async fn serve(socket_path: PathBuf, signer: Arc<dyn Signer>) -> Result<()> {
    serve_with_backend(socket_path, Arc::new(AgentBackend::raw_only(signer))).await
}

/// Bind `socket_path`, set tight permissions, and serve agent connections
/// forever. The backend is shared across connections via `Arc`.
pub async fn serve_with_backend(socket_path: PathBuf, backend: Arc<AgentBackend>) -> Result<()> {
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
        let backend = backend.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, backend).await {
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

async fn handle_connection(mut stream: UnixStream, backend: Arc<AgentBackend>) -> Result<()> {
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

        let response = handle_message(&msg, backend.as_ref()).unwrap_or_else(|err| {
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

fn handle_message(msg: &[u8], backend: &AgentBackend) -> Result<Vec<u8>> {
    let (&kind, rest) = msg
        .split_first()
        .context("ssh-agent message has no type byte")?;

    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => Ok(build_identities_answer(backend)?),
        SSH_AGENTC_SIGN_REQUEST => build_sign_response(rest, backend),
        _ => Ok(vec![SSH_AGENT_FAILURE]),
    }
}

fn build_identities_answer(backend: &AgentBackend) -> Result<Vec<u8>> {
    let user_blob = backend.user_signer.public_key_blob()?;
    let comment_host = hostname();

    // When a CA is wired, advertise a freshly minted cert. If the mint fails
    // (e.g. user dismissed the Touch ID prompt for the CA key), fall back to
    // advertising the raw user key so the user still has a usable identity —
    // and log the reason so the failure is surfaced in journalctl/Console.
    let (advertised_blob, comment) = match backend.cert_minter.as_ref() {
        Some(minter) => match minter.mint_user_cert(&user_blob) {
            Ok(cert) => (cert, format!("lockshell-user-cert@{comment_host}")),
            Err(err) => {
                eprintln!("lockshelld: cert mint failed, advertising raw key: {err}");
                (user_blob, format!("lockshell-user@{comment_host}"))
            }
        },
        None => (user_blob, format!("lockshell-user@{comment_host}")),
    };

    let mut out = Vec::with_capacity(1 + 4 + 4 + advertised_blob.len() + 4 + comment.len());
    out.push(SSH_AGENT_IDENTITIES_ANSWER);
    lockshell_ssh::wire::encode_uint32(&mut out, 1);
    lockshell_ssh::wire::encode_string(&mut out, &advertised_blob);
    lockshell_ssh::wire::encode_string(&mut out, comment.as_bytes());
    Ok(out)
}

fn build_sign_response(body: &[u8], backend: &AgentBackend) -> Result<Vec<u8>> {
    let (key_blob, rest) = lockshell_ssh::wire::decode_string(body)?;
    let (data, rest) = lockshell_ssh::wire::decode_string(rest)?;
    if rest.len() < 4 {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    // u32 flags trail; we accept and ignore (Phase 2 supports default ECDSA).

    let our_user_blob = backend.user_signer.public_key_blob()?;
    if !blob_addresses_user_key(key_blob, &our_user_blob) {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }

    let signature = backend.user_signer.sign(data, "ssh signature")?;

    let mut out = Vec::with_capacity(1 + 4 + signature.len());
    out.push(SSH_AGENT_SIGN_RESPONSE);
    lockshell_ssh::wire::encode_string(&mut out, &signature);
    Ok(out)
}

/// True if `presented_blob` is either the raw user pubkey blob, or an OpenSSH
/// certificate whose embedded user pubkey matches ours.
fn blob_addresses_user_key(presented_blob: &[u8], our_user_blob: &[u8]) -> bool {
    if presented_blob == our_user_blob {
        return true;
    }
    cert_embeds_user_blob(presented_blob, our_user_blob).unwrap_or(false)
}

/// Parse an `ecdsa-sha2-nistp256-cert-v01@openssh.com` blob and check that
/// the curve name + Q point inside the cert match `our_user_blob` (which is a
/// raw `string("ecdsa-sha2-nistp256") || string(curve) || string(Q)` blob).
///
/// Returns `Ok(false)` for any blob that isn't a recognised cert; only
/// genuine parse errors propagate, and even those are downgraded to `false`
/// at the call site so a malformed blob never panics the agent.
fn cert_embeds_user_blob(cert_blob: &[u8], our_user_blob: &[u8]) -> Result<bool> {
    // cert layout: string(alg) || string(nonce) || string(curve) || string(Q) || ...
    let (alg, rest) = lockshell_ssh::wire::decode_string(cert_blob)?;
    if alg != CERT_ALG_ECDSA_P256.as_bytes() {
        return Ok(false);
    }
    let (_nonce, rest) = lockshell_ssh::wire::decode_string(rest)?;
    let (curve, rest) = lockshell_ssh::wire::decode_string(rest)?;
    let (q, _rest) = lockshell_ssh::wire::decode_string(rest)?;

    // Compare curve+Q against the raw key blob's curve+Q.
    let (raw_alg, raw_rest) = lockshell_ssh::wire::decode_string(our_user_blob)?;
    if raw_alg != b"ecdsa-sha2-nistp256" {
        return Ok(false);
    }
    let (raw_curve, raw_rest) = lockshell_ssh::wire::decode_string(raw_rest)?;
    let (raw_q, _) = lockshell_ssh::wire::decode_string(raw_rest)?;

    Ok(curve == raw_curve && q == raw_q)
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

    /// Wire-format raw ECDSA P-256 blob with the given Q payload.
    fn raw_ecdsa_blob(q: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        lockshell_ssh::wire::encode_string(&mut out, b"ecdsa-sha2-nistp256");
        lockshell_ssh::wire::encode_string(&mut out, b"nistp256");
        lockshell_ssh::wire::encode_string(&mut out, q);
        out
    }

    /// Build a minimal cert blob that embeds `q` so we can assert
    /// `blob_addresses_user_key` accepts it. Only the prefix
    /// (alg, nonce, curve, Q) is exercised here — `_tail` is opaque.
    fn fake_cert_blob(q: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        lockshell_ssh::wire::encode_string(&mut out, CERT_ALG_ECDSA_P256.as_bytes());
        lockshell_ssh::wire::encode_string(&mut out, &[0xAB; 32]); // nonce
        lockshell_ssh::wire::encode_string(&mut out, b"nistp256");
        lockshell_ssh::wire::encode_string(&mut out, q);
        out.extend_from_slice(tail);
        out
    }

    /// CertMinter that returns a deterministic blob built around the user Q.
    struct EchoMinter;
    impl CertMinter for EchoMinter {
        fn mint_user_cert(&self, user_pubkey_blob: &[u8]) -> Result<Vec<u8>> {
            // Extract Q from the raw blob and re-wrap as a fake cert.
            let (_alg, rest) = lockshell_ssh::wire::decode_string(user_pubkey_blob)?;
            let (_curve, rest) = lockshell_ssh::wire::decode_string(rest)?;
            let (q, _) = lockshell_ssh::wire::decode_string(rest)?;
            Ok(fake_cert_blob(q, b""))
        }
    }

    #[test]
    fn unknown_message_returns_failure() {
        let backend = AgentBackend::raw_only(Arc::new(StubSigner {
            blob: vec![1, 2, 3],
        }));
        let resp = handle_message(&[99], &backend).unwrap();
        assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn identities_answer_carries_raw_key_when_no_minter() {
        let blob = raw_ecdsa_blob(&[0x04; 65]);
        let backend = AgentBackend::raw_only(Arc::new(StubSigner { blob: blob.clone() }));
        let resp = build_identities_answer(&backend).unwrap();
        assert_eq!(resp[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&resp[1..5], &[0, 0, 0, 1]);
        let (advertised, rest) = lockshell_ssh::wire::decode_string(&resp[5..]).unwrap();
        assert_eq!(advertised, blob.as_slice());
        let (comment, _) = lockshell_ssh::wire::decode_string(rest).unwrap();
        assert!(std::str::from_utf8(comment)
            .unwrap()
            .starts_with("lockshell-user@"));
    }

    #[test]
    fn identities_answer_advertises_cert_when_minter_present() {
        let q = &[0x04; 65];
        let blob = raw_ecdsa_blob(q);
        let backend = AgentBackend::with_cert_minter(
            Arc::new(StubSigner { blob: blob.clone() }),
            Arc::new(EchoMinter),
        );
        let resp = build_identities_answer(&backend).unwrap();
        let (advertised, rest) = lockshell_ssh::wire::decode_string(&resp[5..]).unwrap();
        let (alg, _) = lockshell_ssh::wire::decode_string(advertised).unwrap();
        assert_eq!(alg, CERT_ALG_ECDSA_P256.as_bytes());
        let (comment, _) = lockshell_ssh::wire::decode_string(rest).unwrap();
        assert!(std::str::from_utf8(comment)
            .unwrap()
            .starts_with("lockshell-user-cert@"));
    }

    #[test]
    fn sign_request_with_matching_raw_blob_returns_signature() {
        let blob = raw_ecdsa_blob(&[0x04; 65]);
        let backend = AgentBackend::raw_only(Arc::new(StubSigner { blob: blob.clone() }));
        let mut body = Vec::new();
        lockshell_ssh::wire::encode_string(&mut body, &blob);
        lockshell_ssh::wire::encode_string(&mut body, b"payload");
        lockshell_ssh::wire::encode_uint32(&mut body, 0);

        let resp = build_sign_response(&body, &backend).unwrap();
        assert_eq!(resp[0], SSH_AGENT_SIGN_RESPONSE);
        let (sig, _) = lockshell_ssh::wire::decode_string(&resp[1..]).unwrap();
        assert_eq!(sig, b"payload");
    }

    #[test]
    fn sign_request_with_cert_blob_referring_to_our_key_returns_signature() {
        let q = vec![0x04u8; 65];
        let blob = raw_ecdsa_blob(&q);
        let backend = AgentBackend::raw_only(Arc::new(StubSigner { blob: blob.clone() }));
        let cert_blob = fake_cert_blob(&q, b"");

        let mut body = Vec::new();
        lockshell_ssh::wire::encode_string(&mut body, &cert_blob);
        lockshell_ssh::wire::encode_string(&mut body, b"payload");
        lockshell_ssh::wire::encode_uint32(&mut body, 0);

        let resp = build_sign_response(&body, &backend).unwrap();
        assert_eq!(resp[0], SSH_AGENT_SIGN_RESPONSE);
    }

    #[test]
    fn sign_request_with_cert_blob_for_other_key_returns_failure() {
        let our_blob = raw_ecdsa_blob(&[0x04; 65]);
        let backend = AgentBackend::raw_only(Arc::new(StubSigner { blob: our_blob }));
        // cert embeds a different Q
        let cert_blob = fake_cert_blob(&[0x05; 65], b"");

        let mut body = Vec::new();
        lockshell_ssh::wire::encode_string(&mut body, &cert_blob);
        lockshell_ssh::wire::encode_string(&mut body, b"payload");
        lockshell_ssh::wire::encode_uint32(&mut body, 0);

        let resp = build_sign_response(&body, &backend).unwrap();
        assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn sign_request_truncated_flags_returns_failure() {
        let blob = raw_ecdsa_blob(&[0x04; 65]);
        let backend = AgentBackend::raw_only(Arc::new(StubSigner { blob: blob.clone() }));
        let mut body = Vec::new();
        lockshell_ssh::wire::encode_string(&mut body, &blob);
        lockshell_ssh::wire::encode_string(&mut body, b"payload");
        // omit flags

        let resp = build_sign_response(&body, &backend).unwrap();
        assert_eq!(resp, vec![SSH_AGENT_FAILURE]);
    }
}
