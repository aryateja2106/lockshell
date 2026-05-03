// SPDX-License-Identifier: Apache-2.0

//! End-to-end smoke test for the OpenSSH agent protocol server. Spins up
//! `ssh_agent::serve` against a `MockSigner` on a tempdir socket, then
//! exercises REQUEST_IDENTITIES (11) and SIGN_REQUEST (13).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[path = "common/mock_signer.rs"]
mod mock_signer;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

#[tokio::test]
async fn request_identities_returns_one_key() -> Result<()> {
    let (sock, signer) = spawn_agent().await?;
    let mut stream = connect_with_retry(&sock).await?;

    write_message(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).await?;
    let resp = read_message(&mut stream).await?;

    assert_eq!(resp[0], SSH_AGENT_IDENTITIES_ANSWER);
    let count = u32::from_be_bytes(resp[1..5].try_into().unwrap());
    assert_eq!(count, 1);

    let (blob, rest) = decode_string(&resp[5..]);
    assert_eq!(blob, signer.public_blob());

    let (comment, _) = decode_string(rest);
    let comment_str = std::str::from_utf8(comment)?;
    assert!(
        comment_str.starts_with("lockshell-user@"),
        "unexpected comment: {comment_str}"
    );

    Ok(())
}

#[tokio::test]
async fn sign_request_round_trip() -> Result<()> {
    let (sock, signer) = spawn_agent().await?;
    let mut stream = connect_with_retry(&sock).await?;

    let payload = b"hello-from-smoke-test";
    let mut body = Vec::new();
    body.push(SSH_AGENTC_SIGN_REQUEST);
    encode_string(&mut body, signer.public_blob());
    encode_string(&mut body, payload);
    body.extend(&0u32.to_be_bytes());

    write_message(&mut stream, &body).await?;
    let resp = read_message(&mut stream).await?;

    assert_eq!(resp[0], SSH_AGENT_SIGN_RESPONSE);
    let (signature, _) = decode_string(&resp[1..]);

    // Signature wire format: string("ecdsa-sha2-nistp256") || string(blob)
    let (alg, rest) = decode_string(signature);
    assert_eq!(alg, b"ecdsa-sha2-nistp256");
    let (rs_blob, _) = decode_string(rest);
    assert!(!rs_blob.is_empty(), "signature payload must be non-empty");

    Ok(())
}

#[tokio::test]
async fn unknown_message_yields_failure_byte() -> Result<()> {
    let (sock, _signer) = spawn_agent().await?;
    let mut stream = connect_with_retry(&sock).await?;

    write_message(&mut stream, &[99]).await?;
    let resp = read_message(&mut stream).await?;
    assert_eq!(resp, vec![5u8], "expected SSH_AGENT_FAILURE");
    Ok(())
}

async fn spawn_agent() -> Result<(PathBuf, Arc<mock_signer::MockSigner>)> {
    let tmp = tempfile::tempdir()?;
    let sock = tmp.path().join("agent.sock");
    let sock_clone = sock.clone();

    let signer = Arc::new(mock_signer::MockSigner::new());
    let signer_for_serve: Arc<dyn lockshell_ssh::Signer> = signer.clone();

    tokio::spawn(async move {
        let _ = lockshelld::ssh_agent::serve(sock_clone, signer_for_serve).await;
    });

    // Keep tempdir alive for the duration of the test.
    Box::leak(Box::new(tmp));

    Ok((sock, signer))
}

async fn connect_with_retry(path: &PathBuf) -> Result<UnixStream> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(path).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                if std::time::Instant::now() > deadline {
                    return Err(e.into());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
}

async fn write_message(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_message(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

fn encode_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend(&(data.len() as u32).to_be_bytes());
    out.extend(data);
}

fn decode_string(buf: &[u8]) -> (&[u8], &[u8]) {
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    (&buf[4..4 + len], &buf[4 + len..])
}
