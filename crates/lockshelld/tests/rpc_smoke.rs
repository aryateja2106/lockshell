// SPDX-License-Identifier: Apache-2.0

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[tokio::test]
async fn vault_status_smoke() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let socket = tmp.path().join("control.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lockshelld"))
        .arg("--foreground")
        .arg("--socket")
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let output = child.wait_with_output()?;
            panic!(
                "socket {} did not appear in 5s. stderr: {}",
                socket.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let stream = UnixStream::connect(&socket).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"vault.status\"}\n";
    write_half.write_all(request).await?;
    write_half.flush().await?;

    let line = tokio::time::timeout(Duration::from_secs(5), reader.next_line())
        .await?
        .map_err(anyhow::Error::from)?
        .ok_or_else(|| anyhow::anyhow!("daemon closed without response"))?;

    let value: serde_json::Value = serde_json::from_str(&line)?;
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["id"], 1);
    assert!(
        value["error"].is_null(),
        "unexpected error: {}",
        value["error"]
    );
    assert_eq!(value["result"]["status"], "NoSession");

    drop(write_half);
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}
