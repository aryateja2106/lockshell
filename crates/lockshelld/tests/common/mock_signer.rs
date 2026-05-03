// SPDX-License-Identifier: Apache-2.0

//! Deterministic in-memory signer for ssh-agent integration tests. Mirrors the
//! shape of a real ECDSA P-256 SSH key without performing any cryptography:
//! the public-key blob is well-formed enough for parsers to accept, and
//! `sign` deterministically echoes a tagged copy of the input so wire-format
//! assertions stay tight.

use anyhow::Result;
use lockshell_ssh::Signer;

pub struct MockSigner {
    blob: Vec<u8>,
}

impl MockSigner {
    pub fn new() -> Self {
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend(std::iter::repeat(0x11u8).take(32));
        point.extend(std::iter::repeat(0x22u8).take(32));

        let mut blob = Vec::new();
        lockshell_ssh::wire::encode_string(&mut blob, b"ecdsa-sha2-nistp256");
        lockshell_ssh::wire::encode_string(&mut blob, b"nistp256");
        lockshell_ssh::wire::encode_string(&mut blob, &point);

        Self { blob }
    }

    pub fn public_blob(&self) -> &[u8] {
        &self.blob
    }
}

impl Signer for MockSigner {
    fn algorithm(&self) -> &'static str {
        "ecdsa-sha2-nistp256"
    }

    fn public_key_blob(&self) -> Result<Vec<u8>> {
        Ok(self.blob.clone())
    }

    fn sign(&self, data: &[u8], _reason: &str) -> Result<Vec<u8>> {
        let mut rs = Vec::new();
        lockshell_ssh::wire::encode_mpint(&mut rs, &derive_scalar(data, 0xAA));
        lockshell_ssh::wire::encode_mpint(&mut rs, &derive_scalar(data, 0xBB));

        let mut out = Vec::new();
        lockshell_ssh::wire::encode_string(&mut out, b"ecdsa-sha2-nistp256");
        lockshell_ssh::wire::encode_string(&mut out, &rs);
        Ok(out)
    }
}

fn derive_scalar(data: &[u8], tag: u8) -> Vec<u8> {
    let mut acc = [tag; 32];
    for (i, byte) in data.iter().enumerate() {
        acc[i % 32] ^= byte;
    }
    acc[0] &= 0x7f;
    acc.to_vec()
}
