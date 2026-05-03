// SPDX-License-Identifier: Apache-2.0

//! In-process software ECDSA P-256 signer.
//!
//! **Stress-mode / CI use only.** This signer holds the private key in
//! ordinary heap memory — anyone with code-execution as the daemon's uid
//! can read or copy it. The Secure Enclave signer in `secure_enclave.rs`
//! is the production path. The software signer exists so the stress-test
//! rig can run end-to-end on machines where the SEP is not reachable
//! (Intel Macs, virtualised hosts, non-Aqua subshells inside cmux/tmux).
//!
//! The wire output is byte-identical to the SE signer (same algorithm
//! string, same SSH wire format), so the rest of the stack (cert minting,
//! ssh-agent, ssh client) cannot tell them apart.

use anyhow::{Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::signer::Signer;
use crate::wire;

/// Ephemeral ECDSA P-256 keypair signing in software.
///
/// Drop the value to drop the key. Construction is the only way to obtain
/// the private bytes, so callers wanting persistence must own the lifecycle
/// explicitly — there is no on-disk path by design.
pub struct SoftwareEcdsaSigner {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl SoftwareEcdsaSigner {
    /// Create a fresh ephemeral ECDSA P-256 keypair using the OS RNG.
    pub fn generate() -> Result<Self> {
        let (signer, _pkcs8) = Self::generate_pkcs8()?;
        Ok(signer)
    }

    /// Generate a fresh keypair and return both the signer and the PKCS8
    /// DER bytes so the caller can persist them. The two views point at
    /// the same private key — saving the PKCS8 bytes lets a future
    /// process load an identical signer via [`Self::from_pkcs8`].
    pub fn generate_pkcs8() -> Result<(Self, Vec<u8>)> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("ECDSA P-256 keygen failed: {e:?}"))?;
        let bytes = pkcs8.as_ref().to_vec();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes, &rng)
            .map_err(|e| anyhow::anyhow!("loading freshly-generated PKCS8: {e:?}"))?;
        Ok((Self { key_pair, rng }, bytes))
    }

    /// Load a previously-persisted keypair from PKCS8 DER bytes. Pair this
    /// with [`Self::generate_pkcs8`] for cross-process key sharing
    /// (stress-rig daemon ↔ CLI).
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, bytes, &rng)
            .map_err(|e| anyhow::anyhow!("from_pkcs8 failed: {e:?}"))?;
        Ok(Self { key_pair, rng })
    }
}

impl Signer for SoftwareEcdsaSigner {
    fn algorithm(&self) -> &'static str {
        "ecdsa-sha2-nistp256"
    }

    fn public_key_blob(&self) -> Result<Vec<u8>> {
        // ring's `public_key().as_ref()` returns the SEC1 uncompressed point
        // (0x04 || X(32) || Y(32)) — exactly what the SSH wire format wants
        // as the body of the `point` field.
        let point = self.key_pair.public_key().as_ref();
        if point.len() != 65 || point[0] != 0x04 {
            anyhow::bail!(
                "unexpected SEC1 layout from ring: len={}, first={:#x}",
                point.len(),
                point.first().copied().unwrap_or(0)
            );
        }

        let mut blob = Vec::with_capacity(128);
        wire::encode_string(&mut blob, b"ecdsa-sha2-nistp256");
        wire::encode_string(&mut blob, b"nistp256");
        wire::encode_string(&mut blob, point);
        Ok(blob)
    }

    fn sign(&self, data: &[u8], _reason: &str) -> Result<Vec<u8>> {
        // ring's FIXED signing returns r||s as 64 raw bytes. SSH wants
        // each as a length-prefixed mpint inside an inner string body.
        let sig = self
            .key_pair
            .sign(&self.rng, data)
            .map_err(|e| anyhow::anyhow!("ring sign failed: {e:?}"))
            .context("software ECDSA P-256 sign")?;
        let raw = sig.as_ref();
        if raw.len() != 64 {
            anyhow::bail!(
                "expected 64-byte fixed ECDSA sig from ring, got {}",
                raw.len()
            );
        }
        let r = strip_leading_zeros(&raw[..32]);
        let s = strip_leading_zeros(&raw[32..]);

        let mut sig_body = Vec::with_capacity(80);
        wire::encode_mpint(&mut sig_body, r);
        wire::encode_mpint(&mut sig_body, s);

        let mut out = Vec::with_capacity(96);
        wire::encode_string(&mut out, b"ecdsa-sha2-nistp256");
        wire::encode_string(&mut out, &sig_body);
        Ok(out)
    }
}

/// Drop leading zero bytes so `encode_mpint` can re-add the sign byte
/// only when the high bit of the magnitude is set. This matches how the
/// SE path normalises ring-style fixed-width integers.
fn strip_leading_zeros(input: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < input.len() && input[i] == 0 {
        i += 1;
    }
    &input[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_metadata_matches_se_path() {
        let s = SoftwareEcdsaSigner::generate().expect("software signer generates");
        assert_eq!(s.algorithm(), "ecdsa-sha2-nistp256");
        let blob = s.public_key_blob().expect("public_key_blob");

        // Decode the SSH wire format and check we got the same shape as SE.
        let (alg, rest) = wire::decode_string(&blob).unwrap();
        assert_eq!(alg, b"ecdsa-sha2-nistp256");
        let (curve, rest) = wire::decode_string(rest).unwrap();
        assert_eq!(curve, b"nistp256");
        let (point, _) = wire::decode_string(rest).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
    }

    #[test]
    fn sign_roundtrip_verifies_with_ring() {
        let s = SoftwareEcdsaSigner::generate().unwrap();
        let blob = s.public_key_blob().unwrap();

        // Re-extract the SEC1 point we encoded.
        let (_alg, rest) = wire::decode_string(&blob).unwrap();
        let (_curve, rest) = wire::decode_string(rest).unwrap();
        let (point, _) = wire::decode_string(rest).unwrap();

        let payload = b"lockshell stress-rig sample";
        let ssh_sig = s.sign(payload, "test").unwrap();

        // Parse SSH wire signature: outer string alg, outer string body,
        // body = mpint r, mpint s. Reassemble fixed 64-byte ring signature.
        let (sig_alg, sig_rest) = wire::decode_string(&ssh_sig).unwrap();
        assert_eq!(sig_alg, b"ecdsa-sha2-nistp256");
        let (sig_body, _) = wire::decode_string(sig_rest).unwrap();
        let (r_bytes, rest) = wire::decode_string(sig_body).unwrap();
        let (s_bytes, _) = wire::decode_string(rest).unwrap();

        let r = pad32(r_bytes);
        let s_v = pad32(s_bytes);
        let mut fixed = [0u8; 64];
        fixed[..32].copy_from_slice(&r);
        fixed[32..].copy_from_slice(&s_v);

        let alg = &ring::signature::ECDSA_P256_SHA256_FIXED;
        let pk = ring::signature::UnparsedPublicKey::new(alg, point);
        pk.verify(payload, &fixed)
            .expect("ring verifies our software-signer signature");
    }

    fn pad32(input: &[u8]) -> [u8; 32] {
        let trimmed = if input.len() > 32 && input[0] == 0 {
            &input[input.len() - 32..]
        } else {
            input
        };
        let mut out = [0u8; 32];
        out[32 - trimmed.len()..].copy_from_slice(trimmed);
        out
    }
}
