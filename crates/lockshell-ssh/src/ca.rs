// SPDX-License-Identifier: Apache-2.0

//! Local SSH user certificate authority.
//!
//! Lockshell mints a short-lived OpenSSH user certificate per session. The CA
//! private key is itself an SE-resident ECDSA P-256 key; signing requires
//! Touch ID. Certs are valid for 5 minutes by default (max 60).
//!
//! Wire format reference:
//! <https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys>

use crate::signer::Signer;
use crate::wire;
use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// SSH user certificate algorithm name for ECDSA P-256.
pub const CERT_TYPE_ECDSA_P256: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// `cert_type` value indicating an SSH user certificate.
pub const SSH_CERT_TYPE_USER: u32 = 1;

/// Minimum-validity user cert TTL (seconds). Below this we refuse to mint.
pub const MIN_TTL_SECS: u64 = 30;
/// Maximum-validity user cert TTL (seconds). Above this we refuse to mint.
pub const MAX_TTL_SECS: u64 = 3600;
/// Default user cert TTL (seconds). 5 minutes.
pub const DEFAULT_TTL_SECS: u64 = 300;

const CLOCK_SKEW_BACKDATE_SECS: u64 = 30;
const NONCE_LEN: usize = 32;
const REASON_CERT_SIGN: &str = "lockshell-cert";

/// Trait for a clock source. Production uses [`SystemClock`]; tests inject a
/// fake clock so TTL bounds can be asserted deterministically.
pub trait Clock: Send + Sync {
    fn now_unix_secs(&self) -> u64;
}

/// Real wall-clock implementation.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A lockshell certificate authority.
///
/// The CA's private key sits in the Secure Enclave; this struct holds the
/// signer interface to it and a cached copy of the SSH wire-format CA public
/// key blob (so we don't re-fetch it from the SE on every mint).
pub struct Ca<'a> {
    pub ca_signer: &'a (dyn Signer + Send + Sync),
    pub ca_pubkey_blob: Vec<u8>,
}

/// Per-mint cert parameters.
#[derive(Clone, Copy, Debug)]
pub struct CertOptions<'a> {
    /// SSH principal to embed (typically `$USER`).
    pub principal: &'a str,
    /// Cert validity window in seconds. Must satisfy
    /// [`MIN_TTL_SECS`]`..=`[`MAX_TTL_SECS`].
    pub ttl_secs: u64,
    /// Human-readable cert identifier (audit-log friendly).
    pub key_id: &'a str,
}

impl<'a> Ca<'a> {
    /// Bind a CA signer. Caches the CA's SSH wire-format public key blob.
    pub fn new(ca_signer: &'a (dyn Signer + Send + Sync)) -> Result<Self> {
        if ca_signer.algorithm() != "ecdsa-sha2-nistp256" {
            bail!(
                "ca: only ecdsa-sha2-nistp256 supported, got {}",
                ca_signer.algorithm()
            );
        }
        let ca_pubkey_blob = ca_signer
            .public_key_blob()
            .context("ca: fetch public key blob")?;
        Ok(Self {
            ca_signer,
            ca_pubkey_blob,
        })
    }

    /// Mint a user certificate for `user_pubkey_blob` (an SSH wire-format
    /// `ecdsa-sha2-nistp256` public key). Returns the SSH wire-format
    /// certificate blob.
    pub fn mint_user_cert(
        &self,
        user_pubkey_blob: &[u8],
        opts: CertOptions<'_>,
        clock: &dyn Clock,
    ) -> Result<Vec<u8>> {
        if opts.ttl_secs < MIN_TTL_SECS {
            bail!("ca: ttl {}s below minimum {}s", opts.ttl_secs, MIN_TTL_SECS);
        }
        if opts.ttl_secs > MAX_TTL_SECS {
            bail!("ca: ttl {}s above maximum {}s", opts.ttl_secs, MAX_TTL_SECS);
        }
        if opts.principal.is_empty() {
            bail!("ca: principal must be non-empty");
        }
        if opts.key_id.is_empty() {
            bail!("ca: key_id must be non-empty");
        }

        let (curve, point) =
            decode_ecdsa_p256_pubkey(user_pubkey_blob).context("ca: decode user pubkey")?;

        let now = clock.now_unix_secs();
        let valid_after = now.saturating_sub(CLOCK_SKEW_BACKDATE_SECS);
        let valid_before = now
            .checked_add(opts.ttl_secs)
            .ok_or_else(|| anyhow!("ca: valid_before overflow"))?;
        let serial = now;

        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Cert body up to and including signature_key. The signature is
        // computed over these bytes and then appended.
        let mut body = Vec::with_capacity(512);
        wire::encode_string(&mut body, CERT_TYPE_ECDSA_P256.as_bytes());
        wire::encode_string(&mut body, &nonce);
        wire::encode_string(&mut body, curve);
        wire::encode_string(&mut body, point);
        body.extend_from_slice(&serial.to_be_bytes());
        body.extend_from_slice(&SSH_CERT_TYPE_USER.to_be_bytes());
        wire::encode_string(&mut body, opts.key_id.as_bytes());
        wire::encode_string_list(&mut body, &[opts.principal.as_bytes()]);
        body.extend_from_slice(&valid_after.to_be_bytes());
        body.extend_from_slice(&valid_before.to_be_bytes());
        // critical_options: empty.
        wire::encode_string(&mut body, &[]);
        // extensions: { permit-pty: "" }. No X11, port, or agent forwarding.
        let mut exts = Vec::with_capacity(32);
        wire::encode_string(&mut exts, b"permit-pty");
        wire::encode_string(&mut exts, &[]);
        wire::encode_string(&mut body, &exts);
        // reserved.
        wire::encode_string(&mut body, &[]);
        // signature_key: the CA's SSH wire-format public key blob, wrapped.
        wire::encode_string(&mut body, &self.ca_pubkey_blob);

        let signature = self
            .ca_signer
            .sign(&body, REASON_CERT_SIGN)
            .context("ca: sign cert body")?;
        wire::encode_string(&mut body, &signature);

        Ok(body)
    }
}

/// Strip the SSH `ecdsa-sha2-nistp256` algorithm prefix off `pubkey_blob` and
/// return `(curve_name, Q)` slices borrowed from `pubkey_blob`.
fn decode_ecdsa_p256_pubkey(pubkey_blob: &[u8]) -> Result<(&[u8], &[u8])> {
    let (alg, rest) = wire::decode_string(pubkey_blob).context("alg")?;
    if alg != b"ecdsa-sha2-nistp256" {
        bail!(
            "user pubkey alg = {:?}, expected ecdsa-sha2-nistp256",
            String::from_utf8_lossy(alg)
        );
    }
    let (curve, rest) = wire::decode_string(rest).context("curve")?;
    if curve != b"nistp256" {
        bail!(
            "user pubkey curve = {:?}, expected nistp256",
            String::from_utf8_lossy(curve)
        );
    }
    let (point, _trailing) = wire::decode_string(rest).context("Q")?;
    if point.len() != 65 || point[0] != 0x04 {
        bail!(
            "user pubkey point malformed: len={}, first={:#x}",
            point.len(),
            point.first().copied().unwrap_or(0)
        );
    }
    Ok((curve, point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair};
    use std::sync::Mutex;

    /// Test signer backed by a real ring ECDSA P-256 keypair. The wire-format
    /// signature output matches what the SE signer produces (alg + body of
    /// mpint(r) || mpint(s)).
    struct RingSigner {
        // EcdsaKeyPair is Send+Sync but we wrap in Mutex defensively for tests.
        keypair: Mutex<EcdsaKeyPair>,
        rng: SystemRandom,
        ssh_pubkey: Vec<u8>,
        raw_pub: Vec<u8>,
    }

    impl RingSigner {
        fn new() -> Self {
            let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            let keypair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap();
            let raw_pub = keypair.public_key().as_ref().to_vec();
            assert_eq!(raw_pub.len(), 65);
            assert_eq!(raw_pub[0], 0x04);
            let mut blob = Vec::new();
            wire::encode_string(&mut blob, b"ecdsa-sha2-nistp256");
            wire::encode_string(&mut blob, b"nistp256");
            wire::encode_string(&mut blob, &raw_pub);
            Self {
                keypair: Mutex::new(keypair),
                rng,
                ssh_pubkey: blob,
                raw_pub,
            }
        }
    }

    impl Signer for RingSigner {
        fn algorithm(&self) -> &'static str {
            "ecdsa-sha2-nistp256"
        }

        fn public_key_blob(&self) -> Result<Vec<u8>> {
            Ok(self.ssh_pubkey.clone())
        }

        fn sign(&self, data: &[u8], _reason: &str) -> Result<Vec<u8>> {
            let kp = self.keypair.lock().expect("ring keypair poisoned");
            let sig = kp
                .sign(&self.rng, data)
                .map_err(|_| anyhow!("ring sign failed"))?;
            let raw = sig.as_ref();
            // FIXED variant: 64 bytes = r(32) || s(32).
            assert_eq!(raw.len(), 64);
            let r = &raw[..32];
            let s = &raw[32..];
            let mut sig_body = Vec::with_capacity(72);
            wire::encode_mpint(&mut sig_body, r);
            wire::encode_mpint(&mut sig_body, s);
            let mut out = Vec::with_capacity(96);
            wire::encode_string(&mut out, b"ecdsa-sha2-nistp256");
            wire::encode_string(&mut out, &sig_body);
            Ok(out)
        }
    }

    /// Deterministic clock for TTL assertions.
    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_unix_secs(&self) -> u64 {
            self.0
        }
    }

    /// Decoded cert fields used by tests.
    struct DecodedCert<'a> {
        nonce: &'a [u8],
        serial: u64,
        cert_type: u32,
        key_id: Vec<u8>,
        principals: Vec<Vec<u8>>,
        valid_after: u64,
        valid_before: u64,
        critical_options: &'a [u8],
        extensions: Vec<(Vec<u8>, Vec<u8>)>,
        signature_key: &'a [u8],
        signed_body: Vec<u8>,
        signature: &'a [u8],
    }

    fn read_u64(buf: &[u8]) -> (u64, &[u8]) {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&buf[..8]);
        (u64::from_be_bytes(arr), &buf[8..])
    }

    fn read_u32(buf: &[u8]) -> (u32, &[u8]) {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&buf[..4]);
        (u32::from_be_bytes(arr), &buf[4..])
    }

    fn decode_options(buf: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let mut cur = buf;
        while !cur.is_empty() {
            let (name, rest) = wire::decode_string(cur).unwrap();
            let (data, rest) = wire::decode_string(rest).unwrap();
            out.push((name.to_vec(), data.to_vec()));
            cur = rest;
        }
        out
    }

    fn decode_principals(buf: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut cur = buf;
        while !cur.is_empty() {
            let (p, rest) = wire::decode_string(cur).unwrap();
            out.push(p.to_vec());
            cur = rest;
        }
        out
    }

    fn decode_cert(cert: &[u8]) -> DecodedCert<'_> {
        let total_len = cert.len();
        let (alg, rest) = wire::decode_string(cert).unwrap();
        assert_eq!(alg, CERT_TYPE_ECDSA_P256.as_bytes());
        let (nonce, rest) = wire::decode_string(rest).unwrap();
        let (curve, rest) = wire::decode_string(rest).unwrap();
        assert_eq!(curve, b"nistp256");
        let (_q, rest) = wire::decode_string(rest).unwrap();
        let (serial, rest) = read_u64(rest);
        let (cert_type, rest) = read_u32(rest);
        let (key_id_b, rest) = wire::decode_string(rest).unwrap();
        let (principals_b, rest) = wire::decode_string(rest).unwrap();
        let (valid_after, rest) = read_u64(rest);
        let (valid_before, rest) = read_u64(rest);
        let (critical, rest) = wire::decode_string(rest).unwrap();
        let (extensions_b, rest) = wire::decode_string(rest).unwrap();
        let (_reserved, rest) = wire::decode_string(rest).unwrap();
        let (sig_key, rest_after_sigkey) = wire::decode_string(rest).unwrap();

        // bytes signed by the CA = everything from cert start up to and
        // including signature_key (i.e. excluding the trailing signature field).
        let signed_len = total_len - rest_after_sigkey.len();
        let signed_body = cert[..signed_len].to_vec();

        let (sig, _tail) = wire::decode_string(rest_after_sigkey).unwrap();

        DecodedCert {
            nonce,
            serial,
            cert_type,
            key_id: key_id_b.to_vec(),
            principals: decode_principals(principals_b),
            valid_after,
            valid_before,
            critical_options: critical,
            extensions: decode_options(extensions_b),
            signature_key: sig_key,
            signed_body,
            signature: sig,
        }
    }

    fn build_ca_and_user() -> (RingSigner, RingSigner) {
        (RingSigner::new(), RingSigner::new())
    }

    #[test]
    fn mint_within_ttl_window() {
        let (ca_signer, user_signer) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let user_pub = user_signer.public_key_blob().unwrap();
        let clock = FixedClock(1000);
        let opts = CertOptions {
            principal: "alice",
            ttl_secs: 300,
            key_id: "lockshell-alice-1000",
        };
        let cert = ca.mint_user_cert(&user_pub, opts, &clock).unwrap();
        let dec = decode_cert(&cert);
        assert_eq!(dec.cert_type, SSH_CERT_TYPE_USER);
        assert_eq!(dec.serial, 1000);
        assert_eq!(dec.valid_after, 970, "30s skew backdate");
        assert_eq!(dec.valid_before, 1300);
        assert_eq!(dec.principals.len(), 1);
        assert_eq!(dec.principals[0], b"alice");
        assert_eq!(dec.critical_options, b"");
    }

    #[test]
    fn ttl_below_minimum_rejected() {
        let (ca_signer, user_signer) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let user_pub = user_signer.public_key_blob().unwrap();
        let err = ca
            .mint_user_cert(
                &user_pub,
                CertOptions {
                    principal: "alice",
                    ttl_secs: 10,
                    key_id: "k",
                },
                &FixedClock(1000),
            )
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("below minimum"), "msg={msg}");
    }

    #[test]
    fn ttl_above_maximum_rejected() {
        let (ca_signer, user_signer) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let user_pub = user_signer.public_key_blob().unwrap();
        let err = ca
            .mint_user_cert(
                &user_pub,
                CertOptions {
                    principal: "alice",
                    ttl_secs: 3601,
                    key_id: "k",
                },
                &FixedClock(1000),
            )
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("above maximum"), "msg={msg}");
    }

    #[test]
    fn key_id_includes_principal() {
        let (ca_signer, user_signer) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let user_pub = user_signer.public_key_blob().unwrap();
        let key_id = "lockshell-bob-42";
        let cert = ca
            .mint_user_cert(
                &user_pub,
                CertOptions {
                    principal: "bob",
                    ttl_secs: DEFAULT_TTL_SECS,
                    key_id,
                },
                &FixedClock(42),
            )
            .unwrap();
        let dec = decode_cert(&cert);
        assert_eq!(dec.key_id, key_id.as_bytes());
        assert!(
            String::from_utf8_lossy(&dec.key_id).contains("bob"),
            "key_id should embed principal"
        );
    }

    #[test]
    fn permit_pty_only() {
        let (ca_signer, user_signer) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let user_pub = user_signer.public_key_blob().unwrap();
        let cert = ca
            .mint_user_cert(
                &user_pub,
                CertOptions {
                    principal: "alice",
                    ttl_secs: DEFAULT_TTL_SECS,
                    key_id: "k",
                },
                &FixedClock(1000),
            )
            .unwrap();
        let dec = decode_cert(&cert);
        assert_eq!(dec.extensions.len(), 1, "exactly one extension");
        assert_eq!(dec.extensions[0].0, b"permit-pty");
        assert!(dec.extensions[0].1.is_empty(), "permit-pty data is empty");
        for (name, _) in &dec.extensions {
            let n = String::from_utf8_lossy(name);
            assert!(
                !n.contains("X11") && !n.contains("port-forward") && !n.contains("agent"),
                "forbidden extension: {n}"
            );
        }
    }

    #[test]
    fn nonce_unique() {
        let (ca_signer, user_signer) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let user_pub = user_signer.public_key_blob().unwrap();
        let opts = CertOptions {
            principal: "alice",
            ttl_secs: DEFAULT_TTL_SECS,
            key_id: "k",
        };
        let c1 = ca
            .mint_user_cert(&user_pub, opts, &FixedClock(1000))
            .unwrap();
        let c2 = ca
            .mint_user_cert(&user_pub, opts, &FixedClock(1000))
            .unwrap();
        let d1 = decode_cert(&c1);
        let d2 = decode_cert(&c2);
        assert_eq!(d1.nonce.len(), 32);
        assert_eq!(d2.nonce.len(), 32);
        assert_ne!(d1.nonce, d2.nonce, "nonce must differ between mints");
    }

    #[test]
    fn signature_verifies() {
        let (ca_signer, user_signer) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let user_pub = user_signer.public_key_blob().unwrap();
        let cert = ca
            .mint_user_cert(
                &user_pub,
                CertOptions {
                    principal: "alice",
                    ttl_secs: DEFAULT_TTL_SECS,
                    key_id: "k",
                },
                &FixedClock(1000),
            )
            .unwrap();
        let dec = decode_cert(&cert);

        // signature_key field embeds the CA's SSH wire-format public key blob.
        // Strip alg + curve, recover Q.
        let (alg, rest) = wire::decode_string(dec.signature_key).unwrap();
        assert_eq!(alg, b"ecdsa-sha2-nistp256");
        let (curve, rest) = wire::decode_string(rest).unwrap();
        assert_eq!(curve, b"nistp256");
        let (q, _) = wire::decode_string(rest).unwrap();
        assert_eq!(q, ca_signer.raw_pub.as_slice());

        // Decode SSH signature blob: alg + body(mpint r || mpint s) -> 64 raw bytes.
        let (sig_alg, sig_rest) = wire::decode_string(dec.signature).unwrap();
        assert_eq!(sig_alg, b"ecdsa-sha2-nistp256");
        let (sig_body, _) = wire::decode_string(sig_rest).unwrap();
        let (r_bytes, rest) = wire::decode_string(sig_body).unwrap();
        let (s_bytes, _) = wire::decode_string(rest).unwrap();
        let r = pad_to_32(r_bytes);
        let s = pad_to_32(s_bytes);
        let mut fixed = [0u8; 64];
        fixed[..32].copy_from_slice(&r);
        fixed[32..].copy_from_slice(&s);

        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            &ca_signer.raw_pub,
        );
        pk.verify(&dec.signed_body, &fixed)
            .expect("CA signature must verify");

        assert_eq!(dec.principals[0], b"alice");
    }

    fn pad_to_32(input: &[u8]) -> [u8; 32] {
        let trimmed = if input.len() > 32 && input[0] == 0 {
            &input[input.len() - 32..]
        } else {
            input
        };
        let mut out = [0u8; 32];
        out[32 - trimmed.len()..].copy_from_slice(trimmed);
        out
    }

    #[test]
    fn rejects_non_ecdsa_ca() {
        struct EdMock;
        impl Signer for EdMock {
            fn algorithm(&self) -> &'static str {
                "ssh-ed25519"
            }
            fn public_key_blob(&self) -> Result<Vec<u8>> {
                Ok(vec![])
            }
            fn sign(&self, _: &[u8], _: &str) -> Result<Vec<u8>> {
                Ok(vec![])
            }
        }
        let s = EdMock;
        let err = match Ca::new(&s) {
            Ok(_) => panic!("expected ed25519 CA to be rejected"),
            Err(e) => e,
        };
        assert!(format!("{err:#}").contains("ecdsa-sha2-nistp256"));
    }

    #[test]
    fn rejects_malformed_user_pubkey() {
        let (ca_signer, _user) = build_ca_and_user();
        let ca = Ca::new(&ca_signer).unwrap();
        let bogus = b"not a real ssh pubkey";
        let err = ca
            .mint_user_cert(
                bogus,
                CertOptions {
                    principal: "alice",
                    ttl_secs: DEFAULT_TTL_SECS,
                    key_id: "k",
                },
                &FixedClock(1000),
            )
            .unwrap_err();
        assert!(!format!("{err:#}").is_empty());
    }
}
