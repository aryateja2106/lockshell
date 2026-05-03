// SPDX-License-Identifier: Apache-2.0

//! macOS Secure Enclave-backed signer.
//!
//! The private key never leaves the SEP. Each [`Signer::sign`] call triggers a
//! Touch ID consent prompt because the key's access control includes
//! `kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage`.
//!
//! Variant `load_or_create_no_biometric` omits the biometric flag so unit
//! tests and the stress-test rig run headless. The bio variant is the one
//! used at runtime; the no-bio variant is documented as unsafe-for-production.

#![cfg(target_os = "macos")]

use anyhow::{anyhow, bail, Context, Result};
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, SecAccessControlCreateWithFlags,
};
use security_framework_sys::base::{SecAccessControlRef, SecKeyRef};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
    kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel,
    kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecMatchLimit,
    kSecPrivateKeyAttrs, kSecReturnRef,
};
use security_framework_sys::key::{
    kSecKeyAlgorithmECDSASignatureMessageX962SHA256, SecKeyCopyExternalRepresentation,
    SecKeyCopyPublicKey, SecKeyCreateRandomKey, SecKeyCreateSignature,
};
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete};

// security-framework-sys 2.17 doesn't re-export these constants. Bind them
// directly from Security.framework (already linked transitively).
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
}

use crate::signer::Signer;
use crate::wire;

const ERR_SEC_SUCCESS: OSStatus = 0;
const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;

/// Owns a non-extractable Secure Enclave key handle.
pub struct SecureEnclaveSigner {
    key: SecKeyRef,
    label: String,
}

unsafe impl Send for SecureEnclaveSigner {}
unsafe impl Sync for SecureEnclaveSigner {}

impl Drop for SecureEnclaveSigner {
    fn drop(&mut self) {
        unsafe {
            if !self.key.is_null() {
                CFRelease(self.key as CFTypeRef);
            }
        }
    }
}

impl SecureEnclaveSigner {
    /// Look up an SE key by `label`; create a biometric-gated one if absent.
    pub fn load_or_create(label: &str) -> Result<Self> {
        if let Some(existing) = lookup_key(label)? {
            return Ok(Self {
                key: existing,
                label: label.to_string(),
            });
        }
        let acl = create_access_control(true)?;
        let key = create_se_key(label, acl)?;
        Ok(Self {
            key,
            label: label.to_string(),
        })
    }

    /// **DANGER — stress / CI only.** Constructs an SE-backed key WITHOUT a
    /// biometric ACL gate. Every signing operation succeeds without a Touch ID
    /// prompt. The key is still non-extractable inside the SEP, so it cannot
    /// leak off the device, but anyone with code-execution as the daemon's
    /// uid can use it to authenticate.
    ///
    /// Used by:
    /// - the unit test suite (`load_or_create_no_biometric("lockshell-test-…")`)
    /// - the stress-test rig (gated on `LOCKSHELL_STRESS_MODE=1` plus the
    ///   distinct `lockshell-stress-*` labels via [`crate::labels`]).
    ///
    /// Never call with the production `lockshell-user` / `lockshell-ca`
    /// labels. The `lockshell-stress-*` labels must NOT be reused for any
    /// real workflow — they live alongside production keys in the keychain
    /// only as a known-unsafe escape hatch for benchmarks.
    pub fn load_or_create_no_biometric(label: &str) -> Result<Self> {
        if let Some(existing) = lookup_key(label)? {
            return Ok(Self {
                key: existing,
                label: label.to_string(),
            });
        }
        let acl = create_access_control(false)?;
        let key = create_se_key(label, acl)?;
        Ok(Self {
            key,
            label: label.to_string(),
        })
    }

    /// Remove an SE key entry by `label`. Used by tests to clean up.
    pub fn delete(label: &str) -> Result<()> {
        let tag = CFData::from_buffer(label.as_bytes());
        let class_key = unsafe { CFType::wrap_under_get_rule(kSecClassKey as CFTypeRef) };
        let pairs: Vec<(CFType, CFType)> = vec![
            (
                unsafe { CFType::wrap_under_get_rule(kSecClass as CFTypeRef) },
                class_key,
            ),
            (
                unsafe { CFType::wrap_under_get_rule(kSecAttrApplicationTag as CFTypeRef) },
                tag.into_CFType(),
            ),
        ];
        let query = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef() as CFDictionaryRef) };
        if status != ERR_SEC_SUCCESS && status != ERR_SEC_ITEM_NOT_FOUND {
            bail!("SecItemDelete failed: OSStatus {status}");
        }
        Ok(())
    }

    /// Diagnostic accessor used by tests / debug logging.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl Signer for SecureEnclaveSigner {
    fn algorithm(&self) -> &'static str {
        "ecdsa-sha2-nistp256"
    }

    fn public_key_blob(&self) -> Result<Vec<u8>> {
        let pub_key = unsafe { SecKeyCopyPublicKey(self.key) };
        if pub_key.is_null() {
            bail!("SecKeyCopyPublicKey returned null");
        }
        let mut error: CFErrorRef = std::ptr::null_mut();
        let data_ref = unsafe { SecKeyCopyExternalRepresentation(pub_key, &mut error) };
        unsafe { CFRelease(pub_key as CFTypeRef) };
        if data_ref.is_null() {
            if !error.is_null() {
                unsafe { CFRelease(error as CFTypeRef) };
            }
            bail!("SecKeyCopyExternalRepresentation returned null");
        }
        let cf_data: CFData = unsafe { CFData::wrap_under_create_rule(data_ref) };
        let raw = cf_data.bytes().to_vec();
        if raw.len() != 65 || raw[0] != 0x04 {
            bail!("unexpected EC public key SEC1 layout: len={}", raw.len());
        }
        let mut point = Vec::with_capacity(65);
        point.extend_from_slice(&raw);

        let mut blob = Vec::with_capacity(128);
        wire::encode_string(&mut blob, b"ecdsa-sha2-nistp256");
        wire::encode_string(&mut blob, b"nistp256");
        wire::encode_string(&mut blob, &point);
        Ok(blob)
    }

    fn sign(&self, data: &[u8], _reason: &str) -> Result<Vec<u8>> {
        let cf_data = CFData::from_buffer(data);
        let mut error: CFErrorRef = std::ptr::null_mut();
        let sig_ref = unsafe {
            SecKeyCreateSignature(
                self.key,
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                cf_data.as_concrete_TypeRef(),
                &mut error,
            )
        };
        if sig_ref.is_null() {
            if !error.is_null() {
                unsafe { CFRelease(error as CFTypeRef) };
            }
            bail!("SecKeyCreateSignature returned null");
        }
        let der: CFData = unsafe { CFData::wrap_under_create_rule(sig_ref) };
        let (r, s) = parse_ecdsa_der(der.bytes()).context("parse SEP ECDSA DER")?;

        let mut sig_body = Vec::with_capacity(80);
        wire::encode_mpint(&mut sig_body, &r);
        wire::encode_mpint(&mut sig_body, &s);

        let mut out = Vec::with_capacity(96);
        wire::encode_string(&mut out, b"ecdsa-sha2-nistp256");
        wire::encode_string(&mut out, &sig_body);
        Ok(out)
    }
}

fn lookup_key(label: &str) -> Result<Option<SecKeyRef>> {
    let tag = CFData::from_buffer(label.as_bytes());
    let pairs: Vec<(CFType, CFType)> = vec![
        (
            unsafe { CFType::wrap_under_get_rule(kSecClass as CFTypeRef) },
            unsafe { CFType::wrap_under_get_rule(kSecClassKey as CFTypeRef) },
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrApplicationTag as CFTypeRef) },
            tag.into_CFType(),
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyClass as CFTypeRef) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyClassPrivate as CFTypeRef) },
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecMatchLimit as CFTypeRef) },
            unsafe { CFType::wrap_under_get_rule(kSecMatchLimitOne as CFTypeRef) },
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecReturnRef as CFTypeRef) },
            CFBoolean::true_value().into_CFType(),
        ),
    ];
    let query = CFDictionary::from_CFType_pairs(&pairs);
    let mut out: CFTypeRef = std::ptr::null();
    let status = unsafe {
        SecItemCopyMatching(
            query.as_concrete_TypeRef() as CFDictionaryRef,
            &mut out as *mut CFTypeRef,
        )
    };
    match status {
        ERR_SEC_SUCCESS if !out.is_null() => Ok(Some(out as SecKeyRef)),
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        other => Err(anyhow!("SecItemCopyMatching failed: OSStatus {other}")),
    }
}

fn create_access_control(biometric: bool) -> Result<SecAccessControlRef> {
    let mut flags = kSecAccessControlPrivateKeyUsage;
    if biometric {
        flags |= kSecAccessControlBiometryCurrentSet;
    }
    let mut error: CFErrorRef = std::ptr::null_mut();
    let acl = unsafe {
        SecAccessControlCreateWithFlags(
            std::ptr::null(),
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            flags,
            &mut error,
        )
    };
    if acl.is_null() {
        if !error.is_null() {
            unsafe { CFRelease(error as CFTypeRef) };
        }
        bail!("SecAccessControlCreateWithFlags returned null");
    }
    Ok(acl)
}

fn create_se_key(label: &str, acl: SecAccessControlRef) -> Result<SecKeyRef> {
    let label_cf = CFString::new(label);
    let tag = CFData::from_buffer(label.as_bytes());
    let key_size = CFNumber::from(256i64);

    // Private key sub-attributes: applicationTag + permanent + accessControl.
    let priv_pairs: Vec<(CFType, CFType)> = vec![
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrIsPermanent as CFTypeRef) },
            CFBoolean::true_value().into_CFType(),
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrApplicationTag as CFTypeRef) },
            tag.clone().into_CFType(),
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrAccessControl as CFTypeRef) },
            unsafe { CFType::wrap_under_create_rule(acl as CFTypeRef) },
        ),
    ];
    let priv_attrs = CFDictionary::from_CFType_pairs(&priv_pairs);

    let pairs: Vec<(CFType, CFType)> = vec![
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyType as CFTypeRef) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef) },
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeySizeInBits as CFTypeRef) },
            key_size.into_CFType(),
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrTokenID as CFTypeRef) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave as CFTypeRef) },
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecAttrLabel as CFTypeRef) },
            label_cf.into_CFType(),
        ),
        (
            unsafe { CFType::wrap_under_get_rule(kSecPrivateKeyAttrs as CFTypeRef) },
            priv_attrs.into_CFType(),
        ),
    ];
    let attrs = CFDictionary::from_CFType_pairs(&pairs);

    let mut error: CFErrorRef = std::ptr::null_mut();
    let key = unsafe {
        SecKeyCreateRandomKey(attrs.as_concrete_TypeRef() as CFDictionaryRef, &mut error)
    };
    if key.is_null() {
        if !error.is_null() {
            unsafe { CFRelease(error as CFTypeRef) };
        }
        bail!("SecKeyCreateRandomKey returned null (Secure Enclave required, run on Apple silicon Mac with SEP)");
    }
    Ok(key)
}

/// Parse `SEQUENCE { INTEGER r, INTEGER s }` DER. Returns the raw integer
/// magnitudes (may have a leading `0x00`).
fn parse_ecdsa_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut p = 0;
    if der.get(p).copied() != Some(0x30) {
        bail!("ECDSA DER: expected SEQUENCE tag");
    }
    p += 1;
    let (seq_len, consumed) = der_len(&der[p..]).context("DER seq length")?;
    p += consumed;
    if der[p..].len() < seq_len {
        bail!("ECDSA DER: declared seq length exceeds buffer");
    }
    let r = read_integer(&der[p..])?;
    p += r.consumed;
    let s = read_integer(&der[p..])?;
    Ok((r.value, s.value))
}

struct DerInt {
    value: Vec<u8>,
    consumed: usize,
}

fn read_integer(buf: &[u8]) -> Result<DerInt> {
    if buf.first().copied() != Some(0x02) {
        bail!("ECDSA DER: expected INTEGER tag");
    }
    let (len, consumed) = der_len(&buf[1..]).context("DER int length")?;
    let header = 1 + consumed;
    if buf.len() < header + len {
        bail!("ECDSA DER: integer body truncated");
    }
    Ok(DerInt {
        value: buf[header..header + len].to_vec(),
        consumed: header + len,
    })
}

fn der_len(buf: &[u8]) -> Result<(usize, usize)> {
    let first = *buf.first().ok_or_else(|| anyhow!("DER length missing"))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        bail!("DER length: unsupported byte count {n}");
    }
    if buf.len() < 1 + n {
        bail!("DER length: truncated");
    }
    let mut len = 0usize;
    for &b in &buf[1..1 + n] {
        len = (len << 8) | (b as usize);
    }
    Ok((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// Cleans up the SE keychain entry on Drop, even if the test panics.
    struct LabelGuard(String);
    impl Drop for LabelGuard {
        fn drop(&mut self) {
            let _ = SecureEnclaveSigner::delete(&self.0);
        }
    }

    fn fresh_label() -> (String, LabelGuard) {
        let label = format!("lockshell-test-{}", Uuid::new_v4());
        let g = LabelGuard(label.clone());
        (label, g)
    }

    #[test]
    fn parse_der_simple() {
        // SEQUENCE { INTEGER 0x01, INTEGER 0x02 }
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let (r, s) = parse_ecdsa_der(&der).unwrap();
        assert_eq!(r, vec![0x01]);
        assert_eq!(s, vec![0x02]);
    }

    #[test]
    fn parse_der_long_form_length() {
        // SEQUENCE (long form 0x81 0x06)
        let der = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let (r, s) = parse_ecdsa_der(&der).unwrap();
        assert_eq!(r, vec![0x01]);
        assert_eq!(s, vec![0x02]);
    }

    #[test]
    fn roundtrip_se_signature() {
        let (label, _g) = fresh_label();
        let signer = match SecureEnclaveSigner::load_or_create_no_biometric(&label) {
            Ok(s) => s,
            Err(e) => {
                // CI / VMs without SEP: skip rather than fail loudly.
                eprintln!("skipping roundtrip_se_signature: {e}");
                return;
            }
        };
        let blob = signer.public_key_blob().expect("public_key_blob");
        // Decode SSH wire pubkey: alg, curve, point.
        let (alg, rest) = wire::decode_string(&blob).unwrap();
        assert_eq!(alg, b"ecdsa-sha2-nistp256");
        let (curve, rest) = wire::decode_string(rest).unwrap();
        assert_eq!(curve, b"nistp256");
        let (point, _) = wire::decode_string(rest).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);

        let sig = signer
            .sign(b"hello world", "test")
            .expect("SE sign succeeded");
        // Decode SSH wire signature: alg, blob(r||s as mpint).
        let (sig_alg, sig_rest) = wire::decode_string(&sig).unwrap();
        assert_eq!(sig_alg, b"ecdsa-sha2-nistp256");
        let (sig_body, _) = wire::decode_string(sig_rest).unwrap();
        let (r_bytes, rest) = wire::decode_string(sig_body).unwrap();
        let (s_bytes, _) = wire::decode_string(rest).unwrap();

        let r_fixed = pad_to_32(r_bytes);
        let s_fixed = pad_to_32(s_bytes);
        let mut fixed_sig = Vec::with_capacity(64);
        fixed_sig.extend_from_slice(&r_fixed);
        fixed_sig.extend_from_slice(&s_fixed);

        let pub_uncompressed = &point;
        let alg = &ring::signature::ECDSA_P256_SHA256_FIXED;
        let pk = ring::signature::UnparsedPublicKey::new(alg, pub_uncompressed);
        pk.verify(b"hello world", &fixed_sig)
            .expect("ring verifies SE signature");
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
}
