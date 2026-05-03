// SPDX-License-Identifier: Apache-2.0

//! Signer abstraction. Implementations bind to a hardware or software key and
//! gate every signature behind a user-visible reason string (Touch ID prompt,
//! passphrase prompt, etc.).

use anyhow::Result;

#[cfg(target_os = "macos")]
pub mod secure_enclave;
pub mod software;

/// Produces SSH-format signatures over arbitrary data.
///
/// Implementors hold a reference to a non-extractable key. The `reason` passed
/// to [`Signer::sign`] is surfaced to the user during the consent gate.
pub trait Signer: Send + Sync {
    /// SSH key-type string, e.g. `"ecdsa-sha2-nistp256"` or `"ssh-ed25519"`.
    fn algorithm(&self) -> &'static str;

    /// SSH wire-format public key blob (the body of an `authorized_keys` line
    /// before base64 encoding).
    fn public_key_blob(&self) -> Result<Vec<u8>>;

    /// Sign `data` after the user approves with `reason`.
    fn sign(&self, data: &[u8], reason: &str) -> Result<Vec<u8>>;
}
