// SPDX-License-Identifier: Apache-2.0

//! Pure SSH primitives shared between the lockshell daemon and CLI.
//!
//! Phase 1 surface: the [`signer::Signer`] trait and SSH wire-format helpers
//! in [`wire`]. Phase 2 adds the macOS Secure Enclave signer (gated by
//! `target_os = "macos"`) and the host alias registry in [`hosts`].

pub mod ca;
pub mod hosts;
pub mod labels;
pub mod signer;
pub mod wire;

pub use signer::software::SoftwareEcdsaSigner;
pub use signer::Signer;

#[cfg(target_os = "macos")]
pub use signer::secure_enclave::SecureEnclaveSigner;
