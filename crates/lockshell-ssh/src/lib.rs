// SPDX-License-Identifier: Apache-2.0

//! Pure SSH primitives shared between the lockshell daemon and CLI.
//!
//! Phase 1 surface: the [`signer::Signer`] trait and SSH wire-format helpers
//! in [`wire`]. Concrete signer implementations (Secure Enclave, passphrase
//! fallback) land in later phases.

pub mod signer;
pub mod wire;

pub use signer::Signer;
