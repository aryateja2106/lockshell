// SPDX-License-Identifier: Apache-2.0

//! Library surface for `lockshelld`. Exposed so integration tests under
//! `tests/` can drive the daemon's components (RPC + SSH agent) directly
//! without spawning the binary subprocess for every assertion.

pub mod rpc;
pub mod ssh_agent;

pub use ssh_agent::{AgentBackend, CertMinter};
