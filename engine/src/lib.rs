// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A system for securely managing secrets.
//!
//! This top-level crate contains references to the others that make up
//! the IOTA Stronghold's low-level crates known as "Stronghold-Engine".
//!
//! # Layout
//!
//! This framework is divided into the following crates:
//!
//! - `primitives`: traits for cryptographic primitives
//! - `crypto`: composable Poly1305 and ChaCha20 using traits from the primitives
//! - `random`: a secure random number generator
//! - `vault`: logic and abstractions for the storage layer
//! - `snapshot`: method for storing the state of the vault in a file
//!
//! ## WARNING
//!
//! This library has not yet been audited for security, so use at your own peril.
//! Until a formal third-party security audit has taken place, the IOTA Foundation
//! makes no guarantees to the fitness of this library for any purposes.

pub use crypto;
pub use primitives;
pub use random;
pub use snapshot;
pub use vault;
