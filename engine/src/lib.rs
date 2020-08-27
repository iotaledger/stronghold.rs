// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

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
