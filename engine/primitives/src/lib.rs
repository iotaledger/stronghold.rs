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

/// A general purpose API for Cryptographic Primitives.
/// This crate's aim is to provide an abstraction layer with extensible cryptographic primitives. Each primitive
/// contains an info data structure for describing the constraints of the algorithm and at least one trait.

/// Message Auth Code
pub mod auth;
/// Cipher
pub mod cipher;
/// Hash
pub mod hash;
/// Key derive function
pub mod key_derv_func;
/// PBKDF
pub mod pbkdf;
/// Random Number Generator
pub mod rng;
/// Asymmetric Signing
pub mod signing;
