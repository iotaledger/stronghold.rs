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
