// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::from_over_into)]
#![allow(clippy::upper_case_acronyms)]

//! Vault is an in-memory database specification which is designed to work without a central server. Only the user which
//! holds the associated id and key may modify the data in a vault.  Another owner can take control over the data if
//! they know the id and the key.
//!
//! Data can be added to the chain via a `DataTransaction`.  The `DataTransaction` is associated to the chain
//! through the owner's ID and it contains its own randomly generated ID.
//!
//! Records may also be revoked from the Vault through a `RevocationTransaction`. A `RevocationTransaction` is
//! created and it references the id of a existing `DataTransaction`. The `RevocationTransaction` stages the
//! associated record for deletion. The record is deleted when the [`DbView`] preforms a garbage collection and the
//! `RevocationTransaction` is deleted along with it.

mod base64;
mod crypto_box;
mod types;
pub mod view;

pub use crate::vault::{
    base64::{Base64Decodable, Base64Encodable},
    crypto_box::{BoxProvider, Decrypt, Encrypt, Key},
    types::utils::{ChainId, ClientId, Id, InvalidLength, RecordHint, RecordId, VaultId},
    view::{DbView, RecordError, VaultError},
};
