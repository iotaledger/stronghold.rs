// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroize;

/// The [`KeyProvider`] keeps secrets in [`NonContinguousMemory`] at rest,
/// such that no key can be directly read out from memory. The memory fragments
/// of the key provider will be rotated continuously while not in use.
pub struct KeyProvider {}

impl<D> From<D> for KeyProvider
where
    D: Zeroize,
{
    fn from(data: D) -> Self {
        todo!()
    }
}

impl KeyProvider {}
