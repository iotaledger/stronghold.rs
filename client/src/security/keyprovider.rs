// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use engine::{
    runtime::{
        locked_memory::LockedMemory,
        memories::buffer::{Buffer, Ref},
        Bytes, MemoryError,
    },
    vault::NCKey,
};
use stronghold_utils::GuardDebug;
use zeroize::Zeroize;

use crate::internal::Provider;

/// The [`KeyProvider`] keeps secrets in [`NonContinguousMemory`] at rest,
/// such that no key can be directly read out from memory. The memory fragments
/// of the key provider will be rotated continuously while not in use.
#[derive(GuardDebug)]
pub struct KeyProvider {
    inner: engine::vault::NCKey<Provider>,
}

impl TryFrom<Vec<u8>> for KeyProvider {
    type Error = MemoryError;

    fn try_from(data: Vec<u8>) -> Result<Self, MemoryError> {
        match NCKey::load(data) {
            Some(inner) => Ok(Self { inner }),
            None => Err(MemoryError::NCSizeNotAllowed),
        }
    }
}

impl KeyProvider {
    /// Tries to unlock the inner key and returns it.
    /// If unlocking fails, a [`MemoryError`] will be returned
    /// This operations ensures, that the unlocked key will be fragmented,
    /// when it goes out of scope.
    ///
    /// # Example
    /// ```no_run
    /// use iota_stronghold_new::KeyProvider;
    /// use std::ops::Deref;
    ///
    /// // crate some key data
    /// let keydata = Vec::from_iter(std::iter::repeat(6).take(32));
    ///
    /// // create the keyprovider
    /// let keyprovider = KeyProvider::try_from(keydata.clone()).expect("Fail to create keyprovider");
    ///
    /// // try to unlock the buffer
    /// let buffer = keyprovider.try_unlock();
    /// assert!(buffer.is_ok());
    ///
    /// // get the inner buffer
    /// let buffer = buffer.expect("Failed to get inner buffer");
    ///
    /// // get the inner reference of the buffer
    /// let buffer_ref = buffer.borrow();
    ///
    /// // deref the inner key
    /// let inner_key = buffer_ref.deref();
    /// assert_eq!(keydata, inner_key.to_vec());
    /// ```
    pub fn try_unlock(&self) -> Result<Buffer<u8>, MemoryError> {
        match self.inner.key.unlock() {
            Ok(inner) => Ok(inner),
            Err(memerror) => Err(memerror),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_keyprovider_create() {
        let keydata = Vec::from_iter(std::iter::repeat(6).take(32));
        assert!(KeyProvider::try_from(keydata).is_ok());
    }

    #[test]
    fn test_keyprovider_get() {
        let keydata = Vec::from_iter(std::iter::repeat(6).take(32));
        let keyprovider = KeyProvider::try_from(keydata.clone()).expect("Fail to create keyprovider");

        let buffer = keyprovider.try_unlock();
        assert!(buffer.is_ok());

        let buffer = buffer.expect("Failed to get inner buffer");
        let buffer_ref = buffer.borrow();
        let inner_key = buffer_ref.deref();

        assert_eq!(keydata, inner_key.to_vec());
    }
}
