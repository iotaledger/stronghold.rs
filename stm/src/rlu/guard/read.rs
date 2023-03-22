// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::rlu::RluContext;
use std::{ops::Deref, sync::MutexGuard};

use super::BaseGuard;

/// Provides a read guard over inner value. The inner data can be derefed. [`ReadGuard`] only
/// returns immutable data types.
pub struct ReadGuard<'a, T>
where
    T: Clone,
{
    inner: Option<MutexGuard<'a, T>>,
    context: Option<&'a RluContext<T>>,
    copied: Option<T>,
}

impl<'a, T> ReadGuard<'a, T>
where
    T: Clone,
{
    pub fn from_baseguard(guard: BaseGuard<'a, T>, context: &'a RluContext<T>) -> Self {
        Self {
            inner: Some(guard.inner),
            context: Some(context),
            copied: None,
        }
    }

    pub fn from_guard(mutex: MutexGuard<'a, T>, context: &'a RluContext<T>) -> Self {
        Self {
            inner: Some(mutex),
            context: Some(context),
            copied: None,
        }
    }

    pub fn from_copied(copied: T, context: &'a RluContext<T>) -> Self {
        Self {
            inner: None,
            context: Some(context),
            copied: Some(copied),
        }
    }
}

impl<'a, T> Deref for ReadGuard<'a, T>
where
    T: Clone,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match &self.inner {
            Some(inner) => inner.deref(),
            None => match &self.copied {
                Some(copied) => copied,
                None => unreachable!(),
            },
        }
    }
}

impl<'a, T> Drop for ReadGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        if let Some(context) = self.context {
            // end RLU section
            assert!(context.read_unlock().is_ok());
        }
    }
}
