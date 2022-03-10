// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::RluContext;
use std::{
    ops::{Deref, DerefMut},
    sync::MutexGuard,
};

///
pub struct BaseGuard<'a, T>
where
    T: Clone,
{
    pub(crate) inner: MutexGuard<'a, T>,
    pub(crate) context: Option<&'a RluContext<T>>,
}

impl<'a, T> BaseGuard<'a, T>
where
    T: Clone,
{
    pub fn new(inner: MutexGuard<'a, T>, context: Option<&'a RluContext<T>>) -> Self {
        Self { inner, context }
    }
}

impl<'a, T> Deref for BaseGuard<'a, T>
where
    T: Clone,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T> DerefMut for BaseGuard<'a, T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
