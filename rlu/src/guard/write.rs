// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::{var::InnerVarCopy, InnerVar, RluContext};
use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, MutexGuard},
};

pub enum WriteGuardType<'a, T>
where
    T: Clone,
{
    Mutex(MutexGuard<'a, T>),
    MutexCopy(MutexGuard<'a, InnerVarCopy<T>>, T),
}

pub struct WriteGuard<'a, T>
where
    T: Clone,
{
    inner: WriteGuardType<'a, T>,
    context: &'a RluContext<T>,
    original: Option<Arc<InnerVar<T>>>,
}

impl<'a, T> Deref for WriteGuard<'a, T>
where
    T: Clone,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match &self.inner {
            WriteGuardType::Mutex(mutex) => mutex.deref(),
            WriteGuardType::MutexCopy(_, data) => data,
        }
    }
}

impl<'a, T> DerefMut for WriteGuard<'a, T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.inner {
            WriteGuardType::Mutex(mutex) => mutex.deref_mut(),
            WriteGuardType::MutexCopy(_, data) => data,
        }
    }
}

impl<'a, T> WriteGuard<'a, T>
where
    T: Clone,
{
    pub fn from_guard_copy(
        inner: MutexGuard<'a, InnerVarCopy<T>>,
        copied: T,
        context: &'a RluContext<T>,
        original: Option<Arc<InnerVar<T>>>,
    ) -> Self {
        Self {
            inner: WriteGuardType::MutexCopy(inner, copied),
            context,
            original,
        }
    }

    pub fn from_guard(
        inner: MutexGuard<'a, T>,
        context: &'a RluContext<T>,
        original: Option<Arc<InnerVar<T>>>,
    ) -> Self {
        Self {
            inner: WriteGuardType::Mutex(inner),
            context,
            original,
        }
    }
}

impl<'a, T> Drop for WriteGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        let inner = &self.inner;
        let guard = self.context.log.lock().expect("Lock on log could not be released");
        match inner {
            WriteGuardType::Mutex(m) => {
                //
            }
            WriteGuardType::MutexCopy(mc, _) => {
                //
            }
        };
    }
}
