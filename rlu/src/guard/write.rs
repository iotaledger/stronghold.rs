// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
use crate::{var::InnerVarCopy, InnerVar, RluContext};
use std::{
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, MutexGuard, RwLock,
    },
};

pub enum WriteGuardType<'a, T>
where
    T: Clone,
{
    Mutex(MutexGuard<'a, T>),
    MutexCopy(MutexGuard<'a, Option<InnerVarCopy<T>>>, T),
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
        inner: MutexGuard<'a, Option<InnerVarCopy<T>>>,
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
        let mut guard = self.context.log.lock().expect("Log could not be released");
        match inner {
            WriteGuardType::Mutex(m) => {
                if let Some(original) = &self.original {
                    let locked_id = match &original.locked_thread_id {
                        Some(locked_id) => locked_id.load(Ordering::SeqCst),
                        None => 0,
                    };

                    let data = &*m.deref();

                    let copy = InnerVarCopy {
                        locked_thread_id: Some(AtomicUsize::new(locked_id)),
                        data: Arc::new(RwLock::new(data.clone())),
                        original: original.clone(),
                    };

                    guard.push(Arc::new(copy));
                    drop(guard);
                }
            }
            WriteGuardType::MutexCopy(copy_guard, modified) => {
                if let Some(inner) = &**copy_guard {
                    let mut inner_copy_guard = inner.data.write().expect("Could not lock inner data");
                    *inner_copy_guard = modified.clone();

                    guard.push(Arc::new(inner.clone()))
                }
                drop(guard);
            }
        };

        // end RLU section
        self.context.read_unlock();
    }
}
