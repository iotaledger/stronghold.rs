// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # RLU Guard Types
//!
//! This module has guard types for read and writes for an [`crate::RLUObject`]. The guard
//! types follow the RAII pattern. Dropping the guards will affect the referenced object by either
//! signaling an end of read, or signaling the start of memory commit depending on the type of guard.

use crate::{var::InnerVarCopy, Atomic, Result, RluContext};
use std::ops::{Deref, DerefMut};

pub struct ReadGuard<'a, T>
where
    T: Clone,
{
    inner: Result<&'a Atomic<T>>,
    thread: &'a RluContext<T>,
}

impl<'a, T> ReadGuard<'a, T>
where
    T: Clone,
{
    pub fn new(inner: Result<&'a Atomic<T>>, thread: &'a RluContext<T>) -> Self {
        Self { inner, thread }
    }
}

impl<'a, T> Drop for ReadGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        if let Ok(inner) = self.inner {
            self.thread.read_unlock(inner)
        }
    }
}

impl<'a, T> Deref for ReadGuard<'a, T>
where
    T: Clone,
{
    type Target = Result<&'a Atomic<T>>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// This inner enum of [`WriteGuard`]
pub enum WriteGuardInner<'a, T>
where
    T: Clone,
{
    /// a mutable reference
    Ref(&'a mut T),

    /// a copy, that needs to be written back into the log
    Copy(*mut InnerVarCopy<T>),
}

pub struct WriteGuard<'a, T>
where
    T: Clone,
{
    inner: WriteGuardInner<'a, T>,
    context: &'a mut RluContext<T>,
}

impl<'a, T> Deref for WriteGuard<'a, T>
where
    T: Clone,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match &self.inner {
            WriteGuardInner::Copy(copy, ..) => {
                assert!(!copy.is_null());

                let ptr = unsafe { &**copy };
                &ptr.data
            }
            WriteGuardInner::Ref(reference) => reference,
        }
    }
}

impl<'a, T> DerefMut for WriteGuard<'a, T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.inner {
            WriteGuardInner::Copy(copy, ..) => {
                assert!(!copy.is_null());

                let ptr = unsafe { &mut **copy };
                &mut ptr.data
            }
            WriteGuardInner::Ref(reference) => *reference,
        }
    }
}

impl<'a, T> WriteGuard<'a, T>
where
    T: Clone,
{
    pub fn new(inner: WriteGuardInner<'a, T>, context: &'a mut RluContext<T>) -> Self {
        Self { inner, context }
    }
}

impl<'a, T> Drop for WriteGuard<'a, T>
where
    T: Clone,
{
    fn drop(&mut self) {
        if let WriteGuardInner::Copy(inner) = &mut self.inner {
            self.context.inner_log().push(unsafe { &**inner }.clone());

            // swap inner variable to point to copy
            // unsafe { reference.swap(self.context.inner_log().last().unwrap() as *const _ as *mut _) }
        }
    }
}
