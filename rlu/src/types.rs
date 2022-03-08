// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! RLU Traits
//!
//! The most basic abstraction for implementing types of RLU consists of two traits [`Read`] and [`Write`].
//! Either provide a function to `get()` or `get_mut` of data respectively.

use crate::{RLUVar, ReadGuard, Result, WriteGuard};

/// [`Read<T>`] provides immutable read access to the synchronized data
/// via the current managing context.
pub trait Read<T>
where
    T: Clone,
{
    /// Returns an immutable [`ReadGuard`] on the value of [`RLUVar`]
    ///
    /// This function effectively returns either the original value, if it
    /// has not been modified, or an immutable reference to the underlying
    /// write log, if the log has not been commited to memory yet. The [`ReadGuard`]
    /// ensures that after dereferencing and reading the value, all outstanding
    /// commits to the internal value will be conducted.
    ///
    /// # Example
    /// ```
    /// use stronghold_rlu::*;
    ///
    /// // create simple value, that should be managed by RLU
    /// let value = 6usize;
    ///
    /// // first we need to create a controller
    /// let ctrl = RLU::new();
    ///
    /// // via the controller  we create a RLUVar reference
    /// let rlu_var: RLUVar<usize> = ctrl.create(value);
    ///
    /// // we clone the reference to it to use it inside a thread
    /// let var_1 = rlu_var.clone();
    ///
    /// // via the controller we can spawn a thread safe context
    /// ctrl.execute(move |context| {
    ///     let inner = context.get(&var_1);
    ///     match *inner {
    ///         Ok(inner) => {
    ///             assert_eq!(**inner, 6);
    ///         }
    ///         _ => return Err(TransactionError::Failed),
    ///     }
    ///     Ok(())
    /// });
    /// ```
    fn get<'a>(&'a self, var: &'a RLUVar<T>) -> ReadGuard<T>;
}

/// [`Write<T>`] gives mutable access to synchronized value via the current managing
/// context.
pub trait Write<T>
where
    T: Clone,
{
    /// Returns an mutable [`WriteGuard`] on the value of [`RLUVar`]
    ///
    /// This function returns a mutable copy if the original value. The [`WriteGuard`]
    /// ensures that after dereferencing and writing to the value, the internal log
    /// will be updated to the most recent change
    ///
    /// # Example
    /// ```
    /// use stronghold_rlu::*;
    ///
    /// // create simple value, that should be managed by RLU
    /// let value = 6usize;
    ///
    /// // first we need to create a controller
    /// let ctrl = RLU::new();
    ///
    /// // via the controller  we create a RLUVar reference
    /// let rlu_var: RLUVar<usize> = ctrl.create(value);
    ///
    /// // we clone the reference to it to use it inside a thread
    /// let var_1 = rlu_var.clone();
    ///
    /// // via the controller we can spawn a thread safe context
    /// ctrl.execute(move |mut context| {
    ///     let mut inner = context.get_mut(&var_1)?;
    ///     let data = &mut *inner;
    ///     *data += 10;
    ///     Ok(())
    /// });
    ///
    /// assert_eq!(*rlu_var.get(), 16);
    /// ```
    fn get_mut<'a>(&'a mut self, var: &'a RLUVar<T>) -> Result<WriteGuard<T>>;
}
