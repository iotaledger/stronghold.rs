// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    ops::{Deref, DerefMut, Index, IndexMut},
    sync::atomic::{AtomicUsize, Ordering},
};

/// The number of entries inside the write log
const LOG_ENTRY_SIZE: usize = 32;

pub(crate) struct Node<T> {
    alloc: [Option<T>; LOG_ENTRY_SIZE],
    index: AtomicUsize,
}

impl<T> Node<T>
where
    T: Clone,
{
    /// Selects the next internal log by incrementing the internal index mod the  number of logs
    pub fn next_idx(&self) {
        self.index.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns the current index  of the log
    pub fn current_node_index(&self) -> usize {
        self.index.load(Ordering::SeqCst)
    }

    pub fn push(&mut self, value: T) {
        assert!((self.current_node_index() + 1) < self.alloc.len());
        self.next_idx();

        self.alloc[self.current_node_index()] = Some(value);
    }

    pub fn clear(&mut self) {
        self.alloc = match vec![None; LOG_ENTRY_SIZE].try_into() {
            Ok(array) => array,
            _ => unreachable!(),
        };
        self.index.store(0, Ordering::Release)
    }

    pub fn len(&self) -> usize {
        self.alloc.len()
    }

    pub fn last(&self) -> Option<&T> {
        self.alloc[self.current_node_index()].as_ref()
    }

    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.alloc[self.current_node_index()].as_mut()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Option<T>> {
        (&self.alloc).iter()
    }

    pub fn drain(&mut self) -> impl Iterator<Item = Option<T>> + '_ {
        (&mut self.alloc).iter_mut().map(|n| n.take())
    }
}

impl<T> Default for Node<T>
where
    T: Clone,
{
    fn default() -> Self {
        Self {
            alloc: match vec![None; LOG_ENTRY_SIZE].try_into() {
                Ok(array) => array,
                _ => unreachable!(),
            },
            index: AtomicUsize::new(0),
        }
    }
}

impl<T> Index<usize> for Node<T>
where
    T: Clone,
{
    type Output = Option<T>;

    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < self.alloc.len());
        &self.alloc[self.current_node_index()]
    }
}

impl<T> IndexMut<usize> for Node<T>
where
    T: Clone,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index < self.alloc.len());
        &mut self.alloc[self.current_node_index()]
    }
}

pub(crate) struct RLULog<T>
where
    T: Clone,
{
    clear: AtomicUsize,
    current_log_index: AtomicUsize,
    logs: [Node<T>; 2], // [Vec<T>; 2],
}

impl<T> Default for RLULog<T>
where
    T: Clone,
{
    fn default() -> Self {
        Self {
            clear: AtomicUsize::new(usize::MAX),
            current_log_index: AtomicUsize::new(0),
            logs: [Node::default(), Node::default()],
        }
    }
}

impl<T> RLULog<T>
where
    T: Clone,
{
    /// Selects the next internal log by incrementing the internal index mod the  number of logs
    pub fn next(&self) {
        let next = (self.current() + 1) % self.logs.len();
        self.clear.store(self.current(), Ordering::SeqCst);
        self.current_log_index.store(next, Ordering::SeqCst);
    }

    /// Returns the current index  of the log
    pub fn current(&self) -> usize {
        self.current_log_index.load(Ordering::SeqCst)
    }
}

impl<T> Deref for RLULog<T>
where
    T: Clone,
{
    type Target = Node<T>;

    fn deref(&self) -> &Self::Target {
        &self.logs[self.current()]
    }
}

impl<T> DerefMut for RLULog<T>
where
    T: Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        if let 0..=1 = self.clear.swap(usize::MAX, Ordering::SeqCst) {
            self.logs[self.current()].clear()
        }

        &mut self.logs[self.current()]
    }
}

#[cfg(test)]
mod tests {

    use crate::RLULog;
    use rand_utils::random::{string, usize};

    fn rand_string() -> String {
        string(255)
    }

    #[inline(always)]
    fn rand_usize() -> usize {
        usize(usize::MAX)
    }

    #[test]
    fn test_rlu_log() {
        let mut log = RLULog::<usize>::default();

        // 0
        assert_eq!(log.current(), 0);
        log.push(1);
        log.push(1);
        assert_eq!(log.current_node_index(), 2);

        // 1
        log.next();
        assert_eq!(log.current(), 1);
        log.push(1);
        log.push(1);
        log.push(1);
        assert_eq!(log.current_node_index(), 3);

        // 0
        log.next();
        assert_eq!(log.current(), 0);
        log.push(1);
        log.push(1);
        assert_eq!(log.current_node_index(), 2);

        // 1
        log.next();
        assert_eq!(log.current(), 1);
        log.push(1);
        log.push(1);
        log.push(1);
        log.push(1);
        log.push(1);
        assert_eq!(log.current_node_index(), 5);

        // 0
        log.next();
        assert_eq!(log.current(), 0);
        log.push(1);
        log.push(1);
        assert_eq!(log.current_node_index(), 2);
    }
}
