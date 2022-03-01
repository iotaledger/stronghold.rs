// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! This crate provides implementations of  Maged M. Michael and Michael L. Scott non-blocking stack and queue.
//!
//! The implementation of both data structures are thread-safe and can be used in concurrent
//! contexts to read and write into queues at the same time.

pub use self::{queue::NonBlockingQueue, stack::NonBlockingStack};
use std::sync::{
    atomic::{AtomicPtr, Ordering},
    Arc,
};

pub trait Queue {
    /// The inner item type
    type Item;

    /// Puts an item into the queue at the end
    fn put(&self, value: Self::Item);

    /// Removes the first item. Returns [`None`], if no item is present
    fn poll(&self) -> Option<&Self::Item>;
}

impl<T> dyn Queue<Item = T>
where
    T: 'static,
{
    pub fn default() -> Box<Self> {
        Box::new(NonBlockingQueue::<T>::default())
    }
}

pub trait Stack {
    /// The inner item type
    type Item;

    /// Pushes an item to the top of the stack
    fn push(&self, value: Self::Item);

    /// Pops an item from the top of the stack. Returns [`None`],
    /// if no item is present.
    fn pop(&self) -> Option<&Self::Item>;
}

impl<T> dyn Stack<Item = T>
where
    T: 'static + Clone,
{
    pub fn default() -> Box<Self> {
        Box::new(NonBlockingStack::<T>::default())
    }
}

struct Node<T> {
    value: Option<T>,
    next: AtomicPtr<Node<T>>,
}

impl<T> Node<T> {
    fn new(value: T) -> Self {
        Self {
            value: Some(value),
            next: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    fn empty() -> Self {
        Self {
            value: None,
            next: AtomicPtr::new(std::ptr::null_mut()),
        }
    }
}

mod stack {
    use super::*;

    /// A non blocking stack using the Michael & Scott implementation
    pub struct NonBlockingStack<T> {
        head: Arc<AtomicPtr<Node<T>>>,
    }

    impl<T> Clone for NonBlockingStack<T> {
        fn clone(&self) -> Self {
            Self {
                head: self.head.clone(),
            }
        }
    }

    impl<T> Default for NonBlockingStack<T> {
        fn default() -> Self {
            Self {
                head: Arc::new(AtomicPtr::new(std::ptr::null_mut())),
            }
        }
    }

    impl<T> Stack for NonBlockingStack<T>
    where
        T: Clone,
    {
        type Item = T;

        fn push(&self, value: Self::Item) {
            match self.head.load(Ordering::SeqCst) {
                node_ptr if node_ptr.is_null() => {
                    let new = Node::new(value);
                    self.head.store(Box::into_raw(Box::new(new)), Ordering::SeqCst)
                }
                node_ptr if !node_ptr.is_null() => loop {
                    let new = Node::new(value.clone());
                    let old = unsafe { &mut *node_ptr };
                    new.next.store(old, Ordering::SeqCst);

                    if self
                        .head
                        .compare_exchange(old, Box::into_raw(Box::new(new)), Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        break;
                    }
                },

                _ => {}
            }
        }

        fn pop(&self) -> Option<&Self::Item> {
            match self.head.load(Ordering::SeqCst) {
                node_ptr if node_ptr.is_null() => None,
                node_ptr if !node_ptr.is_null() => loop {
                    let old = unsafe { &mut *node_ptr };
                    match old.next.load(Ordering::SeqCst) {
                        next_ptr if next_ptr.is_null() => {
                            self.head.store(std::ptr::null_mut(), Ordering::SeqCst);
                            return old.value.as_ref();
                        }
                        next_ptr if !next_ptr.is_null() => {
                            if self
                                .head
                                .compare_exchange(old, next_ptr, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                            {
                                return old.value.as_ref();
                            }
                        }
                        _ => return None,
                    };
                },
                _ => None,
            }
        }
    }
}

mod queue {

    use super::*;

    pub struct NonBlockingQueue<T> {
        head: Arc<AtomicPtr<Node<T>>>,
        tail: Arc<AtomicPtr<Node<T>>>,
    }

    impl<T> Default for NonBlockingQueue<T> {
        fn default() -> Self {
            let inner = Box::into_raw(Box::new(Node::<T>::empty()));

            Self {
                head: Arc::new(AtomicPtr::new(inner)),
                tail: Arc::new(AtomicPtr::new(inner)),
            }
        }
    }

    impl<T> Clone for NonBlockingQueue<T> {
        fn clone(&self) -> Self {
            Self {
                head: self.head.clone(),
                tail: self.tail.clone(),
            }
        }
    }

    impl<T> Queue for NonBlockingQueue<T> {
        type Item = T;

        fn put(&self, value: Self::Item) {
            let new = Node::new(value);
            let new_ptr = Box::into_raw(Box::new(new));

            let tail_ptr = self.tail.load(Ordering::SeqCst);

            match tail_ptr.is_null() {
                true => self.tail.store(new_ptr, Ordering::SeqCst),
                false => loop {
                    let tail = unsafe { &*tail_ptr };

                    if tail
                        .next
                        .compare_exchange(std::ptr::null_mut(), new_ptr, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        self.tail.store(tail.next.load(Ordering::SeqCst), Ordering::SeqCst);
                        break;
                    }
                },
            }
        }

        fn poll(&self) -> Option<&Self::Item> {
            loop {
                // TODO replace with immutable retries
                let head_ptr = self.head.load(Ordering::SeqCst);
                let tail_ptr = self.tail.load(Ordering::SeqCst);

                let next_ptr = match head_ptr.is_null() {
                    true => return None,
                    false => {
                        let head = unsafe { &*head_ptr };

                        head.next.load(Ordering::SeqCst)
                    }
                };

                // FIXME: there is a bug
                if head_ptr == self.head.load(Ordering::SeqCst) {
                    if head_ptr == tail_ptr {
                        if next_ptr.is_null() {
                            return None;
                        }

                        self.tail
                            .compare_exchange(tail_ptr, next_ptr, Ordering::SeqCst, Ordering::SeqCst)
                            .expect("swapping tail ptr failed");
                    } else {
                        let result = &unsafe { &*next_ptr }.value;

                        if self
                            .head
                            .compare_exchange(head_ptr, next_ptr, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            return result.as_ref();
                        }
                    }
                }

                // hint cpu we are inside a busy loop to allow optimizations
                std::hint::spin_loop();
            }
        }
    }
}
