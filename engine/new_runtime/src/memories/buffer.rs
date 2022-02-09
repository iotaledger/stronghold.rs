use crate::boxed::Boxed;
use crate::locked_memory::{*, ProtectedConfiguration::*, MemoryError::*};
use crate::types::{Bytes, Zeroed, Randomized, ConstEq};
use core::fmt::{self, Debug, Formatter};
use core::ops::{Deref, DerefMut};
use core::marker::PhantomData;

use serde::{
    de::{Deserialize, Deserializer, SeqAccess, Visitor},
    ser::{Serialize, SerializeSeq, Serializer},
};

/// GuardedMemory is used when we want to store sensitive non encrypted data
/// This shall always be short lived
#[derive(Clone, Eq)]
pub struct Buffer<T: Bytes> {
    boxed : Boxed<T>, // the boxed type of current GuardedVec
}

pub struct Ref<'a, T: Bytes> {
    boxed: &'a Boxed<T>,
}

pub struct RefMut<'a, T: Bytes> {
    boxed: &'a mut Boxed<T>,
}


impl<T: Bytes> ProtectedMemory<T> for Buffer<T> {
    fn alloc(payload: &[T], config: ProtectedConfiguration)
             -> Result<Self, MemoryError> {
        match config {
            BufferConfig(size) => {
                Ok(Buffer {
                    boxed: Boxed::new(size,
                                      |b| b.as_mut_slice().copy_from_slice(&payload)),
                })

            },

            // We don't allow any other configurations for Buffer
            _ => Err(ConfigurationNotAllowed)
        }
    }


    fn dealloc(&mut self) -> Result<(), MemoryError> {
        todo!();
    }
}

impl<T: Bytes> Buffer<T> {
    pub fn len(&self) -> usize {
        self.boxed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.boxed.is_empty()
    }

    pub fn size(&self) -> usize {
        self.boxed.size()
    }

    pub fn borrow(&self) -> Ref<'_, T> {
        Ref::new(&self.boxed)
    }

    pub fn borrow_mut(&mut self) -> RefMut<'_, T> {
        RefMut::new(&mut self.boxed)
    }
}

impl<T: Bytes + Randomized> Buffer<T> {
    pub fn random(len: usize) -> Self {
        Self {
            boxed: Boxed::random(len),
        }
    }
}

impl<T: Bytes + Zeroed> Buffer<T> {
    pub fn zero(len: usize) -> Self {
        Self {
            boxed: Boxed::zero(len),
        }
    }
}

impl<T: Bytes + Zeroed> From<&mut [T]> for Buffer<T> {
    fn from(data: &mut [T]) -> Self {
        Self {
            boxed: data.into(),
        }
    }
}

impl<T: Bytes> Debug for Buffer<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes + ConstEq> PartialEq for Buffer<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.boxed.eq(&rhs.boxed)
    }
}

impl<'a, T: Bytes> Ref<'a, T> {
    fn new(boxed: &'a Boxed<T>) -> Self {
        Self {
            boxed: boxed.unlock(),
        }
    }
}

impl<T: Bytes> Clone for Ref<'_, T> {
    fn clone(&self) -> Self {
        Self {
            boxed: self.boxed.unlock(),
        }
    }
}

impl<T: Bytes> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for Ref<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.boxed.as_slice()
    }
}

impl<T: Bytes> Debug for Ref<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes> PartialEq for Ref<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<RefMut<'_, T>> for Ref<'_, T> {
    fn eq(&self, rhs: &RefMut<'_, T>) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> Eq for Ref<'_, T> {}

impl<'a, T: Bytes> RefMut<'a, T> {
    fn new(boxed: &'a mut Boxed<T>) -> Self {
        Self {
            boxed: boxed.unlock_mut(),
        }
    }
}

impl<T: Bytes> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.boxed.lock();
    }
}

impl<T: Bytes> Deref for RefMut<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.boxed.as_slice()
    }
}

impl<T: Bytes> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.boxed.as_mut_slice()
    }
}

impl<T: Bytes> Debug for RefMut<'_, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.boxed.fmt(f)
    }
}

impl<T: Bytes> PartialEq for RefMut<'_, T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> PartialEq<Ref<'_, T>> for RefMut<'_, T> {
    fn eq(&self, rhs: &Ref<'_, T>) -> bool {
        self.const_eq(rhs)
    }
}

impl<T: Bytes> Eq for RefMut<'_, T> {}

unsafe impl<T: Bytes + Send> Send for Buffer<T> {}
unsafe impl<T: Bytes + Sync> Sync for Buffer<T> {}

impl<T: Bytes> Serialize for Buffer<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_seq(Some(self.len()))?;
        for e in self.borrow().iter() {
            state.serialize_element(e)?;
        }
        state.end()
    }
}

struct BufferVisitor<T: Bytes> {
    marker: PhantomData<fn() -> Buffer<T>>,
}

impl<T: Bytes> BufferVisitor<T> {
    fn new() -> Self {
        BufferVisitor { marker: PhantomData }
    }
}

impl<'de, T: Bytes> Visitor<'de> for BufferVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Buffer<T>;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("Buffer not found")
    }

    fn visit_seq<E>(self, mut access: E) -> Result<Self::Value, E::Error>
    where
        E: SeqAccess<'de>,
    {
        // extern crate alloc;
        // use alloc::vec::Vec;

        let mut seq = Vec::<T>::with_capacity(access.size_hint().unwrap_or(0));

        while let Some(e) = access.next_element()? {
            seq.push(e);
        }

        let seq = Buffer::alloc(seq.as_slice() , BufferConfig(seq.len()))
            .expect("Buffer could not be allocated, this should not happen here");

        Ok(seq)
    }
}

impl<'de, T: Bytes> Deserialize<'de> for Buffer<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BufferVisitor::new())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;

    use alloc::format;

    #[test]
    fn test_init() {
        let buf = Buffer::<u64>::alloc(&[1, 2, 3, 4, 5, 6][..], BufferConfig(6));
        assert!(buf.is_ok());
        assert_eq!((*buf.unwrap().borrow()), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_borrow() {
        let vec = Buffer::<u64>::zero(2);
        let v = vec.borrow();

        assert_eq!(*v, [0, 0]);

        let mut vec = Buffer::<u64>::zero(2);
        let mut v = vec.borrow_mut();

        v.copy_from_slice(&[7, 1][..]);

        assert_eq!(*v, [7, 1]);

        let vec = Buffer::<[u8; 2]>::alloc(&[[1, 2], [3, 4]][..], BufferConfig(2));
        assert!(vec.is_ok());
        assert_eq!(*vec.unwrap().borrow(), [[1, 2], [3, 4]]);
    }

    #[test]
    fn test_properties() {
        let vec = Buffer::<[u64; 4]>::zero(64);
        assert_eq!(vec.len(), 64);
        assert_eq!(vec.size(), 2048);
    }

    #[test]
    fn test_guard() {
        let mut guard = Buffer::<u64>::random(32);

        assert_eq!(format!("{{ size: {}, hidden }}", 256), format!("{:?}", guard),);

        assert_eq!(format!("{{ size: {}, hidden }}", 256), format!("{:?}", guard.borrow()),);

        assert_eq!(
            format!("{{ size: {}, hidden }}", 256),
            format!("{:?}", guard.borrow_mut()),
        );
    }

    #[test]
    fn test_moving_and_cloning() {
        let guard = Buffer::<u8>::zero(1);

        let moved = guard;

        assert_eq!(*moved.borrow(), [0]);

        let guard = Buffer::<u8>::random(8);

        let borrow = guard.borrow();
        let clone = borrow.clone();

        assert_eq!(borrow, clone);
    }

    #[test]
    fn test_comparisons() {
        let guard = Buffer::<u8>::from(&mut [1, 2, 3][..]);

        let clone = guard.clone();

        assert_eq!(guard, clone);

        let guard_a = Buffer::<[u128; 8]>::random(32);
        let guard_b = Buffer::<[u128; 8]>::random(32);

        assert_ne!(guard_a, guard_b);

        let mut guard = Buffer::<u8>::from(&mut [0xaf][..]);
        let mut clone = guard.clone();

        assert_eq!(guard.borrow_mut(), clone.borrow_mut());
        assert_eq!(guard.borrow_mut(), clone.borrow());
        assert_eq!(guard.borrow_mut(), clone.borrow());
        assert_eq!(guard.borrow(), clone.borrow_mut());
    }
}
