// Copyright 2020 IOTA Stiftung
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::mem;

pub use transactions::{DataTransaction, SealedPayload, SealedTransaction};

pub mod transactions;
pub mod utils;

/// a view over raw data.
pub trait AsView<T: Sized>: AsRef<[u8]> {
    /// creates a view over `self`.
    fn view(&self) -> &T {
        // get the bytes
        let bytes = self.as_ref();
        // validate the bytes
        assert!(mem::size_of::<T>() <= bytes.len(), "Can't create view over this memory");
        // get the pointer
        let bytes = bytes.as_ptr();
        // validate alignment
        assert_eq!(
            bytes.align_offset(mem::align_of::<T>()),
            0,
            "View's offset is incorrect"
        );
        // cast the pointer
        unsafe { bytes.cast::<T>().as_ref() }.unwrap()
    }
}

/// a mutable view over raw data.
pub trait AsViewMut<T: Sized>: AsMut<[u8]> {
    /// creates a mutable view over `self`.
    fn view_mut(&mut self) -> &mut T {
        // get bytes
        let bytes = self.as_mut();
        // validate bytes
        assert!(mem::size_of::<T>() <= bytes.len(), "Can't create view over this memory");
        // get mute pointer
        let bytes = bytes.as_mut_ptr();
        // validate alignment
        assert_eq!(
            bytes.align_offset(mem::align_of::<T>()),
            0,
            "View's offset is incorrect"
        );

        // cast mutable pointer
        unsafe { bytes.cast::<T>().as_mut() }.unwrap()
    }
}
