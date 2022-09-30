// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! # Stronghold Client Interface
//!
//! The client interface exposes all functionality to work with a Stronghold instance

// FIXME: remove this later, when feature-complete
#![allow(unused_variables, unused_imports, dead_code)]

#[cfg(feature = "std")]
pub use crate::{internal::Provider, security::*, types::*, utils::*};

#[cfg(feature = "std")]
pub use engine::runtime::MemoryError;

#[cfg(feature = "std")]
pub(crate) use crate::sync::SnapshotHierarchy;

#[cfg(feature = "std")]
pub mod types;

#[cfg(feature = "std")]
pub mod internal;

#[cfg(feature = "std")]
pub mod security;

#[cfg(feature = "std")]
pub mod procedures;

#[cfg(feature = "std")]
pub mod sync;

// is this std?
#[cfg(feature = "std")]
pub mod utils;

#[cfg(feature = "std")]
#[cfg(test)]
mod tests;

#[macro_use]
mod stm;

// macros

// #[macro_export]
// macro_rules! enum_from_inner {
//     ($($Enum:ident$(::<$G:ident>)?::$T:ident),+ $MEnum:ident$(::<$H:ident>)?::$MT:ident from $CEnum:ty) => {
//         impl$(<H>)? From<$CEnum> for $MEnum$(<H>)? {
//             fn from(t: $CEnum) -> Self {
//                 $MEnum::$MT(t.into())
//             }
//         }
//         $(
//             impl$(<$G>)? From<$CEnum> for $Enum$(<$G>)? {
//                 fn from(t: $CEnum) -> Self {
//                     let m: $MEnum$(<H>)? = t.into()
//                     $Enum::$T(m.into())
//                 }
//             }
//         )*
//     };
//     ($($Enum:ident$(::<$G:ident>)?::$T:ident),+ from $CEnum:ty) => {
//         $(
//             impl$(<$G>)? From<$CEnum> for $Enum$(<$G>)? {
//                 fn from(t: $CEnum) -> Self {
//                     $Enum::$T(t.into())
//                 }
//             }
//         )*
//     };
//     ($Enum:ident$(<$G:ident>)? from $TInner:ident$(<$H:ident>)?) => {
//         impl$(<$G>)? From<$TInner$(<$H>)?> for $Enum$(<$G>)? {
//             fn from(t: $TInner$(<$H>)?) -> Self {
//                 $Enum::$TInner(t)
//             }
//         }
//     };
// }
