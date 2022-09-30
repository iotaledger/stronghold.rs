use crate::stm::error::TxError;
use std::fmt::Debug;
use std::collections::{HashSet, HashMap};
use crate::types::{Client, Snapshot};
use engine::vault::ClientId;

/// The different types that can be encapsulated in a TVAr
#[derive(Clone, Debug)]
pub enum SharedValue {
    SharedUsize(usize),
    SharedString(String),
    SharedHashSetOfString(HashSet<String>),
    SharedVectorOfString(Vec<String>),
    SharedVectorOfUsize(Vec<usize>),
    SharedClients(HashMap<ClientId, Client>),
    SharedSnapshot(Snapshot)
}
use SharedValue::*;

// Macro to implement the trait [`TryFrom`] for the variants of [`SharedValue`]
#[macro_export]
macro_rules! impl_try_from {
    ( $type:ty, $variant:ident ) => {
            impl TryFrom<SharedValue> for $type {
                type Error = TxError;

                fn try_from(value: SharedValue) -> Result<Self, Self::Error> {
                    match value {
                        $variant(v) => Ok(v),
                        _ => Err(TxError::SharedValueWrongTypeConversion)
                    }
                }
            }
    };
}

impl_try_from!(usize, SharedUsize);
impl_try_from!(String, SharedString);
impl_try_from!(HashSet<String>, SharedHashSetOfString);
impl_try_from!(Vec<String>, SharedVectorOfString);
impl_try_from!(Vec<usize>, SharedVectorOfUsize);
impl_try_from!(HashMap<ClientId, Client>, SharedClients);
impl_try_from!(Snapshot, SharedSnapshot);
