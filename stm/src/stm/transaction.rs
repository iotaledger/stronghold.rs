// Copyright 2020-2022 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::stm::{error::TxError, shared_value::SharedValue, tvar::*};
use std::{
    collections::{HashMap, HashSet},
    sync::MutexGuard,
};

pub struct Transaction {
    /// Transaction id
    pub id: usize,

    /// A snapshot of the global version counter
    pub version: usize,

    /// All the tvars involved in the transaction during speculative
    /// execution. If value is `None` it means that the tvar was only
    /// loaded. If a new value was stored into the tvar it will be stored
    /// in the hashmap
    tvars_used: HashSet<TVar>,

    tvars_new_values: HashMap<TVar, SharedValue>,
}

impl Transaction {
    pub fn new(version: usize, id: usize) -> Self {
        Self {
            version,
            tvars_used: HashSet::new(),
            tvars_new_values: HashMap::new(),
            id,
        }
    }

    /// this writes the value into the transactional log
    // TODO this erases the information that the tvar may have been read
    pub fn store(&mut self, tvar: &TVar, value: SharedValue) -> Result<(), TxError> {
        self.tvars_used.insert(tvar.clone());
        self.tvars_new_values.insert(tvar.clone(), value);
        Ok(())
    }

    /// This function loads the value from the transactional variable ([`TVar`])
    /// and checks
    /// for version consistency. If the value is present in a write set, this to-be-written value
    /// will be returned.
    pub fn load<T>(&mut self, tvar: &TVar) -> Result<T, TxError>
    where
        T: TryFrom<SharedValue, Error = TxError> + Clone,
    {
        self.tvars_used.insert(tvar.clone());

        // If the value was updated before in the transaction
        let was_tvar_used = self.tvars_new_values.contains_key(tvar);
        if was_tvar_used {
            let tvar_value = self.tvars_new_values.get(tvar).unwrap();
            return T::try_from(tvar_value.clone());
        }

        // Else take the value from the tvar
        let data = tvar.try_get_data()?;
        let version = tvar.try_get_version()?;
        self.check_tvar_version(version)?;
        Ok(data)
    }

    /// Try to lock all the tvar used during speculative execution
    /// Also return the new values from the speculative execution associated
    /// to the tvars
    // NOTE: paper says to only validate updated tvars but this is fishy. In
    //       this scenario we suspect potential race condition when
    //       validating only_read tvars later in the process
    pub(crate) fn lock_tvars_used(&self) -> Result<(Vec<MutexGuard<'_, TVarData>>, Vec<Option<SharedValue>>), TxError> {
        let mut locks = vec![];
        let mut values: Vec<Option<SharedValue>> = vec![];
        for tvar in self.tvars_used.iter() {
            locks.push(tvar.bounded_lock()?);
            let new_value = self.tvars_new_values.get(tvar).cloned();
            values.push(new_value);
        }
        Ok((locks, values))
    }

    /// Check that each tvar used has a tvar version lower or equal
    /// to the transaction version
    pub(crate) fn validate<'a>(&self, locks: &Vec<MutexGuard<'a, TVarData>>) -> Result<(), TxError> {
        for lock in locks {
            let tvar_version = lock.version;
            self.check_tvar_version(tvar_version)?;
        }
        Ok(())
    }

    /// Commit the transaction
    /// - Update each TVar with value from the write set
    /// - Update each TVar version lock with wv
    /// - Release each TVar lock
    pub(crate) fn commit(
        &self,
        wv: usize,
        locks: Vec<MutexGuard<'_, TVarData>>,
        values: Vec<Option<SharedValue>>,
    ) -> Result<(), TxError> {
        for (mut lock, value) in locks.into_iter().zip(values.into_iter()) {
            if let Some(value) = value {
                lock.value = value;
                lock.version = wv;
            }
        }
        Ok(())
    }

    /// Check that the transaction version is superior or equal to
    /// the tvar version
    fn check_tvar_version(&self, tvar_version: usize) -> Result<(), TxError> {
        if self.version >= tvar_version {
            Ok(())
        } else {
            Err(TxError::VersionMismatch)
        }
    }
}
