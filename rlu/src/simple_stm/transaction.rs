use crate::simple_stm::error::TxError;
use crate::simple_stm::tvar::*;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::{MutexGuard};
// use log::*;

pub struct Transaction<T>
where
    T: Clone + Debug,
{
    /// Transaction id
    pub(crate) id: usize,

    /// A snapshot of the global version counter
    pub(crate) version: usize,

    /// All the tvars involved in the transaction during speculative
    /// execution. If value is `None` it means that the tvar was only
    /// loaded. If a new value was stored into the tvar it will be stored
    /// in the hashmap
    // TODO improve and have different treatment for tvars that have only
    //      been read and not been updated
    pub(crate) tvars_used: HashSet<TVar<T>>,

    pub(crate) tvars_new_values: HashMap<TVar<T>, T>,
}

impl<T> Transaction<T>
where
    T: Clone + Debug,
{
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
    pub fn store(&mut self, tvar: &TVar<T>, value: T) -> Result<(), TxError> {
        self.tvars_used.insert(tvar.clone());
        self.tvars_new_values.insert(tvar.clone(), value);
        Ok(())
    }

    /// This function loads the value from the transactional variable ([`TVar`])
    /// and checks
    /// for version consistency. If the value is present in a write set, this to-be-written value
    /// will be returned.
    pub fn load(&mut self, tvar: &TVar<T>) -> Result<T, TxError> {
        self.tvars_used.insert(tvar.clone());

        // If the value was updated before in the transaction
        let was_tvar_used = self.tvars_new_values.contains_key(tvar);
        if was_tvar_used {
            let tvar_value: &T = self.tvars_new_values.get(tvar).unwrap();
            return Ok(tvar_value.clone());
        }

        // Else take the value from the tvar
        let data = tvar.try_get_data()?;
        let version = tvar.try_get_version()?;
        self.check_tvar_version(version).map(|_| data)
    }

    /// Try to lock all the tvar used during speculative execution
    /// Also return the new values from the speculative execution associated
    /// to the tvars
    pub(crate) fn lock_tvars_used(&self) -> Result<(Vec<MutexGuard<'_, TVarData<T>>>, Vec<Option<T>>), TxError> {
        let mut locks = vec![];
        let mut values: Vec<Option<T>> = vec![];
        for tvar in self.tvars_used.iter() {
            locks.push(tvar.bounded_lock()?);
            let new_value = self.tvars_new_values.get(tvar).map(|value| value.clone());
            values.push(new_value);
        }
        Ok((locks, values))
    }

    /// Check each tvar of the read set:
    /// - not locked by another thread
    /// - tvar version is lower or equal to transaction version
    // TODO currently all the tvar is locked by the transaction we just need
    //      to check the version
    // TODO add optmization which does not require any checks if
    //      stm_write_version = tx.version + 1
    pub(crate) fn validate<'a>(&self, locks: &Vec<MutexGuard<'a, TVarData<T>>>) -> Result<(), TxError> {
        for lock in locks {
            let tvar_version = lock.version;
            self.check_tvar_version(tvar_version)?;
        }
        Ok(())

        // Check that tvar is not locked by another thread
        // let is_tvar_locked = tvar.try_lock().is_err();
        // let is_tvar_locked_by_tx = self.write.contains_key(&tvar);
        // let is_tvar_locked_by_another = is_tvar_locked && !is_tvar_locked_by_tx;
        // if is_tvar_locked_by_another {
        //     return Err(TxError::LockPresent)
        // }
    }

    /// Commit the transaction
    /// - Update each TVar with value from the write set
    /// - Update each TVar version lock with wv
    /// - Release each TVar lock
    pub(crate) fn commit<'a>(&self, wv: usize, locks: Vec<MutexGuard<'a, TVarData<T>>>, values: Vec<Option<T>>) -> Result<(), TxError>{
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
