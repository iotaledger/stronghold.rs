// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, VaultId},
};
mod combine;
pub use combine::*;
mod primitives;
use crate::{actors::SecureClient, Location, SLIP10DeriveInput};
pub use primitives::*;
use stronghold_utils::GuardDebug;

// ==========================
// Fundamental structs & traits
// ==========================

pub type CollectedOutput = HashMap<DataKey, Vec<u8>>;

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct DataKey(String);

impl DataKey {
    pub fn new<K: ToString>(key: K) -> Self {
        DataKey(key.to_string())
    }
}

pub struct ProcState {
    aggregated_data: HashMap<DataKey, (Vec<u8>, bool)>,
    write_vault_log: Vec<WriteVaultLog>,
}
impl ProcState {
    pub fn insert_data(&mut self, key: DataKey, value: Vec<u8>, is_temp: bool) {
        self.aggregated_data.insert(key, (value, is_temp));
    }

    pub fn get_data(&mut self, key: &DataKey) -> Result<Vec<u8>, anyhow::Error> {
        self.aggregated_data
            .get(key)
            .map(|(data, _)| data.clone())
            .ok_or_else(|| anyhow::anyhow!("Missing Data"))
    }

    pub fn add_log(&mut self, location: Location, is_temp: bool) {
        let log = WriteVaultLog { location, is_temp };
        self.write_vault_log.push(log)
    }
}

#[derive(Debug)]
pub struct WriteVaultLog {
    location: Location,
    is_temp: bool,
}

#[derive(GuardDebug)]
pub struct ComplexProc<P> {
    inner: P,
}

impl<P> ComplexProc<P>
where
    P: ExecProc,
{
    pub fn run<X: ProcExecutor>(self, executor: &mut X) -> Result<CollectedOutput, anyhow::Error> {
        let mut state = ProcState {
            aggregated_data: HashMap::new(),
            write_vault_log: Vec::new(),
        };
        match self.inner.exec(executor, &mut state) {
            Ok(()) => {
                // Delete temporary records
                let mut vaults = HashSet::new();
                for entry in state.write_vault_log {
                    if entry.is_temp {
                        let (v, _) = SecureClient::resolve_location(&entry.location);
                        let _ = executor.revoke_data(&entry.location);
                        vaults.insert(v);
                    }
                }
                for vault_id in vaults {
                    let _ = executor.garbage_collect(vault_id);
                }
                let mut collected = HashMap::new();
                for (k, (data, is_temp)) in state.aggregated_data.into_iter() {
                    if !is_temp {
                        collected.insert(k, data);
                    }
                }
                Ok(collected)
            }
            Err(e) => {
                // Rollback written data
                let mut vaults = HashSet::new();
                for entry in state.write_vault_log {
                    let (v, _) = SecureClient::resolve_location(&entry.location);
                    let _ = executor.revoke_data(&entry.location);
                    vaults.insert(v);
                }
                for vault_id in vaults {
                    let _ = executor.garbage_collect(vault_id);
                }
                Err(e)
            }
        }
    }
}

impl<P> Message for ComplexProc<P>
where
    P: ExecProc + 'static,
{
    type Result = Result<CollectedOutput, anyhow::Error>;
}

pub trait BuildProc<P> {
    fn build(self) -> ComplexProc<P>;
}

pub trait ExecProc: BuildProc<Self> + Sized {
    fn exec<X: ProcExecutor>(self, executor: &mut X, state: &mut ProcState) -> Result<(), anyhow::Error>;
}

pub trait ProcExecutor {
    fn get_guard<F, I, O>(&mut self, location0: &Location, f: F, input: I) -> Result<O, anyhow::Error>
    where
        F: FnOnce(I, GuardedVec<u8>) -> Result<O, engine::Error>;

    fn exec_proc<F, I, O>(
        &mut self,
        location0: &Location,
        location1: &Location,
        hint: RecordHint,
        f: F,
        input: I,
    ) -> Result<O, anyhow::Error>
    where
        F: FnOnce(I, GuardedVec<u8>) -> Result<ProcOutput<O>, engine::Error>;

    fn write_to_vault(&mut self, location1: &Location, hint: RecordHint, value: Vec<u8>) -> Result<(), anyhow::Error>;

    fn revoke_data(&mut self, location: &Location) -> Result<(), anyhow::Error>;

    fn garbage_collect(&mut self, vault_id: VaultId) -> Result<(), anyhow::Error>;
}

pub trait SourceVaultInfo {
    fn source_location(&self) -> &Location;
    fn source_location_mut(&mut self) -> &mut Location;
}

pub trait TargetVaultInfo {
    fn target_info(&self) -> &(Location, RecordHint, bool);

    fn target_info_mut(&mut self) -> &mut (Location, RecordHint, bool);

    fn target_location(&self) -> Location {
        let (location, _, _) = self.target_info();
        location.clone()
    }

    fn write_secret(mut self, location: Location, hint: RecordHint) -> Self
    where
        Self: Sized,
    {
        let target = self.target_info_mut();
        target.0 = location;
        target.1 = hint;
        target.2 = false;
        self
    }
}

pub trait InputDataInfo {
    type InData;
    fn input_info(&self) -> &InputData<Self::InData>;
    fn input_info_mut(&mut self) -> &mut InputData<Self::InData>;
}

pub trait OutputDataInfo {
    fn output_info(&self) -> &(DataKey, bool);
    fn output_info_mut(&mut self) -> &mut (DataKey, bool);

    fn output_key(&self) -> DataKey {
        let (k, _) = self.output_info();
        k.clone()
    }

    fn store_output(mut self, key: DataKey) -> Self
    where
        Self: Sized,
    {
        let info = self.output_info_mut();
        info.0 = key;
        info.1 = false;
        self
    }
}

impl SourceVaultInfo for Location {
    fn source_location(&self) -> &Location {
        self
    }
    fn source_location_mut(&mut self) -> &mut Location {
        self
    }
}
impl SourceVaultInfo for SLIP10DeriveInput {
    fn source_location(&self) -> &Location {
        match self {
            SLIP10DeriveInput::Seed(l) => l,
            SLIP10DeriveInput::Key(l) => l,
        }
    }

    fn source_location_mut(&mut self) -> &mut Location {
        match self {
            SLIP10DeriveInput::Seed(l) => l,
            SLIP10DeriveInput::Key(l) => l,
        }
    }
}

impl TargetVaultInfo for (Location, RecordHint, bool) {
    fn target_info(&self) -> &(Location, RecordHint, bool) {
        self
    }

    fn target_info_mut(&mut self) -> &mut (Location, RecordHint, bool) {
        self
    }
}

impl<T> InputDataInfo for InputData<T>
where
    T: Clone,
{
    type InData = T;
    fn input_info(&self) -> &InputData<Self::InData> {
        self
    }

    fn input_info_mut(&mut self) -> &mut InputData<Self::InData> {
        self
    }
}

impl OutputDataInfo for (DataKey, bool) {
    fn output_info(&self) -> &(DataKey, bool) {
        self
    }

    fn output_info_mut(&mut self) -> &mut (DataKey, bool) {
        self
    }
}
