// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, RecordId, VaultId},
};
mod combine;
pub use combine::*;
mod primitives;
pub use primitives::*;
use stronghold_utils::GuardDebug;

// ==========================
// Traits
// ==========================

#[derive(GuardDebug)]
pub struct BuildProcedure<P: ExecProc<InData = ()>> {
    pub(crate) inner: P,
}

impl<P: ExecProc<InData = ()> + 'static> Message for BuildProcedure<P> {
    type Result = Result<P::OutData, anyhow::Error>;
}

pub trait ExecProc {
    type InData;
    type OutData;
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: Self::InData)
        -> Result<Self::OutData, anyhow::Error>;
}

pub trait ProcExecutor {
    fn exec_on_guarded<DIn, DOut, VOut>(
        &mut self,
        vault_id: VaultId,
        record_id: RecordId,
        f: &ProcFn<DIn, DOut, GuardedVec<u8>, VOut>,
        input: DIn,
    ) -> Result<ProcFnResult<DOut, VOut>, anyhow::Error>;

    fn write_to_vault(
        &mut self,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
        value: Vec<u8>,
    ) -> Result<(), anyhow::Error>;
}

trait GetSourceVault {
    fn get_source(&self) -> (VaultId, RecordId);
}

pub trait GetTargetVault {
    fn get_target(&self) -> (VaultId, RecordId, RecordHint);
}

impl<T, U> GetSourceVault for T
where
    U: GetSourceVault,
    T: Deref<Target = U>,
{
    fn get_source(&self) -> (VaultId, RecordId) {
        self.deref().get_source()
    }
}

impl<T, U> GetTargetVault for T
where
    U: GetTargetVault,
    T: Deref<Target = U>,
{
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        self.deref().get_target()
    }
}

// ==========================
// Example Application
// ==========================

mod test {
    use crate::{Location, Stronghold};

    use super::*;

    async fn main() {
        let cp = "test client".into();
        let sh = Stronghold::init_stronghold_system(cp, vec![]).await.unwrap();

        let slip10_generate = Slip10Generate {
            size_bytes: 64,
            location: Location::generic("v1", "r1"),
            hint: RecordHint::new("".as_bytes()).unwrap(),
        }
        .into_proc()
        .build();

        let _res = sh.runtime_exec(slip10_generate).await;
    }
}
