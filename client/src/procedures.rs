// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use actix::Message;
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, VaultId},
};
mod combine;
pub use combine::*;
mod primitives;
pub use primitives::*;
use stronghold_utils::GuardDebug;

use crate::Location;

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
    fn get_guard<F, In, Out>(&mut self, location0: Location, f: F, input: In) -> Result<Out, anyhow::Error>
    where
        F: FnOnce(In, GuardedVec<u8>) -> Result<Out, engine::Error>;

    fn create_vault(&mut self, vault_id: VaultId);

    fn exec_proc<F, In, Out>(
        &mut self,
        location0: Location,
        location1: Location,
        hint: RecordHint,
        f: F,
        input: In,
    ) -> Result<Out, anyhow::Error>
    where
        F: FnOnce(In, GuardedVec<u8>) -> Result<ProcOutput<Out>, engine::Error>;

    fn write_to_vault(&mut self, location1: Location, hint: RecordHint, value: Vec<u8>) -> Result<(), anyhow::Error>;
}

pub trait GetSourceVault {
    fn get_source(&self) -> Location;
}

pub trait GetTargetVault {
    fn get_target(&self) -> (Location, RecordHint);

    fn get_target_location(&self) -> Location {
        let (location, _) = self.get_target();
        location
    }
}

impl<T, U> GetSourceVault for T
where
    U: GetSourceVault,
    T: Deref<Target = U>,
{
    fn get_source(&self) -> Location {
        self.deref().get_source()
    }
}

impl<T, U> GetTargetVault for T
where
    U: GetTargetVault,
    T: Deref<Target = U>,
{
    fn get_target(&self) -> (Location, RecordHint) {
        self.deref().get_target()
    }
}

// ==========================
// Example Application
// ==========================

mod test {
    use crypto::keys::slip10::Chain;

    use crate::{SLIP10DeriveInput, Stronghold};

    use super::*;

    async fn main() {
        let cp = "test client".into();
        let sh = Stronghold::init_stronghold_system(cp, vec![]).await.unwrap();

        let generate_seed = Slip10Generate {
            size_bytes: None,
            output: (Location::generic("0", "0"), RecordHint::new("seed".as_bytes()).unwrap()),
        };

        let derive_keypair = SLIP10Derive {
            chain: Chain::empty(),
            input: SLIP10DeriveInput::Seed(generate_seed.get_target_location()),
            output: (Location::generic("1", "1"), RecordHint::new("key".as_bytes()).unwrap()),
        };

        let sign_fixed_msg = Ed25519Sign {
            private_key: derive_keypair.get_target_location(),
            msg: String::from("My secret message").into(),
        };

        let sign_dynamic_msg = Ed25519SignDyn {
            private_key: derive_keypair.get_target_location(),
        };

        let gen_derive_sign = generate_seed
            .and_then(derive_keypair)
            .drop_output()
            .and_then(sign_fixed_msg)
            .and_then(sign_dynamic_msg)
            .build();

        let _res = sh.runtime_exec(gen_derive_sign).await;
    }
}
