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
    fn get_guard<F, In, Out>(
        &mut self,
        vault_id: VaultId,
        record_id: RecordId,
        f: F,
        input: In,
    ) -> Result<Out, anyhow::Error>
    where
        F: FnOnce(In, GuardedVec<u8>) -> Result<Out, engine::Error>;

    fn create_vault(&mut self, vault_id: VaultId);

    #[allow(clippy::too_many_arguments)]
    fn exec_proc<F, In, Out>(
        &mut self,
        vid0: VaultId,
        rid0: RecordId,
        vid1: VaultId,
        rid1: RecordId,
        hint: RecordHint,
        f: F,
        input: In,
    ) -> Result<Out, anyhow::Error>
    where
        F: FnOnce(In, GuardedVec<u8>) -> Result<ProcOutput<Out>, engine::Error>;

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
    use crypto::keys::slip10::Chain;

    use crate::{internals, Stronghold};

    use super::*;

    async fn main() {
        let cp = "test client".into();
        let sh = Stronghold::init_stronghold_system(cp, vec![]).await.unwrap();

        let seed_vault_id = VaultId::random::<internals::Provider>().unwrap();
        let seed_record_id = RecordId::random::<internals::Provider>().unwrap();
        let seed_hint = RecordHint::new("seed".as_bytes()).unwrap();

        let keypair_vault_id = VaultId::random::<internals::Provider>().unwrap();
        let keypair_record_id = RecordId::random::<internals::Provider>().unwrap();
        let keypair_hint = RecordHint::new("key".as_bytes()).unwrap();

        let generate_seed = Slip10Generate {
            size_bytes: 64,
            location: (seed_vault_id, seed_record_id, seed_hint),
        };

        let derive_keypair = SLIP10Derive {
            chain: Chain::empty(),
            input: (seed_vault_id, seed_record_id),
            output: (keypair_vault_id, keypair_record_id, keypair_hint),
        };

        let encrypt_msg: Vec<u8> = String::from("My secret message").into();

        let _sign_msg = Ed25519Sign {
            private_key: (keypair_vault_id, keypair_record_id),
        }
        .with_input(encrypt_msg);

        let gen_derive_sign = generate_seed.and_then(derive_keypair).build(); // .and_then(_sign_msg).build();

        let _res = sh.runtime_exec(gen_derive_sign).await;
    }
}
