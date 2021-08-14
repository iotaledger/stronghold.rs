// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{actors::SecureClient, Location, SLIP10DeriveInput};

use super::{BuildProcedure, ExecProc, GetSourceVault, GetTargetVault, ProcExecutor};
use crypto::{
    keys::{
        bip39,
        slip10::{self, Chain, ChainCode},
    },
    signatures::ed25519,
    utils::rand::fill,
};
use engine::{
    runtime::GuardedVec,
    vault::{RecordHint, RecordId, VaultId},
};
use std::convert::TryFrom;

// ==========================
// Primitive Proc
// ==========================

pub struct ProcFnResult<DOut, VOut> {
    write_vault: VOut,
    return_value: DOut,
}

pub type ProcFn<DIn, DOut, GIn, VOut> = Box<dyn Send + Fn(GIn, DIn) -> Result<ProcFnResult<DOut, VOut>, anyhow::Error>>;

pub struct PrimitiveProc<DIn, DOut, GIn, VOut> {
    f: ProcFn<DIn, DOut, GIn, VOut>,
    location_0: Option<(VaultId, RecordId)>,
    location_1: Option<(VaultId, RecordId, RecordHint)>,
}

impl<DOut, GIn, VOut> PrimitiveProc<(), DOut, GIn, VOut>
where
    Self: ExecProc<InData = ()>,
{
    pub fn build(self) -> BuildProcedure<Self> {
        BuildProcedure { inner: self }
    }
}

// ==========================
// Primitive Proc Types
// ==========================

// ---------------
//=== No secret used, create new secret in vault
// ---------------

pub type Generator<DIn, DOut> = PrimitiveProc<DIn, DOut, (), Vec<u8>>;

// impl ExecProc + GetTargetVault for Generator {}

impl<DOut> Generator<(), DOut> {
    pub(crate) fn new<F>(f: F, vault_id_1: VaultId, record_id_1: RecordId, hint: RecordHint) -> Self
    where
        F: Fn(()) -> Result<ProcFnResult<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
    {
        let f = move |(), _| f(());
        Self {
            f: Box::new(f),
            location_0: None,
            location_1: Some((vault_id_1, record_id_1, hint)),
        }
    }
}

impl<DIn, DOut> Generator<DIn, DOut> {
    pub(crate) fn new_with_input<F>(f: F, vault_id_1: VaultId, record_id_1: RecordId, hint: RecordHint) -> Self
    where
        F: Fn((), DIn) -> Result<ProcFnResult<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
    {
        Self {
            f: Box::new(f),
            location_0: None,
            location_1: Some((vault_id_1, record_id_1, hint)),
        }
    }
}

// ---------------
//=== Existing secret used, new secret created
// ---------------

pub type Processor<DIn, DOut> = PrimitiveProc<DIn, DOut, GuardedVec<u8>, Vec<u8>>;

// impl ExecProc + GetSourceVault + GetTargetVault for Processor {}

impl<DOut> Processor<(), DOut> {
    pub(crate) fn new<F>(
        f: F,
        vault_id_0: VaultId,
        record_id_0: RecordId,
        vault_id_1: VaultId,
        record_id_1: RecordId,
        hint: RecordHint,
    ) -> Self
    where
        F: Fn(GuardedVec<u8>) -> Result<ProcFnResult<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
    {
        let f = move |guard, _| f(guard);
        Self {
            f: Box::new(f),
            location_0: Some((vault_id_0, record_id_0)),
            location_1: Some((vault_id_1, record_id_1, hint)),
        }
    }
}

impl<DIn, DOut> Processor<DIn, DOut> {
    pub(crate) fn new_with_input<F>(
        f: F,
        vault_id_0: VaultId,
        record_id_0: RecordId,
        vault_id_1: VaultId,
        record_id_1: RecordId,
        hint: RecordHint,
    ) -> Self
    where
        F: Fn(GuardedVec<u8>, DIn) -> Result<ProcFnResult<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
    {
        Self {
            f: Box::new(f),
            location_0: Some((vault_id_0, record_id_0)),
            location_1: Some((vault_id_1, record_id_1, hint)),
        }
    }
}
// ---------------
//=== Existing secret used, no new secret created
// ---------------

pub type Sink<DIn, DOut> = PrimitiveProc<DIn, DOut, GuardedVec<u8>, ()>;

// impl ExecProc + GetSourceVault for Sink {}

impl<DOut> Sink<(), DOut> {
    pub(crate) fn new<F>(f: F, vault_id_0: VaultId, record_id_0: RecordId) -> Self
    where
        F: Fn(GuardedVec<u8>) -> Result<ProcFnResult<DOut, ()>, anyhow::Error> + 'static + Send + Sync,
    {
        let f = move |guard, _| f(guard);
        Self {
            f: Box::new(f),
            location_0: Some((vault_id_0, record_id_0)),
            location_1: None,
        }
    }
}

impl<DIn, DOut> Sink<DIn, DOut> {
    pub(crate) fn new_with_input<F>(f: F, vault_id_0: VaultId, record_id_0: RecordId) -> Self
    where
        F: Fn(GuardedVec<u8>, DIn) -> Result<ProcFnResult<DOut, ()>, anyhow::Error> + 'static + Send + Sync,
    {
        Self {
            f: Box::new(f),
            location_0: Some((vault_id_0, record_id_0)),
            location_1: None,
        }
    }
}

// ==========================
// Trait implementations
// ==========================

impl<DIn, DOut> ExecProc for Generator<DIn, DOut> {
    type InData = DIn;
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, anyhow::Error> {
        let (vault_id_1, record_id_1, hint) = self.get_target();
        let f = self.f;
        let ProcFnResult {
            write_vault,
            return_value,
        } = f((), input)?;
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(return_value)
    }
}

impl<DIn, DOut> ExecProc for Processor<DIn, DOut> {
    type InData = DIn;
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, anyhow::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let ProcFnResult {
            write_vault,
            return_value,
        } = executor.exec_on_guarded(vault_id_0, record_id_0, &self.f, input)?;
        let (vault_id_1, record_id_1, hint) = self.get_target();
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(return_value)
    }
}

impl<DIn, DOut> ExecProc for Sink<DIn, DOut> {
    type InData = DIn;
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, anyhow::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let ProcFnResult {
            write_vault: (),
            return_value,
        } = executor.exec_on_guarded(vault_id_0, record_id_0, &self.f, input)?;
        Ok(return_value)
    }
}

// A PrimitiveProc<_, _, _, GuardedVec<u8>, _> can only be created via Processor::new or Sink::new, in both cases there
// is a location_0 / source-vault.
impl<DIn, DOut, VOut> GetSourceVault for PrimitiveProc<DIn, DOut, GuardedVec<u8>, VOut> {
    fn get_source(&self) -> (VaultId, RecordId) {
        self.location_0.unwrap()
    }
}

// A PrimitiveProc<_, _, _, _, Vec<u8>> can only be created via Generator::new or Processor::new, in both cases there is
// a location_1 / target-vault.
impl<DIn, DOut, GIn> GetTargetVault for PrimitiveProc<DIn, DOut, GIn, Vec<u8>> {
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        self.location_1.unwrap()
    }
}

// ==========================
// Old Procedures
// ==========================

pub trait IntoProc {
    type InGuard;
    type OutData;
    type OutVault;
    fn into_proc(self) -> PrimitiveProc<(), Self::OutData, Self::InGuard, Self::OutVault>;
}

pub struct Slip10Generate {
    pub size_bytes: usize,
    pub location: Location,
    pub hint: RecordHint,
}

impl IntoProc for Slip10Generate {
    type InGuard = ();
    type OutData = ();
    type OutVault = Vec<u8>;

    fn into_proc(self) -> PrimitiveProc<(), Self::OutData, Self::InGuard, Self::OutVault> {
        let (vault_id, record_id) = SecureClient::resolve_location(self.location);
        let hint = self.hint;
        let size_bytes = self.size_bytes;
        let f = move |()| {
            let mut seed = vec![0u8; size_bytes];
            fill(&mut seed).map_err(|e| anyhow::anyhow!(e))?;

            let result = ProcFnResult {
                write_vault: seed,
                return_value: (),
            };
            Ok(result)
        };
        Generator::new(f, vault_id, record_id, hint)
    }
}

pub struct SLIP10Derive {
    pub chain: Chain,
    pub input: SLIP10DeriveInput,
    pub output: Location,
    pub hint: RecordHint,
}

impl IntoProc for SLIP10Derive {
    type InGuard = GuardedVec<u8>;
    type OutData = ChainCode;
    type OutVault = Vec<u8>;
    fn into_proc(self) -> PrimitiveProc<(), Self::OutData, Self::InGuard, Self::OutVault> {
        let (v_id_0, r_id_0) = match self.input {
            SLIP10DeriveInput::Key(parent) => SecureClient::resolve_location(parent),
            SLIP10DeriveInput::Seed(seed) => SecureClient::resolve_location(seed),
        };
        let (v_id_1, r_id_1) = SecureClient::resolve_location(self.output);
        let chain = self.chain;
        // TODO: create vault if missing
        let f = move |guard: GuardedVec<u8>| {
            let parent = slip10::Key::try_from(&*guard.borrow()).unwrap();
            let dk = parent.derive(&chain).unwrap();

            let data: Vec<u8> = dk.into();
            let result = ProcFnResult {
                write_vault: data,
                return_value: dk.chain_code(),
            };
            Ok(result)
        };
        Processor::new(f, v_id_0, r_id_0, v_id_1, r_id_1, self.hint)
    }
}

pub struct BIP39Generate {
    pub passphrase: String,
    pub output: Location,
    pub hint: RecordHint,
}

impl IntoProc for BIP39Generate {
    type InGuard = ();
    type OutData = ();
    type OutVault = Vec<u8>;

    fn into_proc(self) -> PrimitiveProc<(), Self::OutData, Self::InGuard, Self::OutVault> {
        let passphrase = self.passphrase;
        let f = move |()| {
            let mut entropy = [0u8; 32];
            if let Err(e) = fill(&mut entropy) {
                return Err(anyhow::anyhow!(e));
            }

            let mnemonic = match bip39::wordlist::encode(
                &entropy,
                &bip39::wordlist::ENGLISH, // TODO: make this user configurable
            ) {
                Ok(encoded) => encoded,
                Err(e) => {
                    return Err(anyhow::anyhow!(format!("{:?}", e)));
                }
            };

            let mut seed = [0u8; 64];
            bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

            let result = ProcFnResult {
                write_vault: seed.to_vec(),
                return_value: (),
            };
            Ok(result)
        };
        let (v_id_1, r_id_1) = SecureClient::resolve_location(self.output);
        Generator::new(f, v_id_1, r_id_1, self.hint)
    }
}

pub struct BIP39Recover {
    pub mnemonic: String,
    pub passphrase: String,
    pub output: Location,
    pub hint: RecordHint,
}

impl IntoProc for BIP39Recover {
    type InGuard = ();
    type OutData = ();
    type OutVault = Vec<u8>;

    fn into_proc(self) -> PrimitiveProc<(), Self::OutData, Self::InGuard, Self::OutVault> {
        let passphrase = self.passphrase;
        let mnemonic = self.mnemonic;
        let f = move |()| {
            let mut seed = [0u8; 64];
            bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);
            let result = ProcFnResult {
                write_vault: seed.to_vec(),
                return_value: (),
            };
            Ok(result)
        };
        let (v_id_1, r_id_1) = SecureClient::resolve_location(self.output);
        Generator::new(f, v_id_1, r_id_1, self.hint)
    }
}

pub struct Ed25519PublicKey {
    pub private_key: Location,
}

impl IntoProc for Ed25519PublicKey {
    type InGuard = GuardedVec<u8>;
    type OutData = [u8; crypto::signatures::ed25519::PUBLIC_KEY_LENGTH];
    type OutVault = ();

    fn into_proc(self) -> PrimitiveProc<(), Self::OutData, Self::InGuard, Self::OutVault> {
        let (v_id_0, r_id_0) = SecureClient::resolve_location(self.private_key);
        let f = |guard: GuardedVec<u8>| {
            let raw = guard.borrow();
            let mut raw = (*raw).to_vec();
            if raw.len() < 32 {
                // the client actor will interupt the control flow
                // but could this be an option to return an error
                let e = engine::Error::CryptoError(crypto::error::Error::BufferSize {
                    has: raw.len(),
                    needs: 32,
                    name: "data buffer",
                });
                return Err(anyhow::anyhow!(e));
            }
            raw.truncate(32);
            let mut bs = [0; 32];
            bs.copy_from_slice(&raw);

            let sk = ed25519::SecretKey::from_bytes(bs);
            let pk = sk.public_key();

            let result = ProcFnResult {
                write_vault: (),
                return_value: pk.to_bytes(),
            };
            Ok(result)
        };
        Sink::new(f, v_id_0, r_id_0)
    }
}

pub struct Ed25519Sign {
    pub private_key: Location,
    pub msg: Vec<u8>,
}

impl IntoProc for Ed25519Sign {
    type InGuard = GuardedVec<u8>;
    type OutData = [u8; crypto::signatures::ed25519::SIGNATURE_LENGTH];
    type OutVault = ();
    fn into_proc(self) -> PrimitiveProc<(), Self::OutData, Self::InGuard, Self::OutVault> {
        let (v_id_0, r_id_0) = SecureClient::resolve_location(self.private_key);
        let msg = self.msg;
        let f = move |guard: GuardedVec<u8>| {
            let raw = guard.borrow();
            let mut raw = (*raw).to_vec();

            if raw.len() <= 32 {
                let e = engine::Error::CryptoError(crypto::error::Error::BufferSize {
                    has: raw.len(),
                    needs: 32,
                    name: "data buffer",
                });
                return Err(anyhow::anyhow!(e));
            }
            raw.truncate(32);
            let mut bs = [0; 32];
            bs.copy_from_slice(&raw);

            let sk = ed25519::SecretKey::from_bytes(bs);

            let sig = sk.sign(&msg);
            let result = ProcFnResult {
                write_vault: (),
                return_value: sig.to_bytes(),
            };
            Ok(result)
        };
        Sink::new(f, v_id_0, r_id_0)
    }
}
