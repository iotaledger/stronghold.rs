// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{marker::PhantomData, ops::Deref};

use engine::{
    runtime::GuardedVec,
    vault::{BoxProvider, RecordHint, RecordId, VaultId},
};

// ==========================
// Traits
// ==========================

trait GetSourceVault {
    fn get_source(&self) -> (VaultId, RecordId);
}

trait GetTargetVault {
    fn get_target(&self) -> (VaultId, RecordId, RecordHint);
}

trait ExecProc<I, O, G, W> {
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: I) -> Result<O, engine::Error>;
}

trait ProcExecutor {
    fn exec_on_guarded<F, I, O, W>(
        &mut self,
        vault_id: VaultId,
        record_id: RecordId,
        f: F,
        input: I,
    ) -> Result<(W, O), engine::Error>
    where
        F: FnOnce(GuardedVec<u8>, I) -> Result<(W, O), engine::Error>;

    fn write_to_vault(
        &mut self,
        vault_id: VaultId,
        record_id: RecordId,
        hint: RecordHint,
        value: Vec<u8>,
    ) -> Result<(), engine::Error>;
}

// ==========================
// Primitive Procs
// ==========================

struct PrimitiveProc<F, I, O, G, W>
where
    F: FnOnce(G, I) -> Result<(W, O), engine::Error>,
{
    f: F,
    location_0: Option<(VaultId, RecordId)>,
    location_1: Option<(VaultId, RecordId, RecordHint)>,
    _marker: (PhantomData<I>, PhantomData<O>, PhantomData<G>, PhantomData<W>),
}

impl<F, I, O, G, W> PrimitiveProc<F, I, O, G, W>
where
    F: FnOnce(G, I) -> Result<(W, O), engine::Error>,
    Self: ExecProc<I, O, G, W>,
{
    fn into_complex(self) -> ComplexProc<Self, I, O, G, W> {
        ComplexProc {
            proc: self,
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

// A PrimitiveProc<_, _, _, GuardedVec<u8>, _> can only be created via Processor::new or Sink::new, in both cases there
// is a location_0 / source-vault.
impl<F, I, O, W> GetSourceVault for PrimitiveProc<F, I, O, GuardedVec<u8>, W>
where
    F: FnOnce(GuardedVec<u8>, I) -> Result<(W, O), engine::Error>,
{
    fn get_source(&self) -> (VaultId, RecordId) {
        self.location_0.unwrap()
    }
}

// A PrimitiveProc<_, _, _, _, Vec<u8>> can only be created via Generator::new or Processor::new, in both cases there is
// a location_1 / target-vault.
impl<F, I, O, G> GetTargetVault for PrimitiveProc<F, I, O, G, Vec<u8>>
where
    F: FnOnce(G, I) -> Result<(Vec<u8>, O), engine::Error>,
{
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        self.location_1.unwrap()
    }
}

impl<F, I, O, G, W> ExecProc<I, O, G, W> for PrimitiveProc<F, I, O, G, W>
where
    F: FnOnce(G, I) -> Result<(W, O), engine::Error>,
    Self: ExecOnGuard<I, O, W> + WriteVault<W>,
{
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: I) -> Result<O, engine::Error> {
        let (write_vault, output) = self.exec_on_guard(executor, input)?;
        self.write_secret(executor, write_vault)?;
        Ok(output)
    }
}

trait ExecOnGuard<I, O, W> {
    fn exec_on_guard<PExe: ProcExecutor>(&self, executor: &mut PExe, input: I) -> Result<(W, O), engine::Error>;
}

impl<F, I, O, W> ExecOnGuard<I, O, W> for PrimitiveProc<F, I, O, (), W>
where
    F: FnOnce((), I) -> Result<(W, O), engine::Error>,
{
    fn exec_on_guard<PExe: ProcExecutor>(&self, _: &mut PExe, input: I) -> Result<(W, O), engine::Error> {
        let f = self.f;
        f((), input)
    }
}

impl<F, I, O, W> ExecOnGuard<I, O, W> for PrimitiveProc<F, I, O, GuardedVec<u8>, W>
where
    F: FnOnce(GuardedVec<u8>, I) -> Result<(W, O), engine::Error>,
    Self: GetSourceVault,
{
    fn exec_on_guard<PExe: ProcExecutor>(&self, executor: &mut PExe, input: I) -> Result<(W, O), engine::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        executor.exec_on_guarded(vault_id_0, record_id_0, self.f, input)
    }
}

trait WriteVault<W> {
    fn write_secret<PExe: ProcExecutor>(&self, executor: &mut PExe, value: W) -> Result<(), engine::Error>;
}

impl<F, I, O, G> WriteVault<()> for PrimitiveProc<F, I, O, G, ()>
where
    F: FnOnce(G, I) -> Result<((), O), engine::Error>,
{
    fn write_secret<PExe: ProcExecutor>(&self, executor: &mut PExe, value: ()) -> Result<(), engine::Error> {
        Ok(())
    }
}

impl<F, I, O, G> WriteVault<Vec<u8>> for PrimitiveProc<F, I, O, G, Vec<u8>>
where
    F: FnOnce(G, I) -> Result<(Vec<u8>, O), engine::Error>,
    Self: GetTargetVault,
{
    fn write_secret<PExe: ProcExecutor>(&self, executor: &mut PExe, value: Vec<u8>) -> Result<(), engine::Error> {
        let (vault_id, record_id, hint) = self.get_target();
        executor.write_to_vault(vault_id, record_id, hint, value)
    }
}

// ==========================
// Primitive Proc Types
// ==========================

// No secret used, no new secret created
type PlainProc<F, I, O> = PrimitiveProc<F, I, O, (), ()>;

impl<F, I, O> PlainProc<F, I, O>
where
    F: FnOnce((), I) -> Result<((), O), engine::Error>,
{
    fn new(f: F) -> Self {
        Self {
            f,
            location_0: None,
            location_1: None,
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

// No secret used, create new secret in vault
type Generator<F, I, O> = PrimitiveProc<F, I, O, (), Vec<u8>>;

impl<F, I, O> Generator<F, I, O>
where
    F: FnOnce((), I) -> Result<(Vec<u8>, O), engine::Error>,
{
    fn new(f: F, vault_id_1: VaultId, record_id_1: RecordId, hint: RecordHint) -> Self {
        Self {
            f,
            location_0: None,
            location_1: Some((vault_id_1, record_id_1, hint)),
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

// Existing secret used, no new secret created
type Processor<F, I, O> = PrimitiveProc<F, I, O, GuardedVec<u8>, Vec<u8>>;

impl<F, I, O> Processor<F, I, O>
where
    F: FnOnce(GuardedVec<u8>, I) -> Result<(Vec<u8>, O), engine::Error>,
{
    fn new(
        f: F,
        vault_id_0: VaultId,
        record_id_0: RecordId,
        vault_id_1: VaultId,
        record_id_1: RecordId,
        hint: RecordHint,
    ) -> Self {
        Self {
            f,
            location_0: Some((vault_id_0, record_id_0)),
            location_1: Some((vault_id_1, record_id_1, hint)),
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

// Existing secret used, no new secret created
type Sink<F, I, O> = PrimitiveProc<F, I, O, GuardedVec<u8>, ()>;

impl<F, I, O> Sink<F, I, O>
where
    F: FnOnce(GuardedVec<u8>, I) -> Result<((), O), engine::Error>,
{
    fn new(f: F, vault_id_0: VaultId, record_id_0: RecordId) -> Self {
        Self {
            f,
            location_0: Some((vault_id_0, record_id_0)),
            location_1: None,
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

// ==========================
// Complex Proc
// ==========================

struct ComplexProc<P: ExecProc<I, O, G, W>, I, O, G, W> {
    proc: P,
    _marker: (PhantomData<I>, PhantomData<O>, PhantomData<G>, PhantomData<W>),
}

impl<P, I, O, G, W> Deref for ComplexProc<P, I, O, G, W>
where
    P: ExecProc<I, O, G, W> + GetSourceVault,
{
    type Target = P;
    fn deref(&self) -> &Self::Target {
        &self.proc
    }
}

impl<P: ExecProc<I, O, G, W>, I, O, G, W> ExecProc<I, O, G, W> for ComplexProc<P, I, O, G, W> {
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: I) -> Result<O, engine::Error> {
        self.proc.exec(executor, input)
    }
}

// ==========================
// Example for a Combinator
// ==========================

impl<P, I, O, G> ComplexProc<P, I, O, G, Vec<u8>>
where
    P: ExecProc<I, O, G, Vec<u8>> + GetTargetVault,
{
    fn and_then<F, O1>(self, other: F) -> ComplexProc<ChainedProc<P, Sink<F, O, O1>, I, O, O1, G, ()>, I, O1, G, ()>
    where
        F: FnOnce(GuardedVec<u8>, O) -> Result<((), O1), engine::Error>,
    {
        let (vault_id, record_id, _) = self.proc.get_target();
        let proc_1 = Sink::new(other, vault_id, record_id);
        ComplexProc {
            proc: ChainedProc {
                proc_0: self,
                proc_1,
                _marker: (PhantomData, PhantomData, PhantomData),
            },
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

struct ChainedProc<P, P1, I, O, O1, G, W1>
where
    P: ExecProc<I, O, G, Vec<u8>> + GetTargetVault,
    P1: ExecProc<O, O1, GuardedVec<u8>, W1>,
{
    proc_0: ComplexProc<P, I, O, G, Vec<u8>>,
    proc_1: P1,
    _marker: (PhantomData<G>, PhantomData<O1>, PhantomData<W1>),
}

impl<P, P1, I, O, O1, G, W1> ExecProc<I, O1, G, W1> for ChainedProc<P, P1, I, O, O1, G, W1>
where
    P: ExecProc<I, O, G, Vec<u8>> + GetTargetVault,
    P1: ExecProc<O, O1, GuardedVec<u8>, W1>,
{
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: I) -> Result<O1, engine::Error> {
        let out = self.proc_0.exec(executor, input)?;
        self.proc_1.exec(executor, out)
    }
}

// ==========================
// Example Applications
// ==========================

mod test {
    use engine::vault::{DbView, Key};

    use crate::state::key_store::KeyStore;

    use super::*;

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
    struct MockProvider;

    impl BoxProvider for MockProvider {
        fn box_key_len() -> usize {
            todo!()
        }
        fn box_overhead() -> usize {
            todo!()
        }
        fn box_seal(key: &Key<Self>, ad: &[u8], data: &[u8]) -> engine::Result<Vec<u8>> {
            todo!()
        }
        fn box_open(key: &Key<Self>, ad: &[u8], data: &[u8]) -> engine::Result<Vec<u8>> {
            todo!()
        }
        fn random_buf(buf: &mut [u8]) -> engine::Result<()> {
            todo!()
        }
    }

    struct ProcedureExecutor {
        db: DbView<MockProvider>,
        keystore: KeyStore<MockProvider>,
    }
    impl ProcedureExecutor {
        fn new() -> Self {
            todo!()
        }
    }
    impl ProcExecutor for ProcedureExecutor {
        fn exec_on_guarded<F, I, O, W>(
            &mut self,
            vault_id: VaultId,
            record_id: RecordId,
            f: F,
            input: I,
        ) -> Result<(W, O), engine::Error>
        where
            F: FnOnce(GuardedVec<u8>, I) -> Result<(W, O), engine::Error>,
        {
            let key = self.keystore.get_key(vault_id);
            if let Some(pkey) = key.as_ref() {
                self.keystore.insert_key(vault_id, pkey.clone());
            };
            let key = key.ok_or(engine::Error::OtherError("Not existing".to_string()))?;
            let mut ret = None;
            self.db.get_guard(&key, vault_id, record_id, |guard: GuardedVec<u8>| {
                let r = f(guard, input);
                ret = Some(r);
                Ok(())
            })?;
            ret.unwrap()
        }

        fn write_to_vault(
            &mut self,
            vault_id: VaultId,
            record_id: RecordId,
            hint: RecordHint,
            value: Vec<u8>,
        ) -> Result<(), engine::Error> {
            let key = if !self.keystore.vault_exists(vault_id) {
                let k = self.keystore.create_key(vault_id);
                self.db.init_vault(&k, vault_id)?;
                k
            } else {
                let k = self
                    .keystore
                    .get_key(vault_id)
                    .ok_or(engine::Error::OtherError("Not existing".to_string()))?;
                k
            };
            self.db.write(&key, vault_id, record_id, &value, hint)
        }
    }

    fn generate_secret<T>(_: (), data: T) -> Result<(Vec<u8>, T), engine::Error> {
        Ok(("Super secret Secret".as_bytes().to_vec(), data))
    }

    struct DummyCipher;

    impl DummyCipher {
        fn encrypt(guard: GuardedVec<u8>, data: String) -> Result<((), String), engine::Error> {
            Ok(((), data))
        }
    }

    fn main() {
        let mut executor = ProcedureExecutor::new();

        let encrypt_string = "This is my message".to_string();
        let vault_id = VaultId::random::<MockProvider>().unwrap();
        let record_id = RecordId::random::<MockProvider>().unwrap();
        let hint = RecordHint::new("".as_bytes()).unwrap();

        let proc = Generator::new(generate_secret, vault_id, record_id, hint)
            .into_complex()
            .and_then(DummyCipher::encrypt);
        let res = proc.exec(&mut executor, encrypt_string).unwrap();
    }
}
