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

type ProcFn<DIn, DOut, SIn, SOut> = Box<dyn Fn(SIn, DIn) -> Result<(SOut, DOut), engine::Error>>;

trait GetSourceVault {
    fn get_source(&self) -> (VaultId, RecordId);
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

trait GetTargetVault {
    fn get_target(&self) -> (VaultId, RecordId, RecordHint);
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

trait ExecProc {
    type InputData;
    type OutputData;
    type InputSecret; // GuardedVec<u8> | ()     impl<P: ExecProc<InputSecret = GuardedVec<u8>>> + GetSourceVault
    type OutputSecret; // Vec<u8> | ()
    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InputData,
    ) -> Result<Self::OutputData, engine::Error>;
}

trait ProcExecutor {
    fn exec_on_guarded<DIn, DOut, SOut>(
        &mut self,
        vault_id: VaultId,
        record_id: RecordId,
        f: &ProcFn<DIn, DOut, GuardedVec<u8>, SOut>,
        input: DIn,
    ) -> Result<(SOut, DOut), engine::Error>;

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

struct PrimitiveProc<DIn, DOut, SIn, SOut> {
    f: ProcFn<DIn, DOut, SIn, SOut>,
    location_0: Option<(VaultId, RecordId)>,
    location_1: Option<(VaultId, RecordId, RecordHint)>,
    _marker: (PhantomData<DIn>, PhantomData<DOut>, PhantomData<SIn>, PhantomData<SOut>),
}

impl<DIn, DOut, SIn, SOut> PrimitiveProc<DIn, DOut, SIn, SOut>
where
    Self: ExecProc<InputData = DIn, OutputData = DOut>,
{
    fn into_complex(self) -> ComplexProc<Self> {
        ComplexProc { proc: self }
    }
}

// A PrimitiveProc<_, _, _, GuardedVec<u8>, _> can only be created via Processor::new or Sink::new, in both cases there
// is a location_0 / source-vault.
impl<DIn, DOut, SOut> GetSourceVault for PrimitiveProc<DIn, DOut, GuardedVec<u8>, SOut> {
    fn get_source(&self) -> (VaultId, RecordId) {
        self.location_0.unwrap()
    }
}

// A PrimitiveProc<_, _, _, _, Vec<u8>> can only be created via Generator::new or Processor::new, in both cases there is
// a location_1 / target-vault.
impl<DIn, DOut, SIn> GetTargetVault for PrimitiveProc<DIn, DOut, SIn, Vec<u8>> {
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        self.location_1.unwrap()
    }
}

// ==========================
// Primitive Proc Types
// ==========================

// ---------------
//=== No secret used, create new secret in vault
// ---------------

type Generator<DIn, DOut> = PrimitiveProc<DIn, DOut, (), Vec<u8>>;

impl<DIn, DOut> Generator<DIn, DOut> {
    pub fn new(
        f: ProcFn<DIn, DOut, (), Vec<u8>>,
        vault_id_1: VaultId,
        record_id_1: RecordId,
        hint: RecordHint,
    ) -> Self {
        Self {
            f,
            location_0: None,
            location_1: Some((vault_id_1, record_id_1, hint)),
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

impl<DIn, DOut> ExecProc for Generator<DIn, DOut>
where
    Self: GetTargetVault,
{
    type InputData = DIn;
    type OutputData = DOut;
    type InputSecret = ();
    type OutputSecret = Vec<u8>;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, engine::Error> {
        let (vault_id_1, record_id_1, hint) = self.get_target();
        let f = self.f;
        let (write_vault, output) = f((), input)?;
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(output)
    }
}

// ---------------
//=== Existing secret used, new secret created
// ---------------

type Processor<DIn, DOut> = PrimitiveProc<DIn, DOut, GuardedVec<u8>, Vec<u8>>;

impl<DIn, DOut> Processor<DIn, DOut> {
    fn new(
        f: ProcFn<DIn, DOut, GuardedVec<u8>, Vec<u8>>,
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

impl<DIn, DOut> ExecProc for Processor<DIn, DOut>
where
    Self: GetSourceVault + GetTargetVault,
{
    type InputData = DIn;
    type OutputData = DOut;
    type InputSecret = GuardedVec<u8>;
    type OutputSecret = Vec<u8>;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, engine::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let (write_vault, output) = executor.exec_on_guarded(vault_id_0, record_id_0, &self.f, input)?;
        let (vault_id_1, record_id_1, hint) = self.get_target();
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(output)
    }
}

// ---------------
//=== Existing secret used, no new secret created
// ---------------

type Sink<DIn, DOut> = PrimitiveProc<DIn, DOut, GuardedVec<u8>, ()>;

impl<DIn, DOut> Sink<DIn, DOut> {
    fn new(f: ProcFn<DIn, DOut, GuardedVec<u8>, ()>, vault_id_0: VaultId, record_id_0: RecordId) -> Self {
        Self {
            f,
            location_0: Some((vault_id_0, record_id_0)),
            location_1: None,
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        }
    }
}

impl<DIn, DOut> ExecProc for Sink<DIn, DOut>
where
    Self: GetSourceVault,
{
    type InputData = DIn;
    type OutputData = DOut;
    type InputSecret = GuardedVec<u8>;
    type OutputSecret = ();

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, engine::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let ((), output) = executor.exec_on_guarded(vault_id_0, record_id_0, &self.f, input)?;
        Ok(output)
    }
}

// ==========================
// Complex Proc: combine Primitive Procs with other Procs and ProcFns
// ==========================

struct ComplexProc<P: ExecProc> {
    proc: P,
}

impl<P> Deref for ComplexProc<P>
where
    P: ExecProc,
{
    type Target = P;
    fn deref(&self) -> &Self::Target {
        &self.proc
    }
}

impl<P: ExecProc> ExecProc for ComplexProc<P> {
    type InputData = P::InputData;
    type OutputData = P::OutputData;
    type InputSecret = P::InputSecret;
    type OutputSecret = P::OutputSecret;

    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InputData,
    ) -> Result<Self::OutputData, engine::Error> {
        self.proc.exec(executor, input)
    }
}

// ==========================
// Combinators
// ==========================

// ---------------
// === Map ExecProc::OutputData into a new type
// ---------------

impl<P: ExecProc> ComplexProc<P> {
    fn map_output<F: Fn(P::OutputData) -> OData1, OData1>(self, f: F) -> ComplexProc<MapProc<P, F, OData1>> {
        let proc = MapProc { proc: self.proc, f };
        ComplexProc { proc }
    }
}

struct MapProc<P, F, OData1>
where
    P: ExecProc,
    F: Fn(P::OutputData) -> OData1,
{
    proc: P,
    f: F,
}

impl<P, F, OData1> Deref for MapProc<P, F, OData1>
where
    P: ExecProc,
    F: Fn(P::OutputData) -> OData1,
{
    type Target = P;
    fn deref(&self) -> &Self::Target {
        &self.proc
    }
}

impl<P, F, OData1> ExecProc for MapProc<P, F, OData1>
where
    P: ExecProc,
    F: Fn(P::OutputData) -> OData1,
{
    type InputData = P::InputData;
    type OutputData = OData1;
    type InputSecret = P::InputSecret;
    type OutputSecret = P::OutputSecret;

    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InputData,
    ) -> Result<Self::OutputData, engine::Error> {
        self.proc.exec(executor, input).map(self.f)
    }
}

// ---------------
// === Chain a next procedure P1 that takes Self::OutputData as P1::InputData
// ---------------

impl<P> ComplexProc<P>
where
    P: ExecProc<OutputSecret = Vec<u8>> + GetTargetVault,
{
    fn and_then<OData1, ISecret1, OSecret1>(
        self,
        other: ProcFn<P::OutputData, OData1, ISecret1, OSecret1>,
    ) -> ComplexProc<
        impl ExecProc<InputData = P::InputData, OutputData = OData1, InputSecret = P::InputSecret, OutputSecret = OSecret1>,
    >
    where
        PrimitiveProc<P::OutputData, OData1, ISecret1, OSecret1>:
            ExecProc<InputData = P::OutputData, OutputData = OData1, InputSecret = ISecret1, OutputSecret = OSecret1>,
    {
        let (vault_id, record_id, _) = self.proc.get_target();
        let proc_1 = PrimitiveProc {
            f: other,
            location_0: Some((vault_id, record_id)),
            location_1: None,
            _marker: (PhantomData, PhantomData, PhantomData, PhantomData),
        };
        ComplexProc {
            proc: ChainedProc {
                proc_0: self.proc,
                proc_1,
            },
        }
    }
}

struct ChainedProc<P, P1>
where
    P: ExecProc,
    P1: ExecProc,
{
    proc_0: P,
    proc_1: P1,
}

impl<P, P1> GetTargetVault for ChainedProc<P, P1>
where
    P: ExecProc,
    P1: ExecProc + GetTargetVault,
{
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        self.proc_1.get_target()
    }
}

impl<P, P1> GetSourceVault for ChainedProc<P, P1>
where
    P: ExecProc + GetSourceVault,
    P1: ExecProc,
{
    fn get_source(&self) -> (VaultId, RecordId) {
        self.proc_0.get_source()
    }
}

impl<P, P1> ExecProc for ChainedProc<P, P1>
where
    P: ExecProc,
    P1: ExecProc<InputData = P::OutputData>,
{
    type InputData = P::InputData;
    type OutputData = P1::OutputData;
    type InputSecret = P::InputSecret;
    type OutputSecret = P1::OutputSecret;

    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InputData,
    ) -> Result<Self::OutputData, engine::Error> {
        let out = self.proc_0.exec(executor, input)?;
        self.proc_1.exec(executor, out)
    }
}

// ---------------
// === Reduce the Result of two Procedures to one
// ---------------

struct ReduceProc<P, P1, F, DOut, SOut>
where
    P: ExecProc<InputData = ()>,
    P1: ExecProc<InputData = ()>,
    F: FnOnce(P::OutputData, P1::OutputData) -> DOut,
{
    proc_0: P,
    proc_1: P1,
    f: F,
    _marker: PhantomData<SOut>,
}

impl<P, P1, F, DOut, SOut> ExecProc for ReduceProc<P, P1, F, DOut, SOut>
where
    P: ExecProc<InputData = ()>,
    P1: ExecProc<InputData = ()>,
    F: FnOnce(P::OutputData, P1::OutputData) -> DOut,
{
    type InputData = ();
    type OutputData = DOut;
    type InputSecret = ();
    type OutputSecret = SOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, _: ()) -> Result<Self::OutputData, engine::Error> {
        let out_0 = self.proc_0.exec(executor, ())?;
        let out_1 = self.proc_1.exec(executor, ())?;
        let f = self.f;
        Ok(f(out_0, out_1))
    }
}

// ==========================
// Example Application
// ==========================

mod test {
    use std::collections::HashMap;

    use engine::vault::{DbView, Key};

    struct KeyStore<P: BoxProvider + Clone + Send + Sync + 'static> {
        store: HashMap<VaultId, Key<P>>,
    }

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
        fn box_seal(_key: &Key<Self>, _ad: &[u8], _data: &[u8]) -> engine::Result<Vec<u8>> {
            todo!()
        }
        fn box_open(_key: &Key<Self>, _ad: &[u8], _data: &[u8]) -> engine::Result<Vec<u8>> {
            todo!()
        }
        fn random_buf(_buf: &mut [u8]) -> engine::Result<()> {
            todo!()
        }
    }

    struct ProcedureExecutor {
        db: DbView<MockProvider>,
        keystore: KeyStore<MockProvider>,
    }
    impl<P: BoxProvider + Clone + Send + Sync + 'static> KeyStore<P> {
        pub fn new() -> Self {
            todo!()
        }
        pub fn get_key(&mut self, _: VaultId) -> Option<Key<P>> {
            todo!()
        }
        pub fn vault_exists(&self, _: VaultId) -> bool {
            todo!()
        }
        pub fn create_key(&mut self, _: VaultId) -> Key<P> {
            todo!()
        }
        pub fn insert_key(&mut self, _: VaultId, _: Key<P>) -> &Key<P> {
            todo!()
        }
    }

    impl ProcedureExecutor {
        fn new() -> Self {
            todo!()
        }
    }
    impl ProcExecutor for ProcedureExecutor {
        fn exec_on_guarded<DIn, DOut, SOut>(
            &mut self,
            vault_id: VaultId,
            record_id: RecordId,
            f: &ProcFn<DIn, DOut, GuardedVec<u8>, SOut>,
            input: DIn,
        ) -> Result<(SOut, DOut), engine::Error> {
            let key = self.keystore.get_key(vault_id);
            if let Some(pkey) = key.as_ref() {
                self.keystore.insert_key(vault_id, pkey.clone());
            };
            let key = key.ok_or_else(|| engine::Error::OtherError("Not existing".to_string()))?;
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
                self.keystore
                    .get_key(vault_id)
                    .ok_or_else(|| engine::Error::OtherError("Not existing".to_string()))?
            };
            self.db.write(&key, vault_id, record_id, &value, hint)
        }
    }

    fn generate_secret(_: (), _: ()) -> Result<(Vec<u8>, ()), engine::Error> {
        Ok(("Super secret Secret".as_bytes().to_vec(), ()))
    }

    struct DummyCipher;

    impl DummyCipher {
        fn encrypt(_guard: GuardedVec<u8>, data: String) -> Result<((), String), engine::Error> {
            Ok(((), data))
        }
    }

    fn main() {
        let mut executor = ProcedureExecutor::new();

        let vault_id = VaultId::random::<MockProvider>().unwrap();
        let record_id = RecordId::random::<MockProvider>().unwrap();
        let hint = RecordHint::new("".as_bytes()).unwrap();

        let proc = Generator::new(Box::new(generate_secret), vault_id, record_id, hint)
            .into_complex()
            .map_output(|()| "This is my message".to_string())
            .and_then(Box::new(DummyCipher::encrypt));
        let _res = proc.exec(&mut executor, ()).unwrap();
    }
}
