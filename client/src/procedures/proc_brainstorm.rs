// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// ===================================================
// Drafted Traits / Struct during brainstorming phase
// ===================================================

struct ProcedureBuilder<A, C> {
    curr_vault_id: Option<VaultId>,
    curr_record_id: Option<RecordId>,
    acc_fn: fn(A) -> C
}

impl<A> ProcedureBuilder<A, A> {
    fn new(init: A) -> Self {
        ProcedureBuilder {
            curr_record_id: None,
            curr_vault_id: None,
            acc_fn: |init| init
        }
    }
}

impl<A, C>  ProcedureBuilder<A, C>  {

    fn switch_vault(mut self, vault_id: VaultId, record_id: RecordId) -> Self {
        self.curr_vault_id = Some(vault_id);
        self.curr_record_id = Some(record_id);
        self
    }

    fn switch_record(mut self, record_id: RecordId) -> Self {
        self.curr_record_id = Some(record_id);
        self
    }

    // abstract from different procedure types
    fn and_then<F, R>(mut self, proc: F) -> ProcedureBuilder<A, R>
    where
        F: FnOnce(C) -> R,
        P: Proc<C, W>,
        Self: AsMut<P::Context>,
    {
        let curr_acc_fn = self.acc_fn;
        let acc_fn = proc_fn(curr_acc_fn);
        ProcedureBuilder {
            curr_record_id: self.curr_record_id,
            curr_vault_id: self.curr_vault_id,
            acc_fn
        }
    }

    // abstract from different procedure types
    fn and_then<P>(mut self, proc: P) -> ProcedureBuilder<A, P::Return>
    where
        P: Proc<Input = C>,
        Self: AsMut<P::Context>,
    {
        let curr_acc_fn = self.acc_fn;
        let acc_fn = proc_fn(curr_acc_fn);
        ProcedureBuilder {
            curr_record_id: self.curr_record_id,
            curr_vault_id: self.curr_vault_id,
            acc_fn
        }
    }

    fn flush_state(self) -> Self {
        todo!()
    }

    pub fn build<'a, Bp>(self) -> Runner<'a, Bp>
    where
        Bp: BoxProvider + Clone + Send + Sync + 'static,
    {
        todo!()
    }
}

enum PType {
    ReadSecret {
        vault_id_0: VaultId,
        record_id_0: RecordId
    },
    Execute {
        vault_id_0: VaultId,
        record_id_0: RecordId,
        vault_id_1: VaultId,
        record_id_1: RecordId,
    },
    WriteVault {
        vault_id_1: VaultId,
        record_id_1: RecordId,
    }
}

trait GetType {
    fn get_type(&self) -> PType;
}

trait ReadSecret1<I, O>: Proc<I, O, UseGuard = GuardedVec<u8>> {
    fn get_source(&self) -> (VaultId, RecordId);
}

trait WriteVault1<I, O>: Proc<I, O, WriteVault = Vec<u8>> {
    fn get_target(&self) -> (VaultId, RecordId);
    fn get_hint(&self) -> RecordHint;
}

trait UseSecret<I, O>: Proc<I, O, WriteVault = ()> + ReadSecret<I, O> {}
impl<I, O, P: Proc<I, O, WriteVault = ()> + ReadSecret<I, O>> UseSecret<I, O> for P {}
impl<I, O, P: UseSecret<I, O>> GetType for P {
    fn get_type(&self) -> PType {
        let (vault_id, record_id) = self.get_source();
        PType::ReadSecret {
            vault_id_0: vault_id,
            record_id_0: record_id
        }
    }
}

trait ExecOnSecret<I, O>: ReadSecret<I, O> + WriteVault<I, O> {}
impl<I, O, P: ReadSecret<I, O> + WriteVault<I, O>> ExecOnSecret<I, O> for P {}
impl<I, O, P: ReadSecret<I, O>> GetType for P {
    fn get_type(&self) -> PType {
        let (vault_id_0, record_id_0) = self.get_source();
        let (vault_id_1, record_id_1) = self.get_target();
        PType::Execute {
            vault_id_0, record_id_0, vault_id_1, record_id_1
        }
    }
}

trait CreateSecret<I, O>: Proc<I, O, UseGuard = ()> + WriteVault<I, O> {}
impl<I, O, P: Proc<I, O, UseGuard = ()> + WriteVault<I, O>> CreateSecret<I, O> for P {}
impl<I, O, P: CreateSecret<I, O>> GetType for P {
    fn get_type(&self) -> PType {
        let (vault_id, record_id) = self.get_target();
        PType::WriteVault {
            vault_id_1: vault_id,
            record_id_1: record_id
        }
    }
}

impl<'a, Bp> Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{
    fn get_source_key(&mut self, vault_id: VaultId) -> Option<Key<Bp>> {
        let key = self.keystore.get_key(vault_id);
        if let Some(pkey) = key.as_ref() {
            self.keystore.insert_key(vault_id, pkey.clone());
        }
        key
    }

    fn get_or_insert_target_key(&mut self, vault_id: VaultId) -> Result<Key<Bp>, anyhow::Error> {
        if !self.keystore.vault_exists(vault_id) {
            let k = self.keystore.create_key(vault_id);
            if let Err(e) = self.db_view.init_vault(&k, vault_id) {
                return Err(anyhow::anyhow!(e));
            };
            Ok(k)
        } else {
            match self.keystore.get_key(vault_id) {
                Some(key) => Ok(key),
                None => {
                    return Err(anyhow::anyhow!("Non existing"));
                }
            }
        }
    }

    fn run<P>(&mut self, proc: P) -> Result<P::Return, engine::Error>
    where
        P: Proc
    {
        match proc.get_type() {
            ProcType::ReadSecret => {},
            _ => {}
        }
    }
}

trait RunProc<I, O, P: Proc<I, O>> {
    fn run_proc(&mut self, proc: P) -> Result<O, engine::Error>;
}

trait GetGuard<I, O>: Proc<I, O> {
    fn get_guard() -> Proc::UseGuard;
}

impl<'a, Bp, P, I, O> RunProc<P, I, O> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: UseSecret<I, O>
{
    fn run_proc(&mut self, proc: P) -> Result<P::Return, engine::Error> {
        let (vault_id, record_id) = proc.get_source();
        let key = self
            .get_source_key(vault_id)
            .ok_or(engine::Error::OtherError("Access error".to_string()))?;
        self.keystore.insert_key(vault_id, key.clone());
        let mut ret = None;

        self.db_view.get_guard(&key, vault_id, record_id, |guard| {
            let ((), r) = proc.exec(guard)?;
            ret = Some(r);
            Ok(())
        })?;
        Ok(ret.unwrap())
    }
}

impl<'a, Bp, P> RunProc<P, (), Vec<u8>> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: Proc<(), Vec<u8>> + WriteVault,
{
    fn run_proc(&mut self, proc: P) -> Result<P::Return, engine::Error> {
        let (vault_id, record_id) = proc.get_target();
        let key = self
            .get_or_insert_target_key(vault_id)
            .map_err(|_| engine::Error::OtherError("Non existing".to_string()))?;

        let hint = proc.get_hint();
        let (write, ret) = proc.exec(())?;

        self.db_view.write(&key, vault_id, record_id, &write, hint)?;
        Ok(ret)
    }
}

impl<'a, Bp, P> RunProc<P, GuardedVec<u8>, Vec<u8>> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: Proc<GuardedVec<u8>, Vec<u8>> + ReadSecret + WriteVault,
{
    fn run_proc(&mut self, proc: P) -> Result<P::Return, engine::Error> {
        let (src_vault_id, src_record_id) = proc.get_source();
        let src_key = self
            .get_source_key(src_vault_id)
            .ok_or(engine::Error::OtherError("Access error".to_string()))?;

        let (target_vault_id, target_record_id) = proc.get_target();
        let target_key = self
            .get_or_insert_target_key(target_vault_id)
            .map_err(|_| engine::Error::OtherError("Non existing".to_string()))?;

        let hint = proc.get_hint();

        let mut ret = None;

        self.db_view.exec_proc(
            &src_key,
            src_vault_id,
            src_record_id,
            &target_key,
            target_vault_id,
            target_record_id,
            hint,
            |guard| {
                let (w, r) = proc.exec(guard)?;
                ret = Some(r);
                Ok(w)
            },
        )?;
        Ok(ret.unwrap())
    }
}

trait ExecOnProvider<'a, Bp, I, O>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{
    fn run(self, db: &'a mut DbView<Bp>, keystore: &'a mut KeyStore<Bp>, i: I) -> Result<O, engine::Error> { }
}

impl<'a, Bp, I, O, P> ExecOnProvider<'a, Bp, I, O> for P
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: ExecOnGuard<I, O> + DoWriteVault<I, O>
{
    fn run(self, db: &'a mut DbView<Bp>, keystore: &'a mut KeyStore<Bp>, i: I) -> Result<O, engine::Error> {
        let (write_vault, return_value) = self.exec_on_guard(i)?;
        self.write_vault(write_vault)?;
        Ok(return_value)
    }
}

trait ExecOnGuard<I, O, W> {
    fn exec_on_guard(&mut self, i: I) -> Result<(W, O), engine::Error>;
}

trait DoWriteVault<'a, Bp, W, I, O>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static
{
    fn write_vault(&mut self, db: &'a mut DbView<Bp>, keystore: &'a mut KeyStore<Bp>, value: W) -> Result<(),engine::Error>; }

impl<P, I, O> ExecOnGuard<I, O, P::WriteVault> for P
where
    P: Proc<I, O, UseGuard = ()>
{
    fn exec_on_guard(&mut self, i: I, p: &P) -> Result<(P::WriteVault, O), engine::Error> {
        p.exec((), i)
    }
}

impl<'a, Bp, I, O, P>  ExecOnGuard<GuardedVec<u8>, P, I, O> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: Proc<I, O, UseGuard = GuardedVec<u8>> + ReadSecret
{
    fn exec_on_guard(&mut self, i: I, p: &P) -> Result<(P::WriteVault, O), engine::Error> {
        let (vault_id, record_id) = p.get_source();
        let key = self.keystore.get_key(vault_id);
        if let Some(pkey) = key.as_ref() {
            self.keystore.insert_key(vault_id, pkey.clone());
        };
        let key = key.ok_or(engine::Error::OtherError("Not existing".to_string()))?;
        let mut ret = None;
        self.db.get_guard(&key, vault_id, record_id, |guard| {
            let r = p.exec(guard, i)?;
            ret = Some(r);
            Ok(())
        })?;
        Ok(ret.unwrap())
    }
}

impl<P, I, O>  DoWriteVault<(), I, O> for P
where
    P: Proc<I, O, WriteVault = ()>
{
    fn write_vault(&mut self, _: ()) -> Result<(), engine::Error> {
        Ok(())
    }
}

impl<P, I, O>  DoWriteVault<Vec<u8>, I, O> for P
where
    P: Proc<I, O, WriteVault = Vec<u8>>
{
    fn write_vault(&mut self, value: Vec<u8>, keystore: todo!()) -> Result<(), engine::Error> {
        let (vault_id, record_id) = self.get_target();
        let key = if !self.keystore.vault_exists(vault_id) {
            let k = self.keystore.create_key(vault_id);
            self.db.init_vault(&k, vault_id)?;
            k
        } else {
            let k = self.keystore.get_key(vault_id).ok_or(engine::Error::OtherError("Not existing".to_string()))?;
            k
        };
        let hint = p.get_hint();
        self.db.write(&key, vault_id, record_id, &value, hint)
    }
}

struct Runner<'a, Bp: BoxProvider>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{
    db: &'a mut DbView<Bp>,
    keystore: &'a mut KeyStore<Bp>,
}

impl<'a, Bp> Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
{

    fn write_to_location(&mut self, vault_id: VaultId, record_id: RecordId, hint: RecordHint, value: Vec<u8>) ->
Result<(), engine::Error> {         let key = if !self.keystore.vault_exists(vault_id) {
            let k = self.keystore.create_key(vault_id);
            self.db.init_vault(&k, vault_id)?;
            k
        } else {
            let k = self.keystore.get_key(vault_id).ok_or(engine::Error::OtherError("Not existing".to_string()))?;
            k
        };
        let hint = hint;
        self.db.write(&key, vault_id, record_id, &value, hint)
    }

    fn exec_on_guarded<F: FnOnce(GuardedVec<u8>), T>(&mut self, vault_id: VaultId, record_id: RecordId, f: F) ->
Result<T, engine::Error>     where
        F: FnOnce(GuardedVec<u8>) -> Result<T, engine::Error>
    {
        let key = self.keystore.get_key(vault_id);
        if let Some(pkey) = key.as_ref() {
            self.keystore.insert_key(vault_id, pkey.clone());
        };
        let key = key.ok_or(engine::Error::OtherError("Not existing".to_string()))?;
        let mut ret  = None;
        self.db.get_guard(&key, vault_id, record_id, |guard: GuardedVec<u8>| {
            let r = f(guard);
            ret = Some(r);
            Ok(())
        })?;
        ret.unwrap()
    }

    fn run_proc<P, I, O>(&mut self, i: I, proc: P) -> Result<O, engine::Error>
    where
        P: Proc<I, O>,
        Self: ExecOnGuard<P::UseGuard, P, I, O> + DoWriteVault<P::WriteVault, P, I, O>
    {
        let (write_vault, output) = self.exec_on_guard(i, &proc)?;
        self.write_vault(&proc, write_vault)?;
        Ok(output)
    }
}

trait ExecOnGuard<G, P, I, O>
where
    P: Proc<I, O, UseGuard = G>
{
    fn exec_on_guard(&mut self, i: I, p: &P) -> Result<(P::WriteVault, O), engine::Error>;
}

trait DoWriteVault<V, P, I, O>
where
    P: Proc<I, O, WriteVault = V>
{
    fn write_vault(&mut self, p: &P, value: V) -> Result<(), engine::Error>;
}
impl<'a, Bp, P, I, O>  ExecOnGuard<(), P, I, O> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: Proc<I, O, UseGuard = ()>
{
    fn exec_on_guard(&mut self, i: I, p: &P) -> Result<(P::WriteVault, O), engine::Error> {
        p.exec((), i)
    }
}

impl<'a, Bp, P, I, O>  ExecOnGuard<GuardedVec<u8>, P, I, O> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: Proc<I, O, UseGuard = GuardedVec<u8>> + ReadSecret
{
    fn exec_on_guard(&mut self, i: I, p: &P) -> Result<(P::WriteVault, O), engine::Error> {
        let (vault_id, record_id) = p.get_source();
        self.exec_on_guarded(vault_id, record_id, |guard| p.exec(guard, i))
    }
}

impl<'a, Bp, P, I, O>  DoWriteVault<(), P, I, O> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: Proc<I, O, WriteVault = ()>
{
    fn write_vault(&mut self, _: &P, _: ()) -> Result<(), engine::Error> {
        Ok(())
    }
}

impl<'a, Bp, P, I, O>  DoWriteVault<Vec<u8>, P, I, O> for Runner<'a, Bp>
where
    Bp: BoxProvider + Clone + Send + Sync + 'static,
    P: Proc<I, O, WriteVault = Vec<u8>> + WriteVault
{
    fn write_vault(&mut self, p: &P, value: Vec<u8>) -> Result<(), engine::Error> {
        let (vault_id, record_id) = p.get_target();
        let hint = p.get_hint();
        self.write_to_location(vault_id, record_id, hint, value)
    }
}

trait Proc<I, O>: Sized { // I: () | GuardedVec<>, W: () | Vec<>
    type UseGuard;
    type WriteVault;
    // type Return;
    // type Context;
    // type Exec: Exec2Proc<Self::Input, Self::Write, Return = Self::Return>;

    // fn exec<F>(&self) -> F
    // where  F: FnOnce(Self::UseGuard, I) -> Result<(Self::WriteVault, O), engine::Error>;

    fn exec(&self, guard: Self::UseGuard, input: I) -> Result<(Self::WriteVault, O), engine::Error>;
    // fn exec<R>(&self, runner: &mut R, input: I) -> Result<O, engine::Error>
    // where R: ExecOnGuard<Self::UseGuard, Self, I, O> + DoWriteVault<Self::WriteVault, Self, I, O>;

    fn exec_on_runner<'a, Bp>(&self, runner: &mut Runner<'a, Bp>, input: I) -> Result<O, engine::Error>
    where
       Bp: BoxProvider + Clone + Send + Sync + 'static,
    {
        let (write_vault, output) = runner.exec_on_guard(input, self)?;
        runner.write_vault(self, write_vault)?;
        Ok(output)
    }
    // fn new(ctx: &mut Self::Context) -> Self;
    // fn get_type(&self) -> ProcType;
    // fn exec(&self, guard: Self::UseGuard, additional: I) -> Result<(Self::WriteVault, O), engine::Error>;
    // fn exec_on_ctx(self, context: &mut Self::Context) -> Self::Exec;
}

struct ProcBuilder<A, O> {
    exec: fn(A) -> O
}

impl<A> ProcBuilder<A, A> {

    fn new(init: A) -> Self {
        Self {
            exec: |init| init
        }
    }
}

trait ExecProc<I, O> {
    fn get_input(&self) -> I;
    fn set_input(&mut self, input: I);
    fn exec(self) -> O;
}

impl<I,O> ExecProc<I,O> for ProcBuilder<I, O> {
    fn get_input(&self) -> I {
        todo!()
    }

    fn set_input(&mut self, input: I) {
        todo!()
    }

    fn exec(self) -> O {
        let f = self.exec;
        f(self.get_input())
    }
}

impl<A, O> ProcBuilder<A, O> {
    fn and_then<N, P: ExecProc<O, N>>(self, proc: P) -> ProcBuilder<A, N> {
        let last_in =  self.get_input();
        proc.set_input(last_in);
        ProcBuilder { exec: proc.exec(self.exec())}
    }
}

trait ExecProc<P: ProcFn<I, O, G, W>, I, O, G, W> {
    fn exec_proc(&mut self, proc: P, input: I) -> Result<(W, O), engine::Error>;
}

impl<PExe, P, I, O, W> ExecProc<P, I, O, (), W>  for PExe
where
    PExe: ProcExecutor,
    P: ProcFn<I, O, (), W>
{
    fn exec_proc(&mut self, proc: P, input: I) -> Result<(W, O), engine::Error> {
        proc.run((), input)
    }
}

impl<PExe, P, I, O, W> ExecProc<P, I, O, GuardedVec<u8>, W>  for PExe
where
    PExe: ProcExecutor,
    P: ProcFn<I, O, GuardedVec<u8>, W> + ReadSecret
{
    fn exec_proc(&mut self, proc: P, input: I) -> Result<(W, O), engine::Error> {
        let (vault_id, record_id) = proc.get_source();
        self.exec_on_guarded(vault_id, record_id, proc, input)
    }
}

trait WriteResult<P: ProcFn<I, O, G, W>, I, O, G, W> {
    fn write_vault(&mut self, p: &P, value: W) -> Result<(), engine::Error>;
}

impl<PExe, P, I, O, G>  WriteResult<P, I, O, G, ()> for PExe
where
    PExe: ProcExecutor,
    P: ProcFn<I, O, G, ()>
{
    fn write_vault(&mut self, _: &P, _: ()) -> Result<(), engine::Error> {
        Ok(())
    }
}

impl<PExe, P, I, O, G>  WriteResult<P, I, O, G, Vec<u8>> for PExe
where
    PExe: ProcExecutor,
    P: ProcFn<I, O, G,  Vec<u8>> + WriteVault
{
    fn write_vault(&mut self, p: &P, value: Vec<u8>) -> Result<(), engine::Error> {
        let (vault_id, record_id) = p.get_target();
        let hint = p.get_hint();
        self.write_to_location(vault_id, record_id, hint, value)
    }
}


trait ProcFn<I, O, G, W> {
    fn run(&self, guard: G, input: I) -> Result<(W, O), engine::Error>;
}

trait CipherType {
    fn encrypt(data: Vec<u8>) -> Vec<u8>;
    fn decrypt(data: Vec<u8>) -> Vec<u8>;
}

struct Cipher<T: CipherType> {
    vault_id: VaultId,
    record_id: RecordId,
    data: Vec<u8>,
    _marker: PhantomData<T>
}

impl<T: CipherType> Cipher<T> {
    fn encrypt(self: Self) -> Vec<u8> {
        T::encrypt(self.data)
    }
    fn decrypt(self: Self) -> Vec<u8> {
        T::decrypt(self.data)
    }
}

impl<T: CipherType> Proc<GuardedVec<u8>, ()> for Cipher<T> {
    // type Input = GuardedVec<u8>;
    // type Write = ();
    type Return = Vec<u8>;
    type Context = CipherContext;
    // type Exec = ExecCipher;

    fn new(ctx: &mut Self::Context) -> Self {
        Cipher {
            vault_id: ctx.vault_id.clone(),
            record_id: ctx.record_id.clone(),
            data: Vec::new(),
            _marker: PhantomData
        }
    }

    fn exec(self, input: GuardedVec<u8>) -> Result<((), Self::Return), engine::Error> {
        todo!()
    }

    // fn exec_on_ctx(self, context: &mut Self::Context) -> Self::Exec {
    //     ExecCipher {
    //         vault_id: context.vault_id.clone(),
    //         record_id: context.record_id.clone(),
    //     }
    // }
}

impl<T: CipherType> ReadSecret for Cipher<T> {
    fn get_source(&self) -> (VaultId, RecordId) {
        (self.vault_id.clone(), self.record_id.clone())
    }
}

struct CipherContext {
    vault_id: VaultId,
    record_id: RecordId,
}

impl<A, C> AsMut<CipherContext> for ProcedureBuilder<A, C> {
    fn as_mut(&mut self) -> &mut CipherContext {
        // Provide assurance that vault-id and record-id exist
        let _ctx = CipherContext {
            vault_id: self.curr_vault_id.clone().unwrap(),
            record_id: self.curr_record_id.clone().unwrap(),
        };
        todo!()
    }
}

struct ExecCipher {
    vault_id: VaultId,
    record_id: RecordId,
}

impl ExecProc<GuardedVec<u8>, ()> for ExecCipher {
    type Return = Vec<u8>;
    fn exec(self, _guard: GuardedVec<u8>) -> Result<((), Vec<u8>), engine::Error> {
        todo!();
    }
}

struct PlainCipher;

impl PlainCipher {
    fn new() -> Self {
        PlainCipher
    }
}

impl CipherType for PlainCipher {
    fn encrypt(data: Vec<u8>) -> Vec<u8> {
        data
    }

    fn decrypt(data: Vec<u8>) -> Vec<u8> {
        data
    }
}

// Usage

fn main() {
    let _proc = ProcedureBuilder::new(()).and_then(Cipher::<PlainCipher>::encrypt).flush_state(); //.build();
    let sh = Stronghold::init_stronghold_system(None,Vec::new(),Vec::new()).unwrap();
    sh.runtime_exec(proc)
}

// ==========================
// Wrapper Procs -> used for combining Procs
// ==========================

// Add a source-location for Procs that use a GuardedVec
struct ReaderProc<P, I, O, W>
where
    P: ExecProc<I, O, GuardedVec<u8>, W>,
{
    proc: P,
    vault_id_0: VaultId,
    record_id_0: RecordId,
    _marker: (PhantomData<I>, PhantomData<O>, PhantomData<W>),
}

impl<P, I, O, W> ReaderProc<P, I, O, W>
where
    P: ExecProc<I, O, GuardedVec<u8>, W>,
{
    fn new(proc: P, vault_id_0: VaultId, record_id_0: RecordId) -> Self {
        Self {
            proc,
            vault_id_0,
            record_id_0,
            _marker: (PhantomData, PhantomData, PhantomData),
        }
    }
}

impl<P, I, O, W> ExecProc<I, O, GuardedVec<u8>, W> for ReaderProc<P, I, O, W>
where
    P: ExecProc<I, O, GuardedVec<u8>, W>,
{
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: I) -> Result<O, engine::Error> {
        self.proc.exec(executor, input)
    }
}

impl<P, I, O, W> Deref for ReaderProc<P, I, O, W>
where
    P: ExecProc<I, O, GuardedVec<u8>, W>,
{
    type Target = P;
    fn deref(&self) -> &Self::Target {
        &self.proc
    }
}

impl<P, I, O, W> GetSourceVault for ReaderProc<P, I, O, W>
where
    P: ExecProc<I, O, GuardedVec<u8>, W>,
{
    fn get_source(&self) -> (VaultId, RecordId) {
        (self.vault_id_0, self.record_id_0)
    }
}

// Add a source-location for Procs that use a write to the vault
struct WriterProc<P, I, O, G>
where
    P: ExecProc<I, O, G, Vec<u8>>,
{
    proc: P,
    vault_id_1: VaultId,
    record_id_1: RecordId,
    hint: RecordHint,
    _marker: (PhantomData<I>, PhantomData<O>, PhantomData<G>),
}

impl<P, I, O, G> WriterProc<P, I, O, G>
where
    P: ExecProc<I, O, G, Vec<u8>>,
{
    fn new(proc: P, vault_id_1: VaultId, record_id_1: RecordId, hint: RecordHint) -> Self {
        Self {
            proc,
            vault_id_1,
            record_id_1,
            hint,
            _marker: (PhantomData, PhantomData, PhantomData),
        }
    }
}

impl<P, I, O, G> ExecProc<I, O, G, Vec<u8>> for WriterProc<P, I, O, G>
where
    P: ExecProc<I, O, G, Vec<u8>>,
{
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: I) -> Result<O, engine::Error> {
        self.proc.exec(executor, input)
    }
}

impl<P, I, O, G> Deref for WriterProc<P, I, O, G>
where
    P: ExecProc<I, O, G, Vec<u8>>,
{
    type Target = P;
    fn deref(&self) -> &Self::Target {
        &self.proc
    }
}

impl<P, I, O, G> GetTargetVault for WriterProc<P, I, O, G>
where
    P: ExecProc<I, O, G, Vec<u8>>,
{
    fn get_target(&self) -> (VaultId, RecordId, RecordHint) {
        (self.vault_id_1, self.record_id_1, self.hint)
    }
}



pub struct ComplexProc<P: ExecProc> {
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
    type InData = P::InData;
    type OutData = P::OutData;
    type InSecret = P::InSecret;
    type OutSecret = P::OutSecret;

    fn exec<PExe: ProcExecutor>(
        self,
        executor: &mut PExe,
        input: Self::InData,
    ) -> Result<Self::OutData, engine::Error> {
        self.proc.exec(executor, input)
    }
}

impl<P: ExecProc> ComplexProc<P> {
    pub fn map_output<F, OData1>(
        self,
        f: F,
    ) -> ComplexProc<
        impl ExecProc<InData = P::InData, OutData = OData1, InSecret = P::InSecret, OutSecret = P::OutSecret>,
    >
    where
        F: Fn(P::OutData) -> OData1,
    {
        let proc = MapProc { proc: self.proc, f };
        ComplexProc { proc }
    }
}


impl<P> ComplexProc<P>
where
    P: ExecProc<OutSecret = Vec<u8>> + GetTargetVault,
{
    pub fn and_then<OData1, ISecret1, OSecret1>(
        self,
        other: ProcFn<P::OutData, OData1, ISecret1, OSecret1>,
    ) -> ComplexProc<ChainedProc<P, PrimitiveProc<P::OutData, OData1, ISecret1, OSecret1>>>
    where
        PrimitiveProc<P::OutData, OData1, ISecret1, OSecret1>:
            ExecProc<InData = P::OutData, OutData = OData1, InSecret = ISecret1, OutSecret = OSecret1>,
    {
        let (vault_id, record_id, _) = self.get_target();
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

pub type ProcFn<DIn, DOut, GIn, VOut> = Box<dyn Send + FnOnce(GIn, DIn) -> Result<ProcOutput<DOut, VOut>, anyhow::Error>>;

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

impl<DOut> Generator<(), DOut> {
    pub(crate) fn new<F>(f: F, vault_id_1: VaultId, record_id_1: RecordId, hint: RecordHint) -> Self
    where
        F: Fn(()) -> Result<ProcOutput<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
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
        F: Fn((), DIn) -> Result<ProcOutput<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
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
        F: Fn(GuardedVec<u8>) -> Result<ProcOutput<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
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
        F: Fn(GuardedVec<u8>, DIn) -> Result<ProcOutput<DOut, Vec<u8>>, anyhow::Error> + 'static + Send + Sync,
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

impl<DOut> Sink<(), DOut> {
    pub(crate) fn new<F>(f: F, vault_id_0: VaultId, record_id_0: RecordId) -> Self
    where
        F: Fn(GuardedVec<u8>) -> Result<ProcOutput<DOut, ()>, anyhow::Error> + 'static + Send + Sync,
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
        F: Fn(GuardedVec<u8>, DIn) -> Result<ProcOutput<DOut, ()>, anyhow::Error> + 'static + Send + Sync,
    {
        Self {
            f: Box::new(f),
            location_0: Some((vault_id_0, record_id_0)),
            location_1: None,
        }
    }
}

// ==========================
// Helper Procedures
// ==========================

pub(crate) type Data<DOut> = PrimitiveProc<(), DOut, (), ()>;

impl<DOut: Send + 'static> Data<DOut> {

    pub fn new(data: DOut) -> Self {
        let f = |(), ()| Ok(ProcOutput {write_vault: (), return_value: data});
        Self {
            f: Box::new(f),
            location_0: None,
            location_1: None,
        }
    }
}

pub struct CreateVault {
    vault_id: VaultId
}

impl ExecProc for CreateVault {
    type InData = ();
    type OutData = ();

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, _: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        executor.create_vault(self.vault_id);
        Ok(())
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
        let ProcOutput {
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
        let (vault_id_1, record_id_1, hint) = self.get_target();
        let ProcOutput {
            write_vault,
            return_value,
        } = executor.exec_on_guarded(vault_id_0, record_id_0, self.f, input)?;
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(return_value)
    }
}

impl<DIn, DOut> ExecProc for Sink<DIn, DOut> {
    type InData = DIn;
    type OutData = DOut;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: DIn) -> Result<DOut, anyhow::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let ProcOutput {
            write_vault: (),
            return_value,
        } = executor.exec_on_guarded(vault_id_0, record_id_0, self.f, input)?;
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





impl<P> ExecProc for P
where
    P: AsFn<InGuard = (), OutVault = ()>,
{
    type InData = P::InData;
    type OutData = P::OutData;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        let f = self.f;
        let ProcOutput {
            write_vault: (),
            return_value,
        } = f((), input)?;
        Ok(return_value)
    }
}

impl<P> ExecProc for P
where
    P: AsFn<InGuard = (), OutVault = Vec<u8>> + GetTargetVault
{
    type InData = P::InData;
    type OutData = P::OutData;
    
    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        let (vault_id_1, record_id_1, hint) = self.get_target();
        let f = self.f;
        let ProcOutput {
            write_vault,
            return_value,
        } = f((), input)?;
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(return_value)
    }
}

impl<P> ExecProc for P
where
    P: AsFn<InGuard = GuardedVec<u8>, OutVault = Vec<u8>> + GetSourceVault +  GetTargetVault
{
    type InData = P::InData;
    type OutData = P::OutData;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let (vault_id_1, record_id_1, hint) = self.get_target();
        let ProcOutput {
            write_vault,
            return_value,
        } = executor.exec_on_guarded(vault_id_0, record_id_0, self.f, input)?;
        executor.write_to_vault(vault_id_1, record_id_1, hint, write_vault)?;
        Ok(return_value)
    }
}

impl<P> ExecProc for P
where
    P: AsFn<InGuard = GuardedVec<u8>, OutVault = ()> + GetSourceVault
{
    type InData = P::InData;
    type OutData = P::OutData;

    fn exec<PExe: ProcExecutor>(self, executor: &mut PExe, input: Self::InData) -> Result<Self::OutData, anyhow::Error> {
        let (vault_id_0, record_id_0) = self.get_source();
        let ProcOutput {
            write_vault: (),
            return_value,
        } = executor.exec_on_guarded(vault_id_0, record_id_0, self.f, input)?;
        Ok(return_value)
    }
}

pub type ProcFn<DIn, DOut, GIn, VOut> =
    Box<dyn Send + FnOnce(GIn, DIn) -> Result<ProcOutput<DOut>, anyhow::Error>>;
