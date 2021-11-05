// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::{enum_from_inner, Location};
use crypto::{
    ciphers::traits::consts::Unsigned,
    keys::{bip39, slip10, x25519},
    signatures::ed25519,
    utils::rand::fill,
};

pub mod crypto_reexport {
    pub use crypto::{
        ciphers::{
            aes::Aes256Gcm,
            chacha::XChaCha20Poly1305,
            traits::{Aead, Tag},
        },
        hashes::{
            blake2b::Blake2b256,
            sha::{Sha256, Sha384, Sha512},
            Digest,
        },
        keys::slip10::{Chain, ChainCode},
    };
}
use crypto_reexport::*;
use engine::{runtime::GuardedVec, vault::RecordHint};
use hmac::{
    digest::{BlockInput, FixedOutput, Reset, Update},
    Mac, NewMac,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::{From, Into, TryFrom},
    marker::PhantomData,
};
use stronghold_derive::{execute_procedure, Procedure};
use stronghold_utils::GuardDebug;

// ==========================
// Helper Procedures
// ==========================

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PrimitiveProcedure {
    Helper(HelperProcedure),
    Crypto(CryptoProcedure),
}

impl ProcedureStep for PrimitiveProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            PrimitiveProcedure::Helper(proc) => proc.execute(runner, state),
            PrimitiveProcedure::Crypto(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HelperProcedure {
    WriteVault(WriteVault),
}

impl ProcedureStep for HelperProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            HelperProcedure::WriteVault(proc) => proc.execute(runner, state),
        }
    }
}

// TODO: remove notes, add proper docs.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoProcedure {
    // Generate Random array with length 64
    Slip10Generate(Slip10Generate),
    // for seg: u32 = [u8;4] in chain:
    //   child = HMAC_SH512(data: 0 ++ parent.privatekey ++ seg, key: parent.chaincode)
    //   child: privatekey: [u8;32] ++ chaincode: [u8;32] = [u8;64]
    Slip10Derive(Slip10Derive),
    BIP39Generate(BIP39Generate),

    // bip39::mnemonic_to_seed(mnemonic, passphrase):
    // PBKDF2_HMAC_SHA512(password: mnemonic, salt: "mnemonic" ++ passphrase, count: 2048)
    BIP39Recover(BIP39Recover),
    PublicKey(PublicKeys),
    GenerateKey(GenerateKeys),
    Ed25519Sign(Ed25519Sign),
    X25519DiffieHellman(X25519DiffieHellman),
    Hash(Hashes),
    Hmac(Hmacs),
    Aead(Aeads),
}

impl ProcedureStep for CryptoProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        use CryptoProcedure::*;
        match self {
            Slip10Generate(proc) => proc.execute(runner, state),
            Slip10Derive(proc) => proc.execute(runner, state),
            BIP39Generate(proc) => proc.execute(runner, state),
            BIP39Recover(proc) => proc.execute(runner, state),
            GenerateKey(proc) => proc.execute(runner, state),
            PublicKey(proc) => proc.execute(runner, state),
            Ed25519Sign(proc) => proc.execute(runner, state),
            X25519DiffieHellman(proc) => proc.execute(runner, state),
            Hash(proc) => proc.execute(runner, state),
            Hmac(proc) => proc.execute(runner, state),
            Aead(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct WriteVault {
    #[input_data]
    data: InputData<Vec<u8>>,
    #[target]
    target: TempTarget,
}

impl WriteVault {
    pub fn new<I, T>(data: I, location: Location, hint: RecordHint) -> Self
    where
        I: IntoInput<T>,
        T: Into<Vec<u8>>,
    {
        let data = match data.into_input() {
            InputData::Key(k) => InputData::Key(k),
            InputData::Value(v) => InputData::Value(v.into()),
        };
        WriteVault {
            data,
            target: TempTarget {
                write_to: Target { location, hint },
                is_temp: false,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for WriteVault {
    type Input = Vec<u8>;
    type Output = ();

    fn generate(self, input: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        Ok(Products {
            secret: input,
            output: (),
        })
    }
}

// === implement From Traits from inner types to wrapper enums

enum_from_inner!(PrimitiveProcedure::Helper from HelperProcedure);
enum_from_inner!(PrimitiveProcedure::Helper, HelperProcedure::WriteVault from WriteVault);

enum_from_inner!(PrimitiveProcedure::Crypto  from CryptoProcedure);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Slip10Generate from Slip10Generate);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Slip10Derive from Slip10Derive);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::BIP39Generate from BIP39Generate);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::BIP39Recover from BIP39Recover);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::GenerateKey, GenerateKeys::Ed25519 from GenerateKey<Ed25519>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::GenerateKey, GenerateKeys::X25519 from GenerateKey<X25519>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::PublicKey, PublicKeys::Ed25519 from PublicKey<Ed25519>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::PublicKey, PublicKeys::X25519 from PublicKey<X25519>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Ed25519Sign from Ed25519Sign);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::X25519DiffieHellman from X25519DiffieHellman);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Sha2_256 from Hash<Sha256>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Sha2_384 from Hash<Sha384>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Sha2_512 from Hash<Sha512>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hash, Hashes::Blake2b256 from Hash<Blake2b256>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac, Hmacs::Sha2_256 from Hmac<Sha256>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac, Hmacs::Sha2_384 from Hmac<Sha384>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Hmac, Hmacs::Sha2_512 from Hmac<Sha512>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::Aes256GcmEncrypt from AeadEncrypt<Aes256Gcm>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::Aes256GcmDecrypt from AeadDecrypt<Aes256Gcm>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::XChaCha20Poly1305Encrypt from AeadEncrypt<XChaCha20Poly1305>);
enum_from_inner!(PrimitiveProcedure::Crypto, CryptoProcedure::Aead, Aeads::XChaCha20Poly1305Decrypt from AeadDecrypt<XChaCha20Poly1305>);

// ==========================
// Procedures for Cryptographic Primitives
// ==========================

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MnemonicLanguage {
    English,
    Japanese,
}

/// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
/// passphrase). Store the seed and return the mnemonic sentence as data output.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Generate {
    passphrase: Option<String>,

    language: MnemonicLanguage,

    #[output_key]
    mnemonic_key: TempOutput,

    #[target]
    target: TempTarget,
}

impl BIP39Generate {
    pub fn new(language: MnemonicLanguage, passphrase: Option<String>) -> Self {
        BIP39Generate {
            passphrase,
            language,
            mnemonic_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for BIP39Generate {
    type Input = ();
    type Output = String;

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let mut entropy = [0u8; 32];
        fill(&mut entropy)?;

        let wordlist = match self.language {
            MnemonicLanguage::English => bip39::wordlist::ENGLISH,
            MnemonicLanguage::Japanese => bip39::wordlist::JAPANESE,
        };

        let mnemonic = bip39::wordlist::encode(&entropy, &wordlist).unwrap();

        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);

        Ok(Products {
            secret: seed.to_vec(),
            output: mnemonic,
        })
    }
}

/// Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover
/// a BIP39 seed and store it in the `output` location
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Recover {
    passphrase: Option<String>,

    #[input_data]
    mnemonic: InputData<String>,

    #[target]
    target: TempTarget,
}

impl BIP39Recover {
    pub fn new<I>(mnemonic: I, passphrase: Option<String>) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        BIP39Recover {
            passphrase,
            mnemonic: mnemonic.into_input(),
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl GenerateSecret for BIP39Recover {
    type Input = String;
    type Output = ();

    fn generate(self, mnemonic: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&mnemonic, &passphrase, &mut seed);
        Ok(Products {
            secret: seed.to_vec(),
            output: (),
        })
    }
}

/// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
/// the `output` location
///
/// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
/// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Generate {
    size_bytes: usize,

    #[target]
    target: TempTarget,
}

impl Default for Slip10Generate {
    fn default() -> Self {
        Slip10Generate {
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
            size_bytes: 64,
        }
    }
}

impl Slip10Generate {
    pub fn new(size_bytes: usize) -> Self {
        Slip10Generate {
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
            size_bytes,
        }
    }
}

#[execute_procedure]
impl GenerateSecret for Slip10Generate {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let mut seed = vec![0u8; self.size_bytes];
        fill(&mut seed)?;
        Ok(Products {
            secret: seed,
            output: (),
        })
    }
}

#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum SLIP10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed(Location),
    Key(Location),
}

impl SourceInfo for SLIP10DeriveInput {
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

/// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
/// return the corresponding chain code
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Derive {
    chain: Chain,

    #[output_key]
    output_key: TempOutput,

    #[source]
    source: SLIP10DeriveInput,

    #[target]
    target: TempTarget,
}

impl Slip10Derive {
    pub fn new_from_seed(seed: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Seed(seed))
    }

    pub fn new_from_key(parent: Location, chain: Chain) -> Self {
        Self::new(chain, SLIP10DeriveInput::Key(parent))
    }

    fn new(chain: Chain, source: SLIP10DeriveInput) -> Self {
        Slip10Derive {
            chain,
            source,
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl DeriveSecret for Slip10Derive {
    type Input = ();
    type Output = ChainCode;

    fn derive(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Products<ChainCode>, FatalProcedureError> {
        let dk = match self.source {
            SLIP10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&self.chain))
            }
            SLIP10DeriveInput::Seed(_) => {
                slip10::Seed::from_bytes(&guard.borrow()).derive(slip10::Curve::Ed25519, &self.chain)
            }
        }?;
        Ok(Products {
            secret: dk.into(),
            output: dk.chain_code(),
        })
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519;

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct X25519;

pub trait Keys: Sized {
    type SecretKey;
    fn generate() -> Result<Vec<u8>, crypto::Error>;
    fn from_guard(guard: GuardedVec<u8>) -> Result<Self::SecretKey, crypto::Error>;
    fn public_key(sk: Self::SecretKey) -> Vec<u8>;
}

impl Keys for Ed25519 {
    type SecretKey = ed25519::SecretKey;

    fn generate() -> Result<Vec<u8>, crypto::Error> {
        ed25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())
    }

    fn from_guard(guard: GuardedVec<u8>) -> Result<Self::SecretKey, crypto::Error> {
        let raw = guard.borrow();
        let mut raw = (*raw).to_vec();
        if raw.len() < ed25519::SECRET_KEY_LENGTH {
            // the client actor will interrupt the control flow
            // but could this be an option to return an error
            let e = crypto::Error::BufferSize {
                has: raw.len(),
                needs: ed25519::SECRET_KEY_LENGTH,
                name: "data buffer",
            };
            return Err(e);
        }
        raw.truncate(ed25519::SECRET_KEY_LENGTH);
        let mut bs = [0; ed25519::SECRET_KEY_LENGTH];
        bs.copy_from_slice(&raw);
        Ok(ed25519::SecretKey::from_bytes(bs))
    }

    fn public_key(sk: Self::SecretKey) -> Vec<u8> {
        sk.public_key().to_bytes().to_vec()
    }
}

impl Keys for X25519 {
    type SecretKey = x25519::SecretKey;

    fn generate() -> Result<Vec<u8>, crypto::Error> {
        ed25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())
    }

    fn from_guard(guard: GuardedVec<u8>) -> Result<Self::SecretKey, crypto::Error> {
        let raw = guard.borrow();
        let raw = (*raw).to_vec();
        if raw.len() != x25519::SECRET_KEY_LENGTH {
            // the client actor will interrupt the control flow
            // but could this be an option to return an error
            let e = crypto::Error::BufferSize {
                has: raw.len(),
                needs: x25519::SECRET_KEY_LENGTH,
                name: "data buffer",
            };
            return Err(e);
        }
        x25519::SecretKey::try_from_slice(&raw)
    }

    fn public_key(sk: Self::SecretKey) -> Vec<u8> {
        sk.public_key().to_bytes().to_vec()
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub enum GenerateKeys {
    Ed25519(GenerateKey<Ed25519>),
    X25519(GenerateKey<X25519>),
}

impl ProcedureStep for GenerateKeys {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            GenerateKeys::Ed25519(proc) => proc.execute(runner, state),
            GenerateKeys::X25519(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKey<T: Keys> {
    #[target]
    target: TempTarget,

    _marker: PhantomData<T>,
}

impl<T: Keys> Default for GenerateKey<T> {
    fn default() -> Self {
        GenerateKey {
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T: Keys> GenerateSecret for GenerateKey<T> {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret = T::generate()?.to_vec();
        Ok(Products { secret, output: () })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PublicKeys {
    Ed25519(PublicKey<Ed25519>),
    X25519(PublicKey<X25519>),
}

impl ProcedureStep for PublicKeys {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            PublicKeys::Ed25519(proc) => proc.execute(runner, state),
            PublicKeys::X25519(proc) => proc.execute(runner, state),
        }
    }
}

/// Derive an Ed25519 public key from the corresponding private key stored at the specified
/// location
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey<T: Keys> {
    #[source]
    private_key: Location,

    #[output_key]
    output_key: TempOutput,

    _marker: PhantomData<T>,
}

impl<T: Keys> PublicKey<T> {
    pub fn new(private_key: Location) -> Self {
        Self {
            private_key,
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T: Keys> UseSecret for PublicKey<T> {
    type Input = ();
    type Output = Vec<u8>;

    fn use_secret(self, _: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        let sk = T::from_guard(guard)?;
        Ok(T::public_key(sk))
    }
}

/// Use the specified Ed25519 compatible key to sign the given message
///
/// Compatible keys are any record that contain the desired key material in the first 32 bytes,
/// in particular SLIP10 keys are compatible.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Sign {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: TempOutput,
}

impl Ed25519Sign {
    pub fn new<I>(msg: I, private_key: Location) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        Self {
            msg: msg.into_input(),
            private_key,
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl UseSecret for Ed25519Sign {
    type Input = Vec<u8>;
    type Output = [u8; ed25519::SIGNATURE_LENGTH];

    fn use_secret(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        let sk = Ed25519::from_guard(guard)?;
        let sig = sk.sign(&msg);
        Ok(sig.to_bytes())
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct X25519DiffieHellman {
    #[input_data]
    public_key: InputData<[u8; x25519::PUBLIC_KEY_LENGTH]>,

    #[source]
    private_key: Location,

    #[target]
    target: TempTarget,
}

impl X25519DiffieHellman {
    pub fn new<I>(public_key: I, private_key: Location) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        Self {
            public_key: public_key.into_input(),
            private_key,
            target: TempTarget {
                write_to: Target::random(),
                is_temp: true,
            },
        }
    }
}

#[execute_procedure]
impl DeriveSecret for X25519DiffieHellman {
    type Input = [u8; x25519::PUBLIC_KEY_LENGTH];
    type Output = ();

    fn derive(self, input: Self::Input, guard: GuardedVec<u8>) -> Result<Products<()>, FatalProcedureError> {
        let sk = X25519::from_guard(guard)?;
        let public = x25519::PublicKey::from_bytes(input);
        let shared_key = sk.diffie_hellman(&public);

        Ok(Products {
            secret: shared_key.to_bytes().to_vec(),
            output: (),
        })
    }
}

#[derive(Procedure, Clone, Serialize, Deserialize)]
pub enum Hashes {
    Sha2_256(Hash<Sha256>),
    Sha2_384(Hash<Sha384>),
    Sha2_512(Hash<Sha512>),
    Blake2b256(Hash<Blake2b256>),
}

impl ProcedureStep for Hashes {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            Hashes::Sha2_256(proc) => proc.execute(runner, state),
            Hashes::Sha2_384(proc) => proc.execute(runner, state),
            Hashes::Sha2_512(proc) => proc.execute(runner, state),
            Hashes::Blake2b256(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Hash<T> {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: TempOutput,

    _marker: PhantomData<T>,
}

impl<T> Hash<T> {
    pub fn new<I>(msg: I) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        Hash {
            msg: msg.into_input(),
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T: Digest> ProcessData for Hash<T> {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn process(self, input: Self::Input) -> Result<Self::Output, FatalProcedureError> {
        let mut digest = vec![0; T::OutputSize::USIZE];
        digest.copy_from_slice(&T::digest(&input));
        Ok(digest)
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub enum Hmacs {
    Sha2_256(Hmac<Sha256>),
    Sha2_384(Hmac<Sha384>),
    Sha2_512(Hmac<Sha512>),
}

impl ProcedureStep for Hmacs {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            Hmacs::Sha2_256(proc) => proc.execute(runner, state),
            Hmacs::Sha2_384(proc) => proc.execute(runner, state),
            Hmacs::Sha2_512(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Hmac<T> {
    #[input_data]
    msg: InputData<Vec<u8>>,

    #[output_key]
    output_key: TempOutput,

    #[source]
    key: Location,

    _marker: PhantomData<T>,
}

impl<T> Hmac<T> {
    pub fn new<I>(msg: I, key: Location) -> Self
    where
        I: IntoInput<<Self as InputInfo>::Input>,
    {
        Hmac {
            msg: msg.into_input(),
            key,
            output_key: TempOutput {
                write_to: OutputKey::random(),
                is_temp: true,
            },
            _marker: PhantomData,
        }
    }
}

#[execute_procedure]
impl<T> UseSecret for Hmac<T>
where
    T: Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn use_secret(self, msg: Self::Input, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        let mut mac = vec![0; <T as Digest>::OutputSize::USIZE];
        let mut m = hmac::Hmac::<T>::new_from_slice(&*guard.borrow()).unwrap();
        m.update(&msg);
        mac.copy_from_slice(&m.finalize().into_bytes());
        Ok(mac)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Aeads {
    Aes256GcmEncrypt(AeadEncrypt<Aes256Gcm>),
    Aes256GcmDecrypt(AeadDecrypt<Aes256Gcm>),
    XChaCha20Poly1305Encrypt(AeadEncrypt<XChaCha20Poly1305>),
    XChaCha20Poly1305Decrypt(AeadDecrypt<XChaCha20Poly1305>),
}

impl ProcedureStep for Aeads {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        match self {
            Aeads::Aes256GcmEncrypt(proc) => proc.execute(runner, state),
            Aeads::Aes256GcmDecrypt(proc) => proc.execute(runner, state),
            Aeads::XChaCha20Poly1305Encrypt(proc) => proc.execute(runner, state),
            Aeads::XChaCha20Poly1305Decrypt(proc) => proc.execute(runner, state),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadEncrypt<T> {
    associated_data: InputData<Vec<u8>>,
    plaintext: InputData<Vec<u8>>,
    nonce: InputData<Vec<u8>>,
    key: Location,

    ciphertext: TempOutput,
    tag: TempOutput,
    _marker: PhantomData<T>,
}

impl<T> AeadEncrypt<T> {
    pub fn new(
        key: Location,
        plaintext: impl IntoInput<Vec<u8>>,
        associated_data: impl IntoInput<Vec<u8>>,
        nonce: impl IntoInput<Vec<u8>>,
    ) -> Self {
        let ciphertext = TempOutput {
            write_to: OutputKey::random(),
            is_temp: true,
        };
        let tag = TempOutput {
            write_to: OutputKey::random(),
            is_temp: true,
        };
        AeadEncrypt {
            associated_data: associated_data.into_input(),
            plaintext: plaintext.into_input(),
            nonce: nonce.into_input(),
            key,
            ciphertext,
            tag,
            _marker: PhantomData,
        }
    }

    pub fn store_ciphertext(mut self, key: OutputKey) -> Self {
        self.ciphertext = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }

    pub fn store_tag(mut self, key: OutputKey) -> Self {
        self.tag = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }
}

impl<T> SourceInfo for AeadEncrypt<T> {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl<T: Aead> ProcedureStep for AeadEncrypt<T> {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        let AeadEncrypt {
            associated_data,
            plaintext,
            nonce,
            key,
            ciphertext,
            tag,
            ..
        } = self;
        let plaintext = match plaintext {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut digested = Vec::new();
        let mut t = Tag::<T>::default();

        let f = |key: GuardedVec<u8>| {
            T::try_encrypt(&*key.borrow(), nonce, ad, plaintext, &mut digested, &mut t)?;
            Ok(())
        };

        runner.get_guard(&key, f)?;
        state.insert_output(ciphertext.write_to, digested.into_procedure_io(), ciphertext.is_temp);
        state.insert_output(tag.write_to, Vec::from(&*t).into_procedure_io(), tag.is_temp);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadDecrypt<T> {
    associated_data: InputData<Vec<u8>>,
    ciphertext: InputData<Vec<u8>>,
    tag: InputData<Vec<u8>>,
    nonce: InputData<Vec<u8>>,
    key: Location,
    plaintext: TempOutput,
    _marker: PhantomData<T>,
}

impl<T> AeadDecrypt<T> {
    pub fn new(
        key: Location,
        ciphertext: impl IntoInput<Vec<u8>>,
        associated_data: impl IntoInput<Vec<u8>>,
        tag: impl IntoInput<Vec<u8>>,
        nonce: impl IntoInput<Vec<u8>>,
    ) -> Self {
        let plaintext = TempOutput {
            write_to: OutputKey::random(),
            is_temp: true,
        };
        AeadDecrypt {
            associated_data: associated_data.into_input(),
            ciphertext: ciphertext.into_input(),
            tag: tag.into_input(),
            nonce: nonce.into_input(),
            key,
            plaintext,
            _marker: PhantomData,
        }
    }

    pub fn store_plaintext(mut self, key: OutputKey) -> Self {
        self.plaintext = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }
}

impl<T> SourceInfo for AeadDecrypt<T> {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl<T: Aead> ProcedureStep for AeadDecrypt<T> {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        let AeadDecrypt {
            associated_data,
            ciphertext,
            tag,
            nonce,
            key,
            plaintext,
            ..
        } = self;
        let ciphertext = match ciphertext {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let tag = match tag {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let nonce = match nonce {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut output = Vec::new();

        let f = |key: GuardedVec<u8>| {
            T::try_decrypt(&*key.borrow(), nonce, ad, &mut output, ciphertext, tag)?;
            Ok(())
        };

        runner.get_guard(&key, f)?;
        state.insert_output(plaintext.write_to, output.into_procedure_io(), plaintext.is_temp);
        Ok(())
    }
}
