// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::{enum_from_inner, Location};
pub use crypto::keys::slip10::{Chain, ChainCode};
use crypto::{
    ciphers::{
        aes::Aes256Gcm,
        chacha::XChaCha20Poly1305,
        traits::{consts::Unsigned, Aead, Tag},
    },
    hashes::{
        blake2b::Blake2b256,
        sha::{Sha256, Sha384, Sha512, SHA256, SHA256_LEN, SHA384, SHA384_LEN, SHA512, SHA512_LEN},
        Digest,
    },
    keys::{
        bip39,
        pbkdf::{PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512},
        slip10, x25519,
    },
    macs::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512},
    signatures::ed25519,
    utils::rand::fill,
};
use engine::new_runtime::memories::buffer::Buffer;
use serde::{Deserialize, Serialize};
use std::convert::{From, Into, TryFrom};
use stronghold_derive::{execute_procedure, Procedure};
use stronghold_utils::GuardDebug;

// ==========================
// Helper Procedures
// ==========================

/// Enum that wraps all cryptographic procedures that are supported by Stronghold.
///
/// A procedure performs a (cryptographic) operation on a secret in the vault and/
/// or generates a new secret.
///
/// **Note**: For all procedures that write output to the vault, the [`PersistSecret`]
/// trait is implement. **A secret is only permanently stored in the vault, if
/// explicitly specified via [`PersistSecret::write_secret`]. Analogous for procedures with
/// non-secret output, the [`PersistOutput`] is implemented and [`PersistOutput::store_output`]
/// has to be called if the procedure's output should be returned to the user.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum PrimitiveProcedure {
    CopyRecord(CopyRecord),
    Slip10Generate(Slip10Generate),
    Slip10Derive(Slip10Derive),
    BIP39Generate(BIP39Generate),
    BIP39Recover(BIP39Recover),
    PublicKey(PublicKey),
    GenerateKey(GenerateKey),
    Ed25519Sign(Ed25519Sign),
    X25519DiffieHellman(X25519DiffieHellman),
    Hash(Hash),
    Hmac(Hmac),
    Hkdf(Hkdf),
    Pbkdf2Hmac(Pbkdf2Hmac),
    AeadEncrypt(AeadEncrypt),
    AeadDecrypt(AeadDecrypt),
}

impl ProcedureStep for PrimitiveProcedure {
    fn execute<R: Runner>(self, runner: &mut R, state: &mut State) -> Result<(), ProcedureError> {
        use PrimitiveProcedure::*;
        match self {
            CopyRecord(proc) => proc.execute(runner, state),
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
            Hkdf(proc) => proc.execute(runner, state),
            Pbkdf2Hmac(proc) => proc.execute(runner, state),
            AeadEncrypt(proc) => proc.execute(runner, state),
            AeadDecrypt(proc) => proc.execute(runner, state),
        }
    }
}

// === implement From Traits from inner types to wrapper enums

enum_from_inner!(PrimitiveProcedure::CopyRecord from CopyRecord);
enum_from_inner!(PrimitiveProcedure::Slip10Generate from Slip10Generate);
enum_from_inner!(PrimitiveProcedure::Slip10Derive from Slip10Derive);
enum_from_inner!(PrimitiveProcedure::BIP39Generate from BIP39Generate);
enum_from_inner!(PrimitiveProcedure::BIP39Recover from BIP39Recover);
enum_from_inner!(PrimitiveProcedure::GenerateKey from GenerateKey);
enum_from_inner!(PrimitiveProcedure::PublicKey from PublicKey);
enum_from_inner!(PrimitiveProcedure::Ed25519Sign from Ed25519Sign);
enum_from_inner!(PrimitiveProcedure::X25519DiffieHellman from X25519DiffieHellman);
enum_from_inner!(PrimitiveProcedure::Hash from Hash);
enum_from_inner!(PrimitiveProcedure::Hmac from Hmac);
enum_from_inner!(PrimitiveProcedure::Hkdf from Hkdf);
enum_from_inner!(PrimitiveProcedure::Pbkdf2Hmac from Pbkdf2Hmac);
enum_from_inner!(PrimitiveProcedure::AeadEncrypt from AeadEncrypt);
enum_from_inner!(PrimitiveProcedure::AeadDecrypt from AeadDecrypt);

// ==========================
// Helper Procedure
// ==========================

/// Copy the content of a record from one location to another.
///
/// Note: This does not remove the old record. Users that would like to move the record instead
/// of just copying it, should run `Stronghold::delete_data` on the old location **after** this
/// procedure was executed.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct CopyRecord {
    #[source]
    source: Location,
    #[target]
    target: TempTarget,
}

impl CopyRecord {
    pub fn new(source: Location) -> Self {
        CopyRecord {
            source,
            target: TempTarget::default(),
        }
    }
}

#[execute_procedure]
impl DeriveSecret for CopyRecord {
    type Input = ();
    type Output = ();

    fn derive(self, _: Self::Input, guard: Buffer<u8>) -> Result<Products<()>, FatalProcedureError> {
        let products = Products {
            secret: (*guard.borrow()).to_vec(),
            output: (),
        };
        Ok(products)
    }
}

// ==========================
// Procedures for Cryptographic Primitives
// ==========================

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum MnemonicLanguage {
    English,
    Japanese,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AeadAlg {
    Aes256Gcm,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    X25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashType {
    Blake2b,
    Sha2(Sha2Hash),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sha2Hash {
    Sha256,
    Sha384,
    Sha512,
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
            mnemonic_key: TempOutput::default(),
            target: TempTarget::default(),
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
    mnemonic: InputData<<Self as GenerateSecret>::Input>,

    #[target]
    target: TempTarget,
}

impl BIP39Recover {
    pub fn new<I>(mnemonic: I, passphrase: Option<String>) -> Self
    where
        I: Into<InputData<<Self as GenerateSecret>::Input>>,
    {
        BIP39Recover {
            passphrase,
            mnemonic: mnemonic.into(),
            target: TempTarget::default(),
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
            target: TempTarget::default(),
            size_bytes: 64,
        }
    }
}

impl Slip10Generate {
    pub fn new(size_bytes: usize) -> Self {
        Slip10Generate {
            target: TempTarget::default(),
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

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
enum Slip10ParentType {
    Seed,
    Key,
}

/// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
/// return the corresponding chain code
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Derive {
    chain: Chain,
    parent_ty: Slip10ParentType,

    #[output_key]
    output_key: TempOutput,

    #[source]
    source: Location,

    #[target]
    target: TempTarget,
}

impl Slip10Derive {
    pub fn new_from_seed(seed: Location, chain: Chain) -> Self {
        Self::new(chain, seed, Slip10ParentType::Seed)
    }

    pub fn new_from_key(parent: Location, chain: Chain) -> Self {
        Self::new(chain, parent, Slip10ParentType::Key)
    }

    fn new(chain: Chain, source: Location, parent_ty: Slip10ParentType) -> Self {
        Slip10Derive {
            parent_ty,
            chain,
            source,
            target: TempTarget::default(),
            output_key: TempOutput::default(),
        }
    }
}

#[execute_procedure]
impl DeriveSecret for Slip10Derive {
    type Input = ();
    type Output = ChainCode;

    fn derive(self, _: Self::Input, guard: Buffer<u8>) -> Result<Products<ChainCode>, FatalProcedureError> {
        let dk = match self.parent_ty {
            Slip10ParentType::Key => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&self.chain))
            }
            Slip10ParentType::Seed => {
                slip10::Seed::from_bytes(&guard.borrow()).derive(slip10::Curve::Ed25519, &self.chain)
            }
        }?;
        Ok(Products {
            secret: dk.into(),
            output: dk.chain_code(),
        })
    }
}

fn x25519_secret_key(guard: Buffer<u8>) -> Result<x25519::SecretKey, crypto::Error> {
    let raw = guard.borrow();
    let raw = (*raw).to_vec();
    if raw.len() != x25519::SECRET_KEY_LENGTH {
        let e = crypto::Error::BufferSize {
            has: raw.len(),
            needs: x25519::SECRET_KEY_LENGTH,
            name: "data buffer",
        };
        return Err(e);
    }
    x25519::SecretKey::try_from_slice(&raw)
}

fn ed25519_secret_key(guard: Buffer<u8>) -> Result<ed25519::SecretKey, crypto::Error> {
    let raw = guard.borrow();
    let mut raw = (*raw).to_vec();
    if raw.len() < ed25519::SECRET_KEY_LENGTH {
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

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKey {
    ty: KeyType,

    #[target]
    target: TempTarget,
}

impl GenerateKey {
    pub fn new(ty: KeyType) -> Self {
        GenerateKey {
            ty,
            target: TempTarget::default(),
        }
    }
}

#[execute_procedure]
impl GenerateSecret for GenerateKey {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret = match self.ty {
            KeyType::Ed25519 => ed25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
            KeyType::X25519 => x25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
        };
        Ok(Products { secret, output: () })
    }
}

/// Derive an Ed25519 public key from the corresponding private key stored at the specified
/// location
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    ty: KeyType,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: TempOutput,
}

impl PublicKey {
    pub fn new(ty: KeyType, private_key: Location) -> Self {
        Self {
            ty,
            private_key,
            output_key: TempOutput::default(),
        }
    }
}

#[execute_procedure]
impl UseSecret for PublicKey {
    type Input = ();
    type Output = Vec<u8>;

    fn use_secret(self, _: Self::Input, guard: Buffer<u8>) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            KeyType::Ed25519 => {
                let sk = ed25519_secret_key(guard)?;
                Ok(sk.public_key().to_bytes().to_vec())
            }
            KeyType::X25519 => {
                let sk = x25519_secret_key(guard)?;
                Ok(sk.public_key().to_bytes().to_vec())
            }
        }
    }
}

/// Use the specified Ed25519 compatible key to sign the given message
///
/// Compatible keys are any record that contain the desired key material in the first 32 bytes,
/// in particular SLIP10 keys are compatible.
#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Sign {
    #[input_data]
    msg: InputData<<Self as UseSecret>::Input>,

    #[source]
    private_key: Location,

    #[output_key]
    output_key: TempOutput,
}

impl Ed25519Sign {
    pub fn new<I>(msg: I, private_key: Location) -> Self
    where
        I: Into<InputData>,
    {
        Self {
            msg: msg.into(),
            private_key,
            output_key: TempOutput::default(),
        }
    }
}

#[execute_procedure]
impl UseSecret for Ed25519Sign {
    type Input = Vec<u8>;
    type Output = [u8; ed25519::SIGNATURE_LENGTH];

    fn use_secret(self, msg: Self::Input, guard: Buffer<u8>) -> Result<Self::Output, FatalProcedureError> {
        let sk = ed25519_secret_key(guard)?;
        let sig = sk.sign(&msg);
        Ok(sig.to_bytes())
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct X25519DiffieHellman {
    public_key: [u8; x25519::PUBLIC_KEY_LENGTH],

    #[source]
    private_key: Location,

    #[target]
    target: TempTarget,
}

impl X25519DiffieHellman {
    pub fn new(public_key: [u8; x25519::PUBLIC_KEY_LENGTH], private_key: Location) -> Self {
        Self {
            public_key,
            private_key,
            target: TempTarget::default(),
        }
    }
}

#[execute_procedure]
impl DeriveSecret for X25519DiffieHellman {
    type Input = ();
    type Output = ();

    fn derive(self, _: Self::Input, guard: Buffer<u8>) -> Result<Products<()>, FatalProcedureError> {
        let sk = x25519_secret_key(guard)?;
        let public = x25519::PublicKey::from_bytes(self.public_key);
        let shared_key = sk.diffie_hellman(&public);

        Ok(Products {
            secret: shared_key.to_bytes().to_vec(),
            output: (),
        })
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Hash {
    ty: HashType,

    #[input_data]
    msg: InputData<<Self as ProcessData>::Input>,

    #[output_key]
    output_key: TempOutput,
}

impl Hash {
    pub fn new<I>(ty: HashType, msg: I) -> Self
    where
        I: Into<InputData>,
    {
        Hash {
            ty,
            msg: msg.into(),
            output_key: TempOutput::default(),
        }
    }
}

#[execute_procedure]
impl ProcessData for Hash {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn process(self, input: Self::Input) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            HashType::Blake2b => {
                let mut digest = [0; <Blake2b256 as Digest>::OutputSize::USIZE];
                digest.copy_from_slice(&Blake2b256::digest(&input));
                Ok(digest.to_vec())
            }
            HashType::Sha2(Sha2Hash::Sha256) => {
                let mut digest = [0; SHA256_LEN];
                SHA256(&input, &mut digest);
                Ok(digest.to_vec())
            }
            HashType::Sha2(Sha2Hash::Sha384) => {
                let mut digest = [0; SHA384_LEN];
                SHA384(&input, &mut digest);
                Ok(digest.to_vec())
            }
            HashType::Sha2(Sha2Hash::Sha512) => {
                let mut digest = [0; SHA512_LEN];
                SHA512(&input, &mut digest);
                Ok(digest.to_vec())
            }
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Hmac {
    ty: Sha2Hash,

    #[input_data]
    msg: InputData<<Self as UseSecret>::Input>,

    #[output_key]
    output_key: TempOutput,

    #[source]
    key: Location,
}

impl Hmac {
    pub fn new<I>(ty: Sha2Hash, msg: I, key: Location) -> Self
    where
        I: Into<InputData>,
    {
        Hmac {
            ty,
            msg: msg.into(),
            key,
            output_key: TempOutput::default(),
        }
    }
}

#[execute_procedure]
impl UseSecret for Hmac {
    type Input = Vec<u8>;
    type Output = Vec<u8>;

    fn use_secret(self, msg: Self::Input, guard: Buffer<u8>) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            Sha2Hash::Sha256 => {
                let mut mac = [0; SHA256_LEN];
                HMAC_SHA256(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha384 => {
                let mut mac = [0; SHA384_LEN];
                HMAC_SHA384(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha512 => {
                let mut mac = [0; SHA512_LEN];
                HMAC_SHA512(&msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
        }
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Hkdf {
    ty: Sha2Hash,

    salt: Vec<u8>,
    label: Vec<u8>,

    #[source]
    ikm: Location,

    #[target]
    okm: TempTarget,
}

impl Hkdf {
    pub fn new(ty: Sha2Hash, salt: Vec<u8>, label: Vec<u8>, ikm: Location) -> Self {
        Hkdf {
            ty,
            salt,
            label,
            ikm,
            okm: TempTarget::default(),
        }
    }
}

#[execute_procedure]
impl DeriveSecret for Hkdf {
    type Input = ();
    type Output = ();

    fn derive(self, _: Self::Input, guard: Buffer<u8>) -> Result<Products<()>, FatalProcedureError> {
        let secret = match self.ty {
            Sha2Hash::Sha256 => {
                let mut okm = [0; SHA256_LEN];
                hkdf::Hkdf::<Sha256>::new(Some(&self.salt), &*guard.borrow())
                    .expand(&self.label, &mut okm)
                    .expect("okm is the correct length");
                okm.to_vec()
            }
            Sha2Hash::Sha384 => {
                let mut okm = [0; SHA384_LEN];
                hkdf::Hkdf::<Sha384>::new(Some(&self.salt), &*guard.borrow())
                    .expand(&self.label, &mut okm)
                    .expect("okm is the correct length");
                okm.to_vec()
            }
            Sha2Hash::Sha512 => {
                let mut okm = [0; SHA512_LEN];
                hkdf::Hkdf::<Sha512>::new(Some(&self.salt), &*guard.borrow())
                    .expand(&self.label, &mut okm)
                    .expect("okm is the correct length");
                okm.to_vec()
            }
        };
        Ok(Products { secret, output: () })
    }
}

#[derive(Procedure, Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2Hmac {
    ty: Sha2Hash,

    password: Vec<u8>,
    salt: Vec<u8>,
    count: u32,

    #[target]
    target: TempTarget,
}

impl Pbkdf2Hmac {
    pub fn new(ty: Sha2Hash, password: Vec<u8>, salt: Vec<u8>, count: u32) -> Self {
        Pbkdf2Hmac {
            ty,
            password,
            salt,
            count,
            target: TempTarget::default(),
        }
    }
}

#[execute_procedure]
impl GenerateSecret for Pbkdf2Hmac {
    type Input = ();
    type Output = ();

    fn generate(self, _: Self::Input) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret;
        match self.ty {
            Sha2Hash::Sha256 => {
                let mut buffer = [0; SHA256_LEN];
                PBKDF2_HMAC_SHA256(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                secret = buffer.to_vec()
            }
            Sha2Hash::Sha384 => {
                let mut buffer = [0; SHA384_LEN];
                PBKDF2_HMAC_SHA384(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                secret = buffer.to_vec()
            }
            Sha2Hash::Sha512 => {
                let mut buffer = [0; SHA512_LEN];
                PBKDF2_HMAC_SHA512(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                secret = buffer.to_vec()
            }
        }
        Ok(Products { secret, output: () })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadEncrypt {
    alg: AeadAlg,

    associated_data: InputData,
    plaintext: InputData,
    nonce: Vec<u8>,
    key: Location,

    ciphertext: TempOutput,
    tag: TempOutput,
}

impl AeadEncrypt {
    /// Create a new aead encryption procedure.
    /// **Note**: The nonce is required to have length [`Aes256Gcm::NONCE_LENGTH`] /
    /// [`XChaCha20Poly1305::NONCE_LENGTH`], (depending on the [`AeadAlg`])
    pub fn new(
        alg: AeadAlg,
        key: Location,
        plaintext: impl Into<InputData>,
        associated_data: impl Into<InputData>,
        nonce: Vec<u8>,
    ) -> Self {
        let ciphertext = TempOutput::default();
        let tag = TempOutput::default();
        AeadEncrypt {
            alg,
            associated_data: associated_data.into(),
            plaintext: plaintext.into(),
            nonce,
            key,
            ciphertext,
            tag,
        }
    }

    pub fn store_ciphertext(mut self, key: OutputKey) -> Self {
        self.ciphertext = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }

    pub fn ciphertext(&self) -> OutputKey {
        self.ciphertext.write_to.clone()
    }

    pub fn store_tag(mut self, key: OutputKey) -> Self {
        self.tag = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }

    pub fn tag(&self) -> OutputKey {
        self.tag.write_to.clone()
    }
}

impl SourceInfo for AeadEncrypt {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl ProcedureStep for AeadEncrypt {
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
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut ctx = vec![0; plaintext.len()];
        let mut t = match self.alg {
            AeadAlg::Aes256Gcm => Tag::<Aes256Gcm>::default(),
            AeadAlg::XChaCha20Poly1305 => Tag::<XChaCha20Poly1305>::default(),
        };

        let alg = self.alg;
        let f = |key: Buffer<u8>| {
            let f = match alg {
                AeadAlg::Aes256Gcm => Aes256Gcm::try_encrypt,
                AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::try_encrypt,
            };
            f(&*key.borrow(), &nonce, ad, plaintext, &mut ctx, &mut t)?;
            Ok(())
        };

        runner.get_guard(&key, f)?;
        state.insert_output(ciphertext.write_to, ctx.into(), ciphertext.is_temp);
        state.insert_output(tag.write_to, Vec::from(&*t).into(), tag.is_temp);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadDecrypt {
    alg: AeadAlg,
    associated_data: InputData,
    ciphertext: InputData,
    tag: InputData,
    nonce: Vec<u8>,
    key: Location,
    plaintext: TempOutput,
}

impl AeadDecrypt {
    /// Create a new aead encryption procedure.
    /// **Note**: It is required for the nonce to have length [`Aes256Gcm::NONCE_LENGTH`] /
    /// [`XChaCha20Poly1305::NONCE_LENGTH`] and the tag to have length [`Aes256Gcm::TAG_LENGTH`] /
    /// [`XChaCha20Poly1305::TAG_LENGTH`] (depending on the [`AeadAlg`])
    pub fn new(
        alg: AeadAlg,
        key: Location,
        ciphertext: impl Into<InputData>,
        associated_data: impl Into<InputData>,
        tag: impl Into<InputData>,
        nonce: Vec<u8>,
    ) -> Self {
        let plaintext = TempOutput::default();
        AeadDecrypt {
            alg,
            associated_data: associated_data.into(),
            ciphertext: ciphertext.into(),
            tag: tag.into(),
            nonce,
            key,
            plaintext,
        }
    }

    pub fn store_plaintext(mut self, key: OutputKey) -> Self {
        self.plaintext = TempOutput {
            write_to: key,
            is_temp: false,
        };
        self
    }

    pub fn plaintext(&self) -> OutputKey {
        self.plaintext.write_to.clone()
    }
}

impl SourceInfo for AeadDecrypt {
    fn source_location(&self) -> &Location {
        &self.key
    }
    fn source_location_mut(&mut self) -> &mut Location {
        &mut self.key
    }
}

impl ProcedureStep for AeadDecrypt {
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
        let ad = match associated_data {
            InputData::Value(ref v) => v,
            InputData::Key(key) => {
                let data = state.get_output(&key).ok_or(ProcedureError::MissingInput)?;
                data.as_ref()
            }
        };

        let mut ptx = vec![0; ciphertext.len()];

        let alg = self.alg;
        let f = |key: Buffer<u8>| {
            let f = match alg {
                AeadAlg::Aes256Gcm => Aes256Gcm::try_decrypt,
                AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::try_decrypt,
            };
            f(&*key.borrow(), &nonce, ad, &mut ptx, ciphertext, tag)?;
            Ok(())
        };

        runner.get_guard(&key, f)?;
        state.insert_output(plaintext.write_to, ptx.into(), plaintext.is_temp);
        Ok(())
    }
}
