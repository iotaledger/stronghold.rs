// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::types::*;
use crate::{state::secure::SecureClient, Location};
pub use crypto::keys::slip10::{Chain, ChainCode};
use crypto::{
    ciphers::{
        aes::Aes256Gcm,
        chacha::XChaCha20Poly1305,
        traits::{Aead, Tag},
    },
    hashes::sha::{Sha256, Sha384, Sha512, SHA256_LEN, SHA384_LEN, SHA512_LEN},
    keys::{
        bip39,
        pbkdf::{PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA384, PBKDF2_HMAC_SHA512},
        slip10, x25519,
    },
    macs::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512},
    signatures::ed25519,
    utils::rand::fill,
};
use engine::{runtime::GuardedVec, vault::RecordHint};
use serde::{Deserialize, Serialize};
use stronghold_utils::GuardDebug;

/// Enum that wraps all cryptographic procedures that are supported by Stronghold.
///  
/// A procedure performs a (cryptographic) operation on a secret in the vault and/
/// or generates a new secret.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum StrongholdProcedure {
    WriteVault(WriteVault),
    RevokeData(RevokeData),
    GarbageCollect(GarbageCollect),
    CopyRecord(CopyRecord),
    Slip10Generate(Slip10Generate),
    Slip10Derive(Slip10Derive),
    BIP39Generate(BIP39Generate),
    BIP39Recover(BIP39Recover),
    PublicKey(PublicKey),
    GenerateKey(GenerateKey),
    Ed25519Sign(Ed25519Sign),
    X25519DiffieHellman(X25519DiffieHellman),
    Hmac(Hmac),
    Hkdf(Hkdf),
    Pbkdf2Hmac(Pbkdf2Hmac),
    AeadEncrypt(AeadEncrypt),
    AeadDecrypt(AeadDecrypt),
}

impl Procedure for StrongholdProcedure {
    type Output = ProcedureOutput;

    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
        use StrongholdProcedure::*;
        match self {
            WriteVault(proc) => proc.execute(runner).map(|o| o.into()),
            RevokeData(proc) => proc.execute(runner).map(|o| o.into()),
            GarbageCollect(proc) => proc.execute(runner).map(|o| o.into()),
            CopyRecord(proc) => proc.execute(runner).map(|o| o.into()),
            Slip10Generate(proc) => proc.execute(runner).map(|o| o.into()),
            Slip10Derive(proc) => proc.execute(runner).map(|o| o.into()),
            BIP39Generate(proc) => proc.execute(runner).map(|o| o.into()),
            BIP39Recover(proc) => proc.execute(runner).map(|o| o.into()),
            GenerateKey(proc) => proc.execute(runner).map(|o| o.into()),
            PublicKey(proc) => proc.execute(runner).map(|o| o.into()),
            Ed25519Sign(proc) => proc.execute(runner).map(|o| o.into()),
            X25519DiffieHellman(proc) => proc.execute(runner).map(|o| o.into()),
            Hmac(proc) => proc.execute(runner).map(|o| o.into()),
            Hkdf(proc) => proc.execute(runner).map(|o| o.into()),
            Pbkdf2Hmac(proc) => proc.execute(runner).map(|o| o.into()),
            AeadEncrypt(proc) => proc.execute(runner).map(|o| o.into()),
            AeadDecrypt(proc) => proc.execute(runner).map(|o| o.into()),
        }
    }
}

impl StrongholdProcedure {
    pub(crate) fn output(&self) -> Option<Location> {
        match self {
            StrongholdProcedure::WriteVault(WriteVault { location: output, .. })
            | StrongholdProcedure::CopyRecord(CopyRecord { target: output, .. })
            | StrongholdProcedure::Slip10Generate(Slip10Generate { output, .. })
            | StrongholdProcedure::Slip10Derive(Slip10Derive { output, .. })
            | StrongholdProcedure::BIP39Generate(BIP39Generate { output, .. })
            | StrongholdProcedure::BIP39Recover(BIP39Recover { output, .. })
            | StrongholdProcedure::GenerateKey(GenerateKey { output, .. })
            | StrongholdProcedure::X25519DiffieHellman(X25519DiffieHellman { shared_key: output, .. })
            | StrongholdProcedure::Hkdf(Hkdf { okm: output, .. })
            | StrongholdProcedure::Pbkdf2Hmac(Pbkdf2Hmac { output, .. }) => Some(output.clone()),
            _ => None,
        }
    }
}

/// Implement StrongholdProcedure: From<T> for all.
/// Implement [`Procedure`] if `$Trait:ident` != `_`.
#[macro_export]
macro_rules! procedures {
    { _ => { $($Proc:ident),+ }} => {
        $(
            impl From<$Proc> for StrongholdProcedure {
                fn from(proc: $Proc) -> Self {
                    StrongholdProcedure::$Proc(proc)

                }
            }
        )+
    };
    { $Trait:ident => { $($Proc:ident),+ }} => {
        $(
            impl Procedure for $Proc {
                type Output = <$Proc as $Trait>::Output;

                fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
                    self.exec(runner)
                }
            }
        )+
        procedures!(_ => { $($Proc),+ });
    };
    { $($Trait:tt => { $($Proc:ident),+ }),+} => {
        $(
            procedures!($Trait => { $($Proc),+ } );
        )+
    };
}

procedures! {
    // Stronghold procedures that implement the `GenerateSecret` trait.
    GenerateSecret => { WriteVault, BIP39Generate, BIP39Recover, Slip10Generate, GenerateKey, Pbkdf2Hmac },
    // Stronghold procedures that implement the `DeriveSecret` trait.
    DeriveSecret => { CopyRecord, Slip10Derive, X25519DiffieHellman, Hkdf },
    // Stronghold procedures that implement the `UseSecret` trait.
    UseSecret => { PublicKey, Ed25519Sign, Hmac, AeadEncrypt, AeadDecrypt },
    // Stronghold procedures that directly implement the `Procedure` trait.
    _ => { RevokeData, GarbageCollect }
}

/// Write data to the specified [`Location`].
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct WriteVault {
    pub data: Vec<u8>,

    pub location: Location,

    pub hint: RecordHint,
}

impl GenerateSecret for WriteVault {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        Ok(Products {
            secret: self.data,
            output: (),
        })
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.location, self.hint)
    }
}

/// Revoke the data from the specified [`Location`]. Revoked data is not readable and can be
/// removed from a vault with the [`GarbageCollect`] Procedure. If the `should_gc` flag is set to `true`,
/// it with automatically cleanup the revoke. Otherwise, the data is just marked as revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeData {
    pub location: Location,
    pub should_gc: bool,
}

impl Procedure for RevokeData {
    type Output = ();
    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
        runner.revoke_data(&self.location)?;
        if self.should_gc {
            runner.garbage_collect(SecureClient::resolve_location(self.location).0);
        }
        Ok(())
    }
}

/// Garbage collects any revokes in a Vault based on the given `vault_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbageCollect {
    pub vault_path: Vec<u8>,
}

impl Procedure for GarbageCollect {
    type Output = ();

    fn execute<R: Runner>(self, runner: &mut R) -> Result<Self::Output, ProcedureError> {
        let vault_id = SecureClient::derive_vault_id(self.vault_path);
        runner.garbage_collect(vault_id);
        Ok(())
    }
}

/// Copy the content of a record from one location to another.
///
/// Note: This does not remove the old record. Users that would like to move the record instead
/// of just copying it, should run the `RevokeData` procedure on the old location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyRecord {
    pub source: Location,

    pub target: Location,

    pub hint: RecordHint,
}

impl DeriveSecret for CopyRecord {
    type Output = ();

    fn derive(self, guard: GuardedVec<u8>) -> Result<Products<()>, FatalProcedureError> {
        let products = Products {
            secret: (*guard.borrow()).to_vec(),
            output: (),
        };
        Ok(products)
    }

    fn source(&self) -> &Location {
        &self.source
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.target, self.hint)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MnemonicLanguage {
    English,
    Japanese,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AeadCipher {
    Aes256Gcm,
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    Ed25519,
    X25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Sha2Hash {
    Sha256,
    Sha384,
    Sha512,
}

/// Generate a BIP39 seed and its corresponding mnemonic sentence (optionally protected by a
/// passphrase). Store the seed and return the mnemonic sentence as data output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Generate {
    pub passphrase: Option<String>,

    pub language: MnemonicLanguage,

    pub output: Location,

    pub hint: RecordHint,
}

impl GenerateSecret for BIP39Generate {
    type Output = String;

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
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

    fn target(&self) -> (&Location, RecordHint) {
        (&self.output, self.hint)
    }
}

/// Use a BIP39 mnemonic sentence (optionally protected by a passphrase) to create or recover
/// a BIP39 seed and store it in the `output` location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BIP39Recover {
    pub passphrase: Option<String>,

    pub mnemonic: String,

    pub output: Location,

    pub hint: RecordHint,
}

impl GenerateSecret for BIP39Recover {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let mut seed = [0u8; 64];
        let passphrase = self.passphrase.unwrap_or_else(|| "".into());
        bip39::mnemonic_to_seed(&self.mnemonic, &passphrase, &mut seed);
        Ok(Products {
            secret: seed.to_vec(),
            output: (),
        })
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.output, self.hint)
    }
}

/// Generate a raw SLIP10 seed of the specified size (in bytes, defaults to 64 bytes/512 bits) and store it in
/// the `output` location
///
/// Note that this does not generate a BIP39 mnemonic sentence and it's not possible to
/// generate one: use `BIP39Generate` if a mnemonic sentence will be required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Generate {
    pub size_bytes: Option<usize>,

    pub output: Location,

    pub hint: RecordHint,
}

impl GenerateSecret for Slip10Generate {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let size_bytes = self.size_bytes.unwrap_or(64);
        let mut seed = vec![0u8; size_bytes];
        fill(&mut seed)?;
        Ok(Products {
            secret: seed,
            output: (),
        })
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.output, self.hint)
    }
}

#[derive(GuardDebug, Clone, Serialize, Deserialize)]
pub enum Slip10DeriveInput {
    /// Note that BIP39 seeds are allowed to be used as SLIP10 seeds
    Seed(Location),
    Key(Location),
}

/// Derive a SLIP10 child key from a seed or a parent key, store it in output location and
/// return the corresponding chain code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slip10Derive {
    pub chain: Chain,

    pub input: Slip10DeriveInput,

    pub output: Location,

    pub hint: RecordHint,
}

impl DeriveSecret for Slip10Derive {
    type Output = ChainCode;

    fn derive(self, guard: GuardedVec<u8>) -> Result<Products<ChainCode>, FatalProcedureError> {
        let dk = match self.input {
            Slip10DeriveInput::Key(_) => {
                slip10::Key::try_from(&*guard.borrow()).and_then(|parent| parent.derive(&self.chain))
            }
            Slip10DeriveInput::Seed(_) => {
                slip10::Seed::from_bytes(&guard.borrow()).derive(slip10::Curve::Ed25519, &self.chain)
            }
        }?;
        Ok(Products {
            secret: dk.into(),
            output: dk.chain_code(),
        })
    }

    fn source(&self) -> &Location {
        match &self.input {
            Slip10DeriveInput::Key(loc) => loc,
            Slip10DeriveInput::Seed(loc) => loc,
        }
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.output, self.hint)
    }
}

fn x25519_secret_key(guard: GuardedVec<u8>) -> Result<x25519::SecretKey, crypto::Error> {
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

fn ed25519_secret_key(guard: GuardedVec<u8>) -> Result<ed25519::SecretKey, crypto::Error> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKey {
    pub ty: KeyType,

    pub output: Location,

    pub hint: RecordHint,
}

impl GenerateSecret for GenerateKey {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret = match self.ty {
            KeyType::Ed25519 => ed25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
            KeyType::X25519 => x25519::SecretKey::generate().map(|sk| sk.to_bytes().to_vec())?,
        };
        Ok(Products { secret, output: () })
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.output, self.hint)
    }
}

/// Derive an Ed25519 public key from the corresponding private key stored at the specified
/// location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub ty: KeyType,

    pub private_key: Location,
}

impl UseSecret for PublicKey {
    type Output = [u8; 32];

    fn use_secret(self, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        match self.ty {
            KeyType::Ed25519 => {
                let sk = ed25519_secret_key(guard)?;
                Ok(sk.public_key().to_bytes())
            }
            KeyType::X25519 => {
                let sk = x25519_secret_key(guard)?;
                Ok(sk.public_key().to_bytes())
            }
        }
    }

    fn source(&self) -> &Location {
        &self.private_key
    }
}

/// Use the specified Ed25519 compatible key to sign the given message
///
/// Compatible keys are any record that contain the desired key material in the first 32 bytes,
/// in particular SLIP10 keys are compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Sign {
    pub msg: Vec<u8>,

    pub private_key: Location,
}

impl UseSecret for Ed25519Sign {
    type Output = [u8; ed25519::SIGNATURE_LENGTH];

    fn use_secret(self, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        let sk = ed25519_secret_key(guard)?;
        let sig = sk.sign(&self.msg);
        Ok(sig.to_bytes())
    }

    fn source(&self) -> &Location {
        &self.private_key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X25519DiffieHellman {
    pub public_key: [u8; x25519::PUBLIC_KEY_LENGTH],

    pub private_key: Location,

    pub shared_key: Location,

    pub hint: RecordHint,
}

impl DeriveSecret for X25519DiffieHellman {
    type Output = ();

    fn derive(self, guard: GuardedVec<u8>) -> Result<Products<()>, FatalProcedureError> {
        let sk = x25519_secret_key(guard)?;
        let public = x25519::PublicKey::from_bytes(self.public_key);
        let shared_key = sk.diffie_hellman(&public);

        Ok(Products {
            secret: shared_key.to_bytes().to_vec(),
            output: (),
        })
    }

    fn source(&self) -> &Location {
        &self.private_key
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.shared_key, self.hint)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hmac {
    pub hash_type: Sha2Hash,

    pub msg: Vec<u8>,

    pub key: Location,
}

impl UseSecret for Hmac {
    type Output = Vec<u8>;

    fn use_secret(self, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        match self.hash_type {
            Sha2Hash::Sha256 => {
                let mut mac = [0; SHA256_LEN];
                HMAC_SHA256(&self.msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha384 => {
                let mut mac = [0; SHA384_LEN];
                HMAC_SHA384(&self.msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
            Sha2Hash::Sha512 => {
                let mut mac = [0; SHA512_LEN];
                HMAC_SHA512(&self.msg, &*guard.borrow(), &mut mac);
                Ok(mac.to_vec())
            }
        }
    }

    fn source(&self) -> &Location {
        &self.key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hkdf {
    pub hash_type: Sha2Hash,

    pub salt: Vec<u8>,

    pub label: Vec<u8>,

    pub ikm: Location,

    pub okm: Location,

    pub hint: RecordHint,
}

impl DeriveSecret for Hkdf {
    type Output = ();

    fn derive(self, guard: GuardedVec<u8>) -> Result<Products<()>, FatalProcedureError> {
        let secret = match self.hash_type {
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

    fn source(&self) -> &Location {
        &self.ikm
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.okm, self.hint)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2Hmac {
    pub hash_type: Sha2Hash,

    pub password: Vec<u8>,

    pub salt: Vec<u8>,

    pub count: u32,

    pub output: Location,

    pub hint: RecordHint,
}

impl GenerateSecret for Pbkdf2Hmac {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let secret = match self.hash_type {
            Sha2Hash::Sha256 => {
                let mut buffer = [0; SHA256_LEN];
                PBKDF2_HMAC_SHA256(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                buffer.to_vec()
            }
            Sha2Hash::Sha384 => {
                let mut buffer = [0; SHA384_LEN];
                PBKDF2_HMAC_SHA384(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                buffer.to_vec()
            }
            Sha2Hash::Sha512 => {
                let mut buffer = [0; SHA512_LEN];
                PBKDF2_HMAC_SHA512(&self.password, &self.salt, self.count as usize, &mut buffer)?;
                buffer.to_vec()
            }
        };
        Ok(Products { secret, output: () })
    }

    fn target(&self) -> (&Location, RecordHint) {
        (&self.output, self.hint)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadEncrypt {
    pub cipher: AeadCipher,

    pub associated_data: Vec<u8>,

    pub plaintext: Vec<u8>,

    /// **Note**: The nonce is required to have length [`Aes256Gcm::NONCE_LENGTH`] /
    /// [`XChaCha20Poly1305::NONCE_LENGTH`], (depending on the [`AeadCipher`])
    pub nonce: Vec<u8>,

    pub key: Location,
}

impl UseSecret for AeadEncrypt {
    type Output = Vec<u8>;

    fn use_secret(self, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        let mut ctx = vec![0; self.plaintext.len()];

        let f = match self.cipher {
            AeadCipher::Aes256Gcm => Aes256Gcm::try_encrypt,
            AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::try_encrypt,
        };
        let mut t = match self.cipher {
            AeadCipher::Aes256Gcm => Tag::<Aes256Gcm>::default(),
            AeadCipher::XChaCha20Poly1305 => Tag::<XChaCha20Poly1305>::default(),
        };
        f(
            &*guard.borrow(),
            &self.nonce,
            &self.associated_data,
            &self.plaintext,
            &mut ctx,
            &mut t,
        )?;
        let mut output = Vec::with_capacity(t.len() + ctx.len());
        output.extend(t);
        output.extend(ctx);
        Ok(output)
    }

    fn source(&self) -> &Location {
        &self.key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadDecrypt {
    pub cipher: AeadCipher,

    pub associated_data: Vec<u8>,

    pub ciphertext: Vec<u8>,

    pub tag: Vec<u8>,

    pub nonce: Vec<u8>,

    pub key: Location,
}

impl UseSecret for AeadDecrypt {
    type Output = Vec<u8>;

    fn use_secret(self, guard: GuardedVec<u8>) -> Result<Self::Output, FatalProcedureError> {
        let mut ptx = vec![0; self.ciphertext.len()];

        let f = match self.cipher {
            AeadCipher::Aes256Gcm => Aes256Gcm::try_decrypt,
            AeadCipher::XChaCha20Poly1305 => XChaCha20Poly1305::try_decrypt,
        };
        f(
            &*guard.borrow(),
            &self.nonce,
            &self.associated_data,
            &mut ptx,
            &self.ciphertext,
            &self.tag,
        )?;
        Ok(ptx)
    }

    fn source(&self) -> &Location {
        &self.key
    }
}
