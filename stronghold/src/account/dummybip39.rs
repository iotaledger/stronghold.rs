use unicode_normalization::UnicodeNormalization;
use pbkdf2;
use hmac::Hmac;
use bip39;
use bitcoin;
use std::str::FromStr;

use bee_signing_ext::binary::ed25519;

const PBKDF2_ROUNDS: usize = 2048;
const PBKDF2_BYTES: usize = 32;//64 for secp256k1 , 32 for ed25

/// PBKDF2 helper, used to generate [`Seed`][Seed] from [`Mnemonic`][Mnemonic]
///
/// [Mnemonic]: ../mnemonic/struct.Mnemonic.html
/// [Seed]: ../seed/struct.Seed.html
///
fn _pbkdf2(input: &[u8], salt: &str) -> Vec<u8> {
    let mut seed = vec![0u8; PBKDF2_BYTES];

    pbkdf2::pbkdf2::<Hmac<sha2::Sha512>>(input, salt.as_bytes(), PBKDF2_ROUNDS, &mut seed);
 
    seed
}

// todo: replace with bip39 library

pub(crate) fn dummy_mnemonic_to_ed25_seed(mnemonic: &bip39::Mnemonic, password: &str) -> ed25519::Seed {    
    let salt = format!("mnemonic{}", password);
    let normalized_salt = salt.nfkd().to_string();
    let bytes = _pbkdf2(mnemonic.phrase().as_bytes(), &normalized_salt);
    ed25519::Seed::from_bytes(&bytes).unwrap()
}

pub(crate) fn dummy_derive(mut seed_to_derivate: bee_signing_ext::binary::ed25519::Seed, path: &str) -> ed25519::PrivateKey {
    let derivation_path = bitcoin::util::bip32::DerivationPath::from_str(path).expect("Unexpected derivation path");
    let iterable = derivation_path.into_iter();
    let iter_len = iterable.len();
    let mut subseed: ed25519::PrivateKey;
    for (i,children) in iterable.enumerate() {
        let index: u64 = u32::from(*children).into();
        let subseed = ed25519::PrivateKey::generate_from_seed(&seed_to_derivate, index).unwrap();
        if i+1 == iter_len {
            return subseed;
        }
        let privkey_bytes: &[u8] = subseed.as_bytes();
        seed_to_derivate = ed25519::Seed::from_bytes(privkey_bytes).unwrap();
    }
    panic!("Unexpected derivation path")
}