use unicode_normalization::UnicodeNormalization;
use pbkdf2;
use hmac::Hmac;

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