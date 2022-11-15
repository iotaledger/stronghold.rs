// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{rename, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use crypto::{
    ciphers::{chacha::XChaCha20Poly1305, traits::Aead},
    hashes::{blake2b, Digest},
    keys::x25519,
    utils::rand,
};
use thiserror::Error as DeriveError;

use crate::snapshot::{compress, decompress};

/// Magic bytes (bytes 0-4 in a snapshot file) aka PARTI
pub const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49];

/// Current version bytes (bytes 5-6 in a snapshot file)
pub const VERSION: [u8; 2] = [0x2, 0x0];
// pub const OLD_VERSION: [u8; 2] = [0x2, 0x0];

/// Key size for the ephemeral key
const KEY_SIZE: usize = 32;
/// Key type alias.
pub type Key = [u8; KEY_SIZE];

/// Nonce size for XChaCha20Poly1305
const NONCE_SIZE: usize = XChaCha20Poly1305::NONCE_LENGTH;
/// Nonce type alias
pub type Nonce = [u8; NONCE_SIZE];

#[derive(Debug, DeriveError)]
pub enum ReadError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupted file: {0}")]
    CorruptedContent(String),

    #[error("invalid File: not a snapshot")]
    InvalidFile,

    #[error("unsupported version: expected `{expected:?}`, found `{found:?}`")]
    UnsupportedVersion { expected: [u8; 2], found: [u8; 2] },
}

#[derive(Debug, DeriveError)]
pub enum WriteError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("generating random bytes failed: {0}")]
    GenerateRandom(String),

    #[error("corrupted data: {0}")]
    CorruptedData(String),
}

/// Encrypt the opaque plaintext bytestring using the specified [`Key`] and optional associated data
/// and writes the ciphertext to the specifed output
pub fn write<O: Write>(plain: &[u8], output: &mut O, key: &Key, associated_data: &[u8]) -> Result<(), WriteError> {
    // create ephemeral key pair.
    let ephemeral_key = x25519::SecretKey::generate().map_err(|e| WriteError::GenerateRandom(format!("{}", e)))?;

    // get public key.
    let ephemeral_pk = ephemeral_key.public_key();

    let ephemeral_pk_bytes = ephemeral_pk.to_bytes();

    // write public key into output.
    output.write_all(&ephemeral_pk_bytes)?;

    // secret key now expects an array
    let mut key_bytes = [0u8; x25519::SECRET_KEY_LENGTH];
    key_bytes.clone_from_slice(key);

    // get `x25519` secret key from public key.
    let pk = x25519::SecretKey::from_bytes(key_bytes).public_key();

    let pk_bytes = pk.to_bytes();

    // do a diffie_hellman exchange to make a shared secret key.
    let shared = ephemeral_key.diffie_hellman(&pk);

    // compute the nonce using the ephemeral keys.
    let nonce = {
        let mut i = ephemeral_pk.to_bytes().to_vec();
        i.extend_from_slice(&pk_bytes);
        let res = blake2b::Blake2b256::digest(&i).to_vec();
        let v: Nonce = res[0..NONCE_SIZE].try_into().expect("slice with incorrect length");
        v
    };

    // create the XChaCha20Poly1305 tag.
    let mut tag = [0; XChaCha20Poly1305::TAG_LENGTH];

    // creates the ciphertext.
    let mut ct = vec![0; plain.len()];

    // decrypt the plain text into the ciphertext buffer.
    XChaCha20Poly1305::try_encrypt(&shared.to_bytes(), &nonce, associated_data, plain, &mut ct, &mut tag)
        .map_err(|e| WriteError::CorruptedData(format!("Encryption failed: {}", e)))?;

    // write tag and ciphertext into the output.
    output.write_all(&tag)?;
    output.write_all(&ct)?;

    Ok(())
}

/// Read ciphertext from the input, decrypts it using the specified key and the associated data
/// specified during encryption and returns the plaintext
pub fn read<I: Read>(input: &mut I, key: &Key, associated_data: &[u8]) -> Result<Vec<u8>, ReadError> {
    // create ephemeral private key.
    let mut ephemeral_pk = [0; x25519::PUBLIC_KEY_LENGTH];
    // get ephemeral private key from input.
    input.read_exact(&mut ephemeral_pk)?;

    // creating the secret key now expects an array
    let mut key_bytes = [0u8; x25519::SECRET_KEY_LENGTH];
    key_bytes.clone_from_slice(key);

    // derive public key from ephemeral private key
    let ephemeral_pk = x25519::PublicKey::from_bytes(ephemeral_pk);

    // get x25519 key pair from ephemeral private key.
    let sk = x25519::SecretKey::from_bytes(key_bytes);
    let pk = sk.public_key();

    // diffie hellman to create the shared secret.
    let shared = sk.diffie_hellman(&ephemeral_pk);

    // compute the nonce using the ephemeral keys.
    let nonce = {
        let mut i = ephemeral_pk.to_bytes().to_vec();
        i.extend_from_slice(&pk.to_bytes());
        let res = blake2b::Blake2b256::digest(&i).to_vec();
        let v: Nonce = res[0..NONCE_SIZE].try_into().expect("slice with incorrect length");
        v
    };

    // create and read tag from input.
    let mut tag = [0; XChaCha20Poly1305::TAG_LENGTH];
    input.read_exact(&mut tag)?;

    // create and read ciphertext from input.
    let mut ct = Vec::new();
    input.read_to_end(&mut ct)?;

    // create plain text buffer.
    let mut pt = vec![0; ct.len()];

    // decrypt the ciphertext into the plain text buffer.
    XChaCha20Poly1305::try_decrypt(&shared.to_bytes(), &nonce, associated_data, &mut pt, &ct, &tag)
        .map_err(|e| ReadError::CorruptedContent(format!("Decryption failed: {}", e)))?;

    Ok(pt)
}

/// Atomically encrypt, add magic and version bytes as file-header, and [`write`][self::write] the specified
/// plaintext to the specified path.
///
/// This is achieved by creating a temporary file in the same directory as the specified path (same
/// filename with a salted suffix). This is currently known to be problematic if the path is a
/// symlink and/or if the target path resides in a directory without user write permission.
pub fn write_to(plain: &[u8], path: &Path, key: &Key, associated_data: &[u8]) -> Result<(), WriteError> {
    // TODO: if path exists and is a symlink, resolve it and then append the salt
    // TODO: if the sibling tempfile isn't writeable (e.g. directory permissions), write to

    let compressed_plain = compress(plain);

    let mut salt = [0u8; 6];
    rand::fill(&mut salt).map_err(|e| WriteError::GenerateRandom(format!("{}", e)))?;

    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(hex::encode(salt));
    let tmp = Path::new(&s);

    let mut f = OpenOptions::new().write(true).create_new(true).open(tmp)?;
    // write magic and version bytes
    f.write_all(&MAGIC)?;
    f.write_all(&VERSION)?;
    write(&compressed_plain, &mut f, key, associated_data)?;
    f.sync_all()?;

    rename(tmp, path)?;

    Ok(())
}

/// Check the file header, [`read`][self::read], and decompress the ciphertext from the specified path.
pub fn read_from(path: &Path, key: &Key, associated_data: &[u8]) -> Result<Vec<u8>, ReadError> {
    let mut f: File = OpenOptions::new().read(true).open(path)?;
    check_min_file_len(&mut f)?;
    // check the header for structure.
    check_header(&mut f)?;
    let pt = read(&mut f, key, associated_data)?;

    decompress(&pt).map_err(|e| ReadError::CorruptedContent(format!("Decompression failed: {}", e)))
}

fn check_min_file_len(input: &mut File) -> Result<(), ReadError> {
    let min = MAGIC.len() + VERSION.len() + x25519::PUBLIC_KEY_LENGTH + XChaCha20Poly1305::TAG_LENGTH;
    if input.metadata()?.len() >= min as u64 {
        Ok(())
    } else {
        Err(ReadError::InvalidFile)
    }
}

/// Checks the header for a specific structure; explicitly the magic and version bytes.
fn check_header<I: Read>(input: &mut I) -> Result<(), ReadError> {
    // check the magic bytes
    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(ReadError::InvalidFile);
    }

    // check the version
    let mut version = [0u8; 2];
    input.read_exact(&mut version)?;

    if version != VERSION {
        return Err(ReadError::UnsupportedVersion {
            expected: VERSION,
            found: version,
        });
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use stronghold_utils::{
        random,
        test_utils::{corrupt, corrupt_file_at},
    };

    fn random_bytestring() -> Vec<u8> {
        random::variable_bytestring(4096)
    }

    fn random_key() -> Key {
        let mut key: Key = [0u8; KEY_SIZE];

        rand::fill(&mut key).expect("Unable to fill buffer");

        key
    }

    #[test]
    fn test_write_read() {
        let key: Key = random_key();
        let bs0 = random_bytestring();
        let ad = random_bytestring();

        let mut buf = Vec::new();
        write(&bs0, &mut buf, &key, &ad).unwrap();
        let read = read(&mut buf.as_slice(), &key, &ad).unwrap();
        assert_eq!(bs0, read);
    }

    #[test]
    #[should_panic]
    fn test_corrupted_read_write() {
        let key: Key = random_key();
        let bs0 = random_bytestring();
        let ad = random_bytestring();

        let mut buf = Vec::new();
        write(&bs0, &mut buf, &key, &ad).unwrap();
        corrupt(&mut buf);
        read(&mut buf.as_slice(), &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = random_key();
        let bs0 = random_bytestring();
        let ad = random_bytestring();

        write_to(&bs0, &pb, &key, &ad).unwrap();
        let bs1 = read_from(&pb, &key, &ad).unwrap();
        assert_eq!(bs0, bs1);
    }

    #[test]
    #[should_panic]
    fn test_currupted_snapshot() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = random_key();
        let bs0 = random_bytestring();
        let ad = random_bytestring();

        write_to(&bs0, &pb, &key, &ad).unwrap();
        corrupt_file_at(&pb);
        read_from(&pb, &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot_overwrite() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        write_to(&random_bytestring(), &pb, &random_key(), &random_bytestring()).unwrap();

        let key: Key = random_key();
        let bs0 = random_bytestring();
        let ad = random_bytestring();
        write_to(&bs0, &pb, &key, &ad).unwrap();
        let bs1 = read_from(&pb, &key, &ad).unwrap();
        assert_eq!(bs0, bs1);
    }

    struct TestVector {
        key: &'static str,
        ad: &'static str,
        data: &'static str,
        snapshot: &'static str,
    }

    #[test]
    fn test_vectors() {
        let tvs = [
            TestVector {
                key: "f6eafe6482445269d3228b3647001c283102116362e870644ba3bfc7f8f109e6",
                ad: "6d5a8ef07126f166a668b2118d09cec01789d3c8c18578aa4454c2f27af4e7e7ba256df789f372ff7f42df4a048eeb95e0794e4996d693ad3824b61e572529a3badf01b8ca199ad082c798a2d089632b2d80f6e621e4d5f29470a190a09234aa0186c44e26690dc0360821438baa6cf45397eeb6d40f56aa7ab039444b53c0b37bf3c204d1b251531d474fae4310ab753957200eaf8236eb3d60ab6baba6cd7add6adea8fe714809b5a67410cd382897e9d770569a7828dab072e3c40630842561cc6db00a95c791466193d027f30071852f4da072bd8e17d1cdd051bb2090121a012247678e7a6d88193ccade1866bd8c78d320cf3f2b68f743c8c13485ec18deffca7da6b0d03250f6b97e71cf36c0b56eb74ea4a65581a026d4379cc4bc5318d9bc46a2a5cc86b4121bf42315a4134116364edc26bee8fd3e8b833ee41ac1fa0b28a781bab75a830f7886e110eb35496fc940b34b53664f4896e8fcee19b1ec4daf9addb4b701ee7fbca65c374061563ab898e469b9b2c878574653b78fb6b483085298591355b841b9b1ea54f8ffd6f77fc0c818705810c77dc3c4f8f08a5a2c177eea17b748e387869554ffe9469316d330abe87bd258c15af149246c84a770cdd77006002a1818422eab51cb6d75a018df20d4f0323c6724ef3563fabb172d8e11c7f8e8f320e943cce9241d329969c90527edc7bc318bfc886869031a2a76ab82ad36f326f8b122d87fcf4bfb838b5c115d527c111f350f196878bf132d711aa2f22fef1df20a94b7bff051fb7c5aec67182e3a95101deb7691e1bfb410bb81300e19888da5f8d1024eb1e79a9f195b26303dbe2f27764fbe0ab393b2e78532ebaca71de02d15fcdaa6638bc5e185bd90cc251d0942024bd57522565b630347d76aa7f5cf5c095673ed2f5f84b533e228488c2fcd022e1a81655fc4fc96a035e02e25162c78246006a623800b31e05092914261dc09743b7a4346380d2be2844e8e8c8e866e28c2d22fc6c131403e2011c5353b1d0b73ab61c69fd3c567fdc8b4d49decb7a81e8b82f1384ff9b94a8421652a196ea2a9ebdace3a30c1c150520b98468df58791a89a0f7bdf08d974ab0afca52fd03885ef42440abb1fef4cdbd4019590effe882df3fe72be81803f3940edb7cbfb6fe48d3dcbd80d8d7e9d459a1602dccbe641893b38428f84addcaec9c3b98bc617a5bf41548d3104085d8e7799b725dd1524549adeef73d9e01af383bf64e7020c273017cf07facd10232b7c8abb4ffb2f8880cc12c5a735d8133e4708ef2aa14a466c5cf7a31db2a1a8b32e5d59d22695d1c12483f9702126815f40c391404801afa5ea58923a393b8be53f63de5c90d6716d6bba4cee05962f3f906e797f89e12c8af0b8419a4612ba6a0e346025cdc606ec89900ca6a60a63d3a699e7d20e5877dbe7924b93d4023e727f2c367d700e71e04ad1ee8de1c7f0f4b23e63e91287945dfc718f7a4522c5c5fe353aacb093e3349d9f0ad393c175f629b928322ddc295393949dd2cae3ccfcf5a39dd8298c3647291a3a6cac0be54ead7eb7627b338dff0f19dc2e634ce69d25522af385b4c68095c25b1aa7d2a38d24adae844aeba0339ba06206933fcb6b371b3328755bf16f4b07ab6743ecc81c40cb61a34cba9f023eb4bcec093fdf7e5d793949d297883ea07ffc1abfd4b171c14d6e02dfc28574b39efd99fb001c0d62874ac78367ea89838f2a7c5e11cc5c0811aceae14e29d782d97b748f63058b79006c16f46c9dff41071a3db90566f3cb3a3bb57129dc07d318d990c9a2e11103cbaf48ffcadd3b199980436196d618c32ffb5d264c751fe10d725a4dcf8790be5841bab7eb7b383c8292d2ec9587cfb3c56a04970fd00e74d62a997eff100c54e23d09fd856d32b0f82632c9ca0ab93df90460692f2cde96366c2ea430843549cc707ef6204c9f796b3ccbac70582c176d7e5c07052f76883dda044454441c61149038fb09caca8f089f80566c764d589d1e05c169ea5f059147f7986312268ab1cc03a215ada364d428a49ceda93da4ef2d3f3730b9382566dfc0d1e96402ca8d43690ce27f2f5699ce1497133e9effd93fb7bdf740f36c49051ba3fc990a2793508c32d24e6401f694e42edcdf403eced570033ed64b1356350d1ec25dc51c06ad4625d38fd7d92f271c830172f4c83d16a8ce6fa4f9aca0c2bb17e17f3da91a5c9406c498edfd09dad177658d14192fa91ec0022e13719cd3f283785b9f83bad9b08b0b63be48eeaa38c35571690f6e1e0023ba946ba8a98a6074d9467fda39b9e15f695908d5b0488ecf46e9d1febce5fd38a3597d7f1285c163f7c93d3f1875bb7d279a4080e4227e195a25fa22c333b775ec7e22bf3dfb7754ac58c79498a60533dbcb62eedbfd6a7dba5727152b18af80049b4106392b03c801a033638142183101012f4f7403954fe33904a00f7ac448bb946379d0815f62cc6237e7fd2db158bd3968126f6281a13ec7be704e0d7ea3a4ba65791573d1f44f272a6f30911dcd619e9c7462ff8c23f9f12b9cb1771ee9aef34212d058e673a771dc2854508dad788d9caeff5010fed2c0f0dc501b721491d8f0ea293f1924138af6ce3ffea55de2dc9909140c826092443fc429f598f6972b70e4193a5209a3b8578b13aa08351f8140e96afa0486163fbea87ff0100e7781faa869ad4328c4556fa4797578746815fd22a2b7a7c3bdaf3e085f5ea4e9b774c910e39637b82adc717fc1dbb7c403b06a0e62ce51cedfeb3d82c7c18e8164807f5f682eecf8415c3b3e7933a7f03a1466e8c2101c436fcfc95ed6933c85892263f46643cb1068797691640fcf7aafa7fcab7a0a5443802fe155ae21c6dabdf7a1ec489a955ead4b47b291cdf7f600a24eb5ab7cf71065507403500c9717c9ed2a663c841fc84e76572a92541a7a299a82acffa68dd1d7f235873fcae33be7d4698706c6d4c44fdf4deb",
                data: "a0dcd6b9a95ca5321cefb443c3d19915eb269072929841d986306982a459229a1866479a64f5ed9ac31ea083ae73859b8e5a3ccd9e3045881602f2ed036d473ef09e88c488f4c0a95e823fd984a1ffd69a9a9d3f7ab63e9bd673020181363b9134f46aa6734a9a9600b01b35740f5161dfad303a8a85ad5edcef31bd76a8d47ae1a46e60824c1023401ddaa5d385f414cc2c1773aca240629e4a80149bdf992d97622c1775399a2c65d5f81f5cfcb79c894971b87a17f655c0c4b88b90ee2ad8bfdcd47d7566b33de7957a5c06d7d5b3cddcf55d45bb78c4d5099753edb51974ab01f9371140b89b56382c7bf28e62e246c2828e0ef45a991cd7b1e5a93ce5587b0e50792c2b44744121e84be0e3d6e01b2488d342622e1602d9a07eca27ffd83fb30e2c0b9700cf45080e415554b75ccfa08913acb9e8",
                snapshot: "50415254490200887607ce96a91114f2e297a2eb31af3bafeeb342ff2371d7c6735bb0f5614104533d3551f29a1128db9a854046ca9ea2a064e9f300c44cf1117272ffd1acd4e7a27f9051b9565d4956679336028176eaa8bc5b3fa0f57504e00ee5a9a4ea9303c2002daef6991453d9eec31e9e84a13a9b6c8536abc90eefc0bcf61191724bc2c7dbad2ec2514ffb90c7813d0746817a6665be70f6aba92caff6e2ba5c4e8d1317a46188d2bb56cca1a4e1d1ce8d4c5a96b33c117284f377c71c020cdfd7b3ace26b51b39e4c20da37747eb8251638a3239f4bdb3b1af6edd3535236462d165b5e44ebed0bcadc0ebb0549a85e2b8cee4c2b1e890c56568f143a15cc0dabc694b4e431d1eb62d435298467d154b629d6a7062f6027de02fc52cf5d0016271838ddf3ffa93deeb033ffc8f5c44ce77245e1670c7af246bcc5b603bbfd5bd227e2d7afc0788391701a59113a745edd413d6421e8d03f6739eb2cc4780faf1d397ad2e90df2824da9",
            },
            TestVector {
                key: "683bd3d6957bf7276d0a616304f1610c57689a96d90118762f4caa9de9bc5bb6",
                ad: "32e8ff038b43f9c0218183472ee239b53426c81de233a0d5a57d64d904c47a6b7e8ad2ee1e0d8838d6151b79bd284cbb3770459625007010d608db7f2476e4bfcfa08990175190e7f48801eb2999e4c8f3e7eb490e96a9892d72f9817af9baae9846944678c4001ca23abd1fd7b6f39d3e42eab0cec60935c94bb6c22f851a122e39bfd42643ee248d444e6bf9316c378443ca40a11f728c4d1313be53949b25b527449efca3c1ada2770edf87d61732fd3791d4cb57eb30baf4d5c09f2a680161a57524bad98659d66f824bc69fccdc7537d6a51a7fb791acf8a34c1de2e701227e6744324af94917eeabb96fafeb6709e0b68de899959896bac30d17a2ff58b3a3715320f52c627021a44bebd3dd3929602b5eb9a91917dcd3377e2f83898ddadd3ffb88e73e3cfce9f696680385613aab6144de1a3f4620b7a967b62c62dda96ad99e71df36d6633b921e2d15eb30cd442b86c747207ece62bc3e7a8be5ff729db97767ab392863f6a4f3ddde6984df976550c1371e4e2b4a65df37481d902550b95f014a7cec3e696b6a23756eeec5aa2447f22035bea4384439e4bd3cf3535741948b42fa5d8469985ad4f0229880678b939dffbb744bb977430eede0a8bfb39522a437b93b48820db3a60ec020eed926693cbf87076328ec9cc21c1d71c803f72d467dab6034d1f80e818b82c95ff418f7531636471bbdde27c74acbeeccad3e406aac5310071da9c00356302871688ebac8080f30ff0df050cc6090a446a1aec740796112b71905b7e731aee395e50e91fcee2648bb08e35a85772b4509daac55b5a2075dfb29f79b154ea02438eb779be67a1353e6e13218901511b40531c83f95c29d2be4fac0b2c76f56e36d7257510d1cccef44a6b8c28bf96a73818832a941e002e7ec5b70a61fc7b94fe9e0c9e904fea904d8dd4f3b2d27f38401d99e4d3cae2e3a9c6a6e85179b2de64568ae8bfd45234faa657f4ec6bfa624aa0b23f6fd52c3e63c4dc181ff5c1598bf8b26ad9ac90e6db668fc70eae82f09fc69d97ccb160f65f25a20352b1ffa1fbaeb2adbf2ff60aec31ffb6c0d2672806679a1bad6ac9e99ab0be5d4d9185a002aeef13265796e61f1645e29ad88ddbcce1c7e59fadcbd1b18f40312efa06f72039c773262db8cafde6b849ecb7add3e8e8d475d1657c200a089b518f8434aa6b9431db69f9e71d317e3cafff8019e49b17a0f3a0106f93137cf5c8681a19df5060e7abeb24f09d57febd637f056400084809c0a5e2789b2b5e9eaa52c6df4c3198eba43807d4bea5e659054932a8219332ca78c5bde5773da4a93f69e2e9a4fdcf298421c04b6f58147f300a40c274bb5573f817cb70d8239857d1d3a9dbbeccbf3486e7408607da89f4336d179237b82c8125433ef7e4a2185b31ea7ac14ed567c7e8c410b8565636443312bf09ac2ad04e413b59c91d57fc97a5da6ea5bc423cf205b04efba315c62fed3b303f96e66308da697f420884c28126af3931cf3ed103fe019b2757546d2d3ec903c7e66be6261db26e8c57908190daf43a022f769dcab356d5202c6c3a118562a68e630f709d3c351f4fac449bd56cf5bac8b0ffe9eb0e6d46a9906150847cb84f74b27ceade192ade1da0ddb148dc4a2f31a1f84aaf808612df6277582fe6be117d09ca75e35c237b097ad4e1eab8c374772308f927292e6e1ac91f2f821c2e3669113c08bb3a783e9f35f23310f04c247a3490f2e8e6b0c9045318048fb0252f033da48cfbf33c8f1d0732f16de516996a9932301bd8ffb7c4fb6473adc755dad5a41667fed8cd2785eaf26b07f06d913a44234e6b6050d67120b82529c18bf4a2f4405697e942db00fc35385be2896087cf56be36a0c0d297cbd167aec7ec2ca581ac0b72beecbb105c90c1d13b7fa77405d7b766eb65d6f3ba1106a309c82e207c6ba222e2e0c878ee5d9542d05e274e1fbddf3395bf8273498ee6f6a8da24efa7f629b164754fc24ef1533ac4bd5763dfc38f0b79cf13bf43f1f95d02b3e7520b0c04fdb65d9ecec03f9ab32c1edb38720cedd129baf6ceb2d045b02b86b0d28c19204d267752c2e7c48dcf91702cecd9caaa782efbe163f9cd88a89f536c19b9b04ea46f832df38a42b42f6cd2fd2caaf54f4c038b0d0b2299944ebbbcf6e4bb84eef0fd95027e3ac851fbecbffe48272c0eb21e6f1ce4e02be1406107d3ae0861a5ac73381f1e2d5baf9a01b8e49bd1351b647a85824cb0aa564668a99c90423fdb724fec709d2f8229e86e4663fdfdee20a5d675d0ee8e7ff212516654651051700dfc1092b57f0abda8009814c5bd055046202595f711b46acf86c4bc18acf82d6acbfe5a5c50987bdc68c2d6e43c86e272bffe17f76706b6856613205e7fc00cea26344c1088e75a86b133bc31550c8e8c7be7fef60d2c7e800519f56ec56b726b93731523d72b29d6b18c8d915e880912be173e6d078a0d8c860c428033b26b9d8db827109",
                data: "",
                snapshot: "50415254490200ff2d2c7d8d37693212ff5fec1cb34f8601884253f58a35fa4edfb68dc487ca7d31805137b89220d788a60b057a56a939",
            },
            TestVector {
                key: "cd250a0b070632dc521cfe35805b2846763a4c698d61d85d3b55f115b9a769da",
                ad: "",
                data: "",
                snapshot: "50415254490200665c393f383466881adbbc788ff49389f2268f9b6d43084e9ff8bfc945b09501ac469b5ad0e666eada7c7566a295574a",
            },
            TestVector {
                key: "9cf33b2539a3e9d89d2586ae6783d781de68df155eb2af22abaca3d6094d6db8",
                ad: "2a66380cd696893f41ec5409a4f06fbc0bd8b498ec7ecb663be6937460c4812bde10bb3343292f65e61bf20c184dd341f7ef63c7125b6684d6a8d09f5430df795569b999293d7f2149970247d9e74fc4259d4eb0fd5d015a89765581232d02e42db93536bdbb90b7060147494c23563a0c912041b7d9eb6d333d8c5add43a3f8fe31f49e392ac6bff410dd746f0346244045d43711187ae2c1efb84c1786607c35f0eb8b1225084168b45edc85b7baeabe3b9510c73c5c5d3a9a6be766cdbca7603a9c06800ef8725a9978f79d43b47ca139161118c4a220f57656ddb907a6f0798e55a87e17f618b7fc41d2339a0876bd92683630c9290c808b0e988f8193c6bc00b1628283a8fd2e816547da6c08d2b0892272e2482396ae306866edd83f4e719863c8e571f7a2a5c0f829303ba12d1d09ec08e32a3ef8b248a0a44281b51885aa481ac5ac01c5663a4223e2bae2b27629e9845dff041ea3a76b2540526fc7c017c45cbc593dd63105a02cbac8c13b0247e44f1d480633092c963a31355a4fdd1c75e80954f7ab30d08677e6c7f811791d941694306779e2ef02bd7645004fb921da5cd9705e00af0e25f79120b277b706218105675ae2fd2fc29921d95ea0087aa44ebc948dff8d8d5cdbfb889b94a4636b2f15623063883dec52f19b65e96d062ae836597299c236af306109146ff3c90eeec117b20284cf67bdc375a03dd62db347dd9aabb64dad418c8fda4fa32efd2d21d09a2772edb6f90a28c7486e7d4801d420d60171bab781a57f63d211df731fe3e73c0e1e9e20a409e157920ffde4a67d57414dc5a0b48138337ce412bedef0ad5451bf65d66f13c76fe645d695030c3b0552be57ff2348be0b10c8ae1220b3a2884be9c5f354c37acb59a84ca4c2c808b4fcf283b536699c73372de75eef420904a82c0bbd504a83900b2df9640e9eb80e9718cec702aca1686f74e297fc8ef80ae3b85dd14f1b92424f28e529b51d18a40f970ba6038c906e7153cd4af4dbf7a3da548f56cbf511bea4d7b56d8c8fbabf6e51e26428c4a1bdcdb2891078ad6a17cc49dd8731c30208643114fbbd8086a19c0df91d2be19e189e39136e65c0e687e9c911c82a101cac99aa601353c0a547951a0ce06e75409361b03fcde82e7c507c85097138dab97dd24b7a9bda2f78d67d28cdf83bf5cd7716a4f0650c26968e7914621e2326c3fad61220e15aa6100abaa284d098e2d1deb4f102c6d992351f25fddc54bd3c1271855b93c9e523fb2e3fd59b4c81cc6f33c48e6a81ad6d55d234cac365d0f49687ace1ef8291becfc90d38bff49e328ec83c2edab309b1bc2435f2a2c669b67b40b194f6d3a7b19824081fb998a216da6c63272797978f7d359bc70f83f600193540dc9440598d4b508308db0d2ab29f426fc29c01befbc653004bf7a85b28e81c4b0dcba222e53e1e03935afbf9c2bec9550a45999798aaa9cdc4385044cc19586bc3138240b619a07e21132b5d0c1aefb9e8ae645a7f5d1f5f3a23b53f35cd9710da140932fcafe45526e539766514873ccbcf826863fb5539d9af4bfdf71708f8db5adb85a34d91becccf6e6accc45d184088a949d42224ce53d241d79afd679d0b382976a9e5d06e92bbda8887311987219af17ed48608c3b8c318b448265827a59e776051a82b8cc29a4efdd4f0fb829b0f538ca77219274ed34bc58aca61f792f19f9857ba734760ec0fffc3ca29ff5cc35838929af3b9d718ceaf82f983967708da0d3d0776538ffe5c705b02b973a210e048a31ee7abf49b397594ced46dc7a8e0d4eac1382c3bd97da423991606830f92ec5607e281fad676fd4fd94035894b3ffc185585f1b9edea4fb47457c96c085e09d0e2b16169e4843f7834c4399ec0587b9d390a6db7cce698e7f0b5ecb934015dbf16373eefd859143b985da4691159efe3b28a5ec75126c2eef1c47328132752dc92500a4df7920c2c97fa8be52058c9cba0dc5770a4d8e4e445bd",
                data: "",
                snapshot: "50415254490200f78bcdd60713c80fdba455f92f4d1efbb84bb7e65b9da36b12194231909a03505008c7d507d2c6b407c00a9310b134b1",
            },
        ];

        for tv in &tvs {
            let mut key = [0; KEY_SIZE];
            hex::decode_to_slice(tv.key, &mut key).unwrap();
            let ad = hex::decode(tv.ad).unwrap();
            let data = hex::decode(tv.data).unwrap();
            let snapshot = hex::decode(tv.snapshot).unwrap();

            let mut slice = snapshot.as_slice();

            // check the header for structure.
            check_header(&mut slice).unwrap();
            let pt = read(&mut slice, &key, &ad).unwrap();

            assert_eq!(pt, data);
        }
    }
}
