// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    convert::TryInto,
    fs::{rename, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use crypto::{
    ciphers::chacha::xchacha20poly1305,
    hashes::{blake2b, Digest},
    x25519,
};

use crate::{compress, decompress};

/// Magic bytes (bytes 0-4 in a snapshot file)
pub const MAGIC: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49];

/// Current version bytes (bytes 5-6 in a snapshot file)
pub const VERSION: [u8; 2] = [0x2, 0x0];

const KEY_SIZE: usize = 32;
pub type Key = [u8; KEY_SIZE];

const NONCE_SIZE: usize = xchacha20poly1305::XCHACHA20POLY1305_NONCE_SIZE;
pub type Nonce = [u8; NONCE_SIZE];

/// Encrypt the opaque plaintext bytestring using the specified key and optional associated data
/// and writes the ciphertext to the specifed output
pub fn write<O: Write>(plain: &[u8], output: &mut O, key: &Key, associated_data: &[u8]) -> crate::Result<()> {
    output.write_all(&MAGIC)?;
    output.write_all(&VERSION)?;

    let ephemeral_key = x25519::SecretKey::generate()?;

    let ephemeral_pk = ephemeral_key.public_key();
    output.write_all(ephemeral_pk.as_bytes())?;

    let pk = x25519::SecretKey::from_bytes(key)?.public_key();
    let shared = ephemeral_key.diffie_hellman(&pk);

    let nonce = {
        let mut i = ephemeral_pk.to_bytes().to_vec();
        i.extend_from_slice(pk.as_bytes());
        let res = blake2b::Blake2b256::digest(&i);
        let v: Nonce = res[0..NONCE_SIZE].try_into().expect("slice with incorrect length");
        v
    };

    let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];

    let mut ct = vec![0; plain.len()];
    xchacha20poly1305::encrypt(&mut ct, &mut tag, &plain, shared.as_bytes(), &nonce, associated_data)?;

    output.write_all(&tag)?;
    output.write_all(&ct)?;

    Ok(())
}

/// Read ciphertext from the input, decrypts it using the specified key and the associated data
/// specified during encryption and returns the plaintext
pub fn read<I: Read>(input: &mut I, key: &Key, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
    // check the header
    check_header(input)?;

    let mut ephemeral_pk = [0; x25519::PUBLIC_KEY_LEN];
    input.read_exact(&mut ephemeral_pk)?;
    let ephemeral_pk = x25519::PublicKey::from_bytes(&ephemeral_pk)?;

    let sk = x25519::SecretKey::from_bytes(key)?;
    let pk = sk.public_key();

    let shared = sk.diffie_hellman(&ephemeral_pk);

    let nonce = {
        let mut i = ephemeral_pk.to_bytes().to_vec();
        i.extend_from_slice(pk.as_bytes());
        let res = blake2b::Blake2b256::digest(&i);
        let v: Nonce = res[0..NONCE_SIZE].try_into().expect("slice with incorrect length");
        v
    };

    let mut tag = [0; xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE];
    input.read_exact(&mut tag)?;

    let mut ct = Vec::new();
    input.read_to_end(&mut ct)?;

    let mut pt = vec![0; ct.len()];
    xchacha20poly1305::decrypt(&mut pt, &ct, shared.as_bytes(), &tag, &nonce, associated_data)?;

    Ok(pt)
}

/// Atomically encrypt and [`write`](fn.write.html) the specified plaintext to the specified path
///
/// This is achieved by creating a temporary file in the same directory as the specified path (same
/// filename with a salted suffix). This is currently known to be problematic if the path is a
/// symlink and/or if the target path resides in a directory without user write permission.
pub fn write_to(plain: &[u8], path: &Path, key: &Key, associated_data: &[u8]) -> crate::Result<()> {
    // TODO: if path exists and is a symlink, resolve it and then append the salt
    // TODO: if the sibling tempfile isn't writeable (e.g. directory permissions), write to
    // env::temp_dir()

    let compressed_plain = compress(plain);

    let mut salt = [0u8; 6];
    crypto::rand::fill(&mut salt)?;

    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(hex::encode(salt));
    let tmp = Path::new(&s);

    let mut f = OpenOptions::new().write(true).create_new(true).open(tmp)?;
    write(&compressed_plain, &mut f, key, associated_data)?;
    f.sync_all()?;

    rename(tmp, path)?;

    Ok(())
}

/// [`read`](fn.read.html) and decrypt the ciphertext from the specified path
pub fn read_from(path: &Path, key: &Key, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
    let mut f: File = OpenOptions::new().read(true).open(path)?;
    check_min_file_len(&mut f)?;
    let pt = read(&mut f, key, associated_data)?;

    decompress(&pt)
}

fn check_min_file_len(input: &mut File) -> crate::Result<()> {
    let min = MAGIC.len() + VERSION.len() + x25519::PUBLIC_KEY_LEN + xchacha20poly1305::XCHACHA20POLY1305_TAG_SIZE;
    if input.metadata()?.len() >= min as u64 {
        Ok(())
    } else {
        Err(crate::Error::SnapshotError("Snapshot is too short to be valid".into()))
    }
}

fn check_header<I: Read>(input: &mut I) -> crate::Result<()> {
    // check the magic bytes
    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(crate::Error::SnapshotError(
            "magic bytes mismatch, is this really a snapshot file?".into(),
        ));
    }

    // check the version
    let mut version = [0u8; 2];
    input.read_exact(&mut version)?;
    if version != VERSION {
        return Err(crate::Error::SnapshotError("snapshot version is incorrect".into()));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use test_utils::{corrupt, corrupt_file_at, fresh};

    #[test]
    fn test_write_read() -> crate::Result<()> {
        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        let mut buf = Vec::new();
        write(&bs0, &mut buf, &key, &ad)?;
        let bs1 = read(&mut buf.as_slice(), &key, &ad)?;

        assert_eq!(bs0, bs1);

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_corrupted_read_write() {
        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        let mut buf = Vec::new();
        write(&bs0, &mut buf, &key, &ad).unwrap();
        corrupt(&mut buf);
        read(&mut buf.as_slice(), &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot() -> crate::Result<()> {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write_to(&bs0, &pb, &key, &ad)?;
        let bs1 = read_from(&pb, &key, &ad)?;
        assert_eq!(bs0, bs1);

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_currupted_snapshot() {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();

        write_to(&bs0, &pb, &key, &ad).unwrap();
        corrupt_file_at(&pb);
        read_from(&pb, &key, &ad).unwrap();
    }

    #[test]
    fn test_snapshot_overwrite() -> crate::Result<()> {
        let f = tempfile::tempdir().unwrap();
        let mut pb = f.into_path();
        pb.push("snapshot");

        write_to(&fresh::bytestring(), &pb, &rand::random(), &fresh::bytestring())?;

        let key: Key = rand::random();
        let bs0 = fresh::bytestring();
        let ad = fresh::bytestring();
        write_to(&bs0, &pb, &key, &ad).unwrap();
        let bs1 = read_from(&pb, &key, &ad)?;
        assert_eq!(bs0, bs1);

        Ok(())
    }

    struct TestVector {
        key: &'static str,
        ad: &'static str,
        data: &'static str,
        snapshot: &'static str,
    }

    #[test]
    fn test_vectors() -> crate::Result<()> {
        let tvs = [
            TestVector {
                key: "710a44779a77149688e91dd6dd1dccba8c128a4008e5e27d9ff00e471f37ca57",
                ad: "0d5379c73a162d3cbc9dd452c9ffbbc4d79ec04199124b24bbe7f11515ba2de67bc55db2a66f03a70287e0ad98a49d51216f45eb8b1071c89b4bb0de36c265a6ee521690b6068a7f363885602a9e1104de1f9cf81484cc9a9822f5f3729dd300ef47cd5dd252c2780b126241c22359ff3df2d21c8e52823d3ddc792bcb765bedb5b9a2d0f4bdcd778c10d86981abb11d8fc753cee0b28694c9f46297ad8e22df96d8ac6849ba872da68fb4d5b11b50e6b5f9fc04ef2dc46d6d5c3ddda12b384fc3d3ccd912157407861494eb682deecef94949653e8c36abff2eb3258ab109e6fc3fc7a5002d3468a425a55ae48d0721f2e868480b17e1985275bd5b61c0e772eea00ee0e2ce52366daab39bdb638cc85ff212fba29fd2ed3e557884b802fca26ddca5ab19c524e617303f1c1527eed8bf0ebe764b6472745e83139b64c6db16f41347b330347c90cfdc24f122f87208cf74e046802f0e4a8ac30341a2b6ff3c9f1f9400f9197c4fdae84b37fc8818c5f6c6bb07f4ecf63c048caecb97531f94a1d7659230e44c1079f915d92fdc71328b010245a284391e40fd861788365c14798bbb9fa46635c75d9e18884fa45ff39aad62d457a084c977fc9ef129bc211f8fdf7d6f8c8e2f2f8ad193fe389dea2605f0927350223c79179c2748e66b1b787090084ab0b5951cc8e030f41a72413ca453f86d05c46ef9a7af3f38963d8ac55d3538f8a105ff6e16c34b339158d236700bb6cbbbc0b6e2e25f3cc8cec690941152cec0f7232062f44bc72018df629bddcbb276caf40b18112403f430f50fd81de7914e9858cf83d32a2542ce7deed78c3e38a1e3c6f28af1a976a72416e0adb4b227015ebaad8df79ab08f7c2ebb678ac08b3b9138",
                data: "",
                snapshot: "504152544902003baaf3b0887a72082691b351dfd2df1aa50c48414605eb8dfdf253ceaf78bc6e2248a59607c911fef2035e713765b936",
            },
            TestVector {
                key: "ffde7cfa5af050eb62e5f03bad95ab3b2612ee2e20511578390e68dddd031121",
                ad: "",
                data: "652809fa092f390d8e79aa8955c3c3792a6082e302275f77d5dced4410f3966cef610106d471eac320f3ebb70dce63dc4733e0faae15dd099e5664cb8a5e252fb24493301906d90847236f7322f4a7892fce9ed6d0faba7be31165caa2112225e348c9fba1953c8bf9309de79bc04c1b2de0a7436030ff9930fd2a3367ec9da5185833cb4e44ed96aee18bf583ee7c53bf567b812e0ba123f8ec7a246e01481bfb6f1954a3ca3e43623c8848c4def5431ed9412dd92d09e8cd103e9bd7b9fbdd6e33f9c25feb08aab5b27e0f28037a7e6c3ca7305498865bfb453baea708fbe36daa94fe554072612509b7caefbbd039ede513acb35bfdf54e16ce56751679e0b231e06bfede50a70d430937e2a747a153b34b9d369e4dc88a27fda2a6fbaf124b8606d3c877622ff53bd34017eac12d937930f5cc216f713f81fd674140",
                snapshot: "504152544902007e00f6d9986a17b46acc7fa1cd75306ce7a85dd21438925f983cfa1a09c6ac47a485adc0ff28c8478d3510afb91fb8ecb7bcf60fc64222d3fd3b81d370a1bc0c2faea84baf58f2cc623fe65ffed25f7a914f6213d48353b3f868d2d6dd2c1f140ba2a32f100486d536bd8aa1780b106d54d00d3a136b596c7fefdd15a70bf095a9fadf3534b1854470c1a894ab677af8b6aa2ad772d9a0d40667e742e16fffe163d7dcd90729ff241555bda57ace34fc4dd5965ed546610c07f182ea21293bbfe1e32e57ea93a30ec1dfb17fde8ff95e918c9ceb4c78ce537189b38187b6bc021d440018e097bc1e42ca70b4445324102b2cfb1249579766a8830a9c90d57153dcf4fd327e6405bafdec0b0dda6e001565ceee1842731da2b5b56c9a2fb706ede22b49ba8c86caaaa445ca0a78e87708d327bb3b1133f7045f92eacd3ee9096172caa9a97da8d4753022de654c71ff4ea32e35180e8933a13827ea201f790699f30e3d4cca0aef3ee29c5f8bc3a6",
            },
            TestVector {
                key: "b7bae5d9416917f2029b37dcde592773718fc69d655dbbe33acbc2ca72ca4b02",
                ad: "",
                data: "",
                snapshot: "50415254490200e1536070c0ad9b1372bcba19844cf8e4dcbca0f6e177991ad1892f32230d0057046994ff7154c7922e7dab153b73827c",
            },
            TestVector {
                key: "dd1f3859e1af013358d6201eea1fd5807d8bbd52b5358f271e8b6409f7fdec15",
                ad: "50a755a003eca23236dc000828f5e8cd21bc9580d27c37721f2de79e1fc304a301f880a8401ea1e20c2651e80714dca2fa90e24259bc9d17fdff77d6891601a3e310a79d9e814bd0afea27f9493b6da1d05a328cce638e4f42adffcc509e651eb5e0459d2deb83be6d24669232969fd1d84e4e1639375ea5978d8a5ef16945edb5",
                data: "5cc4d3e8ff9ec22b7e5358aaf17dfef61eeaef98715b855eb5785d55244787ddde74f9015fc28b0bf4f9c4929137e7bbb660c1666f8caefc9e1461fa72c5d431bca015b257067e3e47c9d911a07a99a6d5f6634a4de4ad9ab9880d9175400c3ea70ae180062200b02f32a1d776cb707f77c9c8ab937a3659da0764b91d0dd887cd279083f6fe6f2b5a5b1e830dbb1f43ef6c5dca5c649114978deaf6f890b04b2af19eb092ab7eb9dc5f358fb5ccb0d86f866555cb5c796073d2e2b786654cdd4c34e2cd196e72659afc",
                snapshot: "5041525449020057b0a04d218a1c64ef50fce13726d2957bff8060ca7906924982c8d945eda7299ab0681aafc29c42ef73bc36222b55c19315f160c14b5da14300d195b3485436523abc47ae7ddc64b1096de6f6b624b1d0a31675cbd135816f2b8c76ce5d0b2df1d45e6798ed60045eff0a8e04fada01a82d050e6d3aa4ddaeaded9be9e56a0394163971df9ae7fbfc80164a7e01d602739cb28f7b61161eebba9dad6904a848245a5562fa9584d7395f9b8c8fc3d90115f3e1e76137fd87d1a4269cd5704e6c9751e6d38687f8e86cd43221605233c3a6d3c71be870cd10d7881ff033c935e43335a6fcbd1816a63085b8617315c1082fdc2e401c5c82522d73",
            },
        ];

        for tv in &tvs {
            let mut key = [0; KEY_SIZE];
            hex::decode_to_slice(&tv.key, &mut key).unwrap();
            let ad = hex::decode(tv.ad).unwrap();
            let data = hex::decode(tv.data).unwrap();
            let snapshot = hex::decode(tv.snapshot).unwrap();

            assert_eq!(data, read(&mut snapshot.as_slice(), &key, &ad)?);
        }

        Ok(())
    }
}
