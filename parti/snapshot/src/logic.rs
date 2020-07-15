use sodiumoxide::crypto::{
    hash, pwhash,
    secretstream::{self, Header, Key, Pull, Push, Stream, Tag},
};

use std::{
    fs::File,
    io::{Read, Write},
};

const CHUNK_SIZE: usize = 4096; // data chunk size
const SIGN: [u8; 5] = [0x50, 0x41, 0x52, 0x54, 0x49]; // PARTI in hex
const VERSION: [u8; 2] = [0x1, 0x0]; // version 1.0 in hex

// generate the salt for the encryption algorithm.
fn generate_salt() -> crate::Result<pwhash::Salt> {
    // generate salt
    let salt = pwhash::gen_salt();
    // hash salt with sha256
    let hash = hash::sha256::hash(&salt.0);
    // repack salt
    let salt = pwhash::Salt::from_slice(hash.as_ref()).expect("Unable to rewrap salt");

    Ok(salt)
}

// derive key from salt and password.
fn derive_key_from_password(password: &[u8], salt: &pwhash::Salt) -> crate::Result<Key> {
    // empty key
    let mut key = [0; secretstream::KEYBYTES];

    // derive key from password and salt.
    match pwhash::derive_key(
        &mut key,
        password,
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    ) {
        Ok(_) => Ok(Key(key)),
        Err(_) => Err(crate::Error::SnapshotError("Could not derive key from password".into())),
    }
}

// create an encryption push stream and a header.
fn create_stream(&Key(ref key): &Key) -> crate::Result<(Stream<Push>, Header)> {
    let stream_key = secretstream::Key(key.to_owned());

    Stream::init_push(&stream_key).map_err(|_| crate::Error::SnapshotError("Unable to create stream".into()))
}

// create a decryption pull stream.
fn pull_stream(header: &[u8], &Key(ref key): &Key) -> crate::Result<Stream<Pull>> {
    let stream_key = secretstream::Key(key.to_owned());
    let header = Header::from_slice(header).expect("Invalid Header size");

    Stream::init_pull(&header, &stream_key).map_err(|_| crate::Error::SnapshotError("Unable to open stream".into()))
}

// encrypt an input with a password in using secretstream.
pub fn encrypt_snapshot(input: Vec<u8>, out: &mut File, password: &[u8]) -> crate::Result<()> {
    // convert vector to slice
    let mut slice = input.as_slice();
    // setup buffer
    let mut buf = [0; CHUNK_SIZE];
    // get input length
    let mut input_len = slice.len();

    // write the signature to the file first.
    out.write_all(&SIGN)?;
    out.write_all(&VERSION)?;

    // get the salt and write it to the file.
    let salt = generate_salt()?;
    out.write_all(&salt.0)?;

    // derive a key from the password and salt.
    let key = derive_key_from_password(password, &salt)?;
    // create the stream and header from the key.
    let (mut stream, header) = create_stream(&key)?;

    // write the header to the file.
    out.write_all(&header.0)?;

    loop {
        // loop through the data and write it to the stream and then to the file.
        match slice.read(&mut buf) {
            Ok(amount_read) if amount_read > 0 => {
                input_len -= amount_read as usize;
                let tag = match input_len {
                    // when input_len reaches 0 pass Tag::Final to the stream.
                    0 => Tag::Final,
                    _ => Tag::Message,
                };
                out.write_all(
                    &stream
                        .push(&buf[..amount_read], None, tag)
                        .map_err(|_| crate::Error::SnapshotError("Failed to encrypt".into()))?,
                )?
            }
            Err(e) => return Err(crate::Error::from(e)),
            _ => break,
        }
    }

    Ok(())
}

// decrypt file into a vector with a password.
pub fn decrypt_snapshot(input: &mut File, output: &mut Vec<u8>, password: &[u8]) -> crate::Result<()> {
    // check to see if the file is long enough
    check_file_len(input)?;

    // setup signature, salt and version buffers.
    let salt = get_salt(input, true)?;

    decrypt_file(input, output, password, salt)?;

    Ok(())
}

// update a snapshot with the new version by re-encrypting the data.
pub fn update_snapshot(input: &mut File, output: &mut File, password: &[u8]) -> crate::Result<()> {
    // setup the buffer to read from the old snapshot.
    let mut buffer: Vec<u8> = Vec::new();

    // check the file len
    check_file_len(input)?;

    // get the salt and ignore the version.
    let salt = get_salt(input, false)?;

    // decrypt the file into the buffer
    decrypt_file(input, &mut buffer, password, salt)?;

    // re-encrypt the file into a new snapshot.
    encrypt_snapshot(buffer, output, password)?;

    Ok(())
}

fn decrypt_file(input: &mut File, output: &mut Vec<u8>, password: &[u8], salt: pwhash::Salt) -> crate::Result<()> {
    // setup header buffer and extract it from the file
    let mut header = [0u8; secretstream::HEADERBYTES];
    input.read_exact(&mut header)?;

    // generate a key from the salt and password.
    let key = derive_key_from_password(&password, &salt)?;

    // create buffer.
    let mut buf = [0u8; CHUNK_SIZE + secretstream::ABYTES];
    // get the pull stream.
    let mut stream = pull_stream(&header, &key)?;

    // iterate through the stream until its finalized.
    while stream.is_not_finalized() {
        // read the input into the buffer
        match input.read(&mut buf) {
            Ok(bytes_read) if bytes_read > 0 => {
                // pull each chunk from the stream and decrypt.
                let (decrypt, _tag) = stream.pull(&buf[..bytes_read], None).map_err(|_| {
                    crate::Error::SnapshotError("Stream pull failed, could not decrypt snapshot".into())
                })?;

                // put the vectors into the output vector.
                output.extend(&decrypt);
            }
            Err(_) => return Err(crate::Error::SnapshotError("Incorrect Password".into())),
            _ => return Err(crate::Error::SnapshotError("Decryption failed... ".into())),
        }
    }

    Ok(())
}

// check to see if the file is long enough.
fn check_file_len(input: &mut File) -> crate::Result<()> {
    if input.metadata()?.len() <= (pwhash::SALTBYTES + secretstream::HEADERBYTES + SIGN.len()) as u64 {
        return Err(crate::Error::SnapshotError("Snapshot is not valid or encrypted".into()));
    }

    Ok(())
}

// check the version if the book is set and check the signature then extract the salt.
fn get_salt(input: &mut File, chk_version: bool) -> crate::Result<pwhash::Salt> {
    // setup the buffers
    let mut sign = [0u8; 5];
    let mut version = [0u8; 2];
    let mut salt = [0u8; pwhash::SALTBYTES];

    // get signature and version
    input.read_exact(&mut sign)?;
    input.read_exact(&mut version)?;

    // if bool is set, check the version
    if chk_version {
        check_version(&version)?;
    }

    // if sign is the same expected read in all of the salt.
    if sign == SIGN {
        input.read_exact(&mut salt)?;
    } else {
        // otherwise take the bytes from the sign and read the rest as the salt.
        salt[..7].copy_from_slice(&sign);
        input.read_exact(&mut salt[7..])?;
    }

    // create a new salt.
    let salt = pwhash::Salt(salt);

    Ok(salt)
}

// check the version on the snapshot.
fn check_version(version: &[u8]) -> crate::Result<()> {
    // probably shouldn't do this, but if version is incorrect reject snapshot with error
    if version != VERSION {
        Err(crate::Error::SnapshotError("Snapshot version is incorrect".into()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sodiumoxide::crypto::secretstream::Tag;
    use std::fs::OpenOptions;

    #[test]
    fn test_key_derivation() {
        let salt = generate_salt().unwrap();
        let key_one = derive_key_from_password(b"some long password", &salt).unwrap();
        let key_two = derive_key_from_password(b"some long password", &salt).unwrap();

        // same keys as long as the salt is the same.
        assert_eq!(key_one, key_two);
    }

    #[test]
    fn test_stream() {
        // get salt and key from password.
        let salt = generate_salt().unwrap();
        let key = derive_key_from_password(b"a password", &salt).unwrap();
        // data to write to stream.
        let data = b"data";

        // create a new push_stream with key.
        let (mut push_stream, header) = create_stream(&key).unwrap();

        // put in the header and key to get the pull_stream.
        let mut pull_stream = pull_stream(&header.0, &key).unwrap();

        // push the data into the push stream to encrypt it.
        let cipher = push_stream.push(data, None, Tag::Final).unwrap();

        // pull the data through the pull_stream to decrypt it.
        let (plain, _) = pull_stream.pull(&cipher, None).unwrap();

        assert_eq!(data, &plain.as_slice());
    }

    #[test]
    fn test_snapshot() {
        let password = b"some_password";
        let data = vec![
            69, 59, 116, 81, 23, 91, 2, 212, 10, 248, 108, 227, 167, 142, 2, 205, 202, 100, 216, 225, 53, 223, 223, 14,
            153, 239, 46, 106, 120, 103, 85, 144, 69, 59, 116, 81, 23, 91, 2, 212, 10, 248, 108, 227, 167, 142, 2, 205,
            202, 100, 216, 225, 53, 223, 223, 14, 153, 239, 46, 106, 120, 103, 85, 144, 69, 59, 116, 81, 23, 91, 2,
            212, 10, 248, 108, 227, 167, 142, 2, 205, 202, 100, 216, 225, 53, 223, 223, 14, 153, 239, 46, 106, 120,
            103, 85, 144,
        ];

        let expected = data.clone();

        let mut encrypt = OpenOptions::new()
            .write(true)
            .create(true)
            .open("test/snapshot.snapshot")
            .unwrap();

        let mut decrypt = OpenOptions::new().read(true).open("test/snapshot.snapshot").unwrap();

        let mut output: Vec<u8> = Vec::new();

        encrypt_snapshot(data, &mut encrypt, password).unwrap();

        decrypt_snapshot(&mut decrypt, &mut output, password).unwrap();

        assert_eq!(expected, output);
    }
}
