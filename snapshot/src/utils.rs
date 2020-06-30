use base32::Alphabet;
use sodiumoxide::crypto::hash;

// base 32 alphabet with padding
const BASE32_ALPHABET: Alphabet = Alphabet::RFC4648 { padding: true };

// concate slices into vectors.
pub(crate) fn concat<T>(slices: &[&[T]]) -> Vec<T>
where
    T: std::clone::Clone,
{
    let mut buf = Vec::new();
    for slice in slices {
        buf.extend_from_slice(slice);
    }
    buf
}

// encode into base32
pub(crate) fn base32_encode(buf: &[u8]) -> String {
    base32::encode(BASE32_ALPHABET, buf)
}

// decode from base32
pub(crate) fn base32_decode(buf: &str) -> Option<Vec<u8>> {
    base32::decode(BASE32_ALPHABET, buf)
}

pub(crate) fn calc_hash(data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&hash::hash(data).0);
    bytes
}
