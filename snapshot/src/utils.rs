use base32::Alphabet;

const BASE32_ALPHABET: Alphabet = Alphabet::RFC4648 { padding: true };

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

pub(crate) fn base32_encode(buf: &[u8]) -> String {
    base32::encode(BASE32_ALPHABET, buf)
}

pub(crate) fn base32_decode(buf: &str) -> Option<Vec<u8>> {
    base32::decode(BASE32_ALPHABET, buf)
}
