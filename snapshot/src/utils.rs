use sodiumoxide::crypto::hash;

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

pub(crate) fn calc_hash(data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&hash::hash(data).0);
    bytes
}
