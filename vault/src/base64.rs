pub struct Base64;
impl Base64 {
    const PADDING: u8 = b'=';

    pub fn encode_data(data: &[u8]) -> String {
        let mut base = Vec::new();

        for chunk in data.chunks(3) {
            let num: usize = [16, 8, 0]
                .iter()
                .zip(chunk.iter())
                .fold(0, |acc, (s, b)| acc + ((*b as usize) << *s));
            [18usize, 12, 6, 0]
                .iter()
                .map(|s| (num >> s) & 0b0011_1111)
                .for_each(|b| base.push(Self::encode_byte(b)));
        }

        let to_pad = match data.len() % 3 {
            2 => 1,
            1 => 2,
            _ => 0,
        };
        base.iter_mut()
            .rev()
            .take(to_pad)
            .for_each(|b| *b = Self::PADDING);

        match String::from_utf8(base) {
            Ok(s) => s,
            Err(_) => panic!("{}", crate::Error::Base64Error),
        }
    }

    pub fn decode_data(base: &[u8]) -> crate::Result<Vec<u8>> {
        let (padded, base) = match base
            .iter()
            .rev()
            .take_while(|b| **b == Self::PADDING)
            .count()
        {
            _ if base.len() % 4 != 0 => Err(crate::Error::Base64Error)?,
            padded if padded > 2 => Err(crate::Error::Base64Error)?,
            padded => (padded, &base[..base.len() - padded]),
        };

        let mut data = Vec::new();
        for chunk in base.chunks(4) {
            let num: usize = [18usize, 12, 6, 0]
                .iter()
                .zip(chunk.iter())
                .try_fold(0, |acc, (s, b)| {
                    Self::decode_byte(*b).map(|b| acc + (b << *s))
                })?;
            [16, 8, 0]
                .iter()
                .map(|s| (num >> s) as u8)
                .for_each(|b| data.push(b));
        }

        data.truncate(data.len() - padded);
        Ok(data)
    }

    fn encode_byte(b: usize) -> u8 {
        match b {
            b @ 0..=25 => (b as u8 - 0) + b'A',
            b @ 26..=51 => (b as u8 - 26) + b'a',
            b @ 52..=61 => (b as u8 - 52) + b'0',
            62 => b'-',
            63 => b'_',
            _ => panic!("{} ({})", crate::Error::Base64Error, b),
        }
    }

    fn decode_byte(b: u8) -> crate::Result<usize> {
        match b {
            b @ b'A'..=b'Z' => Ok((b - b'A') as usize + 0),
            b @ b'a'..=b'z' => Ok((b - b'a') as usize + 26),
            b @ b'0'..=b'9' => Ok((b - b'0') as usize + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(crate::Error::Base64Error),
        }
    }
}

pub trait Base64Encodable {
    fn base64(&self) -> String;
}

pub trait Base64Decodable: Sized {
    fn from_base64(base: impl AsRef<[u8]>) -> crate::Result<Self>;
}

impl<T: AsRef<[u8]>> Base64Encodable for T {
    fn base64(&self) -> String {
        Base64::encode_data(self.as_ref())
    }
}

impl Base64Decodable for Vec<u8> {
    fn from_base64(base: impl AsRef<[u8]>) -> crate::Result<Self> {
        Base64::decode_data(base.as_ref())
    }
}
