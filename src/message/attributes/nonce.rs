use super::*;

/// The NONCE attribute.
///
/// See [RFC8489 Section 14.10](https://datatracker.ietf.org/doc/html/rfc8489#section-14.10) for more details.
#[derive(Clone, PartialEq)]
pub struct Nonce {
    nonce: String,
}

impl Nonce {
    pub fn new(nonce: impl ToString) -> Self {
        Self {
            nonce: nonce.to_string(), // TODO: validate nonce construction
        }
    }
}

impl Attribute for Nonce {
    const TY: u16 = 0x0015;
    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let bytes = self.nonce.as_bytes();
        let len = bytes.len();
        buf[offset..(offset + len)].copy_from_slice(bytes);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let nonce = std::str::from_utf8(&buf[meta.offset..(meta.offset + meta.len)])
            .unwrap()
            .into();

        Self { nonce }
    }

    fn size(&self) -> usize {
        self.nonce.len()
    }
}
