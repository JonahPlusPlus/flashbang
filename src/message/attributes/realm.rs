use std::fmt::Display;

use super::*;

/// The REALM attribute.
///
/// Presence of the REALM attribute in a request indicates that long-term
/// credentials are being used for authentication.
/// Presence in certain error responses indicates that
/// the server wishes the client to use a long term credential
/// in that realm for authentication.
///
/// See [RFC8489 Section 14.9](https://datatracker.ietf.org/doc/html/rfc8489#section-14.9) for more details.
#[derive(Clone, PartialEq)]
pub struct Realm {
    realm: String,
}

impl Realm {
    pub fn new(realm: impl ToString) -> Self {
        Self {
            realm: realm.to_string(),
        }
    }
}

impl Display for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.realm)
    }
}

impl Attribute for Realm {
    const TY: u16 = 0x0014;
    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let bytes = self.realm.as_bytes();
        let len = bytes.len();
        buf[offset..(offset + len)].copy_from_slice(bytes);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let realm = std::str::from_utf8(&buf[meta.offset..(meta.offset + meta.len)])
            .unwrap()
            .into();

        Self { realm }
    }

    fn size(&self) -> usize {
        self.realm.len()
    }
}
