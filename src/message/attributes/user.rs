use std::fmt::Display;

use sha2::{Digest, Sha256};

use super::*;

/// The USERNAME attribute.
///
/// Represents the username of the current client.
///
/// See [RFC8489 Section 14.3](https://datatracker.ietf.org/doc/html/rfc8489#section-14.3) for more details.
#[derive(Clone, PartialEq)]
pub struct Username {
    username: String,
}

impl Username {
    pub fn new(username: impl ToString) -> Self {
        Self {
            username: username.to_string(),
        }
    }
}

impl Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.username)
    }
}

impl Attribute for Username {
    const TY: u16 = 0x0006;
    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let bytes = self.username.as_bytes();
        let len = bytes.len();
        buf[offset..(offset + len)].copy_from_slice(bytes);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let username = std::str::from_utf8(&buf[meta.offset..(meta.offset + meta.len)])
            .unwrap()
            .into();

        Self { username }
    }

    fn size(&self) -> usize {
        self.username.len()
    }
}

/// The USERHASH attribute.
///
/// Used as a replacement for the USERNAME attribute when username anonymity is supported.
///
/// See [RFC8489 Section 14.4](https://datatracker.ietf.org/doc/html/rfc8489#section-14.4) for more details.
#[derive(Clone)]
pub struct Userhash {
    userhash: [u8; 32],
}

impl Userhash {
    pub fn new(username: Username, realm: Realm) -> Self {
        let mut hasher = Sha256::new();

        hasher.update(format!("{username}:{realm}"));

        let result = &*hasher.finalize();

        let userhash = result.try_into().unwrap();

        Self { userhash }
    }
}

impl Attribute for Userhash {
    const TY: u16 = 0x001E;
    const SIZE: usize = 32;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        buf[offset..(offset + 32)].copy_from_slice(&self.userhash);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        assert_eq!(meta.len, 32);
        let userhash = buf[meta.offset..(meta.offset + 32)].try_into().unwrap();
        Self { userhash }
    }
}
