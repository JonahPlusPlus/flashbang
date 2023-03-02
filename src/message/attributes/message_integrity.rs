use bytes::Bytes;
use hmac::Mac;

use super::*;

/// The MESSAGE-INTEGRITY attribute.
///
/// Contains an HMAC-SHA1 of the STUN message.
///
/// See [RFC8489 Section 14.5](https://datatracker.ietf.org/doc/html/rfc8489#section-14.5) for more details.
pub enum MessageIntegrity {
    Incoming { integrity: [u8; Self::SIZE] },
    Outgoing { key: Bytes },
}

impl MessageIntegrity {
    pub fn new(key: &[u8]) -> Self {
        let key = Bytes::copy_from_slice(key);

        Self::Outgoing { key }
    }

    pub fn from_array(integrity: [u8; Self::SIZE]) -> Self {
        Self::Incoming { integrity }
    }
}

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

impl Attribute for MessageIntegrity {
    const TY: u16 = 0x0008;
    const SIZE: usize = 20;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let Self::Outgoing { key } = self else {
            panic!("Attribute needs to be outgoing");
        };

        let mut mac = HmacSha1::new_from_slice(key).unwrap();

        mac.update(&buf[0..(offset - 4)]);

        let result = mac.finalize().into_bytes();
        let integrity = result.as_slice().try_into().unwrap();

        buf[offset..(offset + Self::SIZE)].copy_from_slice(integrity);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        // TODO: Assert length matches

        let integrity = buf[meta.offset..(meta.offset + meta.len)]
            .try_into()
            .unwrap();

        // TODO: Verify integrity matches generated result.

        Self::Incoming { integrity }
    }
}

/// The MESSAGE-INTEGRITY-SHA256 attribute.
///
/// Contains an HMAC-SHA256 of the STUN message.
///
/// See [RFC8489 Section 14.6](https://datatracker.ietf.org/doc/html/rfc8489#section-14.6) for more details.
pub enum MessageIntegritySha256 {
    Incoming { integrity: [u8; Self::SIZE] },
    Outgoing { key: Bytes },
}

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

impl MessageIntegritySha256 {
    pub fn new(key: &[u8]) -> Self {
        let key = Bytes::copy_from_slice(key);

        Self::Outgoing { key }
    }

    pub fn from_array(integrity: [u8; Self::SIZE]) -> Self {
        Self::Incoming { integrity }
    }
}

impl Attribute for MessageIntegritySha256 {
    const TY: u16 = 0x001c;
    const SIZE: usize = 32;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let Self::Outgoing { key } = self else {
            panic!("Attribute needs to be outgoing");
        };

        let mut mac = HmacSha256::new_from_slice(key).unwrap();

        mac.update(&buf[0..(offset - 4)]);

        let result = mac.finalize().into_bytes();
        let integrity = result.as_slice().try_into().unwrap();

        buf[offset..(offset + Self::SIZE)].copy_from_slice(integrity);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        // TODO: Assert length matches

        let integrity = buf[meta.offset..(meta.offset + meta.len)]
            .try_into()
            .unwrap();

        // TODO: Verify integrity matches generated result.

        Self::Incoming { integrity }
    }
}
