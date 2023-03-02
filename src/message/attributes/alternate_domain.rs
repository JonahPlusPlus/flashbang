use super::*;

/// The ALTERNATE-DOMAIN attribute.
///
/// Represents the domain name that is used to verify the IP address in the
/// [AlternateServer] attribute when the transport protocol uses TLS or DTLS.
///
/// See [RFC8489 Section 14.16](https://datatracker.ietf.org/doc/html/rfc8489#section-14.16) for more details.
#[derive(Debug, PartialEq)]
pub struct AlternateDomain {
    alternate_domain: String,
}

impl Attribute for AlternateDomain {
    const TY: u16 = 0x8003;
    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let bytes = self.alternate_domain.as_bytes();
        let len = bytes.len();
        buf[offset..(offset + len)].copy_from_slice(bytes);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let alternate_domain = std::str::from_utf8(&buf[meta.offset..(meta.offset + meta.len)])
            .unwrap()
            .into();

        Self { alternate_domain }
    }

    fn size(&self) -> usize {
        self.alternate_domain.len()
    }
}
