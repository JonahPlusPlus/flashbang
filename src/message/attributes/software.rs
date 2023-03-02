use super::*;

/// The SOFTWARE attribute.
///
/// Contains a textual decription of the software being used by the agent sending the message.
///
/// Serves as a tool for diagnostic and debugging purposes.
///
/// See [RFC8489 Section 14.14](https://datatracker.ietf.org/doc/html/rfc8489#section-14.14) for more details.
#[derive(Debug, PartialEq)]
pub struct Software {
    software: String,
}

impl Attribute for Software {
    const TY: u16 = 0x8022;
    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let bytes = self.software.as_bytes();
        let len = bytes.len();
        buf[offset..(offset + len)].copy_from_slice(bytes);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let software = std::str::from_utf8(&buf[meta.offset..(meta.offset + meta.len)])
            .unwrap()
            .into();

        Self { software }
    }

    fn size(&self) -> usize {
        self.software.len()
    }
}
