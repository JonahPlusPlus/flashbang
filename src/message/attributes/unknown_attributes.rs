use super::*;

/// The UNKNOWN-ATTRIBUTES attribute.
///
/// Contains a list of attribute types that were not
/// understood by the server.
///
/// See [RFC8489 Section 14.13](https://datatracker.ietf.org/doc/html/rfc8489#section-14.13) for more details.
pub struct UnknownAttributes {
    attributes: Vec<u16>,
}

impl Attribute for UnknownAttributes {
    const TY: u16 = 0x000A;

    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        for (i, attr) in self.attributes.iter().enumerate() {
            let i = i * 2;
            buf[(i + offset)..(i + 1 + offset)].copy_from_slice(&attr.to_be_bytes());
        }
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        if meta.len % 2 != 0 {
            panic!("Each attribute type must be two bytes"); // TODO: Remove panic
        }

        let mut attributes = vec!();

        for i in (meta.offset..(meta.offset + meta.len)).step_by(2) {
            attributes.push(u16::from_be_bytes(buf[i..(i+1)].try_into().unwrap()));
        }

        Self {
            attributes,
        }
    }

    fn size(&self) -> usize {
        self.attributes.len() * 2
    }
}
