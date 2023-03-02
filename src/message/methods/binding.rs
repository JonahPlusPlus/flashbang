use super::*;

#[derive(Debug, PartialEq)]
pub struct Binding;

pub const BINDING_METHOD: u16 = 0x01;

impl Method for Binding {
    const METHOD: u16 = 0x01;

    fn encode(&self, buf: &mut [u8], offset: &mut usize) {}

    fn decode(meta: &MessageMeta) -> Self {
        Self
    }

    fn size(&self) -> usize {
        0
    }
}
