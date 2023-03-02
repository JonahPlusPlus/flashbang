mod binding;

pub use binding::Binding;

use super::*;

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Binding {}
}

#[derive(Debug, PartialEq)]
pub enum MethodTy {
    Binding(Binding),
}

impl MethodTy {
    pub fn decode(meta: &MessageMeta) -> Result<Self, IncomingError> {
        return match meta.method {
            binding::BINDING_METHOD => Ok(MethodTy::Binding(Binding::decode(meta))),
            m => Err(IncomingError {
                ty: IncomingErrorTy::UnknownMethod,
                reason: format!("Unknown method: {:#x?}.", m),
            }),
        };
    }
}

/// Sealed trait for method types.
pub trait Method: sealed::Sealed {
    const METHOD: u16;

    fn encode(&self, buf: &mut [u8], offset: &mut usize);

    fn decode(meta: &MessageMeta) -> Self;

    fn size(&self) -> usize;
}
