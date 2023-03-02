pub use authorization::*;

use bytes::{Bytes, BytesMut};

use self::{attributes::*, meta::MessageMeta, methods::*};

pub mod attributes;
pub mod methods;

mod authorization;
mod id;
mod incoming;
mod meta;
mod outgoing;

pub use id::*;
pub use incoming::*;
pub use outgoing::*;

const MAGIC: u32 = 0x2112A442;

#[derive(Debug, PartialEq)]
pub enum ClassTy {
    Request {
        method: MethodTy,
        authorization: Option<Authorization>,
    },
}

impl ClassTy {
    pub fn decode(buf: &[u8], meta: &MessageMeta) -> Result<Self, IncomingError> {
        return match meta.class {
            REQUEST_CLASS => Ok(ClassTy::Request {
                method: MethodTy::decode(meta)?,
                authorization: Authorization::decode(buf, meta),
            }),
            c => Err(IncomingError {
                ty: IncomingErrorTy::UnknownClass,
                reason: format!("Unknown class: {:#x?}.", c),
            }),
        };
    }
}

/// Sealed trait for message class types.
pub trait Class: sealed::Sealed {
    const CLASS: u16;
    const METHOD: u16;

    fn encode(&self, buf: &mut [u8], offset: &mut usize);

    fn size(&self) -> usize;
}

mod sealed {
    pub trait Sealed {}

    impl<T: super::Method> Sealed for super::Request<T> {}
}

/// Request Message Class.
pub struct Request<T: methods::Method> {
    pub method: T,
    pub authorization: Option<Authorization>,
}

const REQUEST_CLASS: u16 = 0b00;

impl<T: methods::Method> Class for Request<T> {
    const CLASS: u16 = REQUEST_CLASS;
    const METHOD: u16 = T::METHOD;

    fn encode(&self, buf: &mut [u8], offset: &mut usize) {
        self.method.encode(buf, offset);

        if let Some(ref a) = self.authorization {
            a.encode(buf, offset);
        }
    }

    fn size(&self) -> usize {
        let mut size = self.method.size();

        if let Some(ref a) = self.authorization {
            size += a.size();
        }

        size
    }
}

#[cfg(test)]
mod tests {
    use crate::message::{methods::Binding, outgoing::OutgoingMessage};

    use super::*;

    use stun::{
        attributes::ATTR_USERNAME,
        message::{Message, BINDING_REQUEST},
    };

    #[test]
    fn binding_request() {
        // "stun" crate
        let mut test_message = Message::new();

        test_message
            .build(&[
                Box::new(BINDING_REQUEST),
                Box::new(stun::agent::TransactionId([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,
                ])),
                Box::new(stun::textattrs::Username::new(
                    ATTR_USERNAME,
                    "Alice".into(),
                )),
                Box::new(stun::integrity::MessageIntegrity::new_short_term_integrity(
                    "Password".into(),
                )),
                Box::new(stun::fingerprint::FingerprintAttr),
            ])
            .expect("Failed to build");

        let test_output = &*test_message.marshal_binary().unwrap();

        // "flashbang" crate
        let message = OutgoingMessage {
            transaction_id: TransactionId::new(32),
            body: Request {
                method: Binding,
                authorization: Some(Authorization {
                    credentials: Credentials::new_short_term(Username::new("Alice"), "Password"),
                    integrity: Integrity::Sha1,
                }),
            },
            software: false,
            fingerprint: true,
        };

        let buf = message.encode();

        assert_eq!(test_output, &*buf);
    }
}
