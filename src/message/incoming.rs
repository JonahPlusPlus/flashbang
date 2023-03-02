use super::{meta::MessageMeta, *};

/// An incoming STUN message.
#[derive(Debug, PartialEq)]
pub struct IncomingMessage {
    pub transaction_id: TransactionId,
    pub body: ClassTy,
    pub software: Option<Software>,
    pub fingerprint: Option<Fingerprint>,
}

impl IncomingMessage {
    pub fn decode(buf: &[u8]) -> Result<Self, IncomingError> {
        let meta = MessageMeta::decode(buf)?;

        let body = ClassTy::decode(buf, &meta)?;

        let mut software = None;

        for attr in meta.attributes {
            match attr.ty {
                Software::TY => {
                    software = Some(Software::decode(buf, &attr));
                }
                _ => (),
            }
        }

        Ok(Self {
            transaction_id: meta.id,
            body,
            software: todo!(),
            fingerprint: todo!(),
        })
    }
}

#[derive(Debug)]
pub struct IncomingError {
    pub ty: IncomingErrorTy,
    pub reason: String,
}

#[derive(Debug)]
pub enum IncomingErrorTy {
    BadFormat,
    BadLength,
    BadMagic,
    UnknownClass,
    UnknownMethod,
}
