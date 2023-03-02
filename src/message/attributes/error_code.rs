use std::str::FromStr;

use super::*;

/// The ERROR-CODE attribute.
///
/// See [RFC8489 Section 14.8](https://datatracker.ietf.org/doc/html/rfc8489#section-14.8) for more details.
pub enum ErrorCode {
    TryAlternate,
    BadRequest,
    Unauthenticated,
    UnknownAttribute,
    StaleNonce,
    ServerError,
    Other(u32, String),
}

impl ErrorCode {
    fn code(&self) -> u32 {
        match self {
            Self::TryAlternate => 300,
            Self::BadRequest => 400,
            Self::Unauthenticated => 401,
            Self::UnknownAttribute => 420,
            Self::StaleNonce => 438,
            Self::ServerError => 500,
            Self::Other(c, _) => *c,
        }
    }

    fn reason(&self) -> &str {
        match self {
            Self::TryAlternate => "Try Alternate",
            Self::BadRequest => "Bad Request",
            Self::Unauthenticated => "Unauthenticated",
            Self::UnknownAttribute => "Unknown Attribute",
            Self::StaleNonce => "Stale Nonce",
            Self::ServerError => "Server Error",
            Self::Other(_, r) => r,
        }
    }

    fn from_parts(code: u32, reason: String) -> Self {
        match code {
            300 => Self::TryAlternate,
            400 => Self::BadRequest,
            401 => Self::Unauthenticated,
            420 => Self::UnknownAttribute,
            438 => Self::StaleNonce,
            500 => Self::ServerError,
            _ => Self::Other(code, reason),
        }
    }
}

impl Attribute for ErrorCode {
    const TY: u16 = 0x0009;

    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let code = self.code();

        let class = code / 100;
        let number = code % 100;

        let encoded_code = (class << 8 | number) & 0x07FF;

        buf[offset..(offset + 4)].copy_from_slice(&encoded_code.to_be_bytes());

        let reason = self.reason();

        let len = reason.len();

        buf[(offset + 4)..(offset + len)].copy_from_slice(reason.as_bytes());
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let encoded_code =
            u32::from_be_bytes(buf[meta.offset..(meta.offset + 4)].try_into().unwrap()) & 0x07FF;

        let class = (encoded_code >> 8) * 100;
        let number = encoded_code & 0x00FF;

        let code = class + number;

        let s = std::str::from_utf8(&buf[(meta.offset + 4)..(meta.offset + meta.len - 4)]).unwrap(); // TODO: Handle bad strings
        let reason = String::from_str(s).unwrap();

        Self::from_parts(code, reason)
    }

    fn size(&self) -> usize {
        4 + self.reason().len()
    }
}
