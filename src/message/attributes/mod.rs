//! Collection of STUN Attributes.

mod alternate_domain;
mod alternate_server;
mod error_code;
mod fingerprint;
mod mapped_address;
mod message_integrity;
mod nonce;
mod password_algorithms;
mod realm;
mod software;
mod unknown_attributes;
mod user;

pub use alternate_domain::*;
pub use alternate_server::*;
pub use error_code::*;
pub use fingerprint::*;
pub use mapped_address::*;
pub use message_integrity::*;
pub use nonce::*;
pub use password_algorithms::*;
pub use realm::*;
pub use software::*;
pub use unknown_attributes::*;
pub use user::*;

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::MappedAddress {}
    impl Sealed for super::XorMappedAddress {}
    impl Sealed for super::Username {}
    impl Sealed for super::Userhash {}
    impl Sealed for super::MessageIntegrity {}
    impl Sealed for super::MessageIntegritySha256 {}
    impl Sealed for super::Fingerprint {}
    impl Sealed for super::ErrorCode {}
    impl Sealed for super::Realm {}
    impl Sealed for super::Nonce {}
    impl Sealed for super::PasswordAlgorithms {}
    impl Sealed for super::PasswordAlgorithm {}
    impl Sealed for super::UnknownAttributes {}
    impl Sealed for super::Software {}
    impl Sealed for super::AlternateServer {}
    impl Sealed for super::AlternateDomain {}
}

/// Sealed trait for attribute types.
///
/// See [RFC8489 Section 14](https://datatracker.ietf.org/doc/html/rfc8489#section-14) for more details.
pub trait Attribute: sealed::Sealed {
    /// The type of attribute.
    ///
    /// Values of 0x0000 to 0x7FFF are comprehension-required attributes,
    /// which means that the STUN agent cannot successfully process
    /// the message unless it understands the attribute.
    ///
    /// Values of 0x8000 to 0xFFFF are comprension-optional attributes,
    /// which means that those attributes can be ignored by the STUN agent
    /// if it does not understand them.
    const TY: u16;

    /// The size of the body of the attribute.
    ///
    /// Dynamically-sized attributes should have a value of 0.
    /// Any other value indicates that the attribute is statically-sized.
    const SIZE: usize;

    /// Encode the body of the attribute.
    fn encode(&self, buf: &mut [u8], offset: usize);

    /// Decode the body of the attribute.
    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self;

    /// Size of the body of the attribute.
    fn size(&self) -> usize {
        Self::SIZE
    }
}

/// Encodes the attribute header and body.
pub(crate) fn encode_attribute<T: Attribute>(attr: &T, buf: &mut [u8], offset: &mut usize) {
    // adds the attribute size to the message length
    let size = attr.size();
    let aligned_size = (size + 4 + 3) & !3;
    let old_size = u16::from_be_bytes(buf[2..4].try_into().unwrap());
    let new_size_bytes = (old_size + aligned_size as u16).to_be_bytes();
    buf[2..4].copy_from_slice(&new_size_bytes);

    // encodes the attribute header
    buf[*offset..(*offset + 2)].copy_from_slice(&T::TY.to_be_bytes());
    buf[(*offset + 2)..(*offset + 4)].copy_from_slice(&(size as u16).to_be_bytes());

    // encodes the attribute
    attr.encode(buf, *offset + 4);

    // increments the offset
    *offset += aligned_size;
}

/// Adds 4 bytes for the attribute header, then aligns to the 32-bit boundary.
///
/// By using the `static` keyword, the calculation can be optimized for statically-sized attributes.
///
/// If the attribute is dynamically-sized, the `dyn` keyword can be used instead.
macro_rules! attribute_size {
    (dyn $name:ident) => {
        ($name.size() + 4 + 3) & !3
    };

    (static $name:ty) => {
        (<$name as Attribute>::SIZE + 4 + 3) & !3
    };

    () => {
        compile_error!("Expected argument");
    };
}

pub(crate) use attribute_size;

use super::meta::{AttributeMeta, MessageMeta};
