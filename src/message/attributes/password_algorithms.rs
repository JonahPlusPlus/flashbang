use bytes::Bytes;
use md5::{Digest, Md5};
use once_cell::unsync::Lazy;
use sha2::Sha256;

use super::*;

/// The PASSWORD-ALGORITHMS attribute.
///
/// Contains the list of algorithms that the server can use to derive the long-term password.
///
/// See [RFC8489 Section 14.11](https://datatracker.ietf.org/doc/html/rfc8489#section-14.11) for more details.
pub struct PasswordAlgorithms {
    algorithms: Vec<PasswordAlgorithm>,
}

impl Attribute for PasswordAlgorithms {
    const TY: u16 = 0x8002;

    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        let mut i = 0;
        for alg in &self.algorithms {
            alg.encode(buf, offset + i);
            i += (alg.size() + 3) & !3;
        }
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let mut i = 0;
        let mut algorithms = vec![];

        while i != meta.len {
            let offset = meta.offset + i;
            let len = 4 + u16::from_be_bytes(buf[(offset + 2)..(offset + 4)].try_into().unwrap())
                as usize;
            let alg_meta = AttributeMeta {
                ty: PasswordAlgorithm::TY,
                offset,
                len,
            };

            algorithms.push(PasswordAlgorithm::decode(buf, &alg_meta));

            i += len;
        }

        Self { algorithms }
    }

    fn size(&self) -> usize {
        let mut offset = 0;
        for alg in &self.algorithms {
            offset += (alg.size() + 3) & !3;
        }

        offset
    }
}

/// The PASSWORD-ALGORITHM attribute.
///
/// Contains the algorithm that the server must use to derive a key for the long-term password.
///
/// An algorithm is comprised of an ID and parameters.
/// Currently, neither the MD5 or SHA256 algorithms use parameters,
/// but the [`Algorithm`] trait still provides forward-compatibility
/// with future algorithms.
///
/// See [RFC8489 Section 14.12](https://datatracker.ietf.org/doc/html/rfc8489#section-14.12) for more details.
#[derive(Clone)]
pub struct PasswordAlgorithm {
    id: u16,
    algorithm: Box<dyn Algorithm>,
}

impl PartialEq for PasswordAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PasswordAlgorithm {
    pub fn hash(&self, input: &[u8]) -> Bytes {
        self.algorithm.hash(input)
    }
}

impl Attribute for PasswordAlgorithm {
    const TY: u16 = 0x001D;

    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        buf[offset..(offset + 2)].copy_from_slice(&self.id.to_be_bytes());

        buf[(offset + 2)..(offset + 4)]
            .copy_from_slice(&(self.algorithm.size() as u16).to_be_bytes());

        self.algorithm.encode(buf, offset + 4);
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        let id = u16::from_be_bytes(buf[meta.offset..(meta.offset + 2)].try_into().unwrap());

        let len = u16::from_be_bytes(
            buf[(meta.offset + 2)..(meta.offset + 4)]
                .try_into()
                .unwrap(),
        );

        let algorithm: Box<dyn Algorithm> = match id {
            MD5_PASSWORD_ALGORITHM_TY => {
                Box::new(Md5Algorithm::decode(buf, meta.offset, len as usize))
            }
            SHA256_PASSWORD_ALGORITHM_TY => {
                Box::new(Sha256Algorithm::decode(buf, meta.offset, len as usize))
            }
            _ => panic!(),
        };

        Self { id, algorithm }
    }

    fn size(&self) -> usize {
        4 + self.algorithm.size()
    }
}

/// Sealed trait for password algorithms.
///
/// NOTE: Since the current algorithms don't have parameters,
/// the `encode` and `size` methods do nothing and only serve
/// to future-proof this implementation against later algorithms.
///
/// See the [IANA Registry for STUN Attributes](https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml)
/// for a list of the current password algorithms.
pub trait Algorithm: sealed::Sealed {
    fn dyn_clone(&self) -> Box<dyn Algorithm>;

    fn hash(&self, input: &[u8]) -> Bytes;

    fn encode(&self, _buf: &mut [u8], _offset: usize) {}

    fn decode(_buf: &[u8], _offset: usize, _len: usize) -> Self
    where
        Self: Sized;

    fn size(&self) -> usize {
        0
    }
}

impl Clone for Box<dyn Algorithm> {
    fn clone(&self) -> Self {
        self.dyn_clone()
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Md5Algorithm {}
    impl Sealed for super::Sha256Algorithm {}
}

const MD5_PASSWORD_ALGORITHM_TY: u16 = 0x0001;

/// The MD5 PASSWORD-ALGORITHM attribute.
pub const MD5_PASSWORD_ALGORITHM: Lazy<PasswordAlgorithm> = Lazy::new(|| PasswordAlgorithm {
    id: MD5_PASSWORD_ALGORITHM_TY,
    algorithm: Box::new(Md5Algorithm),
});

#[derive(Default, Clone)]
struct Md5Algorithm;

impl Algorithm for Md5Algorithm {
    fn dyn_clone(&self) -> Box<dyn Algorithm> {
        Box::new(self.clone())
    }

    fn hash(&self, input: &[u8]) -> Bytes {
        let mut hasher = Md5::new();

        hasher.update(input);

        let result = hasher.finalize();

        Bytes::copy_from_slice(&*result)
    }

    fn decode(_buf: &[u8], _offset: usize, _len: usize) -> Self
    where
        Self: Sized,
    {
        Self::default()
    }
}

const SHA256_PASSWORD_ALGORITHM_TY: u16 = 0x0002;

/// The SHA-256 PASSWORD-ALGORITHM attribute.
pub const SHA256_PASSWORD_ALGORITHM: Lazy<PasswordAlgorithm> = Lazy::new(|| PasswordAlgorithm {
    id: SHA256_PASSWORD_ALGORITHM_TY,
    algorithm: Box::new(Sha256Algorithm),
});

#[derive(Default, Clone)]
struct Sha256Algorithm;

impl Algorithm for Sha256Algorithm {
    fn dyn_clone(&self) -> Box<dyn Algorithm> {
        Box::new(self.clone())
    }

    fn hash(&self, input: &[u8]) -> Bytes {
        let mut hasher = Sha256::new();

        hasher.update(input);

        let result = hasher.finalize();

        Bytes::copy_from_slice(&*result)
    }

    fn decode(_buf: &[u8], _offset: usize, _len: usize) -> Self
    where
        Self: Sized,
    {
        Self::default()
    }
}
