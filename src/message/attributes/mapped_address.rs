use crate::message::MAGIC;

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// The MAPPED-ADDRESS attribute.
///
/// Represents a reflexive transport address of the client.
///
/// See [RFC8489 Section 14.1](https://datatracker.ietf.org/doc/html/rfc8489#section-14.1) for more details.
pub struct MappedAddress {
    addr: SocketAddr,
}

impl MappedAddress {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.addr = addr;
    }
}

impl Attribute for MappedAddress {
    const TY: u16 = 0x0001;
    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        // sanity check: first 8 bits MUST be set to 0
        buf[offset] = 0;

        // encode the family, port and address
        match self.addr {
            SocketAddr::V4(addr) => {
                buf[offset + 1] = 0x01;
                buf[(offset + 2)..(offset + 4)].copy_from_slice(&addr.port().to_be_bytes());
                buf[(offset + 4)..(offset + 8)].copy_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                buf[offset + 1] = 0x02;
                buf[(offset + 2)..(offset + 4)].copy_from_slice(&addr.port().to_be_bytes());
                buf[(offset + 4)..(offset + 20)].copy_from_slice(&addr.ip().octets());
            }
        }
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        // TODO: check first 8 bits

        let addr = match buf[meta.offset + 1] {
            0x01 => {
                let port = u16::from_be_bytes(
                    buf[(meta.offset + 2)..(meta.offset + 4)]
                        .try_into()
                        .unwrap(),
                );

                let octets: [u8; 4] = buf[(meta.offset + 4)..(meta.offset + 8)]
                    .try_into()
                    .unwrap();
                let ip = Ipv4Addr::from(octets);

                SocketAddrV4::new(ip, port).into()
            }
            0x02 => {
                let port = u16::from_be_bytes(
                    buf[(meta.offset + 2)..(meta.offset + 4)]
                        .try_into()
                        .unwrap(),
                );

                let octets: [u8; 16] = buf[(meta.offset + 4)..(meta.offset + 20)]
                    .try_into()
                    .unwrap();
                let ip = Ipv6Addr::from(octets);

                SocketAddrV6::new(ip, port, 0, 0).into()
            }
            _ => {
                panic!("Family must be 1 or 2"); // TODO: add better handling
            }
        };

        Self { addr }
    }

    fn size(&self) -> usize {
        match self.addr {
            SocketAddr::V4(_) => 64,
            SocketAddr::V6(_) => 160,
        }
    }
}

/// The XOR-MAPPED-ADDRESS attribute.
///
/// Identical to [MappedAddress] but obfuscated through the XOR function.
///
/// See [RFC8489 Section 14.2](https://datatracker.ietf.org/doc/html/rfc8489#section-14.2) for more details.
pub struct XorMappedAddress {
    addr: SocketAddr,
}

impl XorMappedAddress {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set_addr(&mut self, addr: SocketAddr) {
        self.addr = addr;
    }
}

impl Attribute for XorMappedAddress {
    const TY: u16 = 0x0020;
    const SIZE: usize = 0;

    fn encode(&self, buf: &mut [u8], offset: usize) {
        // sanity check: first 8 bits MUST be set to 0
        buf[offset] = 0;

        // encode the family, port and address
        match self.addr {
            SocketAddr::V4(addr) => {
                buf[offset + 1] = 0x01;
                let port = addr.port() ^ (MAGIC >> 16) as u16;
                buf[(offset + 2)..(offset + 4)].copy_from_slice(&port.to_be_bytes());
                let address = u32::from_be_bytes(addr.ip().octets()) ^ MAGIC;
                buf[(offset + 4)..(offset + 8)].copy_from_slice(&address.to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf[offset + 1] = 0x02;
                let port = addr.port() ^ (MAGIC >> 16) as u16;
                buf[(offset + 2)..(offset + 4)].copy_from_slice(&port.to_be_bytes());
                let address = u128::from_be_bytes(addr.ip().octets())
                    ^ u128::from_be_bytes(buf[4..20].try_into().unwrap());
                buf[(offset + 4)..(offset + 20)].copy_from_slice(&address.to_be_bytes());
            }
        }
    }

    fn decode(buf: &[u8], meta: &AttributeMeta) -> Self {
        // TODO: check first 8 bits

        let addr = match buf[meta.offset + 1] {
            0x01 => {
                let port = u16::from_be_bytes(
                    buf[(meta.offset + 2)..(meta.offset + 4)]
                        .try_into()
                        .unwrap(),
                ) ^ (MAGIC >> 16) as u16;

                let octets = u32::from_be_bytes(
                    buf[(meta.offset + 4)..(meta.offset + 8)]
                        .try_into()
                        .unwrap(),
                ) ^ MAGIC;
                let ip = Ipv4Addr::from(octets);

                SocketAddrV4::new(ip, port).into()
            }
            0x02 => {
                let port = u16::from_be_bytes(
                    buf[(meta.offset + 2)..(meta.offset + 4)]
                        .try_into()
                        .unwrap(),
                ) ^ (MAGIC >> 16) as u16;

                let octets = u128::from_be_bytes(
                    buf[(meta.offset + 4)..(meta.offset + 20)]
                        .try_into()
                        .unwrap(),
                ) ^ u128::from_be_bytes(buf[4..20].try_into().unwrap());
                let ip = Ipv6Addr::from(octets);

                SocketAddrV6::new(ip, port, 0, 0).into()
            }
            _ => {
                panic!("Family must be 1 or 2"); // TODO: add better handling
            }
        };

        Self { addr }
    }

    fn size(&self) -> usize {
        match self.addr {
            SocketAddr::V4(_) => 64,
            SocketAddr::V6(_) => 160,
        }
    }
}
