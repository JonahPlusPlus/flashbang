//! A STUN implementation.
//!
//! Implements the following specifications:
//! - [RFC8489: Session Traversal Utilities for NAT (STUN)](https://datatracker.ietf.org/doc/html/rfc8489)

pub mod client;
pub mod server;

pub mod message;
pub mod user;

pub mod prelude {}
