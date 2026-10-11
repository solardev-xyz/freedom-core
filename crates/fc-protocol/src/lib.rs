//! The `freedom-cored` wire protocol (design 0001): length-prefixed frames,
//! JSON message envelopes with a caller context, error codes, and secret
//! fields that decode straight into `Zeroizing` buffers.
//!
//! A logic crate: sans-I/O. The core binary and the tests feed bytes in and
//! take bytes out.

pub mod error;
pub mod frame;
pub mod message;
pub mod secret;

/// The protocol version negotiated in `core.hello`.
pub const PROTOCOL_VERSION: u32 = 1;
