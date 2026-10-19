//! The `freedom-cored` wire protocol (design 0001): length-prefixed frames,
//! fragmented responses with bulk credit (design 0005), the service
//! processes' stream frames with per-stream credit (design 0007), JSON
//! message envelopes with a caller context, error codes, and secret fields
//! that decode straight into `Zeroizing` buffers.
//!
//! A logic crate: sans-I/O. The core binary and the tests feed bytes in and
//! take bytes out.

pub mod error;
pub mod fragment;
pub mod frame;
pub mod message;
pub mod methods;
pub mod secret;
pub mod stream;

/// The protocol version negotiated in `core.hello`.
pub const PROTOCOL_VERSION: u32 = 1;
