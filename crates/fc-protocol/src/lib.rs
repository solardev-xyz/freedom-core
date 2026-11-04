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

/// The version at which `freedom-cored`'s connection takes streams in both
/// directions (design 0009, Streams in the core): main offers
/// `frames: ["fragment", "stream"]`, the core's capabilities gain
/// `streams`, and the connection reads [`frame::Kinds::CORE_STREAMS`] with
/// a [`stream::Duplex`]. The core moves to it with its dweb thread.
pub const PROTOCOL_VERSION_STREAMS: u32 = 2;
