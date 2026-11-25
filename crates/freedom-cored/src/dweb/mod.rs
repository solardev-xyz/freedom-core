//! The dweb thread (design 0009, `dweb.verify`: "Thread"): verified
//! fetches from external Swarm and IPFS nodes, one `fc-dweb` verifier per
//! request, and its hashing pool beside it ([`crate::pool`]).
//!
//! - [`engine`]: the thread's logic, behind an `Io`: admission, grants,
//!   pieces, the structure cache and floors, deadlines and cancel;
//! - [`wire`]: the messages, read strictly and written;
//! - [`thread`]: the thread itself, which the event loop starts once a
//!   hello settles protocol 2.

pub mod engine;
pub mod thread;
pub mod wire;
