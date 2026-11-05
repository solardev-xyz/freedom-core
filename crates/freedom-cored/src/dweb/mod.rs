//! The dweb thread (design 0009, `dweb.verify`: "Thread"): verified
//! fetches from external Swarm and IPFS nodes, one `fc-dweb` verifier per
//! request, and the hashing pool beside it.
//!
//! - [`engine`]: the thread's logic, behind an `Io`: admission, grants,
//!   pieces, the structure cache and floors, deadlines and cancel;
//! - [`pool`]: the hashing pool;
//! - [`wire`]: the messages, read strictly and written;
//! - [`thread`]: the thread itself, which the event loop starts once a
//!   hello settles protocol 2.

pub mod engine;
pub mod pool;
pub mod thread;
pub mod wire;
