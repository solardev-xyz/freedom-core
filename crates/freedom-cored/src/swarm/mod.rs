//! The swarm thread (design 0015, "In the core"; SWM-4): `window.swarm`'s
//! backend, each page's `swarm.request` run by fc-swarm-provider's method
//! machines, beside the naming, chain and dweb threads.
//!
//! - [`engine`]: the thread's logic, behind an `Io`: the door, admission,
//!   deadlines, the memory pool, the asks of main and their bounds, the
//!   live facts, a topic's turn and an upload's;
//! - [`memory`]: the thread's 64 MiB, reserved first in, first out;
//! - [`lane`]: the mining lane, GSOC searches on a thread of their own;
//! - [`wire`]: the messages, read strictly and written;
//! - [`thread`]: the thread itself, which the event loop starts once a
//!   hello settles protocol 2.

pub mod engine;
pub mod lane;
pub mod memory;
pub mod thread;
pub mod wire;
