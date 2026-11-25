//! The swarm thread (design 0015, "In the core"; SWM-4): `window.swarm`'s
//! backend, each page's `swarm.request` run by fc-swarm-provider's method
//! machines, beside the naming, chain and dweb threads.
//!
//! - [`engine`]: the thread's logic, behind an `Io`: the door, admission,
//!   deadlines, the memory pool, the asks of main and their bounds, the
//!   live facts, a topic's turn and an upload's, the streams both ways and
//!   their idle bound, and the hashing pool's work;
//! - [`memory`]: the thread's 64 MiB, reserved first in, first out;
//! - [`lane`]: the mining lane, GSOC searches on a thread of their own;
//! - [`wire`]: the messages, read strictly and written;
//! - [`stream`]: the messages around the streams: a part's request and
//!   head, `swarm.body`'s, and the abort codes each way;
//! - [`stores`]: the Swarm stores' files (D3): `swarm-feeds.json`,
//!   `swarm-manifest-grants.json` and `publish-history.sqlite`;
//! - [`thread`]: the thread itself, which the event loop starts once a
//!   hello settles protocol 2.

pub mod engine;
pub mod lane;
pub mod memory;
pub mod stores;
pub mod stream;
pub mod thread;
pub mod wire;
