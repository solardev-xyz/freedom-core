//! The dweb thread (design 0009, `dweb.verify`: "Thread"): verified
//! fetches from external Swarm and IPFS nodes, one `fc-dweb` verifier per
//! request, and the hashing pool beside it.
//!
//! Built in parts (0009, step 5): the hashing pool first. The event loop
//! starts the thread once the core speaks protocol 2.

// Unused until the thread is started (step 5c).
#[allow(dead_code)]
pub mod pool;
