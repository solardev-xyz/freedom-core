//! Name resolution sessions (design 0004): the resolvers' orchestration as a
//! sans-I/O machine. The driver supplies time, randomness and the answers
//! to the I/O the machine asks for.

pub mod exec;
pub mod pool;
pub mod random;
pub mod rpc;
