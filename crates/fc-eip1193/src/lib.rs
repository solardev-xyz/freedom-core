//! The Ethereum dispatcher in the core (design 0012, "fc-eip1193 and
//! approval.request"): a page's EIP-1193 request, run by the core rather
//! than by main's `src/main/page/` (design 0011).
//!
//! A logic crate: a sans-I/O machine like `fc-chain`'s, with time and
//! randomness passed in (AGENTS rule 2). It holds nothing yet. APR-5a adds
//! the contract it is to meet, `vectors/eip1193.json`, recorded from 0011's
//! JS dispatcher at the approvals reference: each scenario's world, each
//! request, every effect main's dispatcher made with its answer, and the
//! result. The later APR-5 steps add the dispatcher and replay those
//! scenarios by their `step`: the reads (APR-5b), the prompts, connects and
//! chain switches (APR-5c), signatures (APR-5d), the prepared send (APR-5e)
//! and names over IPNS (APR-5f).
