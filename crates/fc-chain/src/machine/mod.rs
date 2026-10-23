//! The chain-data machine (design 0005, step 3): the router's reads, fee
//! quotes and broadcasts as a sans-I/O state machine on fc-naming's
//! executor.
//!
//! - **In:** `chain.configure` ([`Machine::configure`]),
//!   `chain.availability` ([`Machine::availability`]), `chain.request`,
//!   `chain.fee_quote`, `chain.fee_reference`, `chain.broadcast` and design
//!   0006's `chain.html` ([`Machine::submit`]),
//!   `cancel` ([`Machine::cancel`]), main's replies to the machine's I/O
//!   ([`Machine::complete`]), and time ([`Machine::fire_next`]).
//! - **Out:** `shell.rpc`, `shell.verified` and `shell.blockscout` requests
//!   and their cancels ([`Machine::take_effects`]), and each request's
//!   one reply ([`Machine::take_replies`]).
//!
//! The machine reproduces the reference's requests, timings and results
//! (`vectors/chain-replay.json`), with design 0005's deviations:
//! `overall-deadline`, `admission`, `abandoned-exchanges`,
//! `order-validation`, `endpoint-dedup`, `singleton-quorum`,
//! `quorum-clamps`, `config-change`, `memory-budgets`,
//! `monotonic-time`, `state-retention`, `rpc-id`, `adapter-error-text`,
//! `cancel-promptly`, `paired-endpoint-text`, `broadcast-outcome` and
//! `fee-combination`. It
//! keeps no wall clock: every instant is the executor's monotonic
//! milliseconds.

mod blockscout;
mod bounds;
mod budget;
mod config;
mod ctx;
mod error;
mod exchange;
mod faults;
mod header;
mod html;
mod io;
mod logs;
#[allow(clippy::module_inception)]
mod machine;
mod quorum;
mod quote;
mod read;
mod route;
mod send;
mod text;
mod trust;

pub use bounds::Bounds;
pub use config::{ChainConfig, Prover, QuorumConfig, RpcEndpoint, SOURCES};
pub use error::{ChainError, ErrorClass, Origin, Prop, Protocol, Thrown};
pub use exchange::{BUSY, FETCH_FAILED, NOT_SENT, TOO_LARGE};
pub use faults::{BackedOff, FaultRecord};
pub use fc_dweb::Class as HtmlClass;
pub use fc_naming::session::exec::{Effect, Fired};
pub use header::Header;
pub use html::HTML_TOO_LARGE_CODE;
pub use io::{
    Answer, ColibriClass, ColibriReply, Endpoint, Ms, MyotisClass, MyotisRejection, MyotisReply,
    Request, Transport, Verdict, VerifiedOp,
};
pub use logs::{CapReader, RangeEntry, Ranker};
pub use machine::{Call, Emitted, Machine, OverBudget, Reply, Reservation, StateTables, Success};
pub use quote::FeeReference;
pub use read::{COLIBRI_FAILED, MYOTIS_FAILED, ReadOptions};
pub use route::RouteState;
pub use send::BroadcastOutcome;
