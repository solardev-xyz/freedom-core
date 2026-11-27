//! A Ledger in the core (design 0016, LDG-2): `fc-ledger`'s operations,
//! their APDUs carried to the device through main.
//!
//! - [`lane`]: the device lane, which runs one operation at a time, sends
//!   each APDU as a `shell.ledger_apdu` and hands its answer to the
//!   operation, under the lane's queue, deadlines and cancel.
//! - [`reply`]: `shell.ledger_apdu`'s replies, read strictly, and the bound
//!   each reply is read within.
//! - [`methods`]: `ledger.accounts` and `ledger.add` (L3), which drive it,
//!   the end of `sign.*` with a Ledger key (L4,
//!   [`crate::signing::prepare`] and [`crate::signing::finish`]), and of a
//!   Ledger's x402 payment (L5, [`crate::approvals::x402`]).

pub mod lane;
pub mod methods;
pub mod reply;
