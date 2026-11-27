//! A Ledger in the core (design 0016, LDG-2): `fc-ledger`'s operations,
//! their APDUs carried to the device through main.
//!
//! - [`lane`]: the device lane, which runs one operation at a time, sends
//!   each APDU as a `shell.ledger_apdu` and hands its answer to the
//!   operation, under the lane's queue, deadlines and cancel.
//! - [`reply`]: `shell.ledger_apdu`'s replies, read strictly, and the bound
//!   each reply is read within.
//! - [`methods`]: `ledger.accounts` and `ledger.add` (L3), which drive it.
//!
//! A Ledger key in `sign.*` comes with L4.

pub mod lane;
pub mod methods;
pub mod reply;
