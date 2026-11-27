//! A Ledger in the core (design 0016, LDG-2): `fc-ledger`'s operations,
//! their APDUs carried to the device through main.
//!
//! - [`lane`]: the device lane, which runs one operation at a time, sends
//!   each APDU as a `shell.ledger_apdu` and hands its answer to the
//!   operation, under the lane's queue, deadlines and cancel.
//! - [`reply`]: `shell.ledger_apdu`'s replies, read strictly, and the bound
//!   each reply is read within.
//!
//! No method drives the lane yet: `ledger.*` comes with L3, a Ledger key in
//! `sign.*` with L4.

#[allow(dead_code)] // driven by ledger.* (L3) and sign.* (L4)
pub mod lane;
#[allow(dead_code)] // the device lane's
pub mod reply;
