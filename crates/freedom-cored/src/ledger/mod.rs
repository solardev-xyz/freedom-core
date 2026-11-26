//! A Ledger in the core (design 0016, LDG-2): `fc-ledger`'s operations,
//! their APDUs carried to the device through main.
//!
//! - [`reply`]: `shell.ledger_apdu`'s replies, read strictly, and the bound
//!   each reply is read within.
//!
//! The device lane, which sends each APDU and hands its answer to the
//! operation, comes with L2.

#[allow(dead_code)] // the device lane's (LDG-2's L2)
pub mod reply;
