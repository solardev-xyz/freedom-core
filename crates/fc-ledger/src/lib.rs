//! A Ledger in the core (design 0016, LDG-1): the logic crate main's relay
//! and the core's device lane (LDG-2) run, sans-I/O.
//!
//! - **Paths** ([`LedgerPath`]): only the two schemes' forms, `live`
//!   `44'/60'/i'/0/0` and `legacy` `44'/60'/0'/i` (deviation
//!   `path-strict`).
//! - **APDUs and their answers** ([`Apdu`]): each row of the grammar,
//!   built from the approved request and the record's path; each answer
//!   read within its length: `E0 02`'s key and address, the address the
//!   key derives (deviation `key-check`), `B0 01`'s format, name and
//!   version, a signature's `v ‖ r ‖ s`.
//! - **The operations** ([`Operation`]): `ledger.accounts` (with its check
//!   of the records no device has matched, D1), `ledger.add`
//!   (with the display, deviation `address-from-device`),
//!   `sign.transaction`, `sign.message` and `sign.typed_data`, each a
//!   machine that yields the next APDU and is handed main's reply. Every
//!   signature first checks the address and the app (deviation
//!   `app-check`). Typed data goes field by field, every value whole in
//!   pieces of 255 (deviation `field-pieces`); the hash-only form only
//!   after `6D00` answered the operation's first `E0 1A` and main said its
//!   warning is shown (Q23, deviation `blind-typed-data`).
//! - **The status mapping** ([`LedgerCode`]): `errors.js`'s table, main's
//!   failures (deviation `no-device`), and the five new codes.
//! - **The checks:** every signature recovered against the account and the
//!   digest the user confirmed, `s` low (deviation `signature-check`); a
//!   legacy transaction's `v` read from the bound chain ID, any width
//!   (deviation `chain-id-width`).
//! - **The bounds** ([`bounds`]): what a Ledger can't carry is refused
//!   before the first APDU (deviations `device-bounds`, `empty-message`);
//!   a name is ASCII, refused otherwise by 0002's identifier rule
//!   (deviation `name-ascii`); an array suffix written in a form the device
//!   wouldn't rebuild from its descriptor (`uint8[02]`) is refused
//!   `LEDGER_TYPE_NOT_CANONICAL`.
//!
//! The crate does no I/O and holds no key: deadlines, cancel and the
//! device belong to the caller.

mod apdu;
pub mod bounds;
mod code;
mod machine;
mod path;
mod typed;

pub use apdu::{AnswerFault, Apdu, MAX_ANSWER, MAX_DATA, MIN_ANSWER};
pub use code::{Failed, LedgerCode};
pub use machine::{
    Account, Cause, Discovered, ETHEREUM_APP, Exchange, Failure, Lapse, MAX_ACCOUNTS, MAX_CHECKS,
    Operation, ProtocolFault, Refusal, Reply, Retained, SignatureFault, Signed, Step,
};
pub use path::{LedgerPath, MAX_INDEX, PathError, Scheme};
