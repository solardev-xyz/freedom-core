//! Approvals in the core (design 0012): approval tokens and what each binds
//! (APR-1); the four grant files and their codecs (APR-2, [`stores`]).
//!
//! A token is the core's record that the user confirmed one request: minted
//! for exactly that request ([`Tokens::issue`]), and spent once, for that
//! request only ([`Tokens::spend`]). The reference is freedom-browser's
//! `src/main/wallet/signing-confirmation.js` (security audit O-7, with
//! SEC-1's eleventh kind and 0011's page tokens); `vectors/approvals.json`,
//! produced from it, is the contract (AGENTS rule 5). What differs from it
//! is design 0012's `token-*` deviations:
//!
//! - `token-strict`: a request is read by the parse `sign.*` uses, never by
//!   `BigInt` or `Number`; what that parse refuses gets no token.
//! - `token-clock`: a token lives two minutes of the vault's clock.
//! - `token-page`: a page kind binds the page (`PageContext`'s origin, frame
//!   and navigation) and 0011's handle, a site's `safe-send` included.
//! - `token-typed-parse`: typed data is bound parsed, with its view, so the
//!   texts of one request share a token.
//! - `token-message-bytes`: a message is bound as the bytes `sign.message`
//!   signs, so its text and its hex in either case share a token.
//!
//! The crate does no I/O: the vault's clock comes in as `now_ms`, and token
//! bytes from the caller's RNG.

mod bind;
mod canonical;
mod error;
mod js;
mod kind;
pub mod stores;
mod tokens;

// The checks a standing rule makes besides its grant (APR-2): R-6's and
// Q9's rate, and 0005's fee check.
pub mod fee;
pub mod rate;

pub use bind::{
    Binding, Handle, Limits, MAX_ACCOUNT, MAX_CHAIN_ID, MAX_CLOSE_HASHES, MAX_NONCE, Page, Request,
    bind,
};
pub use error::{Error, Refusal};
pub use kind::{Kind, PageRule, Scope};
pub use tokens::{Issued, MAX_OUTSTANDING, Spent, TOKEN_TTL_MS, Token, Tokens};
