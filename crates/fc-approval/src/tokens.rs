//! Outstanding tokens: minted for one request, spent once (design 0012,
//! "Tokens"; the reference's `issue` and `consume`).
//!
//! - **Life:** [`TOKEN_TTL_MS`] of the vault's clock, which the caller
//!   passes as `now_ms` (freedom-cored's `clock.rs`: it counts sleep and
//!   never runs back). A token is expired at exactly its end
//!   (`expires_at <= now`). Today's JS counts `Date.now()`, which a wall
//!   clock set back extends (`token-clock`).
//! - **Count:** at most [`MAX_OUTSTANDING`]; minting drops the expired, then
//!   the oldest, to make room.
//! - **Burnt** at its first presentation, whatever the outcome: a mismatch,
//!   an expiry, another kind, another page. [`Tokens::discard`] burns one
//!   without spending it.
//! - **A bearer secret:** 32 bytes from the caller's RNG, never in `Debug`
//!   output, wiped when it is spent, discarded, pruned or evicted, and
//!   compared in constant time against every outstanding token.

use std::fmt;

use fc_evm::TypedDataView;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::bind::{Limits, Request, bind, lower_hex_32};
use crate::error::{Error, Refusal};
use crate::kind::{Kind, Scope};

/// Two minutes (the reference's `CONFIRMATION_TTL_MS`).
pub const TOKEN_TTL_MS: u64 = 2 * 60 * 1000;

/// The reference's `MAX_OUTSTANDING`.
pub const MAX_OUTSTANDING: usize = 32;

/// A minted token: 32 random bytes, sent as 64 lowercase hex digits.
pub struct Token(Zeroizing<[u8; 32]>);

impl Token {
    /// The token's text, for the reply that carries it to its caller.
    pub fn to_text(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = Zeroizing::new(String::with_capacity(64));
        for byte in self.0.iter() {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
        text
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

/// What minting returns.
#[derive(Debug)]
pub struct Issued {
    pub token: Token,
    /// When the token expires, on the vault's clock.
    pub expires_at_ms: u64,
    /// For `sign-typed-data`: the EIP-712 hash and the view the token binds,
    /// for the prompt (`approval.issue`'s `hash` and `view`).
    pub typed_data: Option<TypedDataView>,
}

/// What spending returns: the request matched the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spent {
    pub kind: Kind,
    /// For `sign-typed-data`: the confirmed hash, which `sign.typed_data`
    /// signs as `expected_hash`, and the view, built again and equal to the
    /// one confirmed.
    pub typed_data: Option<TypedDataView>,
}

struct Entry {
    token: Zeroizing<[u8; 32]>,
    kind: Kind,
    scope: Scope,
    digest: [u8; 32],
    expires_at_ms: u64,
}

/// The outstanding tokens, oldest first.
pub struct Tokens {
    entries: Vec<Entry>,
    limits: Limits,
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("outstanding", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Equal, in time that doesn't depend on where two tokens differ.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

impl Tokens {
    pub fn new(limits: Limits) -> Self {
        Tokens {
            entries: Vec::new(),
            limits,
        }
    }

    /// How many tokens are outstanding (the reference's
    /// `_outstandingCount`): expired ones count until the next mint prunes
    /// them.
    pub fn outstanding(&self) -> usize {
        self.entries.len()
    }

    /// Mints a token for exactly `request`. A request its kind can't confirm
    /// gets none, and changes nothing.
    pub fn issue<R: TryCryptoRng + ?Sized>(
        &mut self,
        request: &Request<'_>,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Issued, Error> {
        let binding = bind(request, &self.limits)?;
        let mut token = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(&mut token[..])
            .map_err(|_| Error::Randomness)?;
        self.entries.retain(|entry| entry.expires_at_ms > now_ms);
        // A token is one entry: drawn again, it replaces the old one.
        if let Some(index) = self.position(&token) {
            self.entries.remove(index);
        }
        while self.entries.len() >= MAX_OUTSTANDING {
            self.entries.remove(0);
        }
        let expires_at_ms = now_ms.saturating_add(TOKEN_TTL_MS);
        self.entries.push(Entry {
            token: token.clone(),
            kind: binding.kind(),
            scope: binding.scope(),
            digest: *binding.digest(),
            expires_at_ms,
        });
        Ok(Issued {
            token: Token(token),
            expires_at_ms,
            typed_data: binding.into_typed_data(),
        })
    }

    /// Spends `token` on `request`, burning it first. Refused unless it was
    /// minted for this kind, this request and this page (or none), and is
    /// not expired.
    pub fn spend(
        &mut self,
        token: &str,
        request: &Request<'_>,
        now_ms: u64,
    ) -> Result<Spent, Refusal> {
        if token.is_empty() {
            return Err(Refusal::NoToken);
        }
        let entry = lower_hex_32(token)
            .and_then(|bytes| self.position(&bytes))
            .map(|index| self.entries.remove(index))
            .ok_or(Refusal::UnknownToken)?;
        if entry.expires_at_ms <= now_ms {
            return Err(Refusal::Expired);
        }
        // A site's token is never spent as a wallet's, nor a wallet's as a
        // site's (a `safe-send` is either).
        let scope = if request.page.is_some() {
            Scope::Page
        } else {
            Scope::Wallet
        };
        if entry.scope != scope {
            return Err(Refusal::Mismatch);
        }
        let binding = bind(request, &self.limits).map_err(Refusal::Invalid)?;
        if entry.kind != binding.kind() || !constant_time_eq(&entry.digest, binding.digest()) {
            return Err(Refusal::Mismatch);
        }
        Ok(Spent {
            kind: entry.kind,
            typed_data: binding.into_typed_data(),
        })
    }

    /// Burns `token` without spending it: for a call refused before it named
    /// a request to check the token against (the reference's
    /// `discardConfirmation`).
    pub fn discard(&mut self, token: &str) {
        if let Some(index) = lower_hex_32(token).and_then(|bytes| self.position(&bytes)) {
            self.entries.remove(index);
        }
    }

    /// The outstanding entry for `token`, compared against every one.
    fn position(&self, token: &[u8; 32]) -> Option<usize> {
        let mut found = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if constant_time_eq(&entry.token, token) && found.is_none() {
                found = Some(index);
            }
        }
        found
    }
}
