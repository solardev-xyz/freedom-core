//! What issuing or spending a token can refuse.

/// A request this crate can't confirm, or a token it couldn't mint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The request isn't one its kind confirms: a field missing, malformed
    /// or out of range, as the parse `sign.*` uses reads it (the reference's
    /// `bindingFor` throws for these too, or takes them where the core
    /// doesn't: `token-strict`).
    #[error("{0}")]
    Invalid(String),
    /// A page kind with no page (design 0012, "Tokens": only the `page`
    /// caller mints one, with its `PageContext` and 0011's handle).
    #[error("a {0} confirmation needs the page it is for")]
    PageRequired(&'static str),
    /// A wallet kind that names a page.
    #[error("a {0} confirmation is not for a page")]
    PageForbidden(&'static str),
    /// The injected RNG failed: nothing was minted, and no outstanding
    /// token was dropped.
    #[error("the random number generator failed")]
    Randomness,
}

/// Why a presented token signs nothing. The token is burnt in every case
/// but [`Refusal::NoToken`], when none was presented, and an unknown one,
/// which has nothing to burn.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("no confirmation token")]
    NoToken,
    /// Never issued, already spent, discarded, evicted by the cap, or pruned
    /// after its expiry.
    #[error("unknown or already used confirmation")]
    UnknownToken,
    #[error("confirmation expired")]
    Expired,
    /// Another kind, another account, another request, another page or
    /// handle, or a site's token presented as a wallet's (or a wallet's as a
    /// site's).
    #[error("request differs from what was confirmed")]
    Mismatch,
    /// The presented request doesn't parse for its kind, so it can't be the
    /// one confirmed.
    #[error("{0}")]
    Invalid(Error),
}
