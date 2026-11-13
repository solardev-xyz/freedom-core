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

/// The caller kind that minted a token, for a store that keeps its callers
/// apart: freedom-cored spends a token only under the caller kind that
/// minted it (design 0012, API: `approval.spend`). [`Tokens::issue`] and
/// [`Tokens::spend`] use [`Minter::Unnamed`], which no named caller
/// spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Minter {
    #[default]
    Unnamed,
    Page,
    Chrome,
    Shell,
}

struct Entry {
    token: Zeroizing<[u8; 32]>,
    minter: Minter,
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
        self.issue_as(Minter::Unnamed, request, now_ms, rng)
    }

    /// [`Tokens::issue`], for `minter`: the token is spent only by the same
    /// minter ([`Tokens::spend_as`]).
    pub fn issue_as<R: TryCryptoRng + ?Sized>(
        &mut self,
        minter: Minter,
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
            minter,
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
        self.spend_as(Minter::Unnamed, token, request, now_ms)
    }

    /// [`Tokens::spend`], by `minter`: a token another minter minted is
    /// refused as another request ([`Refusal::Mismatch`]), and burnt.
    pub fn spend_as(
        &mut self,
        minter: Minter,
        token: &str,
        request: &Request<'_>,
        now_ms: u64,
    ) -> Result<Spent, Refusal> {
        self.spend_with(minter, token, now_ms, |kind| {
            (kind == request.kind).then_some(*request)
        })
    }

    /// Spends `token` on the request `request_for` makes for the kind it
    /// was minted for, burning it first: for a caller that presents a token
    /// without naming its kind, where more than one kind binds the same
    /// request (`sign.transaction`'s `wallet-send` and `executor-send`).
    /// `None` from `request_for` is a kind this request can't be, refused
    /// as [`Refusal::Mismatch`].
    pub fn spend_with<'a>(
        &mut self,
        minter: Minter,
        token: &str,
        now_ms: u64,
        request_for: impl FnOnce(Kind) -> Option<Request<'a>>,
    ) -> Result<Spent, Refusal> {
        if token.is_empty() {
            return Err(Refusal::NoToken);
        }
        let entry = self
            .presented(token)
            .map(|index| self.entries.remove(index))
            .ok_or(Refusal::UnknownToken)?;
        if entry.expires_at_ms <= now_ms {
            return Err(Refusal::Expired);
        }
        if entry.minter != minter {
            return Err(Refusal::Mismatch);
        }
        let request = request_for(entry.kind).ok_or(Refusal::Mismatch)?;
        let request = &request;
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
        if let Some(index) = self.presented(token) {
            self.entries.remove(index);
        }
    }

    /// The outstanding entry for a presented token's text. The text is
    /// decoded into a buffer that is wiped when this returns, matched or not.
    fn presented(&self, token: &str) -> Option<usize> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        if !lower_hex_32(token, &mut bytes) {
            return None;
        }
        self.position(&bytes)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::{Value, json};

    use super::*;
    use crate::bind::{Handle, Page};

    const LIMITS: Limits = Limits {
        max_view_len: 1 << 20,
    };

    /// Each fill is the next counter value spread over the bytes, or a
    /// failure once `fail` is set.
    struct TestRng {
        next: u64,
        fail: bool,
    }

    #[derive(Debug)]
    struct TestRngError;

    impl std::fmt::Display for TestRngError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("test rng")
        }
    }

    impl std::error::Error for TestRngError {}

    impl rand_core::TryRng for TestRng {
        type Error = TestRngError;

        fn try_next_u32(&mut self) -> Result<u32, TestRngError> {
            let mut bytes = [0u8; 4];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> Result<u64, TestRngError> {
            let mut bytes = [0u8; 8];
            self.try_fill_bytes(&mut bytes)?;
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), TestRngError> {
            if self.fail {
                return Err(TestRngError);
            }
            let counter = self.next.to_le_bytes();
            for (index, byte) in dst.iter_mut().enumerate() {
                *byte = counter[index % 8] ^ (index as u8);
            }
            self.next += 1;
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for TestRng {}

    fn rng() -> TestRng {
        TestRng {
            next: 0,
            fail: false,
        }
    }

    fn tx() -> Value {
        json!({
            "type": 2,
            "chain_id": "100",
            "gas_limit": "21000",
            "to": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "value": "1000",
            "data": "0x",
            "max_fee_per_gas": "2000000000",
            "max_priority_fee_per_gas": "1000000000",
        })
    }

    fn page() -> Page {
        Page {
            origin: "https://app.example".into(),
            frame: 1,
            navigation: 1,
            handle: Handle::from_bytes([0xa1; 32]),
        }
    }

    const ACCOUNT: Value = Value::Null;

    fn request<'a>(
        kind: Kind,
        account: &'a Value,
        payload: &'a Value,
        page: Option<&'a Page>,
    ) -> Request<'a> {
        Request {
            kind,
            account: Some(account),
            payload,
            page,
        }
    }

    #[test]
    fn a_fixed_rng_gives_a_fixed_token() {
        let payload = json!({ "tx": tx() });
        let account = json!(0);
        let send = request(Kind::WalletSend, &account, &payload, None);
        let text = |store: &mut Tokens| store.issue(&send, 0, &mut rng()).unwrap().token.to_text();
        let first = text(&mut Tokens::new(LIMITS));
        assert_eq!(*first, *text(&mut Tokens::new(LIMITS)));
        // The RNG's first 32 bytes, in lowercase hex.
        let expected: String = (0..32u8).map(|i| format!("{i:02x}")).collect();
        assert_eq!(*first, expected);
    }

    /// A token is spent only by the caller kind that minted it, and burnt
    /// when another presents it.
    #[test]
    fn a_token_is_spent_only_by_its_minter() {
        let payload = json!({ "tx": tx() });
        let account = json!(0);
        let send = request(Kind::WalletSend, &account, &payload, None);
        let mut store = Tokens::new(LIMITS);
        let mut source = rng();
        let chrome = store
            .issue_as(Minter::Chrome, &send, 0, &mut source)
            .unwrap();
        let text = chrome.token.to_text();
        assert_eq!(
            store.spend_as(Minter::Shell, &text, &send, 0).unwrap_err(),
            Refusal::Mismatch
        );
        assert_eq!(
            store.spend_as(Minter::Chrome, &text, &send, 0).unwrap_err(),
            Refusal::UnknownToken
        );
        let chrome = store
            .issue_as(Minter::Chrome, &send, 0, &mut source)
            .unwrap();
        assert!(
            store
                .spend_as(Minter::Chrome, &chrome.token.to_text(), &send, 0)
                .is_ok()
        );
        // An unnamed minter's token is no named caller's.
        let unnamed = store.issue(&send, 0, &mut source).unwrap();
        assert_eq!(
            store
                .spend_as(Minter::Shell, &unnamed.token.to_text(), &send, 0)
                .unwrap_err(),
            Refusal::Mismatch
        );
    }

    /// `spend_with` spends a token as the kind it was minted for, when the
    /// caller can make that kind's request, and burns it otherwise.
    #[test]
    fn spend_with_takes_the_minted_kind() {
        let payload = json!({ "tx": tx() });
        let account = json!(0);
        let executor = request(Kind::ExecutorSend, &account, &payload, None);
        let mut store = Tokens::new(LIMITS);
        let mut source = rng();
        let either = |kind: Kind| {
            matches!(kind, Kind::WalletSend | Kind::ExecutorSend)
                .then(|| request(kind, &account, &payload, None))
        };
        let issued = store
            .issue_as(Minter::Shell, &executor, 0, &mut source)
            .unwrap();
        let spent = store
            .spend_with(Minter::Shell, &issued.token.to_text(), 0, either)
            .unwrap();
        assert_eq!(spent.kind, Kind::ExecutorSend);
        let issued = store
            .issue_as(Minter::Shell, &executor, 0, &mut source)
            .unwrap();
        let text = issued.token.to_text();
        assert_eq!(
            store
                .spend_with(Minter::Shell, &text, 0, |_| None)
                .unwrap_err(),
            Refusal::Mismatch
        );
        assert_eq!(
            store
                .spend_with(Minter::Shell, &text, 0, either)
                .unwrap_err(),
            Refusal::UnknownToken
        );
    }

    #[test]
    fn a_failed_rng_mints_nothing_and_drops_nothing() {
        let payload = json!({ "tx": tx() });
        let account = json!(0);
        let send = request(Kind::WalletSend, &account, &payload, None);
        let mut store = Tokens::new(LIMITS);
        let mut source = rng();
        let oldest = store.issue(&send, 0, &mut source).unwrap();
        for _ in 1..MAX_OUTSTANDING {
            store.issue(&send, 0, &mut source).unwrap();
        }
        source.fail = true;
        assert_eq!(
            store.issue(&send, 0, &mut source).unwrap_err(),
            Error::Randomness
        );
        assert_eq!(store.outstanding(), MAX_OUTSTANDING);
        assert!(store.spend(&oldest.token.to_text(), &send, 0).is_ok());
    }

    #[test]
    fn tokens_are_never_in_debug_output() {
        let payload = json!({ "tx": tx() });
        let account = json!(0);
        let send = request(Kind::WalletSend, &account, &payload, None);
        let mut store = Tokens::new(LIMITS);
        let issued = store.issue(&send, 0, &mut rng()).unwrap();
        let text = issued.token.to_text();
        for debug in [
            format!("{issued:?}"),
            format!("{store:?}"),
            format!("{:?}", issued.token),
        ] {
            assert!(!debug.contains(text.as_str()), "{debug}");
            assert!(!debug.contains("0001020304"), "{debug}");
        }
    }

    #[test]
    fn two_minutes_of_the_injected_clock() {
        let payload = json!({ "tx": tx() });
        let account = json!(0);
        let send = request(Kind::WalletSend, &account, &payload, None);
        let mut store = Tokens::new(LIMITS);
        let mut source = rng();
        let start = 5_000;
        let valid = store.issue(&send, start, &mut source).unwrap();
        let expired = store.issue(&send, start, &mut source).unwrap();
        assert_eq!(valid.expires_at_ms, start + 120_000);
        assert!(
            store
                .spend(&valid.token.to_text(), &send, start + 119_999)
                .is_ok()
        );
        assert_eq!(
            store
                .spend(&expired.token.to_text(), &send, start + 120_000)
                .unwrap_err(),
            Refusal::Expired
        );
        // Burnt: refused even at a time it would have been valid.
        assert_eq!(
            store
                .spend(&expired.token.to_text(), &send, start)
                .unwrap_err(),
            Refusal::UnknownToken
        );
    }

    #[test]
    fn a_token_is_its_lowercase_text() {
        let payload = json!({ "tx": tx() });
        let account = json!(0);
        let send = request(Kind::WalletSend, &account, &payload, None);
        let mut store = Tokens::new(LIMITS);
        let issued = store.issue(&send, 0, &mut rng()).unwrap();
        let text = issued.token.to_text();
        // As the reference's map: another spelling is another (unknown)
        // token, and burns nothing.
        for other in [
            text.to_uppercase(),
            format!("0x{}", text.as_str()),
            text[..63].to_owned(),
        ] {
            assert_eq!(
                store.spend(&other, &send, 0).unwrap_err(),
                Refusal::UnknownToken
            );
        }
        store.discard(&text.to_uppercase());
        assert_eq!(store.outstanding(), 1);
        assert_eq!(store.spend("", &send, 0).unwrap_err(), Refusal::NoToken);
        assert!(store.spend(&text, &send, 0).is_ok());
    }

    #[test]
    fn a_page_kind_needs_its_page_and_a_wallet_kind_names_none() {
        let page = page();
        let account = json!(0);
        let payload = json!({ "tx": tx() });
        let mut store = Tokens::new(LIMITS);
        let mut source = rng();
        assert_eq!(
            store
                .issue(
                    &request(Kind::DappSend, &account, &payload, None),
                    0,
                    &mut source
                )
                .unwrap_err(),
            Error::PageRequired("dapp-send")
        );
        assert_eq!(
            store
                .issue(
                    &request(Kind::WalletSend, &account, &payload, Some(&page)),
                    0,
                    &mut source
                )
                .unwrap_err(),
            Error::PageForbidden("wallet-send")
        );
        let message = json!({ "message": "0x68656c6c6f" });
        assert_eq!(
            store
                .issue(
                    &request(Kind::SignMessage, &account, &message, None),
                    0,
                    &mut source
                )
                .unwrap_err(),
            Error::PageRequired("sign-message")
        );
        let empty_origin = Page {
            origin: String::new(),
            ..page.clone()
        };
        assert!(
            store
                .issue(
                    &request(Kind::SignMessage, &account, &message, Some(&empty_origin)),
                    0,
                    &mut source
                )
                .is_err()
        );
        assert_eq!(store.outstanding(), 0);
        // The intent kinds bind the sender, not an account.
        let resend = json!({
            "intent_id": "7b0c6c1e-0c62-4a6e-9a49-0d6a3f6d1a07",
            "chain_id": "100",
            "sender": "0x".to_owned() + &"ab".repeat(20),
            "nonce": "7",
            "hash": "0x".to_owned() + &"a1".repeat(32),
        });
        assert!(
            store
                .issue(
                    &request(Kind::IntentResend, &ACCOUNT, &resend, None),
                    0,
                    &mut source
                )
                .is_ok()
        );
        assert!(
            store
                .issue(
                    &request(Kind::IntentResend, &account, &resend, None),
                    0,
                    &mut source
                )
                .is_err()
        );
    }

    /// A page kind is refused for another origin, frame, navigation and
    /// handle; a site's `safe-send` refused as a wallet one, and a wallet's
    /// as a site's.
    #[test]
    fn a_page_token_is_for_its_page() {
        let account = json!(7);
        let safe_send = json!({
            "safe": "0x".to_owned() + &"5a".repeat(20),
            "chain_id": "100",
            "tx": { "to": "0x".to_owned() + &"33".repeat(20), "value": "5", "data": "0x" },
        });
        let page = page();
        let others = [
            Page {
                origin: "https://other.example".into(),
                ..page.clone()
            },
            Page {
                frame: 2,
                ..page.clone()
            },
            Page {
                navigation: 2,
                ..page.clone()
            },
            Page {
                handle: Handle::from_bytes([0xb2; 32]),
                ..page.clone()
            },
        ];
        let mut source = rng();
        for other in &others {
            let mut store = Tokens::new(LIMITS);
            let minted = store
                .issue(
                    &request(Kind::SafeSend, &account, &safe_send, Some(&page)),
                    0,
                    &mut source,
                )
                .unwrap();
            let refused = store.spend(
                &minted.token.to_text(),
                &request(Kind::SafeSend, &account, &safe_send, Some(other)),
                0,
            );
            assert_eq!(refused.unwrap_err(), Refusal::Mismatch, "{other:?}");
            assert_eq!(store.outstanding(), 0);
        }
        let mut store = Tokens::new(LIMITS);
        let site = store
            .issue(
                &request(Kind::SafeSend, &account, &safe_send, Some(&page)),
                0,
                &mut source,
            )
            .unwrap();
        let wallet = store
            .issue(
                &request(Kind::SafeSend, &account, &safe_send, None),
                0,
                &mut source,
            )
            .unwrap();
        assert_eq!(
            store
                .spend(
                    &site.token.to_text(),
                    &request(Kind::SafeSend, &account, &safe_send, None),
                    0
                )
                .unwrap_err(),
            Refusal::Mismatch
        );
        assert_eq!(
            store
                .spend(
                    &wallet.token.to_text(),
                    &request(Kind::SafeSend, &account, &safe_send, Some(&page)),
                    0
                )
                .unwrap_err(),
            Refusal::Mismatch
        );
        // The Safe's address is bound beside its index.
        let mut other_safe = safe_send.clone();
        other_safe["safe"] = json!("0x".to_owned() + &"5b".repeat(20));
        let minted = store
            .issue(
                &request(Kind::SafeSend, &account, &safe_send, None),
                0,
                &mut source,
            )
            .unwrap();
        assert_eq!(
            store
                .spend(
                    &minted.token.to_text(),
                    &request(Kind::SafeSend, &account, &other_safe, None),
                    0
                )
                .unwrap_err(),
            Refusal::Mismatch
        );
    }

    #[test]
    fn the_nonce_is_bound_only_by_a_replacement() {
        let account = json!(0);
        let confirmed = json!({ "tx": tx() });
        let mut with_nonce = tx();
        with_nonce["nonce"] = json!("41");
        let signed = json!({ "tx": with_nonce });
        let mut store = Tokens::new(LIMITS);
        let mut source = rng();
        // Main chooses the nonce after the confirmation.
        let minted = store
            .issue(
                &request(Kind::WalletSend, &account, &confirmed, None),
                0,
                &mut source,
            )
            .unwrap();
        assert!(
            store
                .spend(
                    &minted.token.to_text(),
                    &request(Kind::WalletSend, &account, &signed, None),
                    0
                )
                .is_ok()
        );
        // A malformed nonce is refused, bound or not.
        let mut bad = tx();
        bad["nonce"] = json!("0x");
        assert!(
            store
                .issue(
                    &request(Kind::WalletSend, &account, &json!({ "tx": bad }), None),
                    0,
                    &mut source
                )
                .is_err()
        );
        let replace = |nonce: &str| {
            let mut tx = tx();
            tx["nonce"] = json!(nonce);
            json!({
                "intent_id": "7b0c6c1e-0c62-4a6e-9a49-0d6a3f6d1a07",
                "sender": "0x".to_owned() + &"ab".repeat(20),
                "tx": tx,
            })
        };
        let (seven, eight) = (replace("7"), replace("8"));
        let minted = store
            .issue(
                &request(Kind::IntentReplace, &ACCOUNT, &seven, None),
                0,
                &mut source,
            )
            .unwrap();
        assert_eq!(
            store
                .spend(
                    &minted.token.to_text(),
                    &request(Kind::IntentReplace, &ACCOUNT, &eight, None),
                    0
                )
                .unwrap_err(),
            Refusal::Mismatch
        );
        assert!(
            store
                .issue(
                    &request(
                        Kind::IntentReplace,
                        &ACCOUNT,
                        &json!({
                            "intent_id": "7b0c6c1e-0c62-4a6e-9a49-0d6a3f6d1a07",
                            "sender": "0x".to_owned() + &"ab".repeat(20),
                            "tx": tx(),
                        }),
                        None
                    ),
                    0,
                    &mut source
                )
                .is_err()
        );
    }

    fn mail() -> Value {
        json!({
            "domain": { "name": "Ether Mail", "version": "1", "chainId": 1 },
            "types": { "Mail": [{ "name": "contents", "type": "string" }] },
            "message": { "contents": "Hello" },
        })
    }

    #[test]
    fn typed_data_binds_its_chain_by_value_and_refuses_a_view_too_long() {
        let account = json!(0);
        let page = page();
        let one = |chain: &str| json!({ "typed_data": mail(), "primary_type": "Mail", "chain_id": chain });
        let (decimal, hex, other) = (one("1"), one("0x1"), one("2"));
        let mut store = Tokens::new(LIMITS);
        let mut source = rng();
        let minted = store
            .issue(
                &request(Kind::SignTypedData, &account, &decimal, Some(&page)),
                0,
                &mut source,
            )
            .unwrap();
        let typed = minted.typed_data.clone().unwrap();
        assert!(typed.view.contains(r#""chain":"match""#), "{}", typed.view);
        let spent = store
            .spend(
                &minted.token.to_text(),
                &request(Kind::SignTypedData, &account, &hex, Some(&page)),
                0,
            )
            .unwrap();
        assert_eq!(spent.typed_data, Some(typed.clone()));
        // Another chain: the same hash, another view.
        let minted = store
            .issue(
                &request(Kind::SignTypedData, &account, &decimal, Some(&page)),
                0,
                &mut source,
            )
            .unwrap();
        assert_eq!(
            store
                .spend(
                    &minted.token.to_text(),
                    &request(Kind::SignTypedData, &account, &other, Some(&page)),
                    0
                )
                .unwrap_err(),
            Refusal::Mismatch
        );
        // A view the core couldn't reply with gets no token.
        let mut short = Tokens::new(Limits {
            max_view_len: typed.view.len() - 1,
        });
        assert!(
            short
                .issue(
                    &request(Kind::SignTypedData, &account, &decimal, Some(&page)),
                    0,
                    &mut source
                )
                .is_err()
        );
        let mut exact = Tokens::new(Limits {
            max_view_len: typed.view.len(),
        });
        assert!(
            exact
                .issue(
                    &request(Kind::SignTypedData, &account, &decimal, Some(&page)),
                    0,
                    &mut source
                )
                .is_ok()
        );
    }

    /// A presented token is decoded into the caller's buffer, which
    /// `presented` holds in a `Zeroizing` and so wipes on return: the decoder
    /// returns no copy, and writes nothing for text that isn't a token.
    #[test]
    fn a_presented_token_is_decoded_in_place() {
        let mut buffer = Zeroizing::new([0x55u8; 32]);
        for bad in [
            "",
            "AB",
            &"0a".repeat(31),
            &"0A".repeat(32),
            &format!("0x{}", "0a".repeat(31)),
        ] {
            assert!(!lower_hex_32(bad, &mut buffer), "{bad}");
            assert_eq!(*buffer, [0x55; 32]);
        }
        let text: String = (0..32u8).map(|i| format!("{i:02x}")).collect();
        assert!(lower_hex_32(&text, &mut buffer));
        assert_eq!(*buffer, core::array::from_fn::<u8, 32, _>(|i| i as u8));
    }

    #[test]
    fn handles_are_64_lowercase_hex_digits() {
        let text = "a1".repeat(32);
        assert_eq!(Handle::parse(&text).unwrap().to_text(), text);
        for bad in [
            "A1".repeat(32),
            "a1".repeat(31),
            format!("0x{}", "a1".repeat(31)),
            "g1".repeat(32),
        ] {
            assert!(Handle::parse(&bad).is_err(), "{bad}");
        }
    }
}
