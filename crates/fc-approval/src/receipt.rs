//! Finalize receipts (design 0012, "A device send's rule"; freedom-core
//! #373): what a flagged `dapp-send` spent for a device account gives, so
//! that the rule its "Always allow" asked for is written only once main
//! presents the receipt, after the device signed and main recorded the send.
//! A Ledger or a phone signs outside the core, after the token was spent: a
//! rule written at the spend would stand for a send the device then refused.
//!
//! - **Recorded** at the token's spend under `page` ([`Receipts::record`]),
//!   with the document it was spent under (`PageContext`'s origin, frame and
//!   navigation), the account, and the rule `sign.transaction` would write
//!   for the same send ([`ProposedRule::of`]): `to`, the selector, the chain
//!   and `value`.
//! - **An id** of 16 random bytes, sent as 32 lowercase hex digits: never
//!   in `Debug` output, wiped when it goes, and compared in constant time
//!   against every open receipt.
//! - **One use:** taken at its first presentation, whatever the outcome
//!   ([`Receipts::take`]). One presented by another document, or after its
//!   life, is gone as well: it fails closed.
//! - **Life:** [`RECEIPT_TTL_MS`] of the vault's clock, which the caller
//!   passes as `now_ms`; expired at exactly its end (`expires_at <= now`),
//!   as a token is.
//! - **Count:** at most [`MAX_RECEIPTS`]; recording drops the expired, then
//!   the oldest, to make room.
//! - **Forgotten** for a key whose dApp grant narrows, and for an account
//!   that is deleted ([`Receipts::forget_key`], [`Receipts::forget_account`]):
//!   a narrowing after the spend wins over the decision before it.
//! - **In memory only:** a restart forgets every one.

use std::fmt;

use fc_evm::{Transaction, U256};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::safe::{constant_time_eq, lower_hex_16, text_16};

/// Ten minutes: twice a phone job's five (`bridge.js`'s
/// `DEFAULT_TIMEOUT_MS`, design 0012's phone job), so that a job answered
/// at its last moment still leaves main five minutes to record the send,
/// a broadcast's chain session (120 s) included, before it presents the
/// receipt. A Ledger's confirmation is the user's at the device, as a
/// phone's is, and fits the same.
pub const RECEIPT_TTL_MS: u64 = 10 * 60 * 1000;

/// How many receipts are open at once; the oldest is dropped. Twice the
/// tokens outstanding ([`crate::MAX_OUTSTANDING`]): every token minted can
/// be spent into a receipt while as many again wait for their devices, and
/// a Safe approval's count is the same.
pub const MAX_RECEIPTS: usize = 64;

/// A receipt's id.
pub struct ReceiptId(Zeroizing<[u8; 16]>);

impl ReceiptId {
    /// The id's text, for the reply that carries it to its caller.
    pub fn to_text(&self) -> Zeroizing<String> {
        text_16(&self.0)
    }
}

impl fmt::Debug for ReceiptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiptId(..)")
    }
}

/// The document a receipt was given to, and the only one that presents it:
/// `PageContext`'s origin (the permission key), frame and navigation, the
/// facts of the page a token binds but its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub origin: String,
    pub frame: u64,
    pub navigation: u64,
}

/// The transaction rule a flagged `dapp-send` asks for: the call's `to`,
/// the first four bytes of its `data`, its chain and its `value`, each as
/// the transaction has it. One without a `to`, a selector or a chain the
/// rules take writes no rule (`no_rule`), as at `sign.transaction`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProposedRule {
    pub to: Option<[u8; 20]>,
    pub selector: Option<[u8; 4]>,
    pub chain_id: Option<u64>,
    pub value: U256,
}

impl ProposedRule {
    /// The rule for `tx`, worked out as `sign.transaction` works it out.
    pub fn of(tx: &Transaction) -> ProposedRule {
        ProposedRule {
            to: tx.to().copied(),
            selector: tx.data().first_chunk::<4>().copied(),
            chain_id: tx.chain_id().to_u64(),
            value: *tx.value(),
        }
    }
}

/// What a receipt binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub document: Document,
    /// The account the token was minted for.
    pub account: u32,
    pub rule: ProposedRule,
}

/// Why a presented receipt writes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptRefusal {
    /// Never given, already presented, forgotten, dropped by the cap, or
    /// pruned after its expiry (`unknown_token`).
    #[error("unknown or already used receipt")]
    Unknown,
    /// Presented at or after the end of its life (`expired`).
    #[error("receipt expired")]
    Expired,
    /// Presented by another origin, frame or navigation (`mismatch`).
    #[error("the receipt is another document's")]
    Mismatch,
}

struct Entry {
    id: Zeroizing<[u8; 16]>,
    receipt: Receipt,
    expires_at_ms: u64,
}

/// The open receipts, oldest first.
pub struct Receipts {
    entries: Vec<Entry>,
    ttl_ms: u64,
}

impl fmt::Debug for Receipts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receipts")
            .field("open", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Default for Receipts {
    fn default() -> Self {
        Self::new()
    }
}

impl Receipts {
    /// Receipts that live [`RECEIPT_TTL_MS`].
    pub fn new() -> Self {
        Self::with_ttl(RECEIPT_TTL_MS)
    }

    /// Receipts that live `ttl_ms`: for a test of their expiry over the
    /// wire, which has no clock to inject.
    pub fn with_ttl(ttl_ms: u64) -> Self {
        Receipts {
            entries: Vec::new(),
            ttl_ms,
        }
    }

    /// How many are open, expired ones not yet pruned included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records a receipt at `now_ms` and returns its id. Past
    /// [`MAX_RECEIPTS`] the oldest is dropped. A failed RNG records nothing
    /// and drops nothing.
    pub fn record<R: TryCryptoRng + ?Sized>(
        &mut self,
        receipt: Receipt,
        now_ms: u64,
        rng: &mut R,
    ) -> Result<ReceiptId, Error> {
        let mut id = Zeroizing::new([0u8; 16]);
        rng.try_fill_bytes(&mut id[..])
            .map_err(|_| Error::Randomness)?;
        self.entries.retain(|entry| entry.expires_at_ms > now_ms);
        // An id is one entry: drawn again, it replaces the old one.
        if let Some(index) = self.position(&id) {
            self.entries.remove(index);
        }
        while self.entries.len() >= MAX_RECEIPTS {
            self.entries.remove(0);
        }
        self.entries.push(Entry {
            id: id.clone(),
            receipt,
            expires_at_ms: now_ms.saturating_add(self.ttl_ms),
        });
        Ok(ReceiptId(id))
    }

    /// Takes the receipt `id` names, presented by `presenter` at `now_ms`.
    /// It is gone after this whatever the outcome: one expired, or presented
    /// by another document, is consumed too.
    pub fn take(
        &mut self,
        id: &str,
        presenter: &Document,
        now_ms: u64,
    ) -> Result<Receipt, ReceiptRefusal> {
        let entry = self
            .presented(id)
            .map(|index| self.entries.remove(index))
            .ok_or(ReceiptRefusal::Unknown)?;
        if entry.expires_at_ms <= now_ms {
            return Err(ReceiptRefusal::Expired);
        }
        if entry.receipt.document != *presenter {
            return Err(ReceiptRefusal::Mismatch);
        }
        Ok(entry.receipt)
    }

    /// Drops the receipt `id` names, if open: for a request that presented
    /// it and ended before [`Receipts::take`] (a malformed one).
    pub fn discard(&mut self, id: &str) {
        if let Some(index) = self.presented(id) {
            self.entries.remove(index);
        }
    }

    /// Drops every receipt given to a document of `key`: its dApp grant
    /// narrowed (a disconnect, a rule turned off).
    pub fn forget_key(&mut self, key: &str) {
        self.entries
            .retain(|entry| entry.receipt.document.origin != key);
    }

    /// Drops every receipt for `account`: the account was deleted.
    pub fn forget_account(&mut self, account: u32) {
        self.entries
            .retain(|entry| entry.receipt.account != account);
    }

    fn presented(&self, id: &str) -> Option<usize> {
        let mut bytes = Zeroizing::new([0u8; 16]);
        if !lower_hex_16(id, &mut bytes) {
            return None;
        }
        self.position(&bytes)
    }

    fn position(&self, id: &[u8; 16]) -> Option<usize> {
        let mut found = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if constant_time_eq(&entry.id, id) && found.is_none() {
                found = Some(index);
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use serde_json::json;

    struct Counter(u8);

    #[derive(Debug)]
    struct Never;

    impl fmt::Display for Never {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("never")
        }
    }

    impl std::error::Error for Never {}

    impl rand_core::TryRng for Counter {
        type Error = Never;

        fn try_next_u32(&mut self) -> Result<u32, Never> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Never> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Never> {
            self.0 = self.0.wrapping_add(1);
            dst.fill(self.0);
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Counter {}

    /// An RNG that always fails.
    struct Broken;

    impl rand_core::TryRng for Broken {
        type Error = Never;

        fn try_next_u32(&mut self) -> Result<u32, Never> {
            Err(Never)
        }

        fn try_next_u64(&mut self) -> Result<u64, Never> {
            Err(Never)
        }

        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Never> {
            Err(Never)
        }
    }

    impl rand_core::TryCryptoRng for Broken {}

    const TO: [u8; 20] = [0x83; 20];

    fn document(origin: &str, frame: u64, navigation: u64) -> Document {
        Document {
            origin: origin.into(),
            frame,
            navigation,
        }
    }

    fn site() -> Document {
        document("https://app.example", 1, 1)
    }

    fn receipt(account: u32) -> Receipt {
        Receipt {
            document: site(),
            account,
            rule: ProposedRule {
                to: Some(TO),
                selector: Some([0x09, 0x5e, 0xa7, 0xb3]),
                chain_id: Some(100),
                value: U256::from_u64(3),
            },
        }
    }

    #[test]
    fn a_receipt_is_taken_once_by_its_document() {
        let mut receipts = Receipts::new();
        let mut rng = Counter(0);
        let id = receipts.record(receipt(0), 1_000, &mut rng).unwrap();
        let text = id.to_text();
        assert_eq!(text.len(), 32);
        assert_eq!(format!("{id:?}"), "ReceiptId(..)");
        assert_eq!(format!("{receipts:?}"), "Receipts { open: 1, .. }");
        assert_eq!(receipts.take(&text, &site(), 1_001), Ok(receipt(0)));
        // Presented twice: gone.
        assert_eq!(
            receipts.take(&text, &site(), 1_002),
            Err(ReceiptRefusal::Unknown)
        );
        assert!(receipts.is_empty());
        // Never given, or not an id at all.
        for unknown in ["", "not an id", &"0".repeat(32), &text.to_uppercase()] {
            assert_eq!(
                receipts.take(unknown, &site(), 1_002),
                Err(ReceiptRefusal::Unknown),
                "{unknown}"
            );
        }
    }

    #[test]
    fn another_document_consumes_it() {
        for other in [
            document("https://other.example", 1, 1),
            document("https://app.example", 2, 1),
            document("https://app.example", 1, 2),
        ] {
            let mut receipts = Receipts::new();
            let text = receipts
                .record(receipt(0), 0, &mut Counter(0))
                .unwrap()
                .to_text();
            assert_eq!(
                receipts.take(&text, &other, 1),
                Err(ReceiptRefusal::Mismatch),
                "{other:?}"
            );
            // Fails closed: not left for its own document either.
            assert_eq!(
                receipts.take(&text, &site(), 1),
                Err(ReceiptRefusal::Unknown)
            );
        }
    }

    #[test]
    fn a_receipt_expires_at_exactly_its_end() {
        let mut rng = Counter(0);
        let mut receipts = Receipts::new();
        let live = receipts.record(receipt(0), 5_000, &mut rng).unwrap();
        assert_eq!(
            receipts.take(&live.to_text(), &site(), 5_000 + RECEIPT_TTL_MS - 1),
            Ok(receipt(0))
        );
        let dead = receipts.record(receipt(0), 5_000, &mut rng).unwrap();
        assert_eq!(
            receipts.take(&dead.to_text(), &site(), 5_000 + RECEIPT_TTL_MS),
            Err(ReceiptRefusal::Expired)
        );
        // Consumed as well.
        assert_eq!(
            receipts.take(&dead.to_text(), &site(), 5_000),
            Err(ReceiptRefusal::Unknown)
        );
        // A shorter life, and the expired pruned at the next record.
        let mut short = Receipts::with_ttl(10);
        let old = short.record(receipt(0), 0, &mut rng).unwrap();
        short.record(receipt(1), 10, &mut rng).unwrap();
        assert_eq!(short.len(), 1);
        assert_eq!(
            short.take(&old.to_text(), &site(), 10),
            Err(ReceiptRefusal::Unknown)
        );
    }

    #[test]
    fn at_most_64_are_kept_the_oldest_dropped() {
        let mut rng = Counter(0);
        let mut receipts = Receipts::new();
        let first = receipts.record(receipt(0), 0, &mut rng).unwrap();
        let second = receipts.record(receipt(0), 0, &mut rng).unwrap();
        for _ in 0..MAX_RECEIPTS - 1 {
            receipts.record(receipt(0), 0, &mut rng).unwrap();
        }
        assert_eq!(receipts.len(), MAX_RECEIPTS);
        assert_eq!(
            receipts.take(&first.to_text(), &site(), 0),
            Err(ReceiptRefusal::Unknown)
        );
        assert_eq!(receipts.take(&second.to_text(), &site(), 0), Ok(receipt(0)));
        // A failed RNG records nothing and drops nothing.
        let before = receipts.len();
        assert_eq!(
            receipts.record(receipt(0), 0, &mut Broken).map(|_| ()),
            Err(Error::Randomness)
        );
        assert_eq!(receipts.len(), before);
    }

    #[test]
    fn a_narrowing_forgets_its_receipts() {
        let mut rng = Counter(0);
        let mut receipts = Receipts::new();
        let ours = receipts.record(receipt(0), 0, &mut rng).unwrap();
        let mut theirs = receipt(0);
        theirs.document = document("https://other.example", 1, 1);
        let other = receipts.record(theirs.clone(), 0, &mut rng).unwrap();
        let account = receipts.record(receipt(4), 0, &mut rng).unwrap();
        receipts.forget_key("https://app.example");
        assert_eq!(
            receipts.take(&ours.to_text(), &site(), 0),
            Err(ReceiptRefusal::Unknown)
        );
        assert_eq!(
            receipts.take(&account.to_text(), &site(), 0),
            Err(ReceiptRefusal::Unknown)
        );
        let again = receipts.record(receipt(4), 0, &mut rng).unwrap();
        receipts.forget_account(4);
        assert_eq!(
            receipts.take(&again.to_text(), &site(), 0),
            Err(ReceiptRefusal::Unknown)
        );
        assert_eq!(
            receipts.take(&other.to_text(), &theirs.document, 0),
            Ok(theirs)
        );
        // A malformed request's receipt is discarded unread.
        let dropped = receipts.record(receipt(0), 0, &mut rng).unwrap();
        receipts.discard(&dropped.to_text());
        assert!(receipts.is_empty());
    }

    #[test]
    fn the_rule_is_the_one_sign_transaction_works_out() {
        let tx = |data: &str, to: Option<&str>| {
            let mut tx = json!({
                "type": 2, "chain_id": "100", "nonce": "7", "gas_limit": "60000",
                "value": "3", "data": data,
                "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000000",
            });
            // A deployment's `to` is null.
            tx["to"] = json!(to);
            Transaction::from_json(&tx).unwrap()
        };
        let to = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
        let rule = ProposedRule::of(&tx("0x095ea7b300", Some(to)));
        assert_eq!(rule.selector, Some([0x09, 0x5e, 0xa7, 0xb3]));
        assert_eq!(rule.chain_id, Some(100));
        assert_eq!(rule.value, U256::from_u64(3));
        assert_eq!(rule.to.map(|to| fc_evm::to_hex(&to)), Some(to.to_owned()));
        // A plain transfer, and a deployment, name no rule.
        assert_eq!(ProposedRule::of(&tx("0x", Some(to))).selector, None);
        assert_eq!(ProposedRule::of(&tx("0x095ea7b3", None)).to, None);
    }
}
