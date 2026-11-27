//! x402 payments in the daemon (design 0012, "x402"; X402-1, core #392):
//! the caps in `x402-permissions.json`, the `x402-payment` token, and the
//! authorization the core builds and signs itself, or hands a device.
//!
//! - `x402.authorize { account, device?, detection: { tab, id, url },
//!   requirements, accept_index?, grant?, authorization }` (`shell`): the
//!   paid URL's origin is the cap's key (Q11). With `{ token }`, an
//!   `x402-payment` token pays exactly the entry (`accept_index`) and the
//!   grant it binds; with `{ cap: { agent, attributable } }`, the first
//!   entry an active cap covers is paid (`findCoveringPermission`), never
//!   for a tab in Agent custody or a request main couldn't attribute. The
//!   core builds the payload as `@x402/evm` 2.28.0 builds it, and 2.29.0
//!   alike (`fc_approval::x402`, design 0016's D10), with a nonce from the
//!   OS's RNG and `validBefore` from the wall clock, and signs it inline.
//!   **A cap is charged before the signature,** written first: a charge the
//!   file lacks signs nothing (`x402-at-sign`). A token's payment writes its
//!   grant after the signature, then charges a cap that covers it, as
//!   `sign-flow.js` does.
//!   The reply is `{ payload, reservation, accept_index, charged, grant? }`:
//!   `payload` the JSON main base64-encodes into the header.
//! - **A device account** (core #392): `device: { kind, address }`, `kind`
//!   `ledger` or `phone`, `address` the account's. While main owns
//!   `vault-meta.json` that is main's word, as `phone.job`'s is. Once
//!   `vault_meta` is moved (G20) the account's record names the device, as
//!   the reference's `paymentDevice` reads it: a vault account pays with no
//!   `device`, a Ledger's or a phone's with its kind and its record's
//!   address (each in any form ethers' `isAddress` takes, agreeing when
//!   `getAddress` gives both the same), and a Safe, or an account the core
//!   can't name, pays nothing. A request that disagrees is refused
//!   (`invalid_argument`) before any token is spent or cap charged, and so
//!   is an address past 20 bytes (an ICAP past 2^160), which no
//!   authorization can name. The token is checked, or the cap
//!   charged, as for the vault, and no key is used: the reply is `{
//!   device: { typed_data, hash }, reservation, accept_index, charged }`,
//!   the typed data the client would hand its signer, and its EIP-712
//!   hash. A token's grant and charge wait for the device's signature.
//! - **A Ledger account's payment, on the device lane** (design 0016, "x402
//!   from a Ledger account", D2): `now_s`, main's wall-clock reading in
//!   whole seconds, taken once for the payment, comes only with `device: {
//!   kind: "ledger" }`, and only once `vault_meta` is moved: the account's
//!   own Ledger record ([`Approvals::ledger_account`], D9), whose address
//!   the device's must be. A `now_s` more than 30 s from the core's clock
//!   ([`MAX_CLOCK_SKEW_S`]) is refused. Each is refused before any token is
//!   spent or cap charged. The authorization is then built on `now_s`, so
//!   every time byte in it is main's, with the nonce the core drew, and
//!   handed out and kept as a device's is; the cap's window stays the
//!   core's clock.
//! - **A Ledger payment's charge is held, not written** (D2, as L5's review
//!   decided it): under a cap, `x402.authorize` writes nothing. It holds
//!   the charge in memory, and every check of a cap (a cover, a charge,
//!   another hold) counts the open holds as spent, so open payments can't
//!   together pass the cap. The charge is written only once fc-ledger has
//!   checked the device's signature, and before the signature leaves the
//!   core; a charge the file lacks releases nothing (`x402-at-sign`). So a
//!   crash between that write and the reply charges once with nothing
//!   paid, the safe way round, and a restart before it leaves nothing
//!   charged and nothing to give back. Every other way through, the vault
//!   key's inline signature and #392's device payment, writes the charge
//!   before anything is signed or handed out, as before.
//! - `x402.settle { reservation, typed_data }` (`shell`, D2): main's own
//!   rebuild of that authorization, `{ domain, types, primaryType, message
//!   }`, which must equal the reserved one as JSON values (the same members
//!   and values, arrays in order, members in any order). The core then
//!   signs the reserved authorization on the device lane with the record's
//!   path, as `sign.typed_data` with a Ledger key does, and fc-ledger
//!   checks the signature against the record's address over the reserved
//!   digest. Taken, the reply is `{ signature }`'s, `{ payload, charged,
//!   grant?, durable? }`, and the reservation waits for its outcome.
//!   Anything else ends the payment, with nothing of a signature returned:
//!   another authorization (`not_authorized`, `mismatch`), a record that no
//!   longer is the account's, what a Ledger can't carry, the device's
//!   refusal or failure (`device_failed`), the request's cancel, or a held
//!   charge that can't be written (its cap revoked, granted again or
//!   narrowed, or the write failed). Each drops the held charge with
//!   nothing written and spends the reservation, and says in the error's
//!   `refunded` whether its room is back on its cap, as a refused `{
//!   signature }` says it of a charge given back (a cancel's error carries
//!   no data). While the device signs, the reservation is the
//!   operation's alone: no other settle finds it, and none is dropped for
//!   room. A Ledger's reservation made with `now_s` is settled only so (or
//!   `withheld`), and one made without, as a phone's, only with `{
//!   signature }`.
//! - `x402.settle { reservation, outcome }` (`shell`): `withheld` gives the
//!   charge back to the cap it was taken from, if that cap still stands
//!   (not revoked, not granted again: its generation); `sent` keeps it.
//!   Either way the reservation is spent. A device's reservation is `sent`
//!   only once its signature is checked. A cap's payment is `sent` only
//!   while its cap stands: one revoked, or revoked and granted again, since
//!   its charge is refused (`cap_changed`), and main withholds it.
//! - `x402.settle { reservation, signature }` (`shell`, core #392): the
//!   device's signature, checked as PHN-1 checks a phone's: it must recover
//!   to the address over the hash. Then the reply is `{ payload, charged,
//!   grant?, durable? }`, the payload with the device's text in it, a
//!   token's grant written and its cap charged; the reservation waits for
//!   its outcome. Otherwise it is refused (`wrong_account`,
//!   `bad_response`), its charge given back and the reservation spent.
//! - `x402.update { key, cap: { chain_id, asset }, cap_amount?,
//!   window_seconds? }` (`chrome`, `shell`; core #392): a narrowing only.
//!   Each field given must lower the amount or end the window sooner;
//!   anything else is `forbidden`, and nothing is written.
//! - Each answers `not_moved` until `x402` is in `grant_moved`, and changes
//!   nothing: main still writes the file.
//!
//! Each change sends one `approval.changed { store: "x402", key }`.

use std::collections::{BTreeMap, HashMap, VecDeque};

use fc_approval::stores::{Applied, CapStore, Charge, Effect, NarrowRefusal, StoreKind};
use fc_approval::x402::{self, Built, Payment, Requirements};
use fc_evm::U256;
use fc_keys::Secp256k1Key;
use fc_ledger::Operation;
use fc_protocol::error::ErrorCode;
use fc_vault::state::VaultState;
use rand_core::TryRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    Account, Approvals, Clocks, ErrorBody, Kind, Minter, Request, cap_asset_key, forbidden,
    invalid, js_json, json_reply, not_authorized, not_moved, object, refusal, secret_reply, string,
};
use crate::rng::OsRng;

/// The methods this module serves.
pub const METHODS: [&str; 3] = ["x402.authorize", "x402.settle", "x402.update"];

/// How far main's `now_s` may be from the core's own clock, in seconds
/// (design 0016, "x402 from a Ledger account"): 30 s is taken, 31 s
/// refused.
pub const MAX_CLOCK_SKEW_S: u64 = 30;

/// Reservations kept for `x402.settle`, the oldest dropped: a dropped
/// one's charge stands (*inferred*: as a Safe approval's count).
pub const MAX_RESERVATIONS: usize = 64;

/// The largest payload a device's reservation holds until its signature
/// comes (*inferred*): one frame's. A real one is a few kilobytes, as it
/// goes into an HTTP header.
pub const MAX_DEVICE_PAYLOAD: usize = fc_protocol::frame::MAX_PAYLOAD;

/// The longest narrowed window, in seconds: JS adds it to `createdAt` as a
/// double.
const MAX_WINDOW_SECONDS: u64 = (1 << 53) - 1;

/// A charge a reservation holds, and the generation of the cap it was taken
/// from.
#[derive(Debug)]
struct Held {
    charge: Charge,
    generation: u64,
}

/// A Ledger payment's charge under a cap (design 0016, D2, as LDG-2's L5
/// builds it): held in memory and never written until fc-ledger has
/// checked the device's signature, then written before the signature is
/// released. Until then it counts against its cap in every check
/// ([`X402State::held`]), so open payments can't together pass the cap; a
/// restart drops it with nothing written, so nothing is left to give back.
#[derive(Debug, Clone)]
struct Hold {
    origin: String,
    key: String,
    /// The amount as the entry writes it.
    amount: String,
    generation: u64,
    /// The core's clock, in seconds, when it was held: the cap's window is
    /// read at it when the charge is written, as a charge at the
    /// authorization's turn would have been.
    at_s: u64,
}

/// What a reservation holds: its charge, and a device's payment until its
/// signature is checked.
struct Reservation {
    held: Option<Held>,
    /// A Ledger payment's charge, held and not written ([`Hold`]): the
    /// hold's number in [`X402State`].
    hold: Option<u64>,
    /// Paid under a cap (`{ cap }`): its charge is what let it be paid, so
    /// it is `sent` only while that cap stands (`cap_changed`).
    by_cap: bool,
    device: Option<Box<Device>>,
}

/// A device's payment, waiting for its signature (core #392): the
/// authorization built for its address, and what follows the signature.
struct Device {
    built: Built,
    address: [u8; 20],
    origin: String,
    tuple: Option<x402::Tuple>,
    /// A token's payment: its grant as bound (or none), written once the
    /// signature is checked, before the cap that covers it is charged. A
    /// cap's payment is charged already.
    token_grant: Option<Option<Value>>,
    /// How its signature comes.
    form: Form,
}

/// How a device's payment is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// `{ reservation, signature }` (core #392): a phone's, or a Ledger's
    /// made without `now_s`, whose authorization is on the core's clock.
    Signature,
    /// `{ reservation, typed_data }` (design 0016, D2): a Ledger account's
    /// made with main's `now_s`, signed on the device lane with account
    /// `account`'s record.
    Ledger { account: u32 },
}

/// What `x402.*` gives the event loop: its reply now, or a Ledger payment's
/// operation for the device lane (design 0016, D2).
pub enum X402Reply {
    Now(Zeroizing<Vec<u8>>),
    Device(Box<LedgerPayment>),
}

/// A Ledger payment's signature, authorized, for the device lane:
/// fc-ledger's operation over the reserved authorization, and the payment,
/// which [`Approvals::x402_ledger_ended`] finishes once the device ends.
pub struct LedgerPayment {
    pub operation: Operation,
    pub settling: Settling,
}

/// A Ledger payment on the device lane: its reservation, taken from the
/// kept ones while the device signs, so that no other settle reaches it
/// and none is dropped for room.
pub struct Settling {
    id: Zeroizing<String>,
    reservation: Reservation,
}

/// Nothing of it: the reservation's ID is the payment's handle, and its
/// authorization request data.
impl std::fmt::Debug for Settling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settling").finish_non_exhaustive()
    }
}

/// What the daemon keeps beside the cap file: each cap's generation, which
/// tells a cap from one granted again under the same key (within one
/// second, its `createdAt` is the same), and the reservations.
#[derive(Default)]
pub(super) struct X402State {
    reservations: VecDeque<(Zeroizing<String>, Reservation)>,
    generations: HashMap<(String, String), u64>,
    last_generation: u64,
    /// The Ledger payments' charges held and not written, by number: a
    /// reservation's on the device lane among them.
    holds: BTreeMap<u64, Hold>,
    last_hold: u64,
}

impl std::fmt::Debug for X402State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402State")
            .field("reservations", &self.reservations.len())
            .finish_non_exhaustive()
    }
}

impl X402State {
    /// Every cap read from the file is a cap of its own.
    pub(super) fn loaded(&mut self, store: &CapStore) {
        self.generations.clear();
        let caps: Vec<(String, String)> = store
            .caps()
            .map(|(origin, key, _)| (origin.to_owned(), key.to_owned()))
            .collect();
        for (origin, key) in caps {
            self.granted(&origin, &key);
        }
    }

    fn granted(&mut self, origin: &str, key: &str) -> u64 {
        self.last_generation += 1;
        self.generations
            .insert((origin.to_owned(), key.to_owned()), self.last_generation);
        self.last_generation
    }

    fn generation(&self, origin: &str, key: &str) -> Option<u64> {
        self.generations
            .get(&(origin.to_owned(), key.to_owned()))
            .copied()
    }

    pub(super) fn revoked(&mut self, origin: &str, key: Option<&str>) {
        self.generations
            .retain(|(o, k), _| o != origin || key.is_some_and(|key| key != k));
    }

    fn reserve(&mut self, reservation: Reservation) -> Result<Zeroizing<String>, ErrorBody> {
        let mut bytes = Zeroizing::new([0u8; 16]);
        OsRng
            .try_fill_bytes(&mut *bytes)
            .map_err(|_| crate::vault::internal())?;
        let id = Zeroizing::new(fc_evm::to_hex(&*bytes)[2..].to_owned());
        self.keep(id.clone(), reservation);
        Ok(id)
    }

    /// Keeps reservation `id`, the newest, dropping the oldest for room: a
    /// dropped one's written charge stands, and its held one goes.
    fn keep(&mut self, id: Zeroizing<String>, reservation: Reservation) {
        if self.reservations.len() == MAX_RESERVATIONS
            && let Some((_, dropped)) = self.reservations.pop_front()
        {
            self.release(dropped.hold);
        }
        self.reservations.push_back((id, reservation));
    }

    /// A Ledger payment's charge held: its number.
    fn hold(&mut self, hold: Hold) -> u64 {
        self.last_hold += 1;
        self.holds.insert(self.last_hold, hold);
        self.last_hold
    }

    /// Hold `id` released: nothing counts it any more.
    fn release(&mut self, id: Option<u64>) -> Option<Hold> {
        id.and_then(|id| self.holds.remove(&id))
    }

    /// What the open holds take of the cap under `origin` and `key` as it
    /// stands: those held against it, not against one revoked or granted
    /// again since, whose charges are never written.
    fn held(&self, origin: &str, key: &str) -> U256 {
        let Some(generation) = self.generation(origin, key) else {
            return U256::ZERO;
        };
        self.holds
            .values()
            .filter(|hold| hold.origin == origin && hold.key == key)
            .filter(|hold| hold.generation == generation)
            .filter_map(|hold| x402::atomic(&hold.amount))
            .fold(U256::ZERO, |sum, amount| {
                sum.checked_add(&amount).unwrap_or(U256::MAX)
            })
    }

    /// Whether the cap a hold was taken against still stands.
    fn stands(&self, hold: &Hold) -> bool {
        self.generation(&hold.origin, &hold.key) == Some(hold.generation)
    }

    /// How the device's payment at `at` is settled, if one waits there.
    fn form(&self, at: usize) -> Option<Form> {
        self.reservations
            .get(at)
            .and_then(|(_, reservation)| reservation.device.as_ref())
            .map(|device| device.form)
    }

    /// The reservation at `at`, with its ID, no longer kept.
    fn take(&mut self, at: usize) -> Option<(Zeroizing<String>, Reservation)> {
        self.reservations.remove(at)
    }

    /// Where reservation `id` is, if it is kept.
    fn find(&self, id: &str) -> Option<usize> {
        self.reservations
            .iter()
            .position(|(held, _)| held.as_bytes() == id.as_bytes())
    }

    /// Whether the reservation at `at` waits for a device's signature.
    fn awaits_signature(&self, at: usize) -> bool {
        self.reservations
            .get(at)
            .is_some_and(|(_, reservation)| reservation.device.is_some())
    }

    fn remove(&mut self, at: usize) -> Option<Reservation> {
        self.reservations
            .remove(at)
            .map(|(_, reservation)| reservation)
    }
}

/// Signs a payment's digest. Every x402 signature goes through here, so a
/// test counts them (`FREEDOM_CORED_TEST_X402_SIGN_MARKER`; a no-op
/// without the `testhooks` feature).
fn sign(key: &Secp256k1Key, digest: &[u8; 32]) -> Result<[u8; 65], fc_evm::Error> {
    crate::testhooks::x402_signing();
    fc_evm::sign_digest(key.signing_key(), digest)
}

/// How the payment is authorized.
enum Authority {
    Token(Zeroizing<String>),
    Cap,
}

/// A paying device's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    Ledger,
    Phone,
}

/// `device: { kind, address }`: a Ledger or phone account's kind and
/// address, as ethers' `getAddress` gives it (any form `isAddress` takes,
/// as a record stores it and the reference's `paymentDevice` hands it
/// back).
fn device_of(value: &Value) -> Result<(DeviceKind, String), ErrorBody> {
    let device = object(value, &["kind", "address"], &[])?;
    let kind = match string(device, "kind")? {
        "ledger" => DeviceKind::Ledger,
        "phone" => DeviceKind::Phone,
        _ => return Err(invalid("device.kind: expected ledger or phone")),
    };
    let address = fc_wallet_state::normalize_address(string(device, "address")?)
        .ok_or_else(|| invalid("device.address: expected an address"))?;
    Ok((kind, address))
}

/// Once `vault_meta` is moved (G20): the paying device as the account's
/// record names it (the reference's `paymentDevice`), which the request's
/// must be, its address the same as `getAddress` gives both. A Safe has no
/// key, and an account the core can't name (no record at a hardware index,
/// a type it doesn't know) pays nothing.
fn recorded_device(
    recorded: &Account,
    claimed: Option<&(DeviceKind, String)>,
) -> Result<(), ErrorBody> {
    let expected = match recorded {
        Account::Vault => None,
        Account::Ledger(address) => Some((DeviceKind::Ledger, address)),
        Account::Phone(address) => Some((DeviceKind::Phone, address)),
        Account::Safe => {
            return Err(invalid(
                "account: a Safe can't pay an x402 payment (vault-meta.json)",
            ));
        }
        Account::Unknown => {
            return Err(invalid(
                "account: no account that can pay (vault-meta.json)",
            ));
        }
    };
    let agrees = match (expected, claimed) {
        (None, None) => true,
        // A record whose address isn't one agrees with no claim.
        (Some((kind, Some(recorded))), Some((claimed_kind, claimed))) => {
            kind == *claimed_kind && recorded == claimed
        }
        _ => false,
    };
    if agrees {
        Ok(())
    } else {
        Err(invalid("device: not the account's (vault-meta.json)"))
    }
}

/// `now_s` (design 0016, D2): main's wall-clock reading in whole seconds,
/// for a Ledger account's payment only, at most [`MAX_CLOCK_SKEW_S`] from
/// the core's own (`wall_s`).
fn main_clock(
    value: &Value,
    device: Option<&(DeviceKind, String)>,
    wall_s: u64,
) -> Result<u64, ErrorBody> {
    if !matches!(device, Some((DeviceKind::Ledger, _))) {
        return Err(invalid(
            "now_s: only a Ledger account's payment takes main's clock",
        ));
    }
    let now_s = value
        .as_u64()
        .ok_or_else(|| invalid("now_s: expected whole seconds"))?;
    if now_s.abs_diff(wall_s) > MAX_CLOCK_SKEW_S {
        return Err(invalid("now_s: more than 30 s from the core's clock"));
    }
    Ok(now_s)
}

/// fc-ledger's refusal before the first APDU: what a Ledger can't carry
/// is `device_failed` with its code (design 0016, API); anything else an
/// invalid request.
fn device_refusal(refusal: fc_ledger::Refusal) -> ErrorBody {
    match refusal.code() {
        Some(code) => crate::ledger::methods::device_failed(code),
        None => invalid(refusal.to_string()),
    }
}

/// A Ledger payment's refusal, its charge given back or not: `refunded`
/// beside the error's data, as a refused `{ signature }` has it; a cancel's
/// error keeps 0001's form, with no data.
fn with_refunded(mut error: ErrorBody, refunded: bool) -> ErrorBody {
    if error.code == ErrorCode::Cancelled {
        return error;
    }
    match &mut error.data {
        Some(Value::Object(data)) => {
            data.insert("refunded".to_owned(), json!(refunded));
        }
        Some(_) => {}
        None => error.data = Some(json!({ "refunded": refunded })),
    }
    error
}

/// A Ledger payment's operation (design 0016, D2), before the device:
/// main's `typed_data` equal to the reserved authorization, as JSON values;
/// account `account`'s Ledger record still the one whose address the
/// authorization names; and fc-ledger's operation over the reserved
/// authorization and its digest, which refuses what a Ledger can't carry.
fn ledger_operation(
    approvals: &Approvals,
    account: u32,
    reservation: &Reservation,
    typed_data: &Value,
) -> Result<Operation, ErrorBody> {
    let device = reservation
        .device
        .as_ref()
        .ok_or_else(crate::vault::internal)?;
    // The core's own text, read as the params are (`fc_evm::parse_json`),
    // so a value compares as JSON.parse reads it.
    let reserved =
        fc_evm::parse_json(device.built.typed_data()).map_err(|_| crate::vault::internal())?;
    if *typed_data != reserved {
        return Err(not_authorized(
            "mismatch",
            "typed_data: not the reserved authorization",
        ));
    }
    let record = approvals.ledger_account(account)?;
    if record.address != device.address {
        return Err(invalid("device: not the account's (vault-meta.json)"));
    }
    Operation::sign_typed_data(
        record,
        &reserved["domain"],
        &reserved["types"],
        &reserved["message"],
        &device.built.digest,
    )
    .map_err(device_refusal)
}

/// A reply's JSON text, as it is.
fn raw(text: String) -> Result<Box<serde_json::value::RawValue>, ErrorBody> {
    serde_json::value::RawValue::from_string(text).map_err(|_| crate::vault::internal())
}

/// A token's payment, once signed: the charge it took (and whether its
/// write was flushed), the grant's reply, and whether every write was.
type TokenPaid = (Option<(Held, bool)>, Option<Value>, bool);

impl Approvals {
    /// `x402.authorize`, `x402.settle` and `x402.update`. A presented token
    /// is burnt however the request ends, as `sign.*` burns one. A Ledger
    /// payment's `x402.settle { typed_data }` goes on to the device lane
    /// ([`X402Reply::Device`]).
    pub fn x402_request(
        &mut self,
        state: &VaultState,
        id: u64,
        method: &str,
        params: &Value,
        clocks: Clocks,
    ) -> Result<X402Reply, ErrorBody> {
        match method {
            "x402.authorize" => {
                let presented = super::presented_token(params, true);
                let reply = self.x402_authorize(state, id, params, clocks);
                if let Some(token) = presented {
                    self.tokens.discard(&token);
                }
                reply.map(X402Reply::Now)
            }
            "x402.settle" => self.x402_settle(id, params, clocks),
            "x402.update" => self.x402_update(id, params).map(X402Reply::Now),
            _ => Err(invalid("unknown method")),
        }
    }

    fn x402_authorize(
        &mut self,
        state: &VaultState,
        id: u64,
        params: &Value,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(
            params,
            &["account", "detection", "requirements", "authorization"],
            &["accept_index", "grant", "device", "now_s"],
        )?;
        if !self.grants.moved(StoreKind::X402) {
            return Err(not_moved(StoreKind::X402));
        }
        let account = super::account(fields.get("account"), "account")?;
        let device = fields.get("device").map(device_of).transpose()?;
        let wall_s = clocks.wall_ms / 1000;
        // Main's clock, for a Ledger account's payment (design 0016, D2).
        let now_s = fields
            .get("now_s")
            .map(|value| main_clock(value, device.as_ref(), wall_s))
            .transpose()?;
        // The account's own record, once `vault_meta` is moved (G20):
        // checked before anything is spent or charged. The vault pays only
        // for its own accounts (G20b): a mnemonic record in the hardware
        // range is refused as `withVaultAccount` refuses it, before any key.
        if let Some(recorded) = self.recorded(account)? {
            recorded_device(&recorded, device.as_ref())?;
            if recorded == Account::Vault {
                self.vault_signs(account)?;
            }
        }
        // A payment made with `now_s` is signed on the device lane with the
        // account's Ledger record (D9): `not_moved` before `vault_meta` is
        // moved, and the record's address the device's.
        if now_s.is_some() {
            let record = self.ledger_account(account)?;
            let claimed = device
                .as_ref()
                .and_then(|(_, address)| fc_wallet_state::normalized_bytes(address));
            if claimed != Some(record.address) {
                return Err(invalid("device: not the account's (vault-meta.json)"));
            }
        }
        // The authorization names 20 bytes: an address past them (an ICAP
        // past 2^160) can't pay, as the reference's signer would fail.
        let device = device
            .map(|(_, address)| {
                fc_wallet_state::normalized_bytes(&address)
                    .ok_or_else(|| invalid("device.address: not an address of 20 bytes"))
            })
            .transpose()?;
        let detection = object(&fields["detection"], &["tab", "id", "url"], &[])?;
        let origin = x402::cap_key(string(detection, "url")?)
            .ok_or_else(|| invalid("detection.url: x402 pays an http or https resource"))?;
        let requirements =
            Requirements::parse(&fields["requirements"]).map_err(|e| invalid(e.to_string()))?;
        let form = object(&fields["authorization"], &[], &["token", "cap"])?;
        let (authority, index) = match (form.get("token"), form.get("cap")) {
            (Some(_), None) => {
                let token = Zeroizing::new(string(form, "token")?.to_owned());
                let index = fields
                    .get("accept_index")
                    .and_then(Value::as_u64)
                    .and_then(|index| usize::try_from(index).ok())
                    .filter(|index| *index < requirements.accepts.len())
                    .ok_or_else(|| invalid("accept_index: no such entry"))?;
                (Authority::Token(token), index)
            }
            (None, Some(cap)) => {
                // Under a cap the core picks the entry, and no grant comes.
                if fields.contains_key("accept_index") || fields.contains_key("grant") {
                    return Err(invalid(
                        "accept_index and grant come only with an x402-payment token",
                    ));
                }
                let cap = object(cap, &["agent", "attributable"], &[])?;
                let flag = |name: &str| {
                    cap[name]
                        .as_bool()
                        .ok_or_else(|| invalid(format!("cap.{name}: expected a boolean")))
                };
                let (agent, attributable) = (flag("agent")?, flag("attributable")?);
                if agent {
                    return Err(not_authorized(
                        "custody",
                        "a cap pays nothing for a tab in Agent custody",
                    ));
                }
                if !attributable {
                    return Err(not_authorized(
                        "no_rule",
                        "a cap pays only for a request main attributes to a live tab",
                    ));
                }
                // What the open Ledger payments hold counts as spent.
                let store = self.grants.view::<CapStore>(wall_s);
                let holds = &self.x402;
                let (index, _) = store
                    .covering_beyond(&origin, requirements.accepts, wall_s, |key| {
                        holds.held(&origin, key)
                    })
                    .ok_or_else(|| not_authorized("cap", "no active cap covers this payment"))?;
                (Authority::Cap, index)
            }
            _ => {
                return Err(invalid(
                    "authorization: expected an x402-payment token or a cap",
                ));
            }
        };
        let accept = requirements.accepts[index].clone();
        let payment = Payment::new(requirements, index).map_err(|e| invalid(e.to_string()))?;
        let tuple = payment.tuple();
        // The token, after the public work: exactly this entry and grant,
        // for this tab, detection, URL and account.
        if let Authority::Token(token) = &authority {
            let mut payload = json!({
                "detection": fields["detection"],
                "accept_index": index,
                "accept": accept,
            });
            if let Some(grant) = fields.get("grant") {
                payload["grant"] = grant.clone();
            }
            self.tokens
                .spend_as(
                    Minter::Shell,
                    token,
                    &Request {
                        kind: Kind::X402Payment,
                        account: fields.get("account"),
                        payload: &payload,
                        page: None,
                    },
                    clocks.vault_ms,
                )
                .map_err(refusal)?;
        }
        // The vault's key, for the address the authorization names; wiped
        // on drop. A device's address is its record's once `vault_meta` is
        // moved, main's word before, and no key is used.
        let (key, from) = match device {
            Some(address) => (None, address),
            None => {
                let key = state
                    .user_wallet(account)
                    .map_err(crate::vault::locked_or_internal)?;
                let from = fc_evm::address_of(key.signing_key());
                (Some(key), from)
            }
        };
        let mut nonce = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(&mut *nonce)
            .map_err(|_| crate::vault::internal())?;
        crate::testhooks::x402_nonce(&mut nonce);
        // Every time byte on main's clock where it gave one (D2), else on
        // the core's (#392).
        let built = payment
            .build(&from, now_s.unwrap_or(wall_s), &nonce)
            .map_err(|e| invalid(e.to_string()))?;
        // A device's payment is held until its signature: one past a
        // frame's size isn't, before anything is charged.
        if key.is_none()
            && built.payload_with(&format!("0x{}", "0".repeat(130))).len() > MAX_DEVICE_PAYLOAD
        {
            return Err(invalid(
                "requirements: too large a payment to hold for a device",
            ));
        }
        // A cap's charge is written before anything is signed or handed to
        // a device: one the file lacks is not applied, and nothing is
        // signed (`x402-at-sign`). A Ledger payment made with `now_s` only
        // holds it, in memory, until its signature (D2): written then,
        // before the signature leaves ([`Self::x402_ledger_ended`]).
        let mut held = None;
        let mut hold = None;
        if let Authority::Cap = authority {
            let tuple = tuple
                .as_ref()
                .ok_or_else(|| not_authorized("cap", "no active cap covers this payment"))?;
            if now_s.is_some() {
                hold = Some(self.hold_charge(&origin, tuple, wall_s)?);
            } else {
                held =
                    Some(self.charge(&origin, tuple, wall_s, true)?.ok_or_else(|| {
                        not_authorized("cap", "no active cap covers this payment")
                    })?);
            }
        }
        let grant = fields.get("grant").filter(|g| !g.is_null());
        let Some(key) = key else {
            // A device's payment: the typed data and its hash, for the
            // device to sign; a token's grant and charge wait for it.
            let charged = held.is_some() || hold.is_some();
            let durable = held.as_ref().is_none_or(|held| held.1);
            let mut reply = json!({
                "device": {
                    "typed_data": raw(built.typed_data().to_owned())?,
                    "hash": fc_evm::to_hex(&built.digest),
                },
                "accept_index": index,
                "charged": charged,
            });
            let token_grant = match authority {
                Authority::Token(_) => Some(grant.cloned()),
                Authority::Cap => None,
            };
            let by_cap = matches!(authority, Authority::Cap);
            let reservation = self.x402.reserve(Reservation {
                held: held.map(|(held, _)| held),
                hold,
                by_cap,
                device: Some(Box::new(Device {
                    built,
                    address: from,
                    origin,
                    tuple,
                    token_grant,
                    form: now_s.map_or(Form::Signature, |_| Form::Ledger { account }),
                })),
            })?;
            reply["reservation"] = json!(reservation.as_str());
            if !durable {
                reply["durable"] = json!(false);
            }
            return secret_reply(id, &reply, 0);
        };
        let signature = sign(&key, &built.digest).map_err(|_| crate::vault::internal())?;
        drop(key);
        let payload = built.payload(&signature);
        let mut durable = held.as_ref().is_none_or(|held| held.1);
        let mut grant_reply = None;
        if let Authority::Token(_) = authority {
            let (charged, reply, flushed) = self.token_paid(&origin, tuple.as_ref(), grant, wall_s);
            held = charged;
            grant_reply = reply;
            durable &= flushed;
        }
        let charged = held.is_some();
        let reservation = self.x402.reserve(Reservation {
            held: held.map(|(held, _)| held),
            hold: None,
            by_cap: matches!(authority, Authority::Cap),
            device: None,
        })?;
        let mut reply = json!({
            "payload": raw(payload)?,
            "reservation": reservation.as_str(),
            "accept_index": index,
            "charged": charged,
        });
        if let Some(grant) = grant_reply {
            reply["grant"] = grant;
        }
        if !durable {
            reply["durable"] = json!(false);
        }
        secret_reply(id, &reply, 0)
    }

    /// A token's payment, once signed: the grant that came with it, as
    /// bound, then a cap that covers the payment charged, the one just
    /// granted included. The payment stands either way.
    fn token_paid(
        &mut self,
        origin: &str,
        tuple: Option<&x402::Tuple>,
        grant: Option<&Value>,
        wall_s: u64,
    ) -> TokenPaid {
        let Some(tuple) = tuple else {
            return (None, None, true);
        };
        let mut durable = true;
        let mut grant_reply = None;
        if let Some(grant) = grant {
            let (reply, flushed) = self.x402_grant(origin, tuple, grant, wall_s);
            durable &= flushed;
            grant_reply = Some(reply);
        }
        let held = match self.charge(origin, tuple, wall_s, false) {
            Ok(charged) => charged,
            // A narrowing that wasn't saved stands in memory; the
            // reservation can't give it back.
            Err(_) => {
                durable = false;
                None
            }
        };
        if let Some(held) = &held {
            durable &= held.1;
        }
        (held, grant_reply, durable)
    }

    /// Charges the cap covering `tuple`'s amount. `before_signing`: the
    /// charge is applied only once written (`x402-at-sign`); otherwise, as
    /// any narrowing, it stands in memory when its write fails. The charge
    /// and whether its write was flushed.
    fn charge(
        &mut self,
        origin: &str,
        tuple: &x402::Tuple,
        wall_s: u64,
        before_signing: bool,
    ) -> Result<Option<(Held, bool)>, ErrorBody> {
        let key = tuple.key();
        let Some(generation) = self.x402.generation(origin, &key) else {
            return Ok(None);
        };
        // What the open Ledger payments hold counts as spent (D2).
        let holds = self.x402.held(origin, &key);
        let written = self.write::<CapStore, _>(origin, |store| {
            let mut applied = store.charge_beyond(origin, &key, &tuple.amount, wall_s, holds);
            if before_signing && applied.value.is_some() {
                applied.effect = Effect::Widening;
            }
            applied
        })?;
        Ok(written
            .value
            .map(|charge| (Held { charge, generation }, written.durable)))
    }

    /// A Ledger payment's charge held against the cap covering `tuple`
    /// (design 0016, D2): checked as a charge is, the open holds counted as
    /// spent, and kept in memory only. Its number.
    fn hold_charge(
        &mut self,
        origin: &str,
        tuple: &x402::Tuple,
        wall_s: u64,
    ) -> Result<u64, ErrorBody> {
        let key = tuple.key();
        let uncovered = || not_authorized("cap", "no active cap covers this payment");
        let generation = self.x402.generation(origin, &key).ok_or_else(uncovered)?;
        let cap = self
            .grants
            .view::<CapStore>(wall_s)
            .active(origin, &key, wall_s)
            .ok_or_else(uncovered)?;
        let amount = x402::atomic(&tuple.amount).ok_or_else(uncovered)?;
        let all = cap
            .spent
            .checked_add(&self.x402.held(origin, &key))
            .and_then(|taken| taken.checked_add(&amount));
        if all.is_none_or(|all| all > cap.cap) {
            return Err(uncovered());
        }
        Ok(self.x402.hold(Hold {
            origin: origin.to_owned(),
            key,
            amount: tuple.amount.clone(),
            generation,
            at_s: wall_s,
        }))
    }

    /// A Ledger payment's held charge written, once fc-ledger has checked
    /// the device's signature and before the signature leaves (design
    /// 0016, D2): only to the cap it was held against, at the clock it was
    /// held at, the other open holds counted; and applied only once
    /// written (`x402-at-sign`), so a charge the file lacks releases
    /// nothing. The charge and whether its write was flushed; or the
    /// refusal, with whether the hold's room is back on its cap.
    fn write_hold(&mut self, hold: Hold) -> Result<(Held, bool), (ErrorBody, bool)> {
        if !self.x402.stands(&hold) {
            return Err((
                not_authorized(
                    "cap_changed",
                    "the cap this payment was held against was revoked or granted again",
                ),
                false,
            ));
        }
        let others = self.x402.held(&hold.origin, &hold.key);
        let Hold {
            origin,
            key,
            amount,
            generation,
            at_s,
        } = hold;
        let written = self
            .write::<CapStore, _>(&origin, |store| {
                let mut applied = store.charge_beyond(&origin, &key, &amount, at_s, others);
                if applied.value.is_some() {
                    applied.effect = Effect::Widening;
                }
                applied
            })
            .map_err(|error| (error, true))?;
        let charge = written.value.ok_or_else(|| {
            (
                not_authorized("cap", "the cap no longer covers this payment"),
                true,
            )
        })?;
        Ok((Held { charge, generation }, written.durable))
    }

    /// The grant a token bound: `{ cap_amount, window_seconds }` for the
    /// paid entry's chain and asset, under the paid URL's origin. Its
    /// reply, and whether its write was flushed.
    fn x402_grant(
        &mut self,
        origin: &str,
        tuple: &x402::Tuple,
        grant: &Value,
        wall_s: u64,
    ) -> (Value, bool) {
        let key = tuple.key();
        let cap = grant
            .get("cap_amount")
            .and_then(Value::as_str)
            .unwrap_or("");
        let window = grant
            .get("window_seconds")
            .and_then(Value::as_f64)
            .unwrap_or(f64::NAN);
        let written = self.write::<CapStore, _>(origin, |store| {
            store.grant(origin, &key, cap, window, wall_s)
        });
        match written {
            Ok(written) if written.value.is_some() => {
                self.x402.granted(origin, &key);
                let mut reply = json!({ "added": true });
                if !written.durable {
                    reply["durable"] = json!(false);
                }
                (reply, written.durable)
            }
            Ok(_) => (json!({ "added": false, "reason": "invalid" }), true),
            Err(error) => {
                let reason = if error.code == fc_protocol::error::ErrorCode::Storage {
                    "not_saved"
                } else {
                    "bounds"
                };
                (json!({ "added": false, "reason": reason }), true)
            }
        }
    }

    fn x402_settle(
        &mut self,
        id: u64,
        params: &Value,
        clocks: Clocks,
    ) -> Result<X402Reply, ErrorBody> {
        let fields = object(
            params,
            &["reservation"],
            &["outcome", "signature", "typed_data"],
        )?;
        if !self.grants.moved(StoreKind::X402) {
            return Err(not_moved(StoreKind::X402));
        }
        let reservation = string(fields, "reservation")?;
        let withheld = match (
            fields.get("outcome"),
            fields.get("signature"),
            fields.get("typed_data"),
        ) {
            (None, Some(signature), None) => {
                return self
                    .x402_signed(id, reservation, signature, clocks)
                    .map(X402Reply::Now);
            }
            (None, None, Some(typed_data)) => {
                return self.x402_ledger(reservation, typed_data);
            }
            (Some(_), None, None) => match string(fields, "outcome")? {
                "withheld" => true,
                "sent" => false,
                _ => return Err(invalid("outcome: expected withheld or sent")),
            },
            _ => {
                return Err(invalid(
                    "expected an outcome, a device's signature or a Ledger's typed data",
                ));
            }
        };
        let at = self
            .x402
            .find(reservation)
            .ok_or_else(|| invalid("reservation: unknown"))?;
        // A device's payment can't have been sent before its signature
        // came: the reservation stays for its signature or `withheld`.
        if !withheld && self.x402.awaits_signature(at) {
            return Err(invalid(
                "outcome: a device's payment is sent only once its signature is checked",
            ));
        }
        let Some(taken) = self.x402.remove(at) else {
            return Err(crate::vault::internal());
        };
        // A Ledger payment's held charge (D2), only ever withheld here: it
        // goes, with nothing to write; its room is back while its cap
        // stands.
        if let Some(hold) = self.x402.release(taken.hold) {
            let refunded = self.x402.stands(&hold);
            return json_reply(id, &json!({ "refunded": refunded })).map(X402Reply::Now);
        }
        // A cap's payment goes out only while the cap it was charged to
        // stands: one revoked, or revoked and granted again, since tells
        // main to withhold it. Its charge isn't moved to the new cap, and
        // the reservation is spent (*inferred*).
        if !withheld
            && taken.by_cap
            && let Some(held) = &taken.held
            && self.x402.generation(&held.charge.origin, &held.charge.key) != Some(held.generation)
        {
            return Err(not_authorized(
                "cap_changed",
                "the cap this payment was charged to was revoked or granted again: withhold it",
            ));
        }
        let Some(held) = taken.held.filter(|_| withheld) else {
            return json_reply(id, &json!({ "refunded": false })).map(X402Reply::Now);
        };
        let (refunded, durable) = self.give_back(held)?;
        let mut reply = json!({ "refunded": refunded });
        if !durable {
            reply["durable"] = json!(false);
        }
        json_reply(id, &reply).map(X402Reply::Now)
    }

    /// A charge given back, only to the cap it was taken from: not one
    /// revoked or granted again since. A widening: one the file lacks
    /// isn't applied, and the charge stands. Whether it was given back,
    /// and whether its write was flushed.
    fn give_back(&mut self, held: Held) -> Result<(bool, bool), ErrorBody> {
        let Held { charge, generation } = held;
        if self.x402.generation(&charge.origin, &charge.key) != Some(generation) {
            return Ok((false, true));
        }
        let origin = charge.origin.clone();
        let written = self.write::<CapStore, _>(&origin, |store| store.refund(&charge))?;
        Ok((written.value, written.durable))
    }

    /// `x402.settle { reservation, signature }`: a device's signature for
    /// its payment (core #392), checked as PHN-1 checks a phone's. Taken,
    /// it gives the payload, writes a token's grant and charges its cap,
    /// and the reservation waits for its outcome. Refused, the reservation
    /// is spent and its charge given back, as `withheld` gives it.
    fn x402_signed(
        &mut self,
        id: u64,
        reservation: &str,
        signature: &Value,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let at = self
            .x402
            .find(reservation)
            .ok_or_else(|| invalid("reservation: unknown"))?;
        if !self.x402.awaits_signature(at) {
            return Err(invalid("reservation: no device's signature is awaited"));
        }
        // A Ledger's payment made with `now_s` is signed on the device lane,
        // never taken from main (design 0016, D2).
        if self.x402.form(at) != Some(Form::Signature) {
            return Err(invalid(
                "reservation: a Ledger payment made with now_s is settled with its typed_data",
            ));
        }
        let Some(device) = self
            .x402
            .reservations
            .get_mut(at)
            .and_then(|(_, reservation)| reservation.device.take())
        else {
            return Err(crate::vault::internal());
        };
        let text = match fc_approval::phone::check_signature(
            signature,
            &device.built.digest,
            &device.address,
        ) {
            Ok(text) => text.to_owned(),
            Err(refused) => {
                let held = self.x402.remove(at).and_then(|taken| taken.held);
                let refunded = match held {
                    // A refund whose write fails leaves the charge.
                    Some(held) => self.give_back(held).is_ok_and(|(refunded, _)| refunded),
                    None => false,
                };
                return Err(ErrorBody::new(
                    fc_protocol::error::ErrorCode::NotAuthorized,
                    "the device's signature is refused",
                )
                .with_data(json!({ "reason": refused.reason(), "refunded": refunded })));
            }
        };
        let payload = device.built.payload_with(&text);
        let mut durable = true;
        let mut grant_reply = None;
        if let Some(grant) = &device.token_grant {
            let (held, reply, flushed) = self.token_paid(
                &device.origin,
                device.tuple.as_ref(),
                grant.as_ref(),
                clocks.wall_ms / 1000,
            );
            durable &= flushed;
            grant_reply = reply;
            if let Some((_, reservation)) = self.x402.reservations.get_mut(at) {
                reservation.held = held.map(|(held, _)| held);
            }
        }
        let charged = self
            .x402
            .reservations
            .get(at)
            .is_some_and(|(_, reservation)| reservation.held.is_some());
        let mut reply = json!({ "payload": raw(payload)?, "charged": charged });
        if let Some(grant) = grant_reply {
            reply["grant"] = grant;
        }
        if !durable {
            reply["durable"] = json!(false);
        }
        secret_reply(id, &reply, 0)
    }

    /// `x402.settle { reservation, typed_data }` (design 0016, D2): main's
    /// rebuild of a Ledger payment made with `now_s`, which must equal the
    /// reserved authorization. Then fc-ledger's operation over the reserved
    /// one, with the account's record, for the device lane; the reservation
    /// goes with it ([`Settling`]). From the reservation found on, any
    /// refusal drops its held charge and spends it, before the device.
    fn x402_ledger(&mut self, id: &str, typed_data: &Value) -> Result<X402Reply, ErrorBody> {
        let at = self
            .x402
            .find(id)
            .ok_or_else(|| invalid("reservation: unknown"))?;
        let account = match self.x402.form(at) {
            Some(Form::Ledger { account }) => account,
            Some(Form::Signature) => {
                return Err(invalid(
                    "reservation: made without now_s, it is settled with the device's signature",
                ));
            }
            None => return Err(invalid("reservation: no device's signature is awaited")),
        };
        let Some((id, reservation)) = self.x402.take(at) else {
            return Err(crate::vault::internal());
        };
        match ledger_operation(self, account, &reservation, typed_data) {
            Ok(operation) => Ok(X402Reply::Device(Box::new(LedgerPayment {
                operation,
                settling: Settling { id, reservation },
            }))),
            Err(error) => Err(self.x402_spent(reservation, error)),
        }
    }

    /// A Ledger payment that ends without a signature: its held charge
    /// dropped with nothing written (or a written one given back, to the
    /// cap it was taken from, if that cap stands), and the reservation
    /// spent. The error, with `refunded`: whether the charge's room is back
    /// on its cap.
    fn x402_spent(&mut self, reservation: Reservation, error: ErrorBody) -> ErrorBody {
        // A held charge (D2) goes with nothing written: its room is back
        // while its cap stands.
        if let Some(hold) = self.x402.release(reservation.hold) {
            let refunded = self.x402.stands(&hold);
            return with_refunded(error, refunded);
        }
        let refunded = match reservation.held {
            // A refund whose write fails leaves the charge.
            Some(held) => self.give_back(held).is_ok_and(|(refunded, _)| refunded),
            None => false,
        };
        with_refunded(error, refunded)
    }

    /// Request `id`'s Ledger payment, once its operation ended (design
    /// 0016, D2): with the device's signature, which fc-ledger recovered to
    /// the record's address over the reserved digest, the payload, a
    /// token's grant written and its cap charged, as `{ signature }` does;
    /// the reservation is kept again and waits for its outcome. A cap's
    /// held charge is written first ([`Self::write_hold`]), and one that
    /// can't be written releases nothing. Otherwise (the device's refusal
    /// or failure, the lane's end, a cancel) the held charge goes with
    /// nothing written, and the reservation is spent.
    pub fn x402_ledger_ended(
        &mut self,
        id: u64,
        settling: Settling,
        ended: Result<fc_ledger::Signed, ErrorBody>,
        clocks: Clocks,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let Settling {
            id: kept,
            mut reservation,
        } = settling;
        let signature = match ended {
            Ok(fc_ledger::Signed::Signature(signature)) => signature,
            // An operation ends with its own kind of result.
            Ok(_) => return Err(self.x402_spent(reservation, crate::vault::internal())),
            Err(error) => return Err(self.x402_spent(reservation, error)),
        };
        let Some(device) = reservation.device.take() else {
            return Err(self.x402_spent(reservation, crate::vault::internal()));
        };
        // A cap's held charge, written now, before anything of the
        // signature leaves: one the file lacks releases nothing, and the
        // reservation is spent. A crash between this write and the reply
        // charges once with nothing paid, the safe way round.
        let mut durable = true;
        if let Some(hold) = self.x402.release(reservation.hold.take()) {
            match self.write_hold(hold) {
                Ok((held, flushed)) => {
                    reservation.held = Some(held);
                    durable &= flushed;
                }
                Err((error, refunded)) => return Err(with_refunded(error, refunded)),
            }
        }
        let payload = device.built.payload(&signature);
        let mut grant_reply = None;
        if let Some(grant) = &device.token_grant {
            let (held, reply, flushed) = self.token_paid(
                &device.origin,
                device.tuple.as_ref(),
                grant.as_ref(),
                clocks.wall_ms / 1000,
            );
            durable &= flushed;
            grant_reply = reply;
            reservation.held = held.map(|(held, _)| held);
        }
        let charged = reservation.held.is_some();
        self.x402.keep(kept, reservation);
        let mut reply = json!({ "payload": raw(payload)?, "charged": charged });
        if let Some(grant) = grant_reply {
            reply["grant"] = grant;
        }
        if !durable {
            reply["durable"] = json!(false);
        }
        secret_reply(id, &reply, 0)
    }

    /// `x402.update { key, cap: { chain_id, asset }, cap_amount?,
    /// window_seconds? }` (core #392): a narrowing of one cap, as the
    /// activity pane asks it. Each field given must narrow: a lower amount,
    /// in decimal digits with no leading zero; a window, whole seconds from
    /// the cap's `createdAt`, that ends sooner. Anything equal or wider is
    /// `forbidden`, a cap that isn't there `invalid_argument`, and either
    /// writes nothing. The reply is the cap as the file holds it.
    fn x402_update(&mut self, id: u64, params: &Value) -> Result<Zeroizing<Vec<u8>>, ErrorBody> {
        let fields = object(params, &["key", "cap"], &["cap_amount", "window_seconds"])?;
        if !self.grants.moved(StoreKind::X402) {
            return Err(not_moved(StoreKind::X402));
        }
        let key = string(fields, "key")?.to_owned();
        let asset_key = cap_asset_key(&fields["cap"])?;
        let cap_amount = fields
            .get("cap_amount")
            .map(|value| {
                value
                    .as_str()
                    .filter(|text| x402::canonical_amount(text).is_some())
                    .ok_or_else(|| {
                        invalid("cap_amount: expected decimal digits with no leading zero")
                    })
            })
            .transpose()?;
        let window = fields
            .get("window_seconds")
            .map(|value| {
                value
                    .as_u64()
                    .filter(|window| (1..=MAX_WINDOW_SECONDS).contains(window))
                    .ok_or_else(|| invalid("window_seconds: expected whole seconds, at least 1"))
            })
            .transpose()?;
        if cap_amount.is_none() && window.is_none() {
            return Err(invalid("expected cap_amount, window_seconds or both"));
        }
        let mut refused = None;
        let written = self.write::<CapStore, _>(&key, |store| {
            store
                .narrow(&key, &asset_key, cap_amount, window)
                .unwrap_or_else(|refusal| {
                    refused = Some(refusal);
                    Applied {
                        value: None,
                        effect: Effect::Unchanged,
                    }
                })
        })?;
        match refused {
            Some(NarrowRefusal::NoCap) => return Err(invalid("cap: no such cap")),
            Some(NarrowRefusal::NotNarrower) => {
                return Err(forbidden(
                    "a cap update only lowers the amount or shortens the window",
                ));
            }
            None => {}
        }
        let cap = written.value.ok_or_else(crate::vault::internal)?;
        let mut reply = json!({ "cap": js_json(&cap)? });
        if !written.durable {
            reply["durable"] = json!(false);
        }
        json_reply(id, &reply)
    }
}
